/*
 *  Connection Manager
 *
 *  Copyright (C) 2016-2019 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2016-2019 Slava Monich <slava.monich@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include "sailfish_datacounters.h"

#include <connman/wakeup_timer.h>
#include "connman.h"

#include <gutil_timenotify.h>
#include <gutil_idlepool.h>
#include <gutil_misc.h>

#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

G_STATIC_ASSERT(DATACOUNTER_PROPERTY_COUNT < 32);
G_STATIC_ASSERT(DATACOUNTER_PROPERTY_ANY == 0);

#define COUNTER_FILE_PREFIX             "stats."
#define COUNTER_SIGNIFICANT_BYTE_COUNT  (1024)
#define COUNTER_MAX_TIMER_MS            (INT_MAX)
#define COUNTER_MAX_TIMER_SEC           (COUNTER_MAX_TIMER_MS/1000)

struct datacounter_timer_storage {
	guint32 value;
	guint32 unit;
	guint8 at[8];
} __attribute__((packed));

/* File version 1, 72 bytes */
struct datacounter_file_contents_v1 {
	guint32 version;
	guint32 reserved;
	struct connman_stats_data total;
} __attribute__((packed));

/* File version 2, 208 bytes */
#define COUNTER_FILE_VERSION (2)
struct datacounter_file_contents {
	/* datacounter_file_contents_v1 starts */
	guint32 version;
	guint32 flags; /* Was reserved in v1 */
	struct connman_stats_data total;
	/* datacounter_file_contents_v1 ends */
	struct connman_stats_data baseline;
	gint64 reset_time;
	gint64 baseline_reset_time;
	gint64 last_update_time;
	guint64 data_warning;
	guint64 data_limit;
	struct datacounter_timer_storage time_limit;
	struct datacounter_timer_storage autoreset;
} __attribute__((packed));

G_STATIC_ASSERT(TIME_UNITS == 6);

#define COUNTER_FLAG_CUTOFF_ENABLED     (0x01)
#define COUNTER_FLAG_AUTORESET_ENABLED  (0x02)
#define COUNTER_FLAG_TIME_LIMIT_ENABLED (0x04)

#define COUNTER_DEADLINE_FLAGS (\
	COUNTER_FLAG_CUTOFF_ENABLED | \
	COUNTER_FLAG_TIME_LIMIT_ENABLED)

enum datacounter_change {
	COUNTER_CHANGE_NONE,
	COUNTER_CHANGE_MINOR,
	COUNTER_CHANGE_SIGNIFICANT
};

typedef struct datacounter DataCounter;
struct datacounter_priv {
	char *ident;
	char *name;
	char *path;
	char *key;
	GUtilTimeNotify *time_notify;
	GUtilIdlePool *idle_pool;
	GDateTime *last_update_time;
	gulong time_notify_id;
	gint64 cutoff_deadline;
	guint cutoff_timer_id;
	struct datacounter_file_contents storage;
	struct datacounter_timer autoreset;
	struct datacounter_timer time_limit;
	struct connman_stats_data last;
	const char **history_names;
	guint64 bytes_change;
	enum datacounter_change change;
	int changed_properties;
	guint short_write_timeout_id;
	guint long_write_timeout_id;
	guint autoreset_check_id;
};

typedef GObjectClass DataCounterClass;
G_DEFINE_TYPE(DataCounter, datacounter, G_TYPE_OBJECT)
#define PARENT_CLASS datacounter_parent_class
#define DATACOUNTER_TYPE (datacounter_get_type())
#define DATACOUNTER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	DATACOUNTER_TYPE, DataCounter))

enum datacounter_signal {
	SIGNAL_RESET,
	SIGNAL_UPDATE,
	SIGNAL_PROPERTY,
	SIGNAL_COUNT
};

#define SIGNAL_RESET_NAME               "datacounter-reset"
#define SIGNAL_UPDATE_NAME              "datacounter-update"
#define SIGNAL_PROPERTY_NAME            "datacounter-property"
#define SIGNAL_PROPERTY_DETAIL          "%x"
#define SIGNAL_PROPERTY_DETAIL_MAX_LEN  (8)

static guint datacounter_signal[SIGNAL_COUNT];

static void datacounter_autoreset_check(struct datacounter *self);
static void datacounter_deadline_check(struct datacounter *self);
static void datacounter_update_state(struct datacounter *self, gint64 now);
static void datacounter_save(struct datacounter *self);
static void datacounter_save_now(struct datacounter *self,
					enum datacounter_change change);

#define llu_(x) ((long long unsigned int)(x))
#define DBG_(self,format,args...) \
	DBG("%s/%s " format, (self)->ident, (self)->name, ##args)

static const guint datacounter_min_unit[TIME_UNIT_YEAR] = { 0, 0, 0, 1, 1 };

/*==========================================================================*
 * Implementation
 *==========================================================================*/

/*
 * Many functions queue property changes instead of emitting
 * signals right away, in order to make sure that by the time
 * the signal handlers are called, the object is in a consistent
 * state.
 */
static void datacounter_emit_property_change(struct datacounter *self,
					enum datacounter_property prop)
{
	/*
	 * Property quarks are cached here (in addition to being cached
	 * on the glib side) because the array lookup is obviously faster
	 * than a hashtable lookup and doesn't require string formatting,
	 * comparison or anything like that.
	 */
	static GQuark datacounter_property_quarks[DATACOUNTER_PROPERTY_COUNT];
	struct datacounter_priv *priv = self->priv;
	GQuark q = datacounter_property_quarks[prop];

	if (!q) {
		/* This is the first time this property has changed */
		char buf[SIGNAL_PROPERTY_DETAIL_MAX_LEN + 1];
		snprintf(buf, sizeof(buf), SIGNAL_PROPERTY_DETAIL, prop);
		buf[sizeof(buf)-1] = 0;
		q = g_quark_from_string(buf);
		datacounter_property_quarks[prop] = q;
	}
	/* Clear the change bit */
	priv->changed_properties &= ~(1 << prop);
	g_signal_emit(self, datacounter_signal[SIGNAL_PROPERTY], q, prop);
}

static void datacounter_emit_property_changes(struct datacounter *self)
{
	struct datacounter_priv *priv = self->priv;
	enum datacounter_property prop;

	for (prop = DATACOUNTER_PROPERTY_ANY;
	     prop < DATACOUNTER_PROPERTY_COUNT && priv->changed_properties;
	     prop++) {
		if (priv->changed_properties & (1 << prop)) {
			/* This call clears the change bit: */
			datacounter_emit_property_change(self, prop);
		}
	}
}

static inline void datacounter_queue_property_change(struct datacounter *self,
					enum datacounter_property prop)
{
	self->priv->changed_properties |= (1 << prop);
}

/* Serialize/deserialize datacounter_timer */
static void datacounter_timer_get(struct datacounter_timer *timer,
			const struct datacounter_timer_storage *storage)
{
	guint i;

	timer->value = storage->value;
	timer->unit = storage->unit;
	for (i=0; i<G_N_ELEMENTS(timer->at); i++) {
		timer->at[i] = storage->at[i];
	}
	datacounters_validate_timer(timer);
}

static gboolean datacounter_timer_put(const struct datacounter_timer *timer,
				struct datacounter_timer_storage *storage)
{
	guint i;
	gboolean changed = FALSE;

	if (storage->value != timer->value) {
		storage->value = timer->value;
		changed = TRUE;
	}
	if (storage->unit != timer->unit) {
		storage->unit = timer->unit;
		changed = TRUE;
	}
	for (i=0; i<G_N_ELEMENTS(timer->at); i++) {
		if (storage->at[i] != timer->at[i]) {
			storage->at[i] = timer->at[i];
			changed = TRUE;
		}
	}
	for (; i<G_N_ELEMENTS(storage->at); i++) {
		storage->at[i] = 0;
	}
	return changed;
}

/*
 * Formats the time and returns a pointer to the string which is going to be
 * deallocated once control returns to the glibe event loop. Exported mostly
 * for the purposes of unit-testing.
 */
const char *datacounter_format_time(struct datacounter *self, GDateTime *time)
{
	if (G_LIKELY(self) && G_LIKELY(time)) {
		struct datacounter_priv *priv = self->priv;
		char *str = g_date_time_format(time, "%F %H:%M:%S %z");

		if (!priv->idle_pool) {
			priv->idle_pool = gutil_idle_pool_new();
		}
		gutil_idle_pool_add(priv->idle_pool, str, g_free);
		return str;
	}
	return NULL;
}

const char *datacounter_format_time_now(struct datacounter *self)
{
	if (G_LIKELY(self)) {
		GDateTime *now = datacounters_time_now();
		const char *str = datacounter_format_time(self, now);

		g_date_time_unref(now);
		return str;
	}
	return NULL;
}

/*
 * datacounter_autoreset_check is called when the autoreset configuration
 * has changed, autoreset timeout has expired or the system time has changed.
 * Note that autoreset configuration assumes local time zone, while the last
 * reset time is stored in UTC.
 */

static void datacounter_do_reset_baseline(struct datacounter *self)
{
	struct datacounter_priv *priv = self->priv;
	const gint64 now = datacounters_now();
	struct connman_stats_data *baseline = &priv->storage.baseline;
	gboolean save_now = FALSE;

	if (memcmp(baseline, self->value, sizeof(*self->value))) {
		*baseline = *self->value;
		save_now = TRUE;
		datacounter_queue_property_change(self,
				DATACOUNTER_PROPERTY_BASELINE);
	}

	if (priv->storage.baseline_reset_time != now) {
		priv->storage.baseline_reset_time = now;
		save_now = TRUE;
		datacounter_queue_property_change(self,
				DATACOUNTER_PROPERTY_BASELINE_RESET_TIME);
	}

	datacounter_deadline_check(self);

	if (save_now) {
		datacounter_save_now(self, COUNTER_CHANGE_SIGNIFICANT);
	}

	datacounter_update_state(self, now);
}

static GDateTime *datacounter_timer_add_offset(GDateTime *t,
				const struct datacounter_timer *timer)
{
	g_date_time_ref(t);

	/*
	 * Add the required number of smaller units, starting from
	 * the longer ones.
	 */
	if (timer->unit > TIME_UNIT_SECOND) {
		int i;

		for (i = timer->unit-1; i >= TIME_UNIT_SECOND; i--) {
			guint value = timer->at[i];

			if (value != datacounter_min_unit[i]) {
				guint u[TIME_UNITS], u2[TIME_UNITS];
				GDateTime *t2;

				datacounters_time_to_units(u, t);
				t2 = datacounters_time_add(t, value -
						datacounter_min_unit[i], i);
				datacounters_time_to_units(u2, t2);

				/*
				 * If we add e.g. 30 days to Sep 1st, we
				 * end up in October. Reduce the number of
				 * days then. This should be a fairly rare
				 * occasion though.
				 */
				while (u2[i+1] != u[i+1] && value > 0) {
					value--;
					g_date_time_unref(t2);
					t2 = datacounters_time_add(t, value -
						datacounter_min_unit[i], i);
					datacounters_time_to_units(u2, t2);
				}
				g_date_time_unref(t);
				t = t2;
			}
		}
	}
	return t;
}

/*
 * If autoreset is set up to occur on 31st of each month, but the
 * month has less than 31 days, then we want the reset to happen
 * on the last day of that month, e.g. on 30th of September. That
 * complicates things a bit.
 */
static GDateTime *datacounter_timer_next(GDateTime *after,
				const struct datacounter_timer *timer)
{
	GTimeZone *local = g_time_zone_new_local();
	GDateTime *after_local = g_date_time_to_timezone(after, local);
	GDateTime *start = datacounters_time_normalize(after_local, local,
								timer->unit);
	/*
	 * After we add the offset, the time may end up less or greater
	 * than the 'after' time. If it's greater, we are done.
	 */
	GDateTime *next = datacounter_timer_add_offset(start, timer);
	if (g_date_time_difference(next, after_local) <= 0) {
		GDateTime *start2;

		/* Add the required number of time units */
		start2 = datacounters_time_add(start, timer->value,
								timer->unit);
		g_date_time_unref(next);
		next = datacounter_timer_add_offset(start2, timer);
		g_date_time_unref(start2);
	}

	g_date_time_unref(after_local);
	g_date_time_unref(start);
	g_time_zone_unref(local);
	return next;
}

static gboolean datacounter_autoreset_timeout(gpointer arg)
{
	struct datacounter *self = DATACOUNTER(arg);
	struct datacounter_priv *priv = self->priv;

	DBG_(self, "");
	priv->autoreset_check_id = 0;
	datacounter_autoreset_check(self);
	datacounter_emit_property_changes(self);
	return G_SOURCE_REMOVE;
}

static void datacounter_autoreset_check_enabled(struct datacounter *self)
{
	struct datacounter_priv *priv = self->priv;
	GDateTime *now = datacounters_time_now();
	GDateTime *last_utc = g_date_time_new_from_unix_utc
					(priv->storage.baseline_reset_time);
	GDateTime *next = datacounter_timer_next(last_utc, &priv->autoreset);
	GTimeSpan span;
	guint64 ms;

	DBG_(self, "now: %s next: %s",
				datacounter_format_time(self, now),
				datacounter_format_time(self, next));
	span = g_date_time_difference(next, now);
	if (span <= G_TIME_SPAN_MILLISECOND) {
		DBG_(self, "auto-reset activated");
		datacounter_do_reset_baseline(self);
		g_date_time_unref(now);
		g_date_time_unref(next);
		now = datacounters_time_now();
		next = datacounter_timer_next(now, &priv->autoreset);
		span = g_date_time_difference(next, now);
	}

	/* Schedule autoreset to happen at the right time in the future */
	if (priv->autoreset_check_id) {
		g_source_remove(priv->autoreset_check_id);
	}
	ms = (span + G_TIME_SPAN_MILLISECOND - 1)/G_TIME_SPAN_MILLISECOND;
	DBG_(self, "next autoreset at %s in %llu ms",
		datacounter_format_time(self, next), llu_(ms));
	if (ms > COUNTER_MAX_TIMER_MS) {
		ms = COUNTER_MAX_TIMER_MS;
		DBG_(self, "sleeping for %llu ms", llu_(ms));
	}
	priv->autoreset_check_id = connman_wakeup_timer_add((guint)ms,
			datacounter_autoreset_timeout, self);

	g_date_time_unref(last_utc);
	g_date_time_unref(next);
	g_date_time_unref(now);
}

static void datacounter_autoreset_check(struct datacounter *self)
{
	struct datacounter_priv *priv = self->priv;

	if (priv->storage.flags & COUNTER_FLAG_AUTORESET_ENABLED) {
		datacounter_autoreset_check_enabled(self);
	} else {
		/* Autoreset disabled, just cancel the timer */
		if (priv->autoreset_check_id) {
			g_source_remove(priv->autoreset_check_id);
			priv->autoreset_check_id = 0;
		}
	}
}

static char *datacounter_file_path(const char *ident, const char *suffix)
{
	return g_strconcat(STORAGEDIR, G_DIR_SEPARATOR_S, ident,
			G_DIR_SEPARATOR_S, COUNTER_FILE_PREFIX, suffix, NULL);
}

static gboolean datacounter_file_read(const char *path,
				struct datacounter_file_contents *contents)
{
	gboolean ok = false;
	int fd = open(path, O_RDONLY);

	if (fd >= 0) {
		ssize_t nbytes;
		struct datacounter_file_contents buf;

		memset(&buf, 0, sizeof(buf));
		nbytes = read(fd, &buf, sizeof(buf));
		if (nbytes == sizeof(struct datacounter_file_contents_v1) &&
						buf.version == 1) {
			/* File saved by jolla-stats.c */
			DBG("%s version 1", path);
			buf.version = COUNTER_FILE_VERSION;
			buf.flags = 0; /* Just in case, should already be 0 */
			buf.baseline = buf.total;
			buf.baseline_reset_time = datacounters_now();
			nbytes = sizeof(buf);
		}
		if (nbytes == sizeof(buf)) {
			if (buf.version == COUNTER_FILE_VERSION) {
				DBG("%s", path);
				DBG("[RX] %llu packets %llu bytes",
					llu_(buf.total.rx_packets),
					llu_(buf.total.rx_bytes));
				DBG("[TX] %llu packets %llu bytes",
					llu_(buf.total.tx_packets),
					llu_(buf.total.tx_bytes));
				*contents = buf;
				ok = true;
			} else {
				connman_error("%s: unexpected version (%u)",
					path, buf.version);
			}
		} else if (nbytes >= 0) {
			connman_error("%s: failed to read (%u bytes)",
				path, (unsigned int) nbytes);
		} else {
			connman_error("%s: %s", path, strerror(errno));
		}
		close(fd);
	}
	return ok;
}

static gboolean datacounter_file_write(const char *path,
			const struct datacounter_file_contents *contents)
{
	gboolean ok = false;
	int fd = open(path, O_RDWR | O_CREAT, STORAGE_FILE_MODE);

	if (fd >= 0) {
		int err = ftruncate(fd, sizeof(*contents));
		if (err >= 0) {
			ssize_t nbytes = write(fd, contents, sizeof(*contents));

			if (nbytes == sizeof(*contents)) {
				DBG("%s", path);
				ok = true;
			} else if (nbytes >= 0) {
				DBG("%s: failed to write (%u bytes)",
					path, (unsigned int) nbytes);
			} else {
				DBG("%s: %s", path, strerror(errno));
			}
		} else {
			DBG("%s: %s", path, strerror(errno));
		}
		close(fd);
	} else {
		DBG("%s: %s", path, strerror(errno));
	}
	return ok;
}

static gboolean datacounter_short_save_timeout(gpointer data)
{
	struct datacounter *self = data;
	struct datacounter_priv *priv = self->priv;

	DBG_(self, "");
	priv->short_write_timeout_id = 0;
	if (priv->change > COUNTER_CHANGE_MINOR) {
		datacounter_save(self);
	}

	return G_SOURCE_REMOVE;
}

static gboolean datacounter_long_save_timeout(gpointer data)
{
	struct datacounter *self = data;
	struct datacounter_priv *priv = self->priv;

	DBG_(self, "");
	priv->long_write_timeout_id = 0;
	if (priv->change > COUNTER_CHANGE_NONE) {
		datacounter_save(self);
	}

	return G_SOURCE_REMOVE;
}

static void datacounter_save(struct datacounter *self)
{
	struct datacounter_priv *priv = self->priv;

	/* If datacounter_file_write fails, priv->change remains untouched */
	if (datacounter_file_write(priv->path, &priv->storage)) {
		priv->bytes_change = 0;
		priv->change = COUNTER_CHANGE_NONE;
	}

	/* Reset the timeouts */
	if (priv->short_write_timeout_id) {
		g_source_remove(priv->short_write_timeout_id);
	}
	if (priv->long_write_timeout_id) {
		g_source_remove(priv->long_write_timeout_id);
	}

	/* Short timeout prohibits any saves */
	priv->short_write_timeout_id =
		g_timeout_add_seconds(STATS_SHORT_WRITE_PERIOD_SEC,
				datacounter_short_save_timeout, self);

	/* Long timeout prohibits insignificant saves */
	priv->long_write_timeout_id =
		g_timeout_add_seconds(STATS_LONG_WRITE_PERIOD_SEC,
				datacounter_long_save_timeout, self);
}

static void datacounter_save_now(struct datacounter *self,
					enum datacounter_change change)
{
	/* If save fails, the change is kept in priv->change */
	struct datacounter_priv *priv = self->priv;

	priv->change = MAX(priv->change, change);
	datacounter_save(self);
}

/* Recalculate the state and queue property changes */
static void datacounter_update_state(struct datacounter *self, gint64 now)
{
	enum datacounter_cutoff_state state;
	struct datacounter_priv *priv = self->priv;
	const struct datacounter_file_contents *storage = &priv->storage;

	if (!(storage->flags & COUNTER_FLAG_CUTOFF_ENABLED)) {
		state = CUTOFF_DISABLED;
	} else if (!priv->cutoff_deadline &&
				!storage->data_warning &&
				!storage->data_limit) {
		state = CUTOFF_NO_LIMIT;
	} else {
		const struct connman_stats_data *value = self->value;
		const struct connman_stats_data *baseline = self->baseline;
		guint64 total_bytes = 0;

		if (value->rx_bytes > baseline->rx_bytes) {
			total_bytes += value->rx_bytes - baseline->rx_bytes;
		}
		if (value->tx_bytes > baseline->tx_bytes) {
			total_bytes += value->tx_bytes - baseline->tx_bytes;
		}

		if ((storage->data_limit &&
				total_bytes >= storage->data_limit) ||
				(priv->cutoff_deadline &&
					now >= priv->cutoff_deadline)) {
			if (priv->cutoff_timer_id) {
				/*
				 * If cut-off has been activated. We can stop
				 * the deadline timer, there's no use for it
				 * any more.
				 */
				g_source_remove(priv->cutoff_timer_id);
				priv->cutoff_timer_id = 0;
			}
			state = CUTOFF_ACTIVATED;
		} else if (storage->data_warning &&
					total_bytes >= storage->data_warning) {
			state = CUTOFF_WARNING;
		} else {
			state = CUTOFF_BELOW_LIMIT;
		}
	}

	if (self->cutoff_state != state) {
		DBG_(self, "cutoff state %d -> %d", self->cutoff_state, state);
		self->cutoff_state = state;
		datacounter_queue_property_change(self,
					DATACOUNTER_PROPERTY_CUTOFF_STATE);
	}
}

static void datacounter_state_property_changed(struct datacounter *self,
					enum datacounter_property prop)
{
	datacounter_queue_property_change(self, prop);
	datacounter_save_now(self, COUNTER_CHANGE_SIGNIFICANT);
	datacounter_update_state(self, datacounters_now());
	datacounter_emit_property_changes(self);
}

static gboolean datacounter_deadline_timeout(gpointer user_data)
{
	struct datacounter *self = DATACOUNTER(user_data);
	struct datacounter_priv *priv = self->priv;

	DBG_(self, "");
	priv->cutoff_timer_id = 0;
	datacounter_deadline_check(self);
	datacounter_emit_property_changes(self);
	return G_SOURCE_REMOVE;
}

static void datacounter_deadline_check(struct datacounter *self)
{
	struct datacounter_priv *priv = self->priv;
	const gint64 now = datacounters_now();
	gint64 deadline;

	if ((priv->storage.flags & COUNTER_DEADLINE_FLAGS) ==
						COUNTER_DEADLINE_FLAGS) {
		GTimeZone *utc = g_time_zone_new_utc();
		GDateTime *last_utc = g_date_time_new_from_unix_utc
					(priv->storage.baseline_reset_time);
		GDateTime *stop = datacounter_timer_next(last_utc,
							&priv->time_limit);
		GDateTime *stop_utc = g_date_time_to_timezone(stop, utc);

		deadline = g_date_time_to_unix(stop_utc);
		g_date_time_unref(stop);
		g_date_time_unref(stop_utc);
		g_date_time_unref(last_utc);
		g_time_zone_unref (utc);
	} else {
		DBG_(self, "disabled");
		deadline = 0;
	}

	if (priv->cutoff_deadline != deadline || deadline > now) {
		priv->cutoff_deadline = deadline;
		if (deadline) {
			datacounter_update_state(self, now);
			if (deadline > now) {
				guint64 sec;

				/* Set up new timer */
				if (priv->cutoff_timer_id) {
					g_source_remove(priv->cutoff_timer_id);
				}
				sec = deadline - now;
				DBG_(self, "cutoff deadline in %llu s",
								llu_(sec));
				if (sec > COUNTER_MAX_TIMER_SEC) {
					sec = COUNTER_MAX_TIMER_SEC;
					DBG_(self, "sleeping for %llu s",
								llu_(sec));
				}
				priv->cutoff_timer_id =
					connman_wakeup_timer_add_seconds(sec,
						datacounter_deadline_timeout,
						self);
			}
		} else if (priv->cutoff_timer_id) {
			g_source_remove(priv->cutoff_timer_id);
			priv->cutoff_timer_id = 0;
		}
	} else {
		datacounter_update_state(self, now);
	}
}

static void datacounter_time_notify_cb(GUtilTimeNotify *notify, void *arg)
{
	struct datacounter *self = DATACOUNTER(arg);

	DBG_(self, "");
	datacounter_deadline_check(self);
	datacounter_autoreset_check(self);
	datacounter_emit_property_changes(self);
}

/* Returns TRUE if the flag has changed (needs to check the self pointer) */
static gboolean datacounter_set_state_flag(struct datacounter *self,
						gboolean on, guint32 flag)
{
	if (G_LIKELY(self)) {
		struct datacounter_priv *priv = self->priv;
		const gboolean is_on = (priv->storage.flags & flag) == flag;

		if (is_on != on) {
			if (on) {
				priv->storage.flags |= flag;
			} else {
				priv->storage.flags &= ~flag;
			}
			return TRUE;
		}
	}
	return FALSE;
}

/* Protection against counters getting wrapped at 32-bit boundary */
#define STATS_UPPER_BITS_SHIFT (32)
#define STATS_UPPER_BITS (~((1ull << STATS_UPPER_BITS_SHIFT) - 1))
#define datacounter_32bit(value) (((value) & STATS_UPPER_BITS) == 0)

static void datacounter_fix32(guint64 *newval, guint64 oldval)
{
	if (*newval < oldval) {
		const guint64 prev = *newval;

		*newval |= (oldval & STATS_UPPER_BITS);

		if (G_UNLIKELY(*newval < oldval)) {
			*newval += (1ull << STATS_UPPER_BITS_SHIFT);
		}

		DBG("0x%08llx -> 0x%llx", llu_(prev), llu_(*newval));
	}
}

static const struct connman_stats_data *datacounter_fix(
				const struct connman_stats_data *data,
				const struct connman_stats_data *last,
				struct connman_stats_data *fixed)
{
	if ((data->rx_packets < last->rx_packets) ||
	    (data->tx_packets < last->tx_packets) ||
	    (data->rx_bytes   < last->rx_bytes  ) ||
	    (data->tx_bytes   < last->tx_bytes  ) ||
	    (data->rx_errors  < last->rx_errors ) ||
	    (data->tx_errors  < last->tx_errors ) ||
	    (data->rx_dropped < last->rx_dropped) ||
	    (data->tx_dropped < last->tx_dropped)) {

		/*
		 * This can happen if the counter wasn't rebased after
		 * switching the network interface. However most likely
		 * it's the result of 32-bit wrap-around that occurs in
		 * (at least some versions of) 32-bit kernels. Double
		 * check that all the upper 32-bits in all counters are
		 * indeed zero.
		 */

		if (G_UNLIKELY(!datacounter_32bit(data->rx_packets)) ||
		    G_UNLIKELY(!datacounter_32bit(data->tx_packets)) ||
		    G_UNLIKELY(!datacounter_32bit(data->rx_bytes  )) ||
		    G_UNLIKELY(!datacounter_32bit(data->tx_bytes  )) ||
		    G_UNLIKELY(!datacounter_32bit(data->rx_errors )) ||
		    G_UNLIKELY(!datacounter_32bit(data->tx_errors )) ||
		    G_UNLIKELY(!datacounter_32bit(data->rx_dropped)) ||
		    G_UNLIKELY(!datacounter_32bit(data->tx_dropped))) {
			DBG("counter is screwed up");
			return NULL;
		}

		*fixed = *data;
		data = fixed;

		datacounter_fix32(&fixed->rx_packets, last->rx_packets);
		datacounter_fix32(&fixed->tx_packets, last->tx_packets);
		datacounter_fix32(&fixed->rx_bytes,   last->rx_bytes  );
		datacounter_fix32(&fixed->tx_bytes,   last->tx_bytes  );
		datacounter_fix32(&fixed->rx_errors,  last->rx_errors );
		datacounter_fix32(&fixed->tx_errors,  last->tx_errors );
		datacounter_fix32(&fixed->rx_dropped, last->rx_dropped);
		datacounter_fix32(&fixed->tx_dropped, last->tx_dropped);
	}
	return data;
}

static void datacounter_sub(const struct connman_stats_data *minuend,
				const struct connman_stats_data *subtrahend,
				struct connman_stats_data *diff)
{
	diff->rx_packets = minuend->rx_packets - subtrahend->rx_packets;
	diff->tx_packets = minuend->tx_packets - subtrahend->tx_packets;
	diff->rx_bytes   = minuend->rx_bytes   - subtrahend->rx_bytes;
	diff->tx_bytes   = minuend->tx_bytes   - subtrahend->tx_bytes;
	diff->rx_errors  = minuend->rx_errors  - subtrahend->rx_errors;
	diff->tx_errors  = minuend->tx_errors  - subtrahend->tx_errors;
	diff->rx_dropped = minuend->rx_dropped - subtrahend->rx_dropped;
	diff->tx_dropped = minuend->tx_dropped - subtrahend->tx_dropped;
}

static void datacounter_add(const struct connman_stats_data *add1,
				const struct connman_stats_data *add2,
				struct connman_stats_data *sum)
{
	sum->rx_packets = add1->rx_packets + add2->rx_packets;
	sum->tx_packets = add1->tx_packets + add2->tx_packets;
	sum->rx_bytes   = add1->rx_bytes   + add2->rx_bytes;
	sum->tx_bytes   = add1->tx_bytes   + add2->tx_bytes;
	sum->rx_errors  = add1->rx_errors  + add2->rx_errors;
	sum->tx_errors  = add1->tx_errors  + add2->tx_errors;
	sum->rx_dropped = add1->rx_dropped + add2->rx_dropped;
	sum->tx_dropped = add1->tx_dropped + add2->tx_dropped;
}

static void datacounter_changed(struct datacounter *self,
			const struct connman_stats_data *data)
{
	struct datacounter_priv *priv = self->priv;
	struct connman_stats_data *last = &priv->last;
	struct connman_stats_data *total = &priv->storage.total;
	struct connman_stats_data diff;
	enum datacounter_change change;
	GDateTime *now = datacounters_time_now();

	datacounter_sub(data, last, &diff);
	datacounter_add(total, &diff, total);

	DBG_(self, "[RX] %llu packets %llu bytes", llu_(data->rx_packets),
							llu_(data->rx_bytes));
	DBG_(self, "[TX] %llu packets %llu bytes", llu_(data->tx_packets),
							llu_(data->tx_bytes));

	/* Accumulate the changes */
	priv->bytes_change += diff.rx_bytes + diff.tx_bytes;
	change = (priv->bytes_change >= COUNTER_SIGNIFICANT_BYTE_COUNT) ?
		COUNTER_CHANGE_SIGNIFICANT : COUNTER_CHANGE_MINOR;
	priv->change = MAX(priv->change, change);

	/* Store the last values */
	*last = *data;

	/* And the update time */
	if (priv->last_update_time) {
		g_date_time_unref(priv->last_update_time);
	}
	priv->last_update_time = g_date_time_ref(now);
	priv->storage.last_update_time = g_date_time_to_unix(now);

	/* Check if the changes need to be saved right away */
	if (priv->change > COUNTER_CHANGE_MINOR) {
		/* short_write_timeout_id prohibits any saves */
		if (!priv->short_write_timeout_id) {
			datacounter_save(self);
		}
	} else {
		/* long_write_timeout_id prohibits insignificant saves */
		if (!priv->long_write_timeout_id) {
			datacounter_save(self);
		}
	}

	datacounter_update_state(self, g_date_time_to_unix(now));
	datacounter_queue_property_change(self, DATACOUNTER_PROPERTY_VALUE);
	g_signal_emit(self, datacounter_signal[SIGNAL_UPDATE], 0, &diff, now);
	g_date_time_unref(now);
	datacounter_emit_property_changes(self);
}

/*==========================================================================*
 * API
 *==========================================================================*/

gboolean datacounter_file_load(const char *ident, const char *suffix,
				struct connman_stats_data *data)
{
	struct datacounter_file_contents contents;
	char *path = datacounter_file_path(ident, suffix);
	gboolean ok = datacounter_file_read(path, &contents);

	if (data) {
		if (ok) {
			*data = contents.total;
		} else {
			memset(data, 0, sizeof(*data));
		}
	}
	g_free(path);
	return ok;
}

void datacounter_file_clear(const char *ident, const char *suffix)
{
	struct datacounter_file_contents contents;
	char *path = datacounter_file_path(ident, suffix);

	if (datacounter_file_read(path, &contents)) {
		/* This has to match what datacounter_reset() is doing */
		memset(&contents.total, 0, sizeof(contents.total));
		memset(&contents.baseline, 0, sizeof(contents.baseline));
		contents.baseline_reset_time =
		contents.last_update_time =
		contents.reset_time = datacounters_now();
		datacounter_file_write(path, &contents);
	}
	g_free(path);
}

struct datacounter *datacounter_new(const char *ident, const char *name)
{
	struct datacounter *self = g_object_new(DATACOUNTER_TYPE, NULL);
	struct datacounter_priv *priv = self->priv;
	struct datacounter_file_contents *storage = &priv->storage;
	const gint64 now = datacounters_now();

	self->ident = priv->ident = g_strdup(ident);
	self->name = priv->name = g_strdup(name);
	priv->path = datacounter_file_path(ident, name);

	/* Pull saved values from the file */
	datacounter_file_read(priv->path, storage);
	datacounter_timer_get(&priv->autoreset, &storage->autoreset);
	datacounter_autoreset_check(self);
	datacounter_update_state(self, now);

	if (storage->last_update_time) {

		if (storage->last_update_time > now) {
			storage->last_update_time = now;
		}
		priv->last_update_time = g_date_time_new_from_unix_utc(
						storage->last_update_time);
	}

	/*
	 * Some of the above calls might have queued some property changes.
	 * There's no need for that.
	 */
	priv->changed_properties = 0;
	return self;
}

struct datacounter *datacounter_ref(struct datacounter *self)
{
	if (G_LIKELY(self)) {
		g_object_ref(DATACOUNTER(self));
	}
	return self;
}

void datacounter_unref(struct datacounter *self)
{
	if (G_LIKELY(self)) {
		g_object_unref(DATACOUNTER(self));
	}
}

void datacounter_reset(struct datacounter *self)
{
	if (G_LIKELY(self)) {
		static const struct connman_stats_data empty = {0};
		struct datacounter_priv *priv = self->priv;
		const gint64 now = datacounters_now();
		gboolean save_now = FALSE;

		/* This has to match what datacounter_file_clear() is doing */
		DBG_(self, "");
		if (memcmp(&priv->storage.total, &empty, sizeof(empty))) {
			priv->storage.total = empty;
			save_now = TRUE;
			datacounter_queue_property_change(self,
				DATACOUNTER_PROPERTY_VALUE);
		}

		if (memcmp(&priv->storage.baseline, &empty, sizeof(empty))) {
			priv->storage.baseline = empty;
			save_now = TRUE;
			datacounter_queue_property_change(self,
				DATACOUNTER_PROPERTY_BASELINE);
		}

		if (priv->storage.reset_time != now) {
			priv->storage.reset_time = now;
			save_now = TRUE;
			datacounter_queue_property_change(self,
				DATACOUNTER_PROPERTY_RESET_TIME);
		}

		if (priv->storage.baseline_reset_time != now) {
			priv->storage.baseline_reset_time = now;
			save_now = TRUE;
			datacounter_queue_property_change(self,
				DATACOUNTER_PROPERTY_BASELINE_RESET_TIME);
		}

		if (save_now) {
			datacounter_save_now(self, COUNTER_CHANGE_SIGNIFICANT);
		}

		datacounter_deadline_check(self);
		g_signal_emit(self, datacounter_signal[SIGNAL_RESET], 0);
		datacounter_emit_property_changes(self);
	}
}

void datacounter_reset_baseline(struct datacounter *self)
{
	if (G_LIKELY(self)) {
		DBG_(self, "");
		datacounter_do_reset_baseline(self);
		datacounter_emit_property_changes(self);
	}
}

void datacounter_rebase(struct datacounter *self,
			const struct connman_stats_data *data)
{
	if (G_LIKELY(self)) {
		struct datacounter_priv *priv = self->priv;

		if (data) {
			DBG_(self, "[RX] %llu packets %llu bytes",
				llu_(data->rx_packets), llu_(data->rx_bytes));
			DBG_(self, "[TX] %llu packets %llu bytes",
				llu_(data->tx_packets), llu_(data->tx_bytes));
			priv->last = *data;
		} else {
			DBG_(self, "");
			memset(&priv->last, 0, sizeof(priv->last));
		}
	}
}

gboolean datacounter_update(struct datacounter *self,
			const struct connman_stats_data *data)
{
	if (G_LIKELY(self)) {
		struct datacounter_priv *priv = self->priv;
		struct connman_stats_data *last = &priv->last;

		if (memcmp(last, data, sizeof(*data))) {
			struct connman_stats_data fixed;

			data = datacounter_fix(data, last, &fixed);
			if (data) {
				datacounter_changed(self, data);
				return TRUE;
			}
		}
	}
	return FALSE;
}

GDateTime *datacounter_last_update_time(struct datacounter *self)
{
	return G_LIKELY(self) ? self->priv->last_update_time : NULL;
}

gint64 datacounter_reset_time(struct datacounter *self)
{
	return G_LIKELY(self) ? self->priv->storage.reset_time : 0;
}

gint64 datacounter_baseline_reset_time(struct datacounter *self)
{
	return G_LIKELY(self) ? self->priv->storage.baseline_reset_time : 0;
}

guint64 datacounter_data_warning(struct datacounter *self)
{
	return G_LIKELY(self) ? self->priv->storage.data_warning : 0;
}

void datacounter_set_data_warning(struct datacounter *self, guint64 level)
{
	if (G_LIKELY(self)) {
		struct datacounter_priv *priv = self->priv;

		if (priv->storage.data_warning != level) {
			priv->storage.data_warning = level;
			datacounter_state_property_changed(self,
					DATACOUNTER_PROPERTY_DATA_WARNING);
		}
	}
}

guint64 datacounter_data_limit(struct datacounter *self)
{
	return G_LIKELY(self) ? self->priv->storage.data_limit : 0;
}

void datacounter_set_data_limit(struct datacounter *self, guint64 limit)
{
	if (G_LIKELY(self)) {
		struct datacounter_priv *priv = self->priv;
		if (priv->storage.data_limit != limit) {
			priv->storage.data_limit = limit;
			datacounter_state_property_changed(self,
					DATACOUNTER_PROPERTY_DATA_LIMIT);
		}
	}
}

void datacounter_set_time_limit(struct datacounter *self,
				const struct datacounter_timer *new_limit)
{
	if (G_LIKELY(self) && G_LIKELY(new_limit)) {
		struct datacounter_priv *priv = self->priv;
		struct datacounter_timer limit = *new_limit;

		datacounters_validate_timer(&limit);
		if (datacounter_timer_put(&limit, &priv->storage.time_limit)) {
			priv->time_limit = limit;
			datacounter_deadline_check(self);
			datacounter_state_property_changed(self,
					DATACOUNTER_PROPERTY_TIME_LIMIT);
		}
	}
}

gboolean datacounter_cutoff_enabled(struct datacounter *self)
{
	return G_LIKELY(self) && (self->priv->storage.flags &
					COUNTER_FLAG_CUTOFF_ENABLED);
}

gboolean datacounter_time_limit_enabled(struct datacounter *self)
{
	return G_LIKELY(self) && (self->priv->storage.flags &
					COUNTER_FLAG_TIME_LIMIT_ENABLED);
}

void datacounter_set_time_limit_enabled(struct datacounter *self,
							gboolean enabled)
{
	if (datacounter_set_state_flag(self, enabled,
				COUNTER_FLAG_TIME_LIMIT_ENABLED)) {
		datacounter_deadline_check(self);
		datacounter_state_property_changed(self,
				DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED);
	}
}

void datacounter_set_cutoff_enabled(struct datacounter *self, gboolean enabled)
{
	if (datacounter_set_state_flag(self, enabled,
				COUNTER_FLAG_CUTOFF_ENABLED)) {
		datacounter_deadline_check(self);
		datacounter_state_property_changed(self,
				DATACOUNTER_PROPERTY_CUTOFF_ENABLED);
	}
}

gboolean datacounter_autoreset_enabled(struct datacounter *self)
{
	return G_LIKELY(self) && (self->priv->storage.flags &
					COUNTER_FLAG_AUTORESET_ENABLED);
}

void datacounter_set_autoreset_enabled(struct datacounter *self,
							gboolean enabled)
{
	if (datacounter_set_state_flag(self, enabled,
				COUNTER_FLAG_AUTORESET_ENABLED)) {
		datacounter_autoreset_check(self);
		datacounter_state_property_changed(self,
				DATACOUNTER_PROPERTY_AUTORESET_ENABLED);
	}
}

void datacounter_set_autoreset(struct datacounter *self,
			const struct datacounter_timer *new_config)
{
	if (G_LIKELY(self) && G_LIKELY(new_config)) {
		struct datacounter_timer config = *new_config;

		datacounters_validate_timer(&config);
		if (memcmp(self->autoreset, &config, sizeof(config))) {
			struct datacounter_priv *priv = self->priv;
			priv->autoreset = config;
			datacounter_timer_put(&priv->autoreset,
						&priv->storage.autoreset);
			datacounter_autoreset_check(self);
			datacounter_state_property_changed(self,
				DATACOUNTER_PROPERTY_AUTORESET);
		}
	}
}

gulong datacounter_add_reset_handler(struct datacounter *self,
				datacounter_cb_t cb, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
		SIGNAL_RESET_NAME, G_CALLBACK(cb), arg) : 0;
}

gulong datacounter_add_update_handler(struct datacounter *self,
				datacounter_update_cb_t cb, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
		SIGNAL_UPDATE_NAME, G_CALLBACK(cb), arg) : 0;
}

gulong datacounter_add_property_handler(struct datacounter *self,
				enum datacounter_property property,
				datacounter_property_cb_t cb, void *arg)
{
	if (G_LIKELY(self) && G_LIKELY(cb)) {
		char buf[sizeof(SIGNAL_PROPERTY_NAME) + 2 +
			 SIGNAL_PROPERTY_DETAIL_MAX_LEN];
		const char *name;

		if (property == DATACOUNTER_PROPERTY_ANY) {
			name = SIGNAL_PROPERTY_NAME;
		} else {
			name = buf;
			snprintf(buf, sizeof(buf),
				SIGNAL_PROPERTY_NAME "::"
				SIGNAL_PROPERTY_DETAIL, property);
			buf[sizeof(buf)-1] = 0;
		}
		return g_signal_connect(self, name, G_CALLBACK(cb), arg);
	}
	return 0;
}

void datacounter_remove_handler(struct datacounter *self, gulong id)
{
	if (G_LIKELY(self) && G_LIKELY(id)) {
		g_signal_handler_disconnect(self, id);
	}
}

void datacounter_remove_handlers(struct datacounter *self,
						gulong *ids, guint count)
{
	gutil_disconnect_handlers(self, ids, count);
}

/*==========================================================================*
 * Internals
 *==========================================================================*/

static void datacounter_init(struct datacounter *self)
{
	struct datacounter_priv *priv = G_TYPE_INSTANCE_GET_PRIVATE(self,
				DATACOUNTER_TYPE, struct datacounter_priv);

	self->priv = priv;
	self->value = &priv->storage.total;
	self->baseline = &priv->storage.baseline;
	self->autoreset = &priv->autoreset;
	self->time_limit = &priv->time_limit;
	priv->storage.version = COUNTER_FILE_VERSION;
	priv->storage.baseline_reset_time = datacounters_now();
	priv->storage.autoreset.value = 1;
	priv->storage.autoreset.unit = TIME_UNIT_DEFAULT;
	priv->storage.time_limit.value = 1;
	priv->storage.time_limit.unit = TIME_UNIT_DEFAULT;
	datacounter_timer_get(&priv->autoreset, &priv->storage.autoreset);
	datacounter_timer_get(&priv->time_limit, &priv->storage.time_limit);
	priv->time_notify = gutil_time_notify_new();
	priv->time_notify_id = gutil_time_notify_add_handler(priv->time_notify,
					datacounter_time_notify_cb, self);
}

static void datacounter_finalize(GObject *object)
{
	struct datacounter *self = DATACOUNTER(object);
	struct datacounter_priv *priv = self->priv;

	if (priv->change > COUNTER_CHANGE_NONE) {
		datacounter_file_write(priv->path, &priv->storage);
	}
	if (priv->cutoff_timer_id) {
		g_source_remove(priv->cutoff_timer_id);
	}
	if (priv->short_write_timeout_id) {
		g_source_remove(priv->short_write_timeout_id);
	}
	if (priv->long_write_timeout_id) {
		g_source_remove(priv->long_write_timeout_id);
	}
	if (priv->autoreset_check_id) {
		g_source_remove(priv->autoreset_check_id);
	}
	if (priv->last_update_time) {
		g_date_time_unref(priv->last_update_time);
	}
	gutil_time_notify_remove_handler(priv->time_notify,
						priv->time_notify_id);
	gutil_time_notify_unref(priv->time_notify);
	gutil_idle_pool_unref(priv->idle_pool);
	g_free(priv->history_names);
	g_free(priv->ident);
	g_free(priv->name);
	g_free(priv->path);
	g_free(priv->key);
	G_OBJECT_CLASS(PARENT_CLASS)->finalize(object);
}

static void datacounter_class_init(DataCounterClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	object_class->finalize = datacounter_finalize;

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_type_class_add_private(klass, sizeof(struct datacounter_priv));
	G_GNUC_END_IGNORE_DEPRECATIONS

	datacounter_signal[SIGNAL_RESET] =
		g_signal_new(SIGNAL_RESET_NAME, G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			G_TYPE_NONE, 0);
	datacounter_signal[SIGNAL_UPDATE] =
		g_signal_new(SIGNAL_UPDATE_NAME, G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			     G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_DATE_TIME);
	datacounter_signal[SIGNAL_PROPERTY] =
		g_signal_new(SIGNAL_PROPERTY_NAME, G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST | G_SIGNAL_DETAILED,
			0, NULL, NULL, NULL, G_TYPE_NONE, 1, G_TYPE_INT);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
