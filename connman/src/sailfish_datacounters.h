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

#ifndef SAILFISH_DATACOUNTERS_H
#define SAILFISH_DATACOUNTERS_H

#include <glib.h>
#include <glib-object.h>

struct connman_stats_data;

struct datacounters_dbus;
struct datacounter_dbus;
struct datahistory_dbus;
struct datacounters;
struct datacounter;
struct datahistory;

/*
 * To reduce the number of writes, we don't overwrite the stats files more
 * often than once in STATS_SHORT_WRITE_PERIOD_SEC seconds. If the changes
 * are insignificant we overwrite the file after STATS_LONG_WRITE_PERIOD_SEC.
 * If there are no changes, we don't overwrite it at all, except when stats
 * get reset or rebased.
 *
 * N.B. These constants are redefined by unit tests (should they be settable
 * at run time?)
 */
#ifndef STATS_SHORT_WRITE_PERIOD_SEC
#  define STATS_SHORT_WRITE_PERIOD_SEC  (2)
#endif
#ifndef STATS_LONG_WRITE_PERIOD_SEC
#  define STATS_LONG_WRITE_PERIOD_SEC   (30)
#endif

/* Collection of data counters */
struct datacounters {
	GObject object;
	struct datacounters_priv *priv;
	const char *ident;
	const char *const *counters;
};

typedef void (*datacounters_cb_t)(struct datacounters *counters, void *arg);

struct datacounters *datacounters_new(const char *ident);
struct datacounters *datacounters_ref(struct datacounters *counters);
void datacounters_unref(struct datacounters *counters);
struct datacounter *datacounters_get_counter(struct datacounters *counters,
							const char *name);
void datacounters_reset_all_counters(struct datacounters *counters);
gulong datacounters_add_counters_handler(struct datacounters *counters,
				datacounters_cb_t cb, void *arg);
void datacounters_remove_handler(struct datacounters *counters, gulong id);
void datacounters_remove_handlers(struct datacounters *counters,
						gulong *ids, guint count);

/* D-Bus interface for datacounters */
struct datacounters_dbus *datacounters_dbus_new(struct datacounters *counters);
void datacounters_dbus_free(struct datacounters_dbus *dbus);

/*
 * Limit and warning refer to the total amount of transmitted data,
 * i.e. sent + received. And it's relative to the baseline.
 */
enum datacounter_cutoff_state {
	CUTOFF_DISABLED,    /* Cut-off is disabled */
	CUTOFF_NO_LIMIT,    /* No limit or warning is configured */
	CUTOFF_BELOW_LIMIT, /* Neither limit nor warning level is reached */
	CUTOFF_WARNING,     /* Warning level was reached, data enabled */
	CUTOFF_ACTIVATED    /* Data limit was reached, data disabled */
};

enum datacounter_time_unit {
	TIME_UNIT_SECOND,
	TIME_UNIT_MINUTE,
	TIME_UNIT_HOUR,
	TIME_UNIT_DAY,
	TIME_UNIT_MONTH,
	TIME_UNIT_YEAR,
	TIME_UNITS
};

#define TIME_UNIT_DEFAULT  TIME_UNIT_MONTH

enum datacounter_property {
	DATACOUNTER_PROPERTY_ANY,
	DATACOUNTER_PROPERTY_VALUE,
	DATACOUNTER_PROPERTY_BASELINE,
	DATACOUNTER_PROPERTY_RESET_TIME,
	DATACOUNTER_PROPERTY_BASELINE_RESET_TIME,
	DATACOUNTER_PROPERTY_DATA_WARNING,
	DATACOUNTER_PROPERTY_DATA_LIMIT,
	DATACOUNTER_PROPERTY_TIME_LIMIT,
	DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED,
	DATACOUNTER_PROPERTY_CUTOFF_ENABLED,
	DATACOUNTER_PROPERTY_CUTOFF_STATE,
	DATACOUNTER_PROPERTY_AUTORESET_ENABLED,
	DATACOUNTER_PROPERTY_AUTORESET,
	DATACOUNTER_PROPERTY_COUNT
};

struct datacounter_time_period {
	gint value;
	enum datacounter_time_unit unit;
};

struct datacounter_timer {
	guint value;
	enum datacounter_time_unit unit;
	guint at[TIME_UNIT_YEAR]; /* Units >= unit are ignored */
};

/* Time is measured in seconds since 1970-01-01 00:00:00 UTC */
gint64 datacounters_now(void);
GDateTime *datacounters_time_now(void);
void datacounters_validate_timer(struct datacounter_timer *time);
void datacounters_time_to_units(guint *units, GDateTime *time);
GDateTime *datacounters_time_from_units(GTimeZone *tz, const guint *units);
GDateTime *datacounters_time_add_period(GDateTime *time,
				const struct datacounter_time_period *period);
GDateTime *datacounters_time_add(GDateTime *time, gint value,
					enum datacounter_time_unit unit);
GDateTime *datacounters_time_normalize(GDateTime *time, GTimeZone *tz,
					enum datacounter_time_unit unit);

/* Read or clear the last saved counter value */
gboolean datacounter_file_load(const char *ident, const char *suffix,
					struct connman_stats_data *data);
void datacounter_file_clear(const char *ident, const char *suffix);

/* Data counter */
struct datacounter {
	GObject object;
	struct datacounter_priv *priv;
	const char *ident;
	const char *name;
	const struct connman_stats_data *value;
	const struct connman_stats_data *baseline;
	const struct datacounter_timer *time_limit;
	const struct datacounter_timer *autoreset;
	enum datacounter_cutoff_state cutoff_state;
};

typedef void (*datacounter_cb_t)(struct datacounter *counter, void *arg);
typedef void (*datacounter_update_cb_t)(struct datacounter *counter,
			const struct connman_stats_data *change,
			GDateTime *time, void *arg);
typedef void (*datacounter_property_cb_t)(struct datacounter *counter,
			enum datacounter_property property, void *arg);

struct datacounter *datacounter_new(const char *ident, const char *name);
struct datacounter *datacounter_ref(struct datacounter *counter);
void datacounter_unref(struct datacounter *counter);
void datacounter_rebase(struct datacounter *counter,
			const struct connman_stats_data *data);
gboolean datacounter_update(struct datacounter *counter,
			const struct connman_stats_data *data);
void datacounter_reset(struct datacounter *counter);
void datacounter_reset_baseline(struct datacounter *counter);
guint64 datacounter_data_warning(struct datacounter *counter);
guint64 datacounter_data_limit(struct datacounter *counter);
GDateTime *datacounter_last_update_time(struct datacounter *counter);
gint64 datacounter_reset_time(struct datacounter *counter);
gint64 datacounter_baseline_reset_time(struct datacounter *counter);
gboolean datacounter_time_limit_enabled(struct datacounter *counter);
gboolean datacounter_cutoff_enabled(struct datacounter *counter);
gboolean datacounter_autoreset_enabled(struct datacounter *counter);
void datacounter_set_data_limit(struct datacounter *counter, guint64 bytes);
void datacounter_set_data_warning(struct datacounter *counter, guint64 bytes);
void datacounter_set_time_limit(struct datacounter *counter,
				const struct datacounter_timer *limit);
void datacounter_set_time_limit_enabled(struct datacounter *counter,
							gboolean enabled);
void datacounter_set_cutoff_enabled(struct datacounter *counter,
							gboolean enabled);
void datacounter_set_autoreset_enabled(struct datacounter *counter,
							gboolean enabled);
void datacounter_set_autoreset(struct datacounter *counter,
			const struct datacounter_timer *config);
const char *datacounter_format_time(struct datacounter *self, GDateTime *time);
const char *datacounter_format_time_now(struct datacounter *self);
gulong datacounter_add_reset_handler(struct datacounter *counter,
				datacounter_cb_t cb, void *arg);
gulong datacounter_add_update_handler(struct datacounter *counter,
				datacounter_update_cb_t cb, void *arg);
gulong datacounter_add_property_handler(struct datacounter *counter,
				enum datacounter_property property,
				datacounter_property_cb_t cb, void *arg);
void datacounter_remove_handler(struct datacounter *counter, gulong id);
void datacounter_remove_handlers(struct datacounter *counter,
						gulong *ids, guint count);
#define datacounter_remove_all_handlers(counter, ids) \
	datacounter_remove_handlers(counter, ids, G_N_ELEMENTS(ids))

/* D-Bus interface for datacounter */
struct datacounter_dbus *datacounter_dbus_new(struct datacounter *counter,
						const char *const *histories);
void datacounter_dbus_free(struct datacounter_dbus *dbus);
char *datacounter_dbus_path(const char *ident, const char *name);

/* History of the individual counter */
struct datahistory_type {
	GType (*get_type)(void);
	const char *name;
	struct datacounter_time_period period;
	guint max_depth;
};

struct datahistory_sample {
	gint64 time;
	guint64 bytes_sent;
	guint64 bytes_received;
} __attribute__((packed));

struct datahistory_samples {
	gint count;
	const struct datahistory_sample *samples[1];
};

struct datahistory {
	GObject object;
	const char *name;
	struct datahistory_priv *priv;
	struct datacounter *counter;
	const struct datahistory_type *type;
	struct datahistory_sample last_sample;
	gint64 start_time;
	guint update_interval;
};

typedef void (*datahistory_cb_t)(struct datahistory *history, void *arg);
typedef void (*datahistory_sample_cb_t)(struct datahistory *history,
		const struct datahistory_sample *sample, void *arg);

GType datahistory_memory_get_type(void);
GType datahistory_file_get_type(void);

struct datahistory *datahistory_new(struct datacounter *counter,
				const struct datahistory_type *type);
struct datahistory *datahistory_ref(struct datahistory *history);
void datahistory_unref(struct datahistory *history);
void datahistory_add_to_idle_pool(struct datahistory *history,
				gpointer pointer, GDestroyNotify destroy);
gboolean datahistory_persistent(struct datahistory *history);
void datahistory_clear(struct datahistory *history);
gboolean datahistory_get_sample_at_interval(struct datahistory *self,
			int interval, struct datahistory_sample *sample);
const struct datahistory_samples *datahistory_get_samples(
				struct datahistory *history, int max_count);
const struct datahistory_samples *datahistory_get_samples_since(
		struct datahistory *history, gint64 since, int max_count);
gulong datahistory_add_cleared_handler(struct datahistory *history,
				datahistory_cb_t cb, void *arg);
gulong datahistory_add_start_time_handler(struct datahistory *history,
				datahistory_cb_t cb, void *arg);
gulong datahistory_add_sample_added_handler(struct datahistory *history,
				datahistory_sample_cb_t cb, void *arg);
gulong datahistory_add_last_sample_handler(struct datahistory *history,
				datahistory_cb_t cb, void *arg);
void datahistory_remove_handler(struct datahistory *history, gulong id);
void datahistory_remove_handlers(struct datahistory *history, gulong *ids,
								guint count);
#define datahistory_remove_all_handlers(history,ids) \
	datahistory_remove_handlers(history, ids, G_N_ELEMENTS(ids))

/* D-Bus interface for datahistory */
struct datahistory_dbus *datahistory_dbus_new(struct datahistory *history);
void datahistory_dbus_free(struct datahistory_dbus *dbus);
char *datahistory_dbus_history_path(struct datacounter *counter,
						const char *history_name);

#endif /* SAILFISH_DATACOUNTERS_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
