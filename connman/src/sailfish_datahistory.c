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

#include "sailfish_datahistory_p.h"

#include "connman.h"

#include <gutil_misc.h>
#include <gutil_idlepool.h>

enum datahistory_counter_events {
	EVENT_RESET,
	EVENT_UPDATE,
	EVENT_COUNT
};

struct datahistory_priv {
	GUtilIdlePool* pool;
	GDateTime* start_time;
	GDateTime* next_period;
	gulong event_id[EVENT_COUNT];
};

G_DEFINE_ABSTRACT_TYPE(DataHistory, datahistory, G_TYPE_OBJECT)
#define PARENT_CLASS datahistory_parent_class
#define DATAHISTORY_GET_CLASS(obj) G_TYPE_INSTANCE_GET_CLASS((obj),\
        DATAHISTORY_TYPE, DataHistoryClass)
#define DATAHISTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	DATAHISTORY_TYPE, DataHistory))

enum datahistory_signal {
	SIGNAL_CLEARED,
	SIGNAL_START_TIME_CHANGED,
	SIGNAL_LAST_SAMPLE_CHANGED,
	SIGNAL_SAMPLE_ADDED,
	SIGNAL_COUNT
};

#define SIGNAL_CLEARED_NAME             "datahistory-cleared"
#define SIGNAL_START_TIME_CHANGED_NAME  "datahistory-start-time-changed"
#define SIGNAL_LAST_SAMPLE_CHANGED_NAME "datahistory-last-sample-changed"
#define SIGNAL_SAMPLE_ADDED_NAME        "datahistory-sample-added"

static guint datahistory_signal[SIGNAL_COUNT];

static const guint32 datahistory_time_interval [] = {
	1,                              /* TIME_UNIT_SECOND */
	60,                             /* TIME_UNIT_MINUTE */
	60*60,                          /* TIME_UNIT_HOUR */
	60*60*24,                       /* TIME_UNIT_DAY */
	60*60*24*28,                    /* TIME_UNIT_MONTH */
	60*60*24*365                    /* TIME_UNIT_YEAR */
};

G_STATIC_ASSERT(G_N_ELEMENTS(datahistory_time_interval) == TIME_UNITS);

/*==========================================================================*
 * Implementation
 *==========================================================================*/

static GDateTime *datahistory_period_next(GDateTime *time,
				const struct datacounter_time_period *period)
{
	GDateTime *next;

	if (period->unit == TIME_UNIT_SECOND) {
		next = datacounters_time_add_period(time, period);
	} else {
		GTimeZone *utc = g_time_zone_new_utc();
		GDateTime *t1 = datacounters_time_add_period(time, period);

		next = datacounters_time_normalize(t1, utc, period->unit);
		g_time_zone_unref(utc);
		g_date_time_unref(t1);
	}
	return next;
}

static void datahistory_reset_cb(struct datacounter *counter, void *arg)
{
	datahistory_clear(DATAHISTORY(arg));
}

static void datahistory_update_cb(struct datacounter *dc,
	const struct connman_stats_data *change, GDateTime *time, void *arg)
{
	struct datahistory *self = DATAHISTORY(arg);
	struct datahistory_priv *priv = self->priv;
	const struct connman_stats_data *value = dc->value;

	if (g_date_time_compare(time, priv->next_period) < 0) {
		/* We are still within the same period */
		if (self->last_sample.bytes_sent != value->tx_bytes ||
			self->last_sample.bytes_received != value->rx_bytes) {
			/* The last sample has been updated */
			self->last_sample.time = g_date_time_to_unix(time);
			self->last_sample.bytes_sent = value->tx_bytes;
			self->last_sample.bytes_received = value->rx_bytes;
			g_signal_emit(self, datahistory_signal
					[SIGNAL_LAST_SAMPLE_CHANGED], 0);
		}
	} else {
		DataHistoryClass *klass = DATAHISTORY_GET_CLASS(self);
		struct datahistory_sample sample = self->last_sample;

		/*
		 * Archive the current sample, initialize the new one.
		 * Round the sample time to the next period boundary.
		 */
		sample.time = g_date_time_to_unix(priv->next_period);
		klass->push_sample(self, &sample);
		if (self->last_sample.time != sample.time) {
			self->last_sample.time = sample.time;
			g_signal_emit(self, datahistory_signal
				[SIGNAL_LAST_SAMPLE_CHANGED], 0);
		}

		/* Update the time when the next period starts */
		g_date_time_unref(priv->next_period);
		priv->next_period = datahistory_period_next(time,
							&self->type->period);
		DBG("next: %s", datacounter_format_time(dc,
							priv->next_period));

		/* Initialize the next sample */
		self->last_sample.time = g_date_time_to_unix(time);
		self->last_sample.bytes_sent = value->tx_bytes;
		self->last_sample.bytes_received = value->rx_bytes;

		/* Notify the listeners */
		g_signal_emit(self, datahistory_signal
				[SIGNAL_SAMPLE_ADDED], 0, &self->last_sample);
	}
}

/*==========================================================================*
 * API
 *==========================================================================*/

struct datahistory *datahistory_new(struct datacounter *dc,
				const struct datahistory_type *type)
{
	if (G_LIKELY(dc) && G_LIKELY(type)) {
		guint64 interval;
		struct datahistory *self = g_object_new(type->get_type(), NULL);
		struct datahistory_priv *priv = self->priv;
		DataHistoryClass *klass = DATAHISTORY_GET_CLASS(self);

		priv->start_time = datacounter_last_update_time(dc);
		if (priv->start_time) {
			g_date_time_ref(priv->start_time);
		} else {
			priv->start_time = datacounters_time_now();
		}
		priv->next_period = datahistory_period_next(priv->start_time,
							&type->period);
		DBG("next: %s", datacounter_format_time(dc,
						priv->next_period));
		self->counter = datacounter_ref(dc);
		self->start_time = g_date_time_to_unix(priv->start_time);
		self->type = type;
		self->name = type->name;
		self->last_sample.time =
			g_date_time_to_unix(priv->start_time);
		self->last_sample.bytes_sent = dc->value->tx_bytes;
		self->last_sample.bytes_received = dc->value->rx_bytes;
		priv->event_id[EVENT_RESET] =
			datacounter_add_reset_handler(dc,
						datahistory_reset_cb, self);
		priv->event_id[EVENT_UPDATE] =
			datacounter_add_update_handler(dc,
						datahistory_update_cb, self);
		/*
		 * Request periodic updates. The update interval is a worst
		 * case estimate, the actual updates may most likely happen
		 * more often than we have requested.
		 */
		interval = datahistory_time_interval[type->period.unit];
		interval *= type->period.value;
		if (interval < G_MAXUINT) {
			self->update_interval = (guint)interval;
		}
		klass->finish_init(self);
		return self;
	}
	return NULL;
}

struct datahistory *datahistory_ref(struct datahistory *self)
{
	if (G_LIKELY(self)) {
		g_object_ref(DATAHISTORY(self));
	}
	return self;
}

void datahistory_unref(struct datahistory *self)
{
	if (G_LIKELY(self)) {
		g_object_unref(DATAHISTORY(self));
	}
}

void datahistory_add_to_idle_pool(struct datahistory *self,
				gpointer pointer, GDestroyNotify destroy)
{
	if (G_LIKELY(self)) {
		gutil_idle_pool_add(self->priv->pool, pointer, destroy);
	}
}

gboolean datahistory_persistent(struct datahistory *self)
{
	if (G_LIKELY(self)) {
		DataHistoryClass *klass = DATAHISTORY_GET_CLASS(self);
		return klass->persistent;
	}
	return FALSE;
}

void datahistory_clear(struct datahistory *self)
{
	if (G_LIKELY(self)) {
		struct datahistory_priv *priv = self->priv;
		DataHistoryClass *klass = DATAHISTORY_GET_CLASS(self);
		GDateTime *now = datacounters_time_now();
		const gint64 now_sec = g_date_time_to_unix(now);

		if (!klass->is_empty(self)) {
			klass->clear(self);
			g_signal_emit(self, datahistory_signal
						[SIGNAL_CLEARED], 0);
		}

		if (self->last_sample.time != now_sec ||
					self->last_sample.bytes_sent ||
					self->last_sample.bytes_received) {
			self->last_sample.time = now_sec;
			self->last_sample.bytes_sent = 0;
			self->last_sample.bytes_received = 0;
			g_signal_emit(self, datahistory_signal
					[SIGNAL_LAST_SAMPLE_CHANGED], 0);
		}

		if (!g_date_time_equal(now, priv->start_time)) {
			g_date_time_unref(priv->start_time);
			g_date_time_unref(priv->next_period);

			self->start_time = g_date_time_to_unix(now);
			priv->start_time = now;
			priv->next_period = datahistory_period_next(now,
							&self->type->period);
			DBG("next: %s", datacounter_format_time(self->counter,
							priv->next_period));

			g_signal_emit(self, datahistory_signal
					[SIGNAL_START_TIME_CHANGED], 0);
		} else {
			g_date_time_unref(now);
		}
	}
}

gboolean datahistory_get_sample_at_interval(struct datahistory *self,
			int interval, struct datahistory_sample *sample)
{
	if (G_LIKELY(self) && G_LIKELY(sample)) {
		/*
		 * The last sample is the current counter and therefore
		 * somewhat special. Its timestamp is the current time
		 * rather than the end of the interval.
		 *
		 * What it means is that samples 0 and 1 for history
		 * which counts every second would have the same timestamp.
		 * In other words, the end of the previous interval and
		 * the current time is the same thing. The caller has to
		 * be prepared for that.
		 */
		if (interval <= 0) {
			*sample = self->last_sample;
			return TRUE;
		} else {
			GDateTime *dt;
			gint64 max_time;
			struct datacounter_time_period tp = self->type->period;
			struct datahistory_priv *priv = self->priv;

			/* Move time back by specified number of intervals */
			tp.value *= -interval;
			dt = datahistory_period_next(priv->next_period, &tp);
			max_time = g_date_time_to_unix(dt);
			g_date_time_unref(dt);
			if (DATAHISTORY_GET_CLASS(self)->get_sample_at
						(self, max_time, sample)) {
				sample->time = max_time;
				return TRUE;
			}
		}
	}
	return FALSE;
}

const struct datahistory_samples *datahistory_get_samples
				(struct datahistory *self, int max_count)
{
	if (G_LIKELY(self)) {
		return DATAHISTORY_GET_CLASS(self)->get_samples
						(self, max_count);
	}
	return NULL;
}

const struct datahistory_samples *datahistory_get_samples_since(
			struct datahistory *self, gint64 since, int max_count)
{
	if (G_LIKELY(self)) {
		return DATAHISTORY_GET_CLASS(self)->get_samples_since
						(self, since, max_count);
	}
	return NULL;
}

gulong datahistory_add_cleared_handler(struct datahistory *self,
				datahistory_cb_t cb, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
		SIGNAL_CLEARED_NAME, G_CALLBACK(cb), arg) : 0;
}

gulong datahistory_add_start_time_handler(struct datahistory *self,
				datahistory_cb_t cb, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
		SIGNAL_START_TIME_CHANGED_NAME, G_CALLBACK(cb), arg) : 0;
}

gulong datahistory_add_last_sample_handler(struct datahistory *self,
				datahistory_cb_t cb, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
		SIGNAL_LAST_SAMPLE_CHANGED_NAME, G_CALLBACK(cb), arg) : 0;
}

gulong datahistory_add_sample_added_handler(struct datahistory *self,
				datahistory_sample_cb_t cb, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
		SIGNAL_SAMPLE_ADDED_NAME, G_CALLBACK(cb), arg) : 0;
}

void datahistory_remove_handler(struct datahistory *self, gulong id)
{
	if (G_LIKELY(self) && G_LIKELY(id)) {
		g_signal_handler_disconnect(self, id);
	}
}

void datahistory_remove_handlers(struct datahistory *self, gulong *ids,
								guint count)
{
	gutil_disconnect_handlers(self, ids, count);
}

/*==========================================================================*
 * Internals
 *==========================================================================*/

static void datahistory_init(struct datahistory *self)
{
	struct datahistory_priv *priv = G_TYPE_INSTANCE_GET_PRIVATE(self,
				DATAHISTORY_TYPE, struct datahistory_priv);

	self->priv = priv;
	priv->pool = gutil_idle_pool_new();
}

static void datahistory_finalize(GObject *object)
{
	struct datahistory *self = DATAHISTORY(object);
	struct datahistory_priv *priv = self->priv;
	datacounter_remove_all_handlers(self->counter, priv->event_id);
	datacounter_unref(self->counter);
	gutil_idle_pool_unref(priv->pool);
	g_date_time_unref(priv->start_time);
	g_date_time_unref(priv->next_period);
	G_OBJECT_CLASS(PARENT_CLASS)->finalize(object);
}

static void datahistory_class_init(DataHistoryClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = datahistory_finalize;

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_type_class_add_private(klass, sizeof(struct datahistory_priv));
	G_GNUC_END_IGNORE_DEPRECATIONS

	datahistory_signal[SIGNAL_CLEARED] =
		g_signal_new(SIGNAL_CLEARED_NAME, G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			G_TYPE_NONE, 0);
	datahistory_signal[SIGNAL_START_TIME_CHANGED] =
		g_signal_new(SIGNAL_START_TIME_CHANGED_NAME,
			G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			G_TYPE_NONE, 0);
	datahistory_signal[SIGNAL_SAMPLE_ADDED] =
		g_signal_new(SIGNAL_SAMPLE_ADDED_NAME,
			G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			G_TYPE_NONE, 1, G_TYPE_POINTER);
	datahistory_signal[SIGNAL_LAST_SAMPLE_CHANGED] =
		g_signal_new(SIGNAL_LAST_SAMPLE_CHANGED_NAME,
			G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			G_TYPE_NONE, 0);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
