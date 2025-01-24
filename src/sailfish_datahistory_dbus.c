/*
 *  Connection Manager
 *
 *  Copyright (C) 2016-2018 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2016-2018 Slava Monich <slava.monich@jolla.com>
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
#include "sailfish_datacounters_dbus_util.h"

#include "connman.h"

enum datahistory_dbus_event {
	EVENT_CLEARED,
	EVENT_START_TIME_CHANGED,
	EVENT_LAST_SAMPLE_CHANGED,
	EVENT_SAMPLE_ADDED,
	EVENT_COUNT
};

struct datahistory_dbus {
	struct datahistory *history;
	DBusConnection *conn;
	char *name;
	char *path;
	gulong event_id[EVENT_COUNT];
	struct datacounters_dbus_updates updates;
};

typedef void (*datahistory_dbus_append_fn)(DBusMessageIter *it,
					struct datahistory_dbus *dbus);

#define HISTORY_DBUS_INTERFACE          COUNTERS_DBUS_INTERFACE ".History"
#define HISTORY_DBUS_INTERFACE_VERSION  (1)

#define HISTORY_DBUS_UPDATE_FLAG_LAST_SAMPLE_CHANGED (0x01)
#define HISTORY_DBUS_UPDATE_FLAG_SAMPLE_ADDED        (0x02)

#define HISTORY_DBUS_SIGNAL_CREATED             "Created"
#define HISTORY_DBUS_SIGNAL_DELETED             "Deleted"
#define HISTORY_DBUS_SIGNAL_CLEARED             "Cleared"
#define HISTORY_DBUS_SIGNAL_START_TIME_CHANGED  "StartTimeChanged"
#define HISTORY_DBUS_SIGNAL_LAST_SAMPLE_CHANGED "LastSampleChanged"
#define HISTORY_DBUS_SIGNAL_SAMPLE_ADDED        "SampleAdded"

#define HISTORY_DBUS_SAMPLE_SIGNATURE           "xtt"

static DBusMessage *datahistory_dbus_reply(DBusMessage *msg,
	struct datahistory_dbus *dbus, datahistory_dbus_append_fn append)
{
	DBusMessage *reply = dbus_message_new_method_return(msg);

	if (append) {
		DBusMessageIter it;
		dbus_message_iter_init_append(reply, &it);
		append(&it, dbus);
	}
	return reply;
}

static void datahistory_dbus_signal(struct datahistory_dbus *dbus,
			const char *name, datahistory_dbus_append_fn append)
{
	DBusMessage *signal = dbus_message_new_signal(dbus->path,
					HISTORY_DBUS_INTERFACE, name);

	if (append) {
		DBusMessageIter it;

		dbus_message_iter_init_append(signal, &it);
		append(&it, dbus);
	}
	g_dbus_send_message(dbus->conn, signal);
}

static void datahistory_dbus_append_sample(DBusMessageIter *it,
				const struct datahistory_sample *sample)
{
	DBusMessageIter sub;

	dbus_message_iter_open_container(it, DBUS_TYPE_STRUCT, NULL, &sub);
	datacounters_dbus_append_int64(&sub, sample->time);
	datacounters_dbus_append_uint64(&sub, sample->bytes_sent);
	datacounters_dbus_append_uint64(&sub, sample->bytes_received);
	dbus_message_iter_close_container(it, &sub);
}

static void datahistory_dbus_append_time_period(DBusMessageIter *it,
				const struct datacounter_time_period *period)
{
	DBusMessageIter sub;

	dbus_message_iter_open_container(it, DBUS_TYPE_STRUCT, NULL, &sub);
	datacounters_dbus_append_uint32(&sub, period->value);
	datacounters_dbus_append_int32(&sub, period->unit);
	dbus_message_iter_close_container(it, &sub);
}

static void datahistory_dbus_append_version(DBusMessageIter *it,
					struct datahistory_dbus *dbus)
{
	datacounters_dbus_append_int32(it, HISTORY_DBUS_INTERFACE_VERSION);
}

static void datahistory_dbus_append_persistent(DBusMessageIter *it,
					struct datahistory_dbus *dbus)
{
	datacounters_dbus_append_bool(it,
				datahistory_persistent(dbus->history));
}

static void datahistory_dbus_append_start_time(DBusMessageIter *it,
					struct datahistory_dbus *dbus)
{
	datacounters_dbus_append_int64(it, dbus->history->start_time);
}

static void datahistory_dbus_append_minimum_period(DBusMessageIter *it,
					struct datahistory_dbus *dbus)
{
	datahistory_dbus_append_time_period(it, &dbus->history->type->period);
}

static void datahistory_dbus_append_maximum_depth(DBusMessageIter *it,
					struct datahistory_dbus *dbus)
{
	datacounters_dbus_append_uint32(it, dbus->history->type->max_depth);
}

static void datahistory_dbus_append_all(DBusMessageIter *it,
					struct datahistory_dbus *dbus)
{
	datahistory_dbus_append_version(it, dbus);
	datahistory_dbus_append_persistent(it, dbus);
	datahistory_dbus_append_start_time(it, dbus);
	datahistory_dbus_append_minimum_period(it, dbus);
	datahistory_dbus_append_maximum_depth(it, dbus);
}

static DBusMessage *datahistory_dbus_get_all(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_reply(msg, (struct datahistory_dbus *)data,
						datahistory_dbus_append_all);
}

static DBusMessage *datahistory_dbus_get_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_reply(msg, (struct datahistory_dbus *)data,
				datahistory_dbus_append_version);
}

static DBusMessage *datahistory_dbus_get_persistent(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_reply(msg, (struct datahistory_dbus *)data,
				datahistory_dbus_append_persistent);
}

static DBusMessage *datahistory_dbus_get_start_time(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_reply(msg, (struct datahistory_dbus *)data,
				datahistory_dbus_append_start_time);
}

static DBusMessage *datahistory_dbus_get_minimum_period(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_reply(msg, (struct datahistory_dbus *)data,
				datahistory_dbus_append_minimum_period);
}

static DBusMessage *datahistory_dbus_get_maximum_depth(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_reply(msg, (struct datahistory_dbus *)data,
				datahistory_dbus_append_maximum_depth);
}

static DBusMessage *datahistory_dbus_clear(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datahistory_dbus *dbus = data;

	datahistory_clear(dbus->history);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *datahistory_dbus_get_samples_at_intervals
			(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessageIter in;

	if (dbus_message_iter_init(msg, &in)) {
		struct datahistory_dbus *dbus = data;
		DBusMessage *reply = dbus_message_new_method_return(msg);
		DBusMessageIter out, a;
		const dbus_int32_t* intervals;
		int i, n = 0;
		
		dbus_message_iter_recurse(&in, &a);
		dbus_message_iter_get_fixed_array(&a, &intervals, &n);

		dbus_message_iter_init_append(reply, &out);
		dbus_message_iter_open_container(&out, DBUS_TYPE_ARRAY,
				"(" HISTORY_DBUS_SAMPLE_SIGNATURE ")", &a);
		for (i = 0; i < n; i++) {
			struct datahistory_sample sample;

			if (datahistory_get_sample_at_interval(dbus->history,
						intervals[i], &sample)) {
				datahistory_dbus_append_sample(&a, &sample);
			}
		}
		dbus_message_iter_close_container(&out, &a);
		return reply;
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

static DBusMessage *datahistory_dbus_samples_reply(DBusMessage *msg,
			const struct datahistory_samples *samples,
			const struct datahistory_sample *extra_sample)
{
	DBusMessage *reply = dbus_message_new_method_return(msg);
	DBusMessageIter it, a;

	dbus_message_iter_init_append(reply, &it);
	dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY,
				"(" HISTORY_DBUS_SAMPLE_SIGNATURE ")", &a);
	if (samples) {
		guint i;
		for (i = 0; i < samples->count; i++) {
			datahistory_dbus_append_sample(&a,
						samples->samples[i]);
		}
	}
	if (extra_sample) {
		datahistory_dbus_append_sample(&a, extra_sample);
	}
	dbus_message_iter_close_container(&it, &a);
	return reply;
}

static DBusMessage *datahistory_dbus_samples(struct datahistory_dbus *dbus,
					DBusMessage *msg, int maxcount)
{
	/* If maxcount is 1 then we are only sending the last sample */
	const struct datahistory_samples *samples = (maxcount != 1) ?
		samples = datahistory_get_samples(dbus->history,
					maxcount - 1) : NULL;

	return datahistory_dbus_samples_reply(msg, samples,
						&dbus->history->last_sample);
}

static DBusMessage *datahistory_dbus_get_samples(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	dbus_int32_t maxcount;

	if (dbus_message_get_args(msg, NULL,
					DBUS_TYPE_INT32, &maxcount,
					DBUS_TYPE_INVALID)) {
		return datahistory_dbus_samples(data, msg, maxcount);
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

static DBusMessage *datahistory_dbus_get_all_samples(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datahistory_dbus_samples(data, msg, -1);
}

static DBusMessage *datahistory_dbus_get_samples_since(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	dbus_int64_t since;
	dbus_int32_t maxcount;

	if (dbus_message_get_args(msg, NULL,
					DBUS_TYPE_INT64, &since,
					DBUS_TYPE_INT32, &maxcount,
					DBUS_TYPE_INVALID)) {
		struct datahistory_dbus *dbus = data;

		if (dbus->history->last_sample.time >= since) {
			/*
			 * At least the last sample is within the range
			 * If maxcount is 1 then we are only sending
			 * the last sample
			 */
			const struct datahistory_samples *s = (maxcount != 1) ?
				datahistory_get_samples_since(dbus->history,
						since, maxcount - 1) : NULL;

			return datahistory_dbus_samples_reply(msg, s,
						&dbus->history->last_sample);
		}
		return datahistory_dbus_samples_reply(msg, NULL, NULL);
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

static DBusMessage *datahistory_dbus_enable_updates(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datahistory_dbus *dbus = data;

	return datacounter_dbus_updates_enable(&dbus->updates, conn, msg);
}

static DBusMessage *datahistory_dbus_disable_updates(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datahistory_dbus *dbus = data;

	return datacounter_dbus_updates_disable(&dbus->updates, conn, msg);
}

#define HISTORY_DBUS_VERSION_ARG              {"version", "i"}
#define HISTORY_DBUS_PERSISTENT_ARG           {"persistent", "b"}
#define HISTORY_DBUS_START_TIME_ARG           {"start_time", "x"}
#define HISTORY_DBUS_MINIMUM_PERIOD_ARG       {"period", "(ui)"}
#define HISTORY_DBUS_MAXIMUM_DEPTH_ARG        {"depth", "u"}
#define HISTORY_DBUS_GET_ALL_ARGS \
	HISTORY_DBUS_VERSION_ARG, \
	HISTORY_DBUS_PERSISTENT_ARG, \
	HISTORY_DBUS_START_TIME_ARG, \
	HISTORY_DBUS_MINIMUM_PERIOD_ARG, \
	HISTORY_DBUS_MAXIMUM_DEPTH_ARG

static const GDBusMethodTable datahistory_dbus_methods[] = {
	{ GDBUS_METHOD("GetAll",
			NULL, GDBUS_ARGS(HISTORY_DBUS_GET_ALL_ARGS),
			datahistory_dbus_get_all) },
	{ GDBUS_METHOD("GetInterfaceVersion",
			NULL, GDBUS_ARGS(HISTORY_DBUS_VERSION_ARG),
			datahistory_dbus_get_version) },
	{ GDBUS_METHOD("GetPersistent",
			NULL, GDBUS_ARGS(HISTORY_DBUS_PERSISTENT_ARG),
			datahistory_dbus_get_persistent) },
	{ GDBUS_METHOD("GetStartTime",
			NULL, GDBUS_ARGS(HISTORY_DBUS_START_TIME_ARG),
			datahistory_dbus_get_start_time) },
	{ GDBUS_METHOD("GetMinimumPeriod",
			NULL, GDBUS_ARGS(HISTORY_DBUS_MINIMUM_PERIOD_ARG),
			datahistory_dbus_get_minimum_period) },
	{ GDBUS_METHOD("GetMaximumDepth",
			NULL, GDBUS_ARGS(HISTORY_DBUS_MAXIMUM_DEPTH_ARG),
			datahistory_dbus_get_maximum_depth) },
	{ GDBUS_METHOD("Clear",
			NULL, NULL,
			datahistory_dbus_clear) },
	{ GDBUS_METHOD("GetSamplesAtIntervals",
			GDBUS_ARGS({"intervals", "ai"}),
			GDBUS_ARGS({"samples",
			"a(" HISTORY_DBUS_SAMPLE_SIGNATURE ")"}),
			datahistory_dbus_get_samples_at_intervals) },
	{ GDBUS_METHOD("GetAllSamples",
			NULL, GDBUS_ARGS({"samples",
			"a(" HISTORY_DBUS_SAMPLE_SIGNATURE ")"}),
			datahistory_dbus_get_all_samples) },
	{ GDBUS_METHOD("GetSamples",
			GDBUS_ARGS({"maxcount", "i"}),
			GDBUS_ARGS({"samples",
			"a(" HISTORY_DBUS_SAMPLE_SIGNATURE ")"}),
			datahistory_dbus_get_samples) },
	{ GDBUS_METHOD("GetSamplesSince",
			GDBUS_ARGS({"since", "x"}, {"maxcount", "i"}),
			GDBUS_ARGS({"samples",
			"a(" HISTORY_DBUS_SAMPLE_SIGNATURE ")"}),
			datahistory_dbus_get_samples_since) },
	{ GDBUS_METHOD("EnableUpdates",
			GDBUS_ARGS({"flags", "u"}, {"interval", "u"}),
			GDBUS_ARGS({"cookie", "u"}),
			datahistory_dbus_enable_updates) },
	{ GDBUS_METHOD("DisableUpdates",
			GDBUS_ARGS({"cookie", "u"}), NULL,
			datahistory_dbus_disable_updates) },
	{ }
};

static const GDBusSignalTable datahistory_dbus_signals[] = {
	{ GDBUS_SIGNAL(HISTORY_DBUS_SIGNAL_CREATED, NULL) },
	{ GDBUS_SIGNAL(HISTORY_DBUS_SIGNAL_DELETED, NULL) },
	{ GDBUS_SIGNAL(HISTORY_DBUS_SIGNAL_CLEARED, NULL) },
	{ GDBUS_SIGNAL(HISTORY_DBUS_SIGNAL_START_TIME_CHANGED,
			GDBUS_ARGS(HISTORY_DBUS_START_TIME_ARG)) },
	{ GDBUS_SIGNAL(HISTORY_DBUS_SIGNAL_LAST_SAMPLE_CHANGED,
			GDBUS_ARGS({ "last_sample",
			HISTORY_DBUS_SAMPLE_SIGNATURE})) },
	{ GDBUS_SIGNAL(HISTORY_DBUS_SIGNAL_SAMPLE_ADDED,
			GDBUS_ARGS({ "new_sample",
			HISTORY_DBUS_SAMPLE_SIGNATURE})) },
	{ }
};

static void datahistory_dbus_history_cleared(struct datahistory *history,
								void *arg)
{
	datahistory_dbus_signal(arg, HISTORY_DBUS_SIGNAL_CLEARED, NULL);
}

static void datahistory_dbus_start_time_changed(struct datahistory *history,
								void *arg)
{
	datahistory_dbus_signal(arg, HISTORY_DBUS_SIGNAL_START_TIME_CHANGED,
					datahistory_dbus_append_start_time);
}

static void datahistory_dbus_sample_signal(struct datahistory_dbus *dbus,
	const char *name, guint flag, const struct datahistory_sample *sample)
{
	if (dbus->updates.flags & flag) {
		DBusMessageIter it;
		DBusMessage *signal = dbus_message_new_signal(dbus->path,
					HISTORY_DBUS_INTERFACE, name);

		dbus_message_iter_init_append(signal, &it);
		datahistory_dbus_append_sample(&it, sample);
		datacounter_dbus_updates_send(&dbus->updates, flag, signal);
		dbus_message_unref(signal);
	}
}

static void datahistory_dbus_last_sample_changed(struct datahistory *history,
								void *arg)
{
	datahistory_dbus_sample_signal((struct datahistory_dbus *)arg,
				HISTORY_DBUS_SIGNAL_LAST_SAMPLE_CHANGED,
				HISTORY_DBUS_UPDATE_FLAG_LAST_SAMPLE_CHANGED,
				&history->last_sample);
}

static void datahistory_dbus_sample_added(struct datahistory *history,
		const struct datahistory_sample *sample, void *arg)
{
	datahistory_dbus_sample_signal((struct datahistory_dbus *)arg,
				HISTORY_DBUS_SIGNAL_SAMPLE_ADDED,
				HISTORY_DBUS_UPDATE_FLAG_SAMPLE_ADDED,
				sample);
}

char *datahistory_dbus_history_path(struct datacounter *counter,
						const char *history_name)
{
	return g_strconcat(COUNTER_DBUS_PATH_PREFIX, counter->ident,
			COUNTER_DBUS_SUFFIX, counter->name,
			COUNTER_DBUS_HISTORY_SUFFIX, history_name, NULL);
}

struct datahistory_dbus *datahistory_dbus_new(struct datahistory *history)
{
	if (G_LIKELY(history)) {
		struct datacounter *dc = history->counter;
		struct datahistory_dbus *dbus =
					g_new0(struct datahistory_dbus, 1);

		dbus->conn = dbus_connection_ref(connman_dbus_get_connection());
		dbus->history = datahistory_ref(history);
		dbus->path = datahistory_dbus_history_path(dc, history->name);
		dbus->name = g_strconcat(dc->name, "/", history->name, NULL);
		dbus->event_id[EVENT_CLEARED] =
			datahistory_add_cleared_handler(history,
				datahistory_dbus_history_cleared, dbus);
		dbus->event_id[EVENT_START_TIME_CHANGED] =
			datahistory_add_start_time_handler(history,
				datahistory_dbus_start_time_changed, dbus);
		dbus->event_id[EVENT_LAST_SAMPLE_CHANGED] =
			datahistory_add_last_sample_handler(history,
				datahistory_dbus_last_sample_changed, dbus);
		dbus->event_id[EVENT_SAMPLE_ADDED] =
			datahistory_add_sample_added_handler(history,
				datahistory_dbus_sample_added, dbus);
		datacounters_dbus_updates_init(&dbus->updates, dbus->path);
		if (g_dbus_register_interface(dbus->conn, dbus->path,
			HISTORY_DBUS_INTERFACE, datahistory_dbus_methods,
			datahistory_dbus_signals, NULL, dbus, NULL)) {
			datahistory_dbus_signal(dbus,
					HISTORY_DBUS_SIGNAL_CREATED, NULL);
			return dbus;
		} else {
			connman_error("History D-Bus registeration failed");
			datahistory_dbus_free(dbus);
		}
	}
	return NULL;
}

void datahistory_dbus_free(struct datahistory_dbus *dbus)
{

	if (G_LIKELY(dbus)) {
		datahistory_dbus_signal(dbus,
					HISTORY_DBUS_SIGNAL_DELETED, NULL);
		g_dbus_unregister_interface(dbus->conn, dbus->path,
						HISTORY_DBUS_INTERFACE);
		datacounters_dbus_updates_destroy(&dbus->updates);
		datahistory_remove_all_handlers(dbus->history, dbus->event_id);
		datahistory_unref(dbus->history);
		g_free(dbus->name);
		g_free(dbus->path);
		g_free(dbus);
	}
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
