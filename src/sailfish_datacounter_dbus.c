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

#include <gutil_strv.h>

struct datacounter_dbus {
	struct datacounter *counter;
	DBusConnection *conn;
	char *path;
	gulong event_id;
	struct datacounters_dbus_updates updates;
	GStrV *histories;
};

typedef void (*datacounter_dbus_append_fn)(DBusMessageIter *it,
					struct datacounter_dbus *dbus);

#define COUNTER_DBUS_INTERFACE          COUNTERS_DBUS_INTERFACE ".Counter"
#define COUNTER_DBUS_INTERFACE_VERSION  (1)

#define COUNTER_DBUS_UPDATE_FLAG_VALUE  (0x01)

#define COUNTER_DBUS_SIGNAL_CREATED             "Created"
#define COUNTER_DBUS_SIGNAL_DELETED             "Deleted"
#define COUNTER_DBUS_SIGNAL_VALUE               "ValueChanged"
#define COUNTER_DBUS_SIGNAL_BASELINE            "BaselineChanged"
#define COUNTER_DBUS_SIGNAL_RESET_TIME          "ResetTimeChanged"
#define COUNTER_DBUS_SIGNAL_BASELINE_RESET_TIME "BaselineResetTimeChanged"
#define COUNTER_DBUS_SIGNAL_DATA_WARNING        "DataWarningChanged"
#define COUNTER_DBUS_SIGNAL_DATA_LIMIT          "DataLimitChanged"
#define COUNTER_DBUS_SIGNAL_TIME_LIMIT          "TimeLimitChanged"
#define COUNTER_DBUS_SIGNAL_TIME_LIMIT_ENABLED  "TimeLimitEnabledChanged"
#define COUNTER_DBUS_SIGNAL_CUTOFF_ENABLED      "CutOffEnabledChanged"
#define COUNTER_DBUS_SIGNAL_CUTOFF_STATE        "CutOffStateChanged"
#define COUNTER_DBUS_SIGNAL_AUTORESET_ENABLED   "AutoResetEnabledChanged"
#define COUNTER_DBUS_SIGNAL_AUTORESET           "AutoResetChanged"

static gboolean datacounter_dbus_get_timer_arg(DBusMessageIter *it,
				struct datacounter_timer *timer)
{
	/* (uiyyyyy) */
	if (dbus_message_iter_get_arg_type(it) == DBUS_TYPE_STRUCT) {
		dbus_uint32_t value;
		dbus_int32_t unit;
		DBusMessageIter sub;
		unsigned char at[TIME_UNIT_YEAR];

		dbus_message_iter_recurse(it, &sub);
		if (datacounters_dbus_get_args(&sub,
				DBUS_TYPE_UINT32, &value,
				DBUS_TYPE_INT32, &unit,
				DBUS_TYPE_BYTE, at + TIME_UNIT_SECOND,
				DBUS_TYPE_BYTE, at + TIME_UNIT_MINUTE,
				DBUS_TYPE_BYTE, at + TIME_UNIT_HOUR,
				DBUS_TYPE_BYTE, at + TIME_UNIT_DAY,
				DBUS_TYPE_BYTE, at + TIME_UNIT_MONTH,
				DBUS_TYPE_INVALID) &&
				unit >= 0 && unit <= TIME_UNITS) {
			int i;
			dbus_message_iter_next(it);
			timer->value = value;
			timer->unit = unit;
			for (i=0; i<TIME_UNIT_YEAR; i++) timer->at[i] = at[i];
			return TRUE;
		}
	}
	return FALSE;
}

static DBusMessage *datacounter_dbus_set_timer(DBusMessage *msg,
	struct datacounter_dbus *dbus,
	void (*fn)(struct datacounter *, const struct datacounter_timer *))
{
	struct datacounter_timer value;
	DBusMessageIter it;

	if (dbus_message_iter_init(msg, &it) &&
			datacounter_dbus_get_timer_arg(&it, &value)) {
		fn(dbus->counter, &value);
		return dbus_message_new_method_return(msg);
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

static DBusMessage *datacounter_dbus_set_boolean(DBusMessage *msg,
			struct datacounter_dbus *dbus,
			void (*fn)(struct datacounter *, gboolean))
{
	dbus_bool_t value;

	if (dbus_message_get_args(msg, NULL,
					DBUS_TYPE_BOOLEAN, &value,
					DBUS_TYPE_INVALID)) {
		fn(dbus->counter, value);
		return dbus_message_new_method_return(msg);
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

static DBusMessage *datacounter_dbus_set_uint64(DBusMessage *msg,
			struct datacounter_dbus *dbus,
			void (*fn)(struct datacounter *, guint64))
{
	dbus_uint64_t value;

	if (dbus_message_get_args(msg, NULL,
					DBUS_TYPE_UINT64, &value,
					DBUS_TYPE_INVALID)) {
		fn(dbus->counter, value);
	}
	return dbus_message_new_method_return(msg);
}

static DBusMessage *datacounter_dbus_reply(DBusMessage *msg,
	struct datacounter_dbus *dbus, datacounter_dbus_append_fn append)
{
	DBusMessage *reply = dbus_message_new_method_return(msg);

	if (append) {
		DBusMessageIter it;
		dbus_message_iter_init_append(reply, &it);
		append(&it, dbus);
	}
	return reply;
}

static void datacounter_dbus_signal(struct datacounter_dbus *dbus,
			const char *name, datacounter_dbus_append_fn append)
{
	DBusMessage *signal = dbus_message_new_signal(dbus->path,
					COUNTER_DBUS_INTERFACE, name);
	if (append) {
		DBusMessageIter it;

		dbus_message_iter_init_append(signal, &it);
		append(&it, dbus);
	}
	g_dbus_send_message(dbus->conn, signal);
}

static void datacounter_dbus_append_stats(DBusMessageIter *it,
				const struct connman_stats_data *stat)
{
	DBusMessageIter sub;

	dbus_message_iter_open_container(it, DBUS_TYPE_STRUCT, NULL, &sub);
	datacounters_dbus_append_uint64(&sub, stat->rx_packets);
	datacounters_dbus_append_uint64(&sub, stat->tx_packets);
	datacounters_dbus_append_uint64(&sub, stat->rx_bytes);
	datacounters_dbus_append_uint64(&sub, stat->tx_bytes);
	datacounters_dbus_append_uint64(&sub, stat->rx_errors);
	datacounters_dbus_append_uint64(&sub, stat->tx_errors);
	datacounters_dbus_append_uint64(&sub, stat->rx_dropped);
	datacounters_dbus_append_uint64(&sub, stat->tx_dropped);
	dbus_message_iter_close_container(it, &sub);
}

static void datacounters_dbus_append_timer(DBusMessageIter *it,
				const struct datacounter_timer *timer)
{
	guint i;
	DBusMessageIter sub;

	dbus_message_iter_open_container(it, DBUS_TYPE_STRUCT, NULL, &sub);
	datacounters_dbus_append_uint32(&sub, timer->value);
	datacounters_dbus_append_int32(&sub, timer->unit);
	for (i = 0; i<G_N_ELEMENTS(timer->at); i++) {
		datacounters_dbus_append_byte(&sub, (guint8)timer->at[i]);
	}
	dbus_message_iter_close_container(it, &sub);
}

static void datacounter_dbus_append_version(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_int32(it, COUNTER_DBUS_INTERFACE_VERSION);
}

static void datacounter_dbus_append_histories(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	DBusMessageIter array;
	struct datacounter *dc = dbus->counter;
	GStrV *ptr = dbus->histories;
	
	dbus_message_iter_open_container(it, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array);
	if (ptr) {
		while (*ptr) {
			const char *name = *ptr++;
			char *path = datahistory_dbus_history_path(dc, name);

			dbus_message_iter_append_basic(&array,
					DBUS_TYPE_OBJECT_PATH, &path);
			g_free(path);
		}
	}

	dbus_message_iter_close_container(it, &array);
}

static void datacounter_dbus_append_value(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounter_dbus_append_stats(it, dbus->counter->value);
}

static void datacounter_dbus_append_baseline(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounter_dbus_append_stats(it, dbus->counter->baseline);
}

static void datacounter_dbus_append_reset_time(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_int64(it,
			datacounter_reset_time(dbus->counter));
}

static void datacounter_dbus_append_baseline_reset_time(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_int64(it,
			datacounter_baseline_reset_time(dbus->counter));
}

static void datacounter_dbus_append_data_warning(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_uint64(it,
			datacounter_data_warning(dbus->counter));
}

static void datacounter_dbus_append_data_limit(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_uint64(it,
			datacounter_data_limit(dbus->counter));
}

static void datacounter_dbus_append_time_limit(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_timer(it, dbus->counter->time_limit);
}

static void datacounter_dbus_append_time_limit_enabled(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_bool(it,
			datacounter_time_limit_enabled(dbus->counter));
}

static void datacounter_dbus_append_cutoff_enabled(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_bool(it,
			datacounter_cutoff_enabled(dbus->counter));
}

static void datacounter_dbus_append_cutoff_state(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_int32(it, dbus->counter->cutoff_state);
}

static void datacounter_dbus_append_autoreset_enabled(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_bool(it,
			datacounter_autoreset_enabled(dbus->counter));
}

static void datacounter_dbus_append_autoreset(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounters_dbus_append_timer(it, dbus->counter->autoreset);
}

static void datacounter_dbus_append_all(DBusMessageIter *it,
					struct datacounter_dbus *dbus)
{
	datacounter_dbus_append_version(it, dbus);
	datacounter_dbus_append_histories(it, dbus);
	datacounter_dbus_append_value(it, dbus);
	datacounter_dbus_append_baseline(it, dbus);
	datacounter_dbus_append_reset_time(it, dbus);
	datacounter_dbus_append_baseline_reset_time(it, dbus);
	datacounter_dbus_append_data_warning(it, dbus);
	datacounter_dbus_append_data_limit(it, dbus);
	datacounter_dbus_append_time_limit(it, dbus);
	datacounter_dbus_append_time_limit_enabled(it, dbus);
	datacounter_dbus_append_cutoff_enabled(it, dbus);
	datacounter_dbus_append_cutoff_state(it, dbus);
	datacounter_dbus_append_autoreset(it, dbus);
	datacounter_dbus_append_autoreset_enabled(it, dbus);
}

static DBusMessage *datacounter_dbus_get_all(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_all);
}

static DBusMessage *datacounter_dbus_get_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_version);
}

static DBusMessage *datacounter_dbus_get_histories(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_histories);
}

static DBusMessage *datacounter_dbus_get_value(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_value);
}

static DBusMessage *datacounter_dbus_get_baseline(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_baseline);
}

static DBusMessage *datacounter_dbus_get_reset_time(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_reset_time);
}

static DBusMessage *datacounter_dbus_get_baseline_reset_time(
						DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_baseline_reset_time);
}

static DBusMessage *datacounter_dbus_get_data_warning(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_data_warning);
}

static DBusMessage *datacounter_dbus_get_data_limit(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_data_limit);
}

static DBusMessage *datacounter_dbus_get_time_limit(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_time_limit);
}

static DBusMessage *datacounter_dbus_get_time_limit_enabled(
			DBusConnection *conn, DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_time_limit_enabled);
}

static DBusMessage *datacounter_dbus_get_cutoff_enabled(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_cutoff_enabled);
}

static DBusMessage *datacounter_dbus_get_cutoff_state(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_cutoff_state);
}

static DBusMessage *datacounter_dbus_get_autoreset_enabled(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_autoreset_enabled);
}

static DBusMessage *datacounter_dbus_get_autoreset(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_reply(msg, (struct datacounter_dbus *)data,
				datacounter_dbus_append_autoreset);
}

static DBusMessage *datacounter_dbus_reset(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datacounter_dbus *dbus = data;

	datacounter_reset(dbus->counter);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *datacounter_dbus_reset_baseline(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datacounter_dbus *dbus = data;

	datacounter_reset_baseline(dbus->counter);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *datacounter_dbus_set_data_warning(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_uint64(msg, data,
					datacounter_set_data_warning);
}

static DBusMessage *datacounter_dbus_set_data_limit(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_uint64(msg, data,
					datacounter_set_data_limit);
}

static DBusMessage *datacounter_dbus_set_time_limit(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_timer(msg, data,
					datacounter_set_time_limit);
}

static DBusMessage *datacounter_dbus_set_time_limit_enabled(
			DBusConnection *conn, DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_boolean(msg, data,
					datacounter_set_time_limit_enabled);
}

static DBusMessage *datacounter_dbus_set_cutoff_enabled(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_boolean(msg, data,
					datacounter_set_cutoff_enabled);
}

static DBusMessage *datacounter_dbus_set_autoreset_enabled(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_boolean(msg, data,
					datacounter_set_autoreset_enabled);
}

static DBusMessage *datacounter_dbus_set_autoreset(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounter_dbus_set_timer(msg, data,
					datacounter_set_autoreset);
}

static DBusMessage *datacounter_dbus_enable_updates(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datacounter_dbus *dbus = data;

	return datacounter_dbus_updates_enable(&dbus->updates, conn, msg);
}

static DBusMessage *datacounter_dbus_disable_updates(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datacounter_dbus *dbus = data;

	return datacounter_dbus_updates_disable(&dbus->updates, conn, msg);
}

#define COUNTER_DBUS_VERSION_ARG              {"version", "i"}
#define COUNTER_DBUS_HISTORIES_ARG            {"histories", "ao"}
#define COUNTER_DBUS_VALUE_ARG                {"value", "(tttttttt)"}
#define COUNTER_DBUS_BASELINE_ARG             {"baseline", "(tttttttt)"}
#define COUNTER_DBUS_RESET_TIME_ARG           {"time", "x"}
#define COUNTER_DBUS_BASELINE_RESET_TIME_ARG  {"time", "x"}
#define COUNTER_DBUS_DATA_WARNING_ARG         {"data_warning", "t"}
#define COUNTER_DBUS_DATA_LIMIT_ARG           {"data_limit", "t"}
#define COUNTER_DBUS_TIME_LIMIT_ARG           {"time_limit", "(uiyyyyy)"}
#define COUNTER_DBUS_TIME_LIMIT_ENABLED_ARG   {"time_limit_enabled", "b"}
#define COUNTER_DBUS_CUTOFF_ENABLED_ARG       {"enabled", "b"}
#define COUNTER_DBUS_CUTOFF_STATE_ARG         {"state", "i"}
#define COUNTER_DBUS_AUTORESET_ARG            {"autoreset", "(uiyyyyy)"}
#define COUNTER_DBUS_AUTORESET_ENABLED_ARG    {"autoreset_enabled", "b"}
#define COUNTER_DBUS_GET_ALL_ARGS \
	COUNTER_DBUS_VERSION_ARG, \
	COUNTER_DBUS_HISTORIES_ARG, \
	COUNTER_DBUS_VALUE_ARG, \
	COUNTER_DBUS_BASELINE_ARG, \
	COUNTER_DBUS_RESET_TIME_ARG, \
	COUNTER_DBUS_BASELINE_RESET_TIME_ARG, \
	COUNTER_DBUS_DATA_WARNING_ARG, \
	COUNTER_DBUS_DATA_LIMIT_ARG, \
	COUNTER_DBUS_TIME_LIMIT_ARG, \
	COUNTER_DBUS_TIME_LIMIT_ENABLED_ARG, \
	COUNTER_DBUS_CUTOFF_ENABLED_ARG, \
	COUNTER_DBUS_CUTOFF_STATE_ARG, \
	COUNTER_DBUS_AUTORESET_ARG, \
	COUNTER_DBUS_AUTORESET_ENABLED_ARG

static const GDBusMethodTable datacounter_dbus_methods[] = {
	{ GDBUS_METHOD("GetAll",
			NULL, GDBUS_ARGS(COUNTER_DBUS_GET_ALL_ARGS),
			datacounter_dbus_get_all) },
	{ GDBUS_METHOD("GetInterfaceVersion",
			NULL, GDBUS_ARGS(COUNTER_DBUS_VERSION_ARG),
			datacounter_dbus_get_version) },
	{ GDBUS_METHOD("GetHistories",
			NULL, GDBUS_ARGS(COUNTER_DBUS_HISTORIES_ARG),
			datacounter_dbus_get_histories) },
	{ GDBUS_METHOD("GetValue",
			NULL, GDBUS_ARGS(COUNTER_DBUS_VALUE_ARG),
			datacounter_dbus_get_value) },
	{ GDBUS_METHOD("GetBaseline",
			NULL, GDBUS_ARGS(COUNTER_DBUS_BASELINE_ARG),
			datacounter_dbus_get_baseline) },
	{ GDBUS_METHOD("GetResetTime",
			NULL, GDBUS_ARGS(COUNTER_DBUS_RESET_TIME_ARG),
			datacounter_dbus_get_reset_time) },
	{ GDBUS_METHOD("GetBaselineResetTime",
			NULL, GDBUS_ARGS(COUNTER_DBUS_BASELINE_RESET_TIME_ARG),
			datacounter_dbus_get_baseline_reset_time) },
	{ GDBUS_METHOD("GetDataWarning",
			NULL, GDBUS_ARGS(COUNTER_DBUS_DATA_WARNING_ARG),
			datacounter_dbus_get_data_warning) },
	{ GDBUS_METHOD("GetDataLimit",
			NULL, GDBUS_ARGS(COUNTER_DBUS_DATA_LIMIT_ARG),
			datacounter_dbus_get_data_limit) },
	{ GDBUS_METHOD("GetTimeLimit",
			NULL, GDBUS_ARGS(COUNTER_DBUS_TIME_LIMIT_ARG),
			datacounter_dbus_get_time_limit) },
	{ GDBUS_METHOD("GetTimeLimitEnabled",
			NULL, GDBUS_ARGS(COUNTER_DBUS_TIME_LIMIT_ENABLED_ARG),
			datacounter_dbus_get_time_limit_enabled) },
	{ GDBUS_METHOD("GetCutOffEnabled",
			NULL, GDBUS_ARGS(COUNTER_DBUS_CUTOFF_ENABLED_ARG),
			datacounter_dbus_get_cutoff_enabled) },
	{ GDBUS_METHOD("GetCutOffState",
			NULL, GDBUS_ARGS(COUNTER_DBUS_CUTOFF_STATE_ARG),
			datacounter_dbus_get_cutoff_state) },
	{ GDBUS_METHOD("GetAutoReset",
			NULL, GDBUS_ARGS(COUNTER_DBUS_AUTORESET_ARG),
			datacounter_dbus_get_autoreset) },
	{ GDBUS_METHOD("GetAutoResetEnabled",
			NULL, GDBUS_ARGS(COUNTER_DBUS_AUTORESET_ENABLED_ARG),
			datacounter_dbus_get_autoreset_enabled) },
	{ GDBUS_METHOD("Reset",
			NULL, NULL,
			datacounter_dbus_reset) },
	{ GDBUS_METHOD("ResetBaseline",
			NULL, NULL,
			datacounter_dbus_reset_baseline) },
	{ GDBUS_METHOD("SetDataWarning",
			GDBUS_ARGS(COUNTER_DBUS_DATA_WARNING_ARG), NULL,
			datacounter_dbus_set_data_warning) },
	{ GDBUS_METHOD("SetDataLimit",
			GDBUS_ARGS(COUNTER_DBUS_DATA_LIMIT_ARG), NULL,
			datacounter_dbus_set_data_limit) },
	{ GDBUS_METHOD("SetTimeLimit",
			GDBUS_ARGS(COUNTER_DBUS_TIME_LIMIT_ARG), NULL,
			datacounter_dbus_set_time_limit) },
	{ GDBUS_METHOD("SetTimeLimitEnabled",
			GDBUS_ARGS(COUNTER_DBUS_TIME_LIMIT_ENABLED_ARG), NULL,
			datacounter_dbus_set_time_limit_enabled) },
	{ GDBUS_METHOD("SetCutOffEnabled",
			GDBUS_ARGS(COUNTER_DBUS_CUTOFF_ENABLED_ARG), NULL,
			datacounter_dbus_set_cutoff_enabled) },
	{ GDBUS_METHOD("SetAutoReset",
			GDBUS_ARGS(COUNTER_DBUS_AUTORESET_ARG), NULL,
			datacounter_dbus_set_autoreset) },
	{ GDBUS_METHOD("SetAutoResetEnabled",
			GDBUS_ARGS(COUNTER_DBUS_AUTORESET_ENABLED_ARG), NULL,
			datacounter_dbus_set_autoreset_enabled) },
	{ GDBUS_METHOD("EnableUpdates",
			GDBUS_ARGS({"flags", "u"}, {"interval", "u"}),
			GDBUS_ARGS({"cookie", "u"}),
			datacounter_dbus_enable_updates) },
	{ GDBUS_METHOD("DisableUpdates",
			GDBUS_ARGS({"cookie", "u"}), NULL,
			datacounter_dbus_disable_updates) },
	{ }
};

static const GDBusSignalTable datacounter_dbus_signals[] = {
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_CREATED, NULL) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_DELETED, NULL) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_VALUE,
			GDBUS_ARGS(COUNTER_DBUS_VALUE_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_BASELINE,
			GDBUS_ARGS(COUNTER_DBUS_BASELINE_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_RESET_TIME,
			GDBUS_ARGS(COUNTER_DBUS_RESET_TIME_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_BASELINE_RESET_TIME,
			GDBUS_ARGS(COUNTER_DBUS_BASELINE_RESET_TIME_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_DATA_WARNING,
			GDBUS_ARGS(COUNTER_DBUS_DATA_WARNING_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_DATA_LIMIT,
			GDBUS_ARGS(COUNTER_DBUS_DATA_LIMIT_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_TIME_LIMIT,
			GDBUS_ARGS(COUNTER_DBUS_TIME_LIMIT_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_TIME_LIMIT_ENABLED,
			GDBUS_ARGS(COUNTER_DBUS_TIME_LIMIT_ENABLED_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_CUTOFF_ENABLED,
			GDBUS_ARGS(COUNTER_DBUS_CUTOFF_ENABLED_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_CUTOFF_STATE,
			GDBUS_ARGS(COUNTER_DBUS_CUTOFF_STATE_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_AUTORESET_ENABLED,
			GDBUS_ARGS(COUNTER_DBUS_AUTORESET_ENABLED_ARG)) },
	{ GDBUS_SIGNAL(COUNTER_DBUS_SIGNAL_AUTORESET,
			GDBUS_ARGS(COUNTER_DBUS_AUTORESET_ARG)) },
	{ }
};

static gboolean datacounter_dbus_update_signal(struct datacounter_dbus *dbus,
	const char *name, guint flag, datacounter_dbus_append_fn append)
{
	if (dbus->updates.flags & flag) {
		DBusMessageIter it;
		DBusMessage *signal = dbus_message_new_signal(dbus->path,
					COUNTER_DBUS_INTERFACE, name);

		dbus_message_iter_init_append(signal, &it);
		append(&it, dbus);
		datacounter_dbus_updates_send(&dbus->updates, flag, signal);
		dbus_message_unref(signal);
		return TRUE;
	} else {
		return FALSE;
	}
}

static void datacounter_dbus_property_handler(struct datacounter *counter,
			enum datacounter_property property, void *arg)
{
	struct datacounter_dbus *dbus = arg;
	datacounter_dbus_append_fn args;
	const char *name;

	switch (property) {
	case DATACOUNTER_PROPERTY_VALUE:
		datacounter_dbus_update_signal(dbus,
					COUNTER_DBUS_SIGNAL_VALUE,
					COUNTER_DBUS_UPDATE_FLAG_VALUE,
					datacounter_dbus_append_value);
		return;
	case DATACOUNTER_PROPERTY_BASELINE:
		name = COUNTER_DBUS_SIGNAL_BASELINE;
		args = datacounter_dbus_append_baseline;
		break;
	case DATACOUNTER_PROPERTY_RESET_TIME:
		name = COUNTER_DBUS_SIGNAL_RESET_TIME;
		args = datacounter_dbus_append_reset_time;
		break;
	case DATACOUNTER_PROPERTY_BASELINE_RESET_TIME:
		name = COUNTER_DBUS_SIGNAL_BASELINE_RESET_TIME;
		args = datacounter_dbus_append_baseline_reset_time;
		break;
	case DATACOUNTER_PROPERTY_DATA_WARNING:
		name = COUNTER_DBUS_SIGNAL_DATA_WARNING;
		args = datacounter_dbus_append_data_warning;
		break;
	case DATACOUNTER_PROPERTY_DATA_LIMIT:
		name = COUNTER_DBUS_SIGNAL_DATA_LIMIT;
		args = datacounter_dbus_append_data_limit;
		break;
	case DATACOUNTER_PROPERTY_TIME_LIMIT:
		name = COUNTER_DBUS_SIGNAL_TIME_LIMIT;
		args = datacounter_dbus_append_time_limit;
		break;
	case DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED:
		name = COUNTER_DBUS_SIGNAL_TIME_LIMIT_ENABLED;
		args = datacounter_dbus_append_time_limit_enabled;
		break;
	case DATACOUNTER_PROPERTY_CUTOFF_ENABLED:
		name = COUNTER_DBUS_SIGNAL_CUTOFF_ENABLED;
		args = datacounter_dbus_append_cutoff_enabled;
		break;
	case DATACOUNTER_PROPERTY_CUTOFF_STATE:
		name = COUNTER_DBUS_SIGNAL_CUTOFF_STATE;
		args = datacounter_dbus_append_cutoff_state;
		break;
	case DATACOUNTER_PROPERTY_AUTORESET_ENABLED:
		name = COUNTER_DBUS_SIGNAL_AUTORESET_ENABLED;
		args = datacounter_dbus_append_autoreset_enabled;
		break;
	case DATACOUNTER_PROPERTY_AUTORESET:
		name = COUNTER_DBUS_SIGNAL_AUTORESET;
		args = datacounter_dbus_append_autoreset;
		break;
	default:
		return;
	}
	datacounter_dbus_signal(dbus, name, args);
}

char *datacounter_dbus_path(const char *ident, const char *name)
{
	return g_strconcat(COUNTER_DBUS_PATH_PREFIX, ident,
					COUNTER_DBUS_SUFFIX, name, NULL);
}

struct datacounter_dbus *datacounter_dbus_new(struct datacounter *dc,
						const char *const *histories)
{
	if (G_LIKELY(dc)) {
		struct datacounter_dbus *dbus =
					g_new0(struct datacounter_dbus, 1);

		if (histories) {
			dbus->histories = g_strdupv((char**)histories);
		}
		dbus->conn = dbus_connection_ref(connman_dbus_get_connection());
		dbus->counter = datacounter_ref(dc);
		dbus->path = datacounter_dbus_path(dc->ident, dc->name);
		dbus->event_id =  datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_ANY,
				datacounter_dbus_property_handler, dbus);
		datacounters_dbus_updates_init(&dbus->updates, dbus->path);
		if (g_dbus_register_interface(dbus->conn, dbus->path,
			COUNTER_DBUS_INTERFACE, datacounter_dbus_methods,
			datacounter_dbus_signals, NULL, dbus, NULL)) {
			datacounter_dbus_signal(dbus,
					COUNTER_DBUS_SIGNAL_CREATED, NULL);
			return dbus;
		} else {
			connman_error("Counter D-Bus registeration failed");
			datacounter_dbus_free(dbus);
		}
	}
	return NULL;
}

void datacounter_dbus_free(struct datacounter_dbus *dbus)
{
	if (G_LIKELY(dbus)) {
		datacounter_dbus_signal(dbus, COUNTER_DBUS_SIGNAL_DELETED,
								NULL);
		g_dbus_unregister_interface(dbus->conn, dbus->path,
						COUNTER_DBUS_INTERFACE);
		datacounters_dbus_updates_destroy(&dbus->updates);
		datacounter_remove_handler(dbus->counter, dbus->event_id);
		datacounter_unref(dbus->counter);
		dbus_connection_flush(dbus->conn);
		dbus_connection_unref(dbus->conn);
		g_strfreev(dbus->histories);
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
