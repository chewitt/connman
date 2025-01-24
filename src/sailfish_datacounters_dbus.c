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

#include <connman/dbus.h>
#include <connman/log.h>

struct datacounters_dbus {
	gint ref_count;
	struct datacounters *counters;
	DBusConnection *conn;
	char *path;
	gulong handler_id;
};

typedef void (*datacounters_dbus_append_fn)(DBusMessageIter *it,
					struct datacounters_dbus *dbus);

#define COUNTERS_DBUS_PATH_PREFIX        CONNMAN_PATH "/service/"
#define COUNTERS_DBUS_INTERFACE_VERSION  (1)

#define COUNTERS_DBUS_SIGNAL_CREATED            "Created"
#define COUNTERS_DBUS_SIGNAL_DELETED            "Deleted"
#define COUNTERS_DBUS_SIGNAL_COUNTERS_CHANGED   "CountersChanged"

/* Active instances of datacounters_dbus */
static GHashTable *datacounters_dbus_table = NULL;

static DBusMessage *datacounters_dbus_reply(DBusMessage *msg,
	struct datacounters_dbus *dbus, datacounters_dbus_append_fn append)
{
	DBusMessage *reply = dbus_message_new_method_return(msg);
	DBusMessageIter it;

	dbus_message_iter_init_append(reply, &it);
	append(&it, dbus);
	return reply;
}

static void datacounters_dbus_signal(struct datacounters_dbus *dbus,
			const char *name, datacounters_dbus_append_fn append)
{
	DBusMessage *signal = dbus_message_new_signal(dbus->path,
					COUNTERS_DBUS_INTERFACE, name);
	if (append) {
		DBusMessageIter it;
		dbus_message_iter_init_append(signal, &it);
		append(&it, dbus);
	}
	g_dbus_send_message(dbus->conn, signal);
}

static void datacounters_dbus_append_version(DBusMessageIter *it,
					struct datacounters_dbus *dbus)
{
	datacounters_dbus_append_int32(it, COUNTERS_DBUS_INTERFACE_VERSION);
}

static void datacounters_dbus_append_counters(DBusMessageIter *it,
					struct datacounters_dbus *dbus)
{
	DBusMessageIter array;
	const char *ident = dbus->counters->ident;
	const char *const *ptr = dbus->counters->counters;
	
	dbus_message_iter_open_container(it, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array);
	while (*ptr) {
		const char *name = *ptr++;
		char *path = datacounter_dbus_path(ident, name);
		dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH,
								&path);
		g_free(path);
	}

	dbus_message_iter_close_container(it, &array);
}

static void datacounters_dbus_append_all(DBusMessageIter *it,
					struct datacounters_dbus *dbus)
{
	datacounters_dbus_append_version(it, dbus);
	datacounters_dbus_append_counters(it, dbus);
}

static DBusMessage *datacounters_dbus_get_all(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounters_dbus_reply(msg, (struct datacounters_dbus *)data,
				datacounters_dbus_append_all);
}

static DBusMessage *datacounters_dbus_get_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounters_dbus_reply(msg, (struct datacounters_dbus *)data,
				datacounters_dbus_append_version);
}

static DBusMessage *datacounters_dbus_get_counters(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return datacounters_dbus_reply(msg, (struct datacounters_dbus *)data,
				datacounters_dbus_append_counters);
}

static DBusMessage *datacounters_dbus_reset_all(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct datacounters_dbus *dbus = data;

	datacounters_reset_all_counters(dbus->counters);
	return dbus_message_new_method_return(msg);
}

#define COUNTERS_DBUS_GET_ALL_ARGS \
	{"version", "i" }, \
	{"counters", "ao" }

static const GDBusMethodTable datacounters_dbus_methods[] = {
	{ GDBUS_METHOD("GetAll",
			NULL, GDBUS_ARGS(COUNTERS_DBUS_GET_ALL_ARGS),
			datacounters_dbus_get_all) },
	{ GDBUS_METHOD("GetInterfaceVersion",
			NULL, GDBUS_ARGS({ "version", "i" }),
			datacounters_dbus_get_version) },
	{ GDBUS_METHOD("GetCounters",
			NULL, GDBUS_ARGS({ "counters", "ao" }),
			datacounters_dbus_get_counters) },
	{ GDBUS_METHOD("ResetAll",
			NULL, NULL,
			datacounters_dbus_reset_all) },
	{ }
};

static const GDBusSignalTable datacounters_dbus_signals[] = {
	{ GDBUS_SIGNAL(COUNTERS_DBUS_SIGNAL_CREATED, NULL) },
	{ GDBUS_SIGNAL(COUNTERS_DBUS_SIGNAL_DELETED, NULL) },
	{ GDBUS_SIGNAL(COUNTERS_DBUS_SIGNAL_COUNTERS_CHANGED,
			GDBUS_ARGS({ "counters", "ao" })) },
	{ }
};

static void datacounters_dbus_counters_changed(struct datacounters *counters,
								void *arg)
{
	struct datacounters_dbus *dbus = arg;

	datacounters_dbus_signal(dbus, COUNTERS_DBUS_SIGNAL_COUNTERS_CHANGED,
				datacounters_dbus_append_counters);
}

static void datacounters_dbus_really_free(struct datacounters_dbus *dbus)
{
	/* Remove it from the table */
	g_hash_table_remove(datacounters_dbus_table, dbus->counters->ident);
	if (g_hash_table_size(datacounters_dbus_table) == 0) {
		/* Delete the hashtable when we no longer need it */
		g_hash_table_unref(datacounters_dbus_table);
		datacounters_dbus_table = NULL;
	}

	datacounters_dbus_signal(dbus, COUNTERS_DBUS_SIGNAL_DELETED, NULL);
	g_dbus_unregister_interface(dbus->conn, dbus->path,
						COUNTERS_DBUS_INTERFACE);
	datacounters_remove_handler(dbus->counters, dbus->handler_id);
	datacounters_unref(dbus->counters);
	dbus_connection_unref(dbus->conn);
	g_free(dbus->path);
	g_free(dbus);
}

static struct datacounters_dbus *datacounters_dbus_create(
					struct datacounters *counters)
{
	struct datacounters_dbus *dbus = g_new0(struct datacounters_dbus, 1);

	g_atomic_int_set(&dbus->ref_count, 1);
	dbus->conn = dbus_connection_ref(connman_dbus_get_connection());
	dbus->counters = datacounters_ref(counters);
	dbus->path = g_strconcat(COUNTERS_DBUS_PATH_PREFIX,
						counters->ident, NULL);
	dbus->handler_id = datacounters_add_counters_handler(counters,
				datacounters_dbus_counters_changed, dbus);
	if (g_dbus_register_interface(dbus->conn, dbus->path,
			COUNTERS_DBUS_INTERFACE, datacounters_dbus_methods,
			datacounters_dbus_signals, NULL, dbus, NULL)) {
		datacounters_dbus_signal(dbus, COUNTERS_DBUS_SIGNAL_CREATED,
								NULL);
		return dbus;
	} else {
		connman_error("Counters D-Bus registeration failed");
		datacounters_dbus_free(dbus);
	}
	return NULL;
}

struct datacounters_dbus *datacounters_dbus_new(struct datacounters *counters)
{
	struct datacounters_dbus *dbus = NULL;

	if (G_LIKELY(counters)) {
		if (datacounters_dbus_table) {
			dbus = g_hash_table_lookup(datacounters_dbus_table,
							counters->ident);
		} else {
			datacounters_dbus_table = g_hash_table_new(g_str_hash,
								g_str_equal);
		}
		if (dbus) {
			g_atomic_int_inc(&dbus->ref_count);
		} else {
			dbus = datacounters_dbus_create(counters);
			g_hash_table_insert(datacounters_dbus_table,
					(gpointer)counters->ident, dbus);
		}
	}
	return dbus;
}

void datacounters_dbus_free(struct datacounters_dbus *dbus)
{
	if (G_LIKELY(dbus)) {
		if (g_atomic_int_dec_and_test(&dbus->ref_count)) {
			datacounters_dbus_really_free(dbus);
		}
	}
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
