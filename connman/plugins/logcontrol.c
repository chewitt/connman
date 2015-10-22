/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015 Jolla Ltd. All rights reserved.
 *  Contact: Slava Monich <slava.monich@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman.h>

#define LOG_INTERFACE  CONNMAN_SERVICE ".DebugLog"
#define LOG_PATH       "/"

static DBusConnection *connection = NULL;

extern struct connman_debug_desc __start___debug[];
extern struct connman_debug_desc __stop___debug[];

static void logcontrol_update(const char* pattern, unsigned int set_flags,
						unsigned int clear_flags)
{
	struct connman_debug_desc *start = __start___debug;
	struct connman_debug_desc *stop = __stop___debug;
	struct connman_debug_desc *desc;
	const char *alias = NULL, *file = NULL;

	if (!start || !stop)
		return;

	for (desc = start; desc < stop; desc++) {
		const char* name;

		if (desc->flags & CONNMAN_DEBUG_FLAG_ALIAS) {
			file = desc->file;
			alias = desc->name;
			continue;
		}

		if (file && g_strcmp0(desc->file, file)) {
			file = NULL;
			alias = NULL;
		}

		name = desc->name ? desc->name : alias;
		if ((name && g_pattern_match_simple(pattern, name)) ||
			(desc->file && g_pattern_match_simple(pattern,
							desc->file))) {
			unsigned int flags;

			flags = (desc->flags | set_flags) & ~clear_flags;
			if (desc->flags != flags) {
				desc->flags = flags;
				if (desc->notify) {
					desc->notify(desc);
				}
			}
		}
	}
}

static DBusMessage *logcontrol_dbusmsg(DBusConnection *conn, DBusMessage *msg,
			unsigned int set_flags, unsigned int clear_flags)
{
	const char *pattern;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
							DBUS_TYPE_INVALID)) {
		logcontrol_update(pattern, set_flags, clear_flags);
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	} else {
		return __connman_error_invalid_arguments(msg);
	}
}

static DBusMessage *logcontrol_enable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return logcontrol_dbusmsg(conn, msg, CONNMAN_DEBUG_FLAG_PRINT, 0);
}

static DBusMessage *logcontrol_disable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return logcontrol_dbusmsg(conn, msg, 0, CONNMAN_DEBUG_FLAG_PRINT);
}

static gint logcontrol_list_compare(gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

static void logcontrol_list_append(gpointer name, gpointer iter)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &name);
}

static void logcontrol_list_store(GHashTable *hash, const char *name)
{
	if (name && !g_hash_table_contains(hash, (gpointer)name))
		g_hash_table_insert(hash, (gpointer)name, (gpointer)name);
}

static DBusMessage *logcontrol_list(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply = dbus_message_new_method_return(msg);

	if (reply) {
		struct connman_debug_desc *start = __start___debug;
		struct connman_debug_desc *stop = __stop___debug;
		DBusMessageIter iter, array;

		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

		if (start && stop) {
			struct connman_debug_desc *desc;
			GList *names;
			GHashTable *hash = g_hash_table_new_full(g_str_hash,
						g_str_equal, NULL, NULL);

			for (desc = start; desc < stop; desc++) {
				logcontrol_list_store(hash, desc->file);
				logcontrol_list_store(hash, desc->name);
			}

			names = g_list_sort(g_hash_table_get_keys(hash),
						logcontrol_list_compare);
			g_list_foreach(names, logcontrol_list_append, &array);
			g_list_free(names);
			g_hash_table_destroy(hash);
		}

		dbus_message_iter_close_container(&iter, &array);
	}

	return reply;
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("Enable", GDBUS_ARGS({ "pattern", "s" }), NULL,
							logcontrol_enable) },
	{ GDBUS_METHOD("Disable", GDBUS_ARGS({ "pattern", "s" }), NULL,
							logcontrol_disable) },
	{ GDBUS_METHOD("List", NULL, GDBUS_ARGS({ "names", "as" }),
							logcontrol_list) },
	{ },
};

static int logcontrol_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (!connection)
		return -1;

	if (!g_dbus_register_interface(connection, LOG_PATH, LOG_INTERFACE,
					methods, NULL, NULL, NULL, NULL)) {
		connman_error("logcontrol: failed to register " LOG_INTERFACE);
		return -1;
	}

	return 0;
}

static void logcontrol_exit(void)
{
	DBG("");

	if (connection) {
		g_dbus_unregister_interface(connection, LOG_PATH,
								LOG_INTERFACE);
		dbus_connection_unref(connection);
		connection = NULL;
	}
}

CONNMAN_PLUGIN_DEFINE(logcontrol, "Debug log control interface",
			VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			logcontrol_init, logcontrol_exit)
