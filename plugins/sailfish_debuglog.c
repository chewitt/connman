/*
 *  Connection Manager
 *
 *  Copyright (C) 2015-2017 Jolla Ltd.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "src/connman.h"

#include <dbuslog_server_dbus.h>
#include <gutil_log.h>

#include <string.h>
#include <syslog.h>

#define DEBUGLOG_PATH       "/"

enum _debug_server_event {
	DEBUG_EVENT_CATEGORY_ENABLED,
	DEBUG_EVENT_CATEGORY_DISABLED,
	DEBUG_EVENT_COUNT
};

static DBusLogServer *debuglog_server;
static GLogProc2 debuglog_default_log_proc;
static gulong debuglog_event_id[DEBUG_EVENT_COUNT];

static void debuglog_connman_log_hook(const struct connman_debug_desc *desc,
				int priority, const char *format, va_list va)
{
	DBUSLOG_LEVEL dbuslevel;
	const char *category;

	if (desc) {
		category = desc->name ? desc->name : desc->file;
	} else {
		category = NULL;
	}

	/* connman is only using these four priorities: */
	switch (priority) {
	case LOG_ERR:
		dbuslevel = DBUSLOG_LEVEL_ERROR;
		break;
	case LOG_WARNING:
		dbuslevel = DBUSLOG_LEVEL_WARNING;
		break;
	case LOG_INFO:
		dbuslevel = DBUSLOG_LEVEL_INFO;
		break;
	case LOG_DEBUG:
		dbuslevel = DBUSLOG_LEVEL_DEBUG;
		break;
	default:
		dbuslevel = DBUSLOG_LEVEL_UNDEFINED;
		break;
	}

	dbus_log_server_logv(debuglog_server, dbuslevel, category, format, va);
}

static void debuglog_gutil_log_func(const GLogModule* log, int level,
					const char* format, va_list va)
{
	DBUSLOG_LEVEL loglevel;

	switch (level) {
	case GLOG_LEVEL_ERR:
		loglevel = DBUSLOG_LEVEL_ERROR;
		break;
	case GLOG_LEVEL_WARN:
		loglevel = DBUSLOG_LEVEL_WARNING;
		break;
	case GLOG_LEVEL_INFO:
		loglevel = DBUSLOG_LEVEL_INFO;
		break;
	case GLOG_LEVEL_DEBUG:
		loglevel = DBUSLOG_LEVEL_DEBUG;
		break;
	case GLOG_LEVEL_VERBOSE:
		loglevel = DBUSLOG_LEVEL_VERBOSE;
		break;
	default:
		loglevel = DBUSLOG_LEVEL_UNDEFINED;
		break;
	}

	dbus_log_server_logv(debuglog_server, loglevel, log->name, format, va);
	if (debuglog_default_log_proc) {
		debuglog_default_log_proc(log, level, format, va);
	}
}

static gboolean debuglog_match(const char* s1, const char* s2)
{
	return s1 && s2 && !strcmp(s1, s2);
}

static void debuglog_update_flags(const char* name, guint set, guint clear)
{
	const guint flags = set | clear;
	struct connman_debug_desc *start = __start___debug;
	struct connman_debug_desc *stop = __stop___debug;

	if (start && stop) {
		struct connman_debug_desc *desc;

		for (desc = start; desc < stop; desc++) {
			const char *matched = NULL;

			if (debuglog_match(desc->file, name)) {
				matched = desc->file;
			} else if (debuglog_match(desc->name, name)) {
				matched = desc->name;
			}

			if (matched) {
				const guint old_flags = (desc->flags & flags);
				desc->flags |= set;
				desc->flags &= ~clear;
				if ((desc->flags & flags) != old_flags &&
							desc->notify) {
					desc->notify(desc);
				}
			}
		}
	}

}

static void debuglog_category_enabled(DBusLogServer* server,
				const char* category, gpointer user_data)
{
	debuglog_update_flags(category, CONNMAN_DEBUG_FLAG_PRINT, 0);
}

static void debuglog_category_disabled(DBusLogServer* server,
				const char* category, gpointer user_data)
{
	debuglog_update_flags(category, 0, CONNMAN_DEBUG_FLAG_PRINT);
}

static GHashTable *debuglog_update_flags_hash(GHashTable *hash,
					const char *name, guint flags)
{
	if (name) {
		gpointer key = (gpointer)name;
		guint value;
		if (!hash) {
			hash = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);
		}

		value = GPOINTER_TO_INT(g_hash_table_lookup(hash, key));
		value |= flags;
		g_hash_table_insert(hash, key, GINT_TO_POINTER(value));
	}

	return hash;
}

static guint debuglog_translate_flags(unsigned int connman_flags)
{
	guint flags = 0;

	if (connman_flags & CONNMAN_DEBUG_FLAG_PRINT)
		flags |= DBUSLOG_CATEGORY_FLAG_ENABLED;

#ifdef CONNMAN_DEBUG_FLAG_HIDE_NAME
	if (connman_flags & CONNMAN_DEBUG_FLAG_HIDE_NAME)
		flags |= DBUSLOG_CATEGORY_FLAG_HIDE_NAME;
#endif

	return flags;
}

static void debuglog_add_categories(const struct connman_debug_desc *start,
				const struct connman_debug_desc *stop)
{
	if (start && stop) {
		const struct connman_debug_desc *desc;
		GHashTable *hash = NULL;

		/*
		 * There's also CONNMAN_DEBUG_FLAG_ALIAS defined in log.h
		 * but it's not clear what it means because it's not being
		 * used. Let's comment it in log.h (to make sure that it's
		 * not used) and ignore it for now.
		 */
		for (desc = start; desc < stop; desc++) {
			const guint f = debuglog_translate_flags(desc->flags);
			hash = debuglog_update_flags_hash(hash, desc->file, f);
			hash = debuglog_update_flags_hash(hash, desc->name, f);
		}

		if (hash) {
			gpointer key, value;
			GHashTableIter it;

			g_hash_table_iter_init(&it, hash);

			while (g_hash_table_iter_next(&it, &key, &value)) {
				dbus_log_server_add_category(debuglog_server,
						key, DBUSLOG_LEVEL_UNDEFINED,
						GPOINTER_TO_INT(value));
			}

			g_hash_table_destroy(hash);
		}
	}
}

static void debuglog_add_external_plugin(struct connman_plugin_desc *desc,
						int flags, void *user_data)
{
	/*
	 * We are only interested in the external plugins here because
	 * they don't fall into __start___debug .. __stop___debug range.
	 */
	if (!(flags & CONNMAN_PLUGIN_FLAG_BUILTIN)) {
		if (desc->debug_start && desc->debug_stop) {
			DBG("Adding \"%s\" plugin", desc->name);
			debuglog_add_categories(desc->debug_start,
							desc->debug_stop);
		} else {
			DBG("No debug descriptors for \"%s\" plugin",
							desc->name);
		}
	}
}

static int sailfish_debuglog_init(void)
{
	debuglog_server = dbus_log_server_new(connman_dbus_get_connection(),
							DEBUGLOG_PATH);

	/*
	 * First handle the executable and the builtin plugins (including
	 * this one) then the external plugins.
	 */
	debuglog_add_categories(__start___debug, __stop___debug);
	__connman_plugin_foreach(debuglog_add_external_plugin, NULL);

	debuglog_event_id[DEBUG_EVENT_CATEGORY_ENABLED] =
		dbus_log_server_add_category_enabled_handler(
			debuglog_server, debuglog_category_enabled, NULL);
	debuglog_event_id[DEBUG_EVENT_CATEGORY_DISABLED] =
		dbus_log_server_add_category_disabled_handler(
			debuglog_server, debuglog_category_disabled, NULL);

	debuglog_default_log_proc = gutil_log_func2;
	gutil_log_func2 = debuglog_gutil_log_func;
	connman_log_hook = debuglog_connman_log_hook;

	dbus_log_server_set_default_level(debuglog_server, DBUSLOG_LEVEL_DEBUG);
	dbus_log_server_start(debuglog_server);
	return 0;
}

static void sailfish_debuglog_exit(void)
{
	gutil_log_func2 = debuglog_default_log_proc;
	dbus_log_server_remove_handlers(debuglog_server, debuglog_event_id,
					G_N_ELEMENTS(debuglog_event_id));
	dbus_log_server_unref(debuglog_server);
	debuglog_server = NULL;
}

CONNMAN_PLUGIN_DEFINE(sailfish_debuglog, "Sailfish debug log",
			VERSION, CONNMAN_PLUGIN_PRIORITY_HIGH,
			sailfish_debuglog_init, sailfish_debuglog_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
