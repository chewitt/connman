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

#ifndef SAILFISH_DATACOUNTERS_DBUS_UTIL_H
#define SAILFISH_DATACOUNTERS_DBUS_UTIL_H

#include "sailfish_datacounters.h"

#include <gdbus.h>

#define COUNTERS_DBUS_INTERFACE     "org.sailfishos.connman.datacounters"
#define COUNTER_DBUS_PATH_PREFIX    CONNMAN_PATH "/service/"
#define COUNTER_DBUS_SUFFIX         "/"
#define COUNTER_DBUS_HISTORY_SUFFIX "/"

struct datacounters_dbus_updates {
	const char *name;
	guint last_update_cookie;
	guint flags;
	GHashTable *clients;
};

static inline void datacounters_dbus_append_bool(DBusMessageIter *it,
							dbus_bool_t value)
{
	dbus_message_iter_append_basic(it, DBUS_TYPE_BOOLEAN, &value);
}

static inline void datacounters_dbus_append_byte(DBusMessageIter *it,
							unsigned char value)
{
	dbus_message_iter_append_basic(it, DBUS_TYPE_BYTE, &value);
}

static inline void datacounters_dbus_append_int32(DBusMessageIter *it,
							dbus_int32_t value)
{
	dbus_message_iter_append_basic(it, DBUS_TYPE_INT32, &value);
}

static inline void datacounters_dbus_append_uint32(DBusMessageIter *it,
							dbus_uint32_t value)
{
	dbus_message_iter_append_basic(it, DBUS_TYPE_UINT32, &value);
}

static inline void datacounters_dbus_append_int64(DBusMessageIter *it,
							dbus_int64_t value)
{
	dbus_message_iter_append_basic(it, DBUS_TYPE_INT64, &value);
}

static inline void datacounters_dbus_append_uint64(DBusMessageIter *it,
							dbus_uint64_t value)
{
	dbus_message_iter_append_basic(it, DBUS_TYPE_UINT64, &value);
}

gboolean datacounters_dbus_get_args(DBusMessageIter *it, int first_type, ...);

void datacounters_dbus_updates_init(struct datacounters_dbus_updates *up,
							const char *path);
void datacounters_dbus_updates_destroy(struct datacounters_dbus_updates *up);
DBusMessage *datacounter_dbus_updates_enable(
				struct datacounters_dbus_updates *up,
				DBusConnection *conn, DBusMessage *msg);
DBusMessage *datacounter_dbus_updates_disable(
				struct datacounters_dbus_updates *up,
				DBusConnection *conn, DBusMessage *msg);
void datacounter_dbus_updates_send(struct datacounters_dbus_updates *up,
				guint flags, DBusMessage *msg);

#endif /* SAILFISH_DATACOUNTERS_DBUS_UTIL_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
