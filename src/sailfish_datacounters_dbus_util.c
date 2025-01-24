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

#include "sailfish_datacounters_dbus_util.h"

#include "connman.h"

struct datacounters_dbus_client {
	struct datacounters_dbus_updates *up;
	char *peer;
	guint watch_id;
	DBusConnection *conn;
	GHashTable *updates;
	guint flags;
};

struct datacounters_dbus_client_update {
	guint flags;
	guint interval;
};

static void datacounters_dbus_client_update_free(gpointer data)
{
	struct datacounters_dbus_client_update *update = data;

	__connman_rtnl_update_interval_remove(update->interval);
	g_slice_free(struct datacounters_dbus_client_update, update);
}

gboolean datacounters_dbus_get_args(DBusMessageIter *it, int first_type, ...)
{
	gboolean ok = TRUE;
	int type = first_type;
	va_list va;

	va_start(va, first_type);
	while (type != DBUS_TYPE_INVALID) {
		if (dbus_type_is_basic(type) &&
				dbus_message_iter_get_arg_type(it) == type) {
			DBusBasicValue *ptr = va_arg(va, DBusBasicValue*);
			dbus_message_iter_get_basic(it, ptr);
			dbus_message_iter_next(it);
		} else {
			ok = FALSE;
			break;
		}
		type = va_arg(va, int);
	}
	va_end(va);
	return ok;
}

static guint datacounter_dbus_updates_client_flags(
				struct datacounters_dbus_client *client)
{
	client->flags = 0;
	if (g_hash_table_size(client->updates)) {
		gpointer value;
		GHashTableIter it;

		g_hash_table_iter_init(&it, client->updates);
		while (g_hash_table_iter_next(&it, NULL, &value)) {
			struct datacounters_dbus_client_update *update = value;

			client->flags |= update->flags;
		}
	}
	return client->flags;
}

static void datacounter_dbus_updates_refresh_flags(
				struct datacounters_dbus_updates *up)
{
	guint flags = 0;

	if (up->clients && g_hash_table_size(up->clients)) {
		gpointer value;
		GHashTableIter it;

		g_hash_table_iter_init(&it, up->clients);
		while (g_hash_table_iter_next(&it, NULL, &value)) {
			flags |= datacounter_dbus_updates_client_flags(value);
		}
	}
	if (up->flags != flags) {
		up->flags = flags;
		DBG("%s flags => 0x%x", up->name, up->flags);
	}
}

static void datacounters_dbus_client_free(gpointer data)
{
	struct datacounters_dbus_client *client = data;

	g_dbus_remove_watch(client->conn, client->watch_id);
	dbus_connection_unref(client->conn);
	g_hash_table_destroy(client->updates);
	g_free(client->peer);
	g_slice_free(struct datacounters_dbus_client, client);
}

static void datacounters_dbus_client_remove(
				struct datacounters_dbus_client *client)
{
	struct datacounters_dbus_updates *up = client->up;

	g_hash_table_remove(up->clients, client->peer);
	if (!g_hash_table_size(up->clients)) {
		g_hash_table_destroy(up->clients);
		up->clients = NULL;
	}
	datacounter_dbus_updates_refresh_flags(up);
}

static void datacounters_dbus_client_disconnected(DBusConnection *conn,
								void *data)
{
	datacounters_dbus_client_remove(data);
}

static struct datacounters_dbus_client *datacounters_dbus_client_new(
				struct datacounters_dbus_updates *up,
				DBusConnection *conn, const char *peer)
{
	struct datacounters_dbus_client *client =
		g_slice_new0(struct datacounters_dbus_client);

	client->updates = g_hash_table_new_full(g_direct_hash, g_direct_equal,
				NULL, datacounters_dbus_client_update_free);
	client->conn = dbus_connection_ref(conn);
	client->peer = g_strdup(peer);
	client->up = up;
	client->watch_id = g_dbus_add_disconnect_watch(client->conn,
			client->peer, datacounters_dbus_client_disconnected,
			client, NULL);
	return client;
}

void datacounters_dbus_updates_init(struct datacounters_dbus_updates *up,
							const char *path)
{
	static const char prefix[] = "/net/connman/service/";

	/* Assume that the rest is already zero-initialized */
	up->name = (strstr(path, prefix) == path) ?
		(path + sizeof(prefix) - 1) : path;
}

void datacounters_dbus_updates_destroy(struct datacounters_dbus_updates *up)
{
	up->flags = 0;
	if (up->clients) {
		g_hash_table_destroy(up->clients);
		up->clients = NULL;
	}
}

DBusMessage *datacounter_dbus_updates_enable(
				struct datacounters_dbus_updates *up,
				DBusConnection *conn, DBusMessage *msg)
{
	dbus_uint32_t flags, interval;

	if (dbus_message_get_args(msg, NULL,
					DBUS_TYPE_UINT32, &flags,
					DBUS_TYPE_UINT32, &interval,
					DBUS_TYPE_INVALID)) {
		DBusMessageIter it;
		DBusMessage *reply = dbus_message_new_method_return(msg);
		struct datacounters_dbus_client_update *update;
		const char *peer = dbus_message_get_sender(msg);
		struct datacounters_dbus_client *client = NULL;
		guint cookie = ++(up->last_update_cookie);

		/* Cookie and flags should be non-zero */
		if (!cookie) cookie = ++(up->last_update_cookie);
		if (!flags) flags = -1;
		if (up->clients) {
			/* Try to find the existing client */
			client = g_hash_table_lookup(up->clients, peer);
		} else {
			/* Create the table, we need it */
			up->clients = g_hash_table_new_full(g_str_hash,
					g_str_equal, NULL,
					datacounters_dbus_client_free);
		}

		/* If there's no context for this client yet, create it */
		if (!client) {
			client = datacounters_dbus_client_new(up, conn, peer);
			g_hash_table_insert(up->clients, client->peer, client);
		}

		/* Store the cookie => request mapping for this client */
		update = g_slice_new0(struct datacounters_dbus_client_update);
		update->flags = flags;
		update->interval = interval;
		__connman_rtnl_update_interval_add(interval);
		g_hash_table_insert(client->updates, GINT_TO_POINTER(cookie),
								update);
		/* No need to scan all clients if we are setting the bits */
		client->flags |= flags;
		if ((up->flags & flags) != flags) {
			up->flags |= flags;
			DBG("%s flags => 0x%x", up->name, up->flags);
		}

		/* Return the cookie to the client */
		dbus_message_iter_init_append(reply, &it);
		datacounters_dbus_append_uint32(&it, cookie);
		return reply;
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

DBusMessage *datacounter_dbus_updates_disable(
				struct datacounters_dbus_updates *up,
				DBusConnection *conn, DBusMessage *msg)
{
	dbus_uint32_t cookie;
	const char *peer = dbus_message_get_sender(msg);
	struct datacounters_dbus_client *client = up->clients ?
		g_hash_table_lookup(up->clients, peer) : NULL;

	/* The client must exist, otherwise it's an error */
	if (client && dbus_message_get_args(msg, NULL,
					DBUS_TYPE_UINT32, &cookie,
					DBUS_TYPE_INVALID)) {
		g_hash_table_remove(client->updates, GINT_TO_POINTER(cookie));
		if (!g_hash_table_size(client->updates)) {
			/* The last request is gone */
			datacounters_dbus_client_remove(client);
		} else {
			/* Some bits may be cleared */
			datacounter_dbus_updates_refresh_flags(up);
		}
		return dbus_message_new_method_return(msg);
	}
	return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS, "Oops!");
}

void datacounter_dbus_updates_send(struct datacounters_dbus_updates *up,
					guint flags, DBusMessage *msg)
{
	if (g_hash_table_size(up->clients)) {
		GHashTableIter it;
		gpointer value;
		struct datacounters_dbus_client *last_client;

		g_hash_table_iter_init(&it, up->clients);
		g_hash_table_iter_next(&it, NULL, &value);
		last_client = value;

		while (g_hash_table_iter_next(&it, NULL, &value)) {
			struct datacounters_dbus_client *client = value;

			if (client->flags & flags) {
				DBusMessage *cp = dbus_message_copy(msg);

				dbus_message_set_destination(cp, client->peer);
				g_dbus_send_message(client->conn, cp);
			}
		}

		/* The last one */
		if (last_client->flags & flags) {
			dbus_message_set_destination(msg, last_client->peer);
			dbus_message_ref(msg);
			g_dbus_send_message(last_client->conn, msg);
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
