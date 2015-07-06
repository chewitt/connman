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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "connman.h"
#include "gdbus.h"

#include <mce/dbus-names.h>
#include <mce/mode-names.h>

#include <errno.h>

static GSList *poll_services;
static DBusConnection *connection;
static DBusPendingCall *get_display_status_call;
static guint display_status_ind_watch;
static guint signalpoll_timer;
static gboolean display_on;

#define POLL_INTERVAL_SECS (2)

static void signalpoll_poll_service(gpointer service_ptr, gpointer data)
{
	struct connman_service *service = service_ptr;
	struct connman_network *network;

	network = __connman_service_get_network(service);
	if (network) {
		struct connman_device *device;

		device = connman_network_get_device(network);
		if (device) {
			DBG("%s", __connman_service_get_ident(service));
			connman_device_signal_poll(device);
		}
	}
}

static gboolean signalpoll_poll(gpointer data)
{
	g_slist_foreach(poll_services, signalpoll_poll_service, NULL);
	return TRUE;
}

static void signalpoll_update()
{
	if (display_on && poll_services) {
		/* Need polling */
		if (!signalpoll_timer) {
			DBG("starting poll timer");
			signalpoll_timer = g_timeout_add_seconds(
				POLL_INTERVAL_SECS, signalpoll_poll, NULL);
			signalpoll_poll(NULL);
		}
	} else {
		/* Stop poll timer */
		if (signalpoll_timer) {
			DBG("stopping poll timer");
			g_source_remove(signalpoll_timer);
			signalpoll_timer = 0;
		}
	}
}

static gboolean signalpoll_service_needs_poll(struct connman_service *service,
					enum connman_service_state state)
{
	gboolean needs_poll = FALSE;
	struct connman_network *network;

	network = __connman_service_get_network(service);
	if (network) {
		struct connman_device *device;

		device = connman_network_get_device(network);
		if (device && connman_device_supports_signal_poll(device)) {
			switch (state) {
			case CONNMAN_SERVICE_STATE_ASSOCIATION:
			case CONNMAN_SERVICE_STATE_CONFIGURATION:
			case CONNMAN_SERVICE_STATE_READY:
			case CONNMAN_SERVICE_STATE_ONLINE:
			case CONNMAN_SERVICE_STATE_DISCONNECT:
				needs_poll = TRUE;
				break;

			case CONNMAN_SERVICE_STATE_IDLE:
			case CONNMAN_SERVICE_STATE_UNKNOWN:
			case CONNMAN_SERVICE_STATE_FAILURE:
				break;
			}
		}
	}

	return needs_poll;
}

static void signalpoll_add_poll_service(struct connman_service *service)
{
	DBG("%s", __connman_service_get_ident(service));
	if (!g_slist_find(poll_services, service)) {
		DBG("adding %s", __connman_service_get_ident(service));
		poll_services = g_slist_prepend(poll_services, service);
		connman_service_ref(service);
		signalpoll_update();
	}
}

static void signalpoll_remove_poll_service(struct connman_service *service)
{
	GSList* found = g_slist_find(poll_services, service);

	DBG("%s (%sfound)", __connman_service_get_ident(service),
							found ? "" : "not ");
	if (found) {
		poll_services = g_slist_delete_link(poll_services, found);
		connman_service_unref(service);
		if (!poll_services) {
			signalpoll_update();
		}
	}
}

static void signalpoll_service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	DBG("%s %d", __connman_service_get_ident(service), state);

	if (signalpoll_service_needs_poll(service, state)) {
		signalpoll_add_poll_service(service);
	} else {
		signalpoll_remove_poll_service(service);
	}
}

static const char *signalpoll_get_string(DBusMessage *message)
{
	const char *str = NULL;
	DBusMessageIter iter;

	if (dbus_message_iter_init(message, &iter) &&
		dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
		dbus_message_iter_get_basic(&iter, &str);
	}

	return str;
}

static gboolean signalpoll_display_status_ind(DBusConnection *conn,
				DBusMessage *message, void *user_data)
{
	const char* status = signalpoll_get_string(message);

	DBG("\"%s\"", status);
	if (status) {
		display_on = !strcmp(status, MCE_DISPLAY_ON_STRING);
		signalpoll_update();
	}

	return TRUE;
}

static void signalpoll_display_status_reply(DBusPendingCall *call,
							void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	dbus_error_init(&error);
	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("Failed to get display status: %s %s",
						error.name, error.message);
		dbus_error_free(&error);
	} else {
		const char* status = signalpoll_get_string(reply);

		DBG("\"%s\"", status);
		if (status) {
			display_on = !strcmp(status, MCE_DISPLAY_ON_STRING);
			signalpoll_update();
		}
	}

	dbus_message_unref(reply);
	dbus_pending_call_unref(get_display_status_call);
	get_display_status_call = NULL;
}

static void signalpoll_clean_services(gpointer service)
{
	connman_service_unref(service);
}

static struct connman_notifier signalpoll_notifier = {
	.name                   = "signalpoll",
	.priority               = CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.service_state_changed  = signalpoll_service_state_changed,
	.service_remove         = signalpoll_remove_poll_service
};

static int signalpoll_init()
{
	DBusMessage *message;

	DBG("");
	connection = connman_dbus_get_connection();
	if (!connection)
		return -EIO;

	connman_notifier_register(&signalpoll_notifier);
	display_status_ind_watch = g_dbus_add_signal_watch(connection,
		MCE_SERVICE, MCE_SIGNAL_PATH, MCE_SIGNAL_IF, MCE_DISPLAY_SIG,
		signalpoll_display_status_ind, NULL, NULL);
	message = dbus_message_new_method_call(MCE_SERVICE, MCE_REQUEST_PATH,
		MCE_REQUEST_IF, MCE_DISPLAY_STATUS_GET);

	if (message) {
		if (dbus_connection_send_with_reply(connection, message,
			&get_display_status_call, DBUS_TIMEOUT_INFINITE)) {
			dbus_pending_call_set_notify(get_display_status_call,
				signalpoll_display_status_reply, NULL, NULL);
		}
		dbus_message_unref(message);
	}

	return 0;
}

static void signalpoll_exit()
{
	DBG("");
	if (signalpoll_timer) {
		g_source_remove(signalpoll_timer);
		signalpoll_timer = 0;
	}
	if (poll_services) {
		g_slist_free_full(poll_services, signalpoll_clean_services);
		poll_services = NULL;
	}
	if (get_display_status_call) {
		dbus_pending_call_cancel(get_display_status_call);
		dbus_pending_call_unref(get_display_status_call);
		get_display_status_call = NULL;
	}
	connman_notifier_unregister(&signalpoll_notifier);
	dbus_connection_unref(connection);
	connection = NULL;
}

CONNMAN_PLUGIN_DEFINE(jolla_signalpoll, "Jolla signal poll plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, signalpoll_init, signalpoll_exit)
