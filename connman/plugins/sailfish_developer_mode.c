/*
 *  Connection Manager
 *
 *  Copyright (C) 2019 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "src/connman.h"
#include "device.h"
#include "rtnl.h"

#include <errno.h>
#include <netdb.h>
#include <net/if.h>

#include <gdbus.h>
#include <dbus.h>

#include <usb-moded/usb_moded-dbus.h>
#include <usb-moded/usb_moded-modes.h>

/*
 * This is defined in INCLUDEDIR/linux/if.h but in our case, cannot be included
 * because of some structs are also defined in INCLUDEDIR/net/if.h and proper
 * ifdefs are not used
 */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#define NOT_MANAGED	0

enum usb_moded_status_t {
	USB_MODED_NOT_SET = 0, // No signal received or query sent
	USB_MODED_UNDEFINED,
	USB_MODED_ASK,
	USB_MODED_MASS_STORAGE,
	USB_MODED_DEVELOPER_MODE,
	USB_MODED_MTP_MODE,
	USB_MODED_HOST_MODE,
	USB_MODED_CONNECTION_SHARING,
	USB_MODED_DIAG_MODE,
	USB_MODED_ADB_MODE,
	USB_MODED_PC_SUITE,
	USB_MODED_CHARGING,
	USB_MODED_BUSY,
	USB_MODED_CHARGING_FALLBACK,
	USB_MODED_CHARGER,
	USB_MODED_UNKNOWN // State that is not supported
};

static const char *usb_moded_entries[] = {
	"status not set yet",		/* USB_MODED_NOT_SET */
	MODE_UNDEFINED,			/* USB_MODED_UNDEFINED */
	MODE_ASK,			/* USB_MODED_ASK */
	MODE_MASS_STORAGE,		/* USB_MODED_MASS_STORAGE */
	MODE_DEVELOPER,			/* USB_MODED_DEVELOPER_MODE */
	MODE_MTP,			/* USB_MODED_MTP_MODE */
	MODE_HOST,			/* USB_MODED_HOST_MODE */
	MODE_CONNECTION_SHARING,	/* USB_MODED_CONNECTION_SHARING */
	MODE_DIAG,			/* USB_MODED_DIAG_MODE */
	MODE_ADB,			/* USB_MODED_ADB_MODE */
	MODE_PC_SUITE,			/* USB_MODED_PC_SUITE */
	MODE_CHARGING,			/* USB_MODED_CHARGING */
	MODE_BUSY,			/* USB_MODED_BUSY */
	MODE_CHARGING_FALLBACK,		/* USB_MODED_CHARGING_FALLBACK */
	MODE_CHARGER,			/* USB_MODED_CHARGER */
	NULL				/* USB_MODED_UNKNOWN */
};

enum usb_moded_service_state_t {
	USB_MODED_SERVICE_UNKNOWN = 0,
	USB_MODED_SERVICE_CONNECT,
	USB_MODED_SERVICE_DISCONNECT
};

struct usb_moded_service_data {
	const char *mode;
	const char *interface;
	dbus_int32_t network;
	dbus_int32_t dhcp_server;
};

static enum usb_moded_status_t usb_moded_status = USB_MODED_NOT_SET;
static char *usb_moded_interface = NULL;
static enum usb_moded_service_state_t usb_moded_service_state =
			USB_MODED_SERVICE_UNKNOWN;
static DBusConnection *connection = NULL;
static GHashTable *pending_devices = NULL;
static DBusPendingCall *pending_call = NULL;

static const char *usb_moded_status_to_str()
{
	return usb_moded_entries[usb_moded_status];
}

static void set_developer_mode_interface(const char *interface)
{
	if (!interface || !interface) {
		DBG("cannot set NULL/empty interface");
		return;
	}

	/* Do nothing if interface isn't changed */
	if (!g_strcmp0(usb_moded_interface, interface))
		return;

	g_free(usb_moded_interface);
	usb_moded_interface = g_strdup(interface);
	DBG("developer mode interface %s", usb_moded_interface);
}

static bool is_developer_mode_device(struct connman_device *device)
{
	const char *interface;

	if (!device || !usb_moded_interface || !*usb_moded_interface) {
		DBG("no device or no interface set");
		return false;
	}

	interface = connman_device_get_string(device, "Interface");

	if (!g_strcmp0(usb_moded_interface, interface))
		return true;

	DBG("device %p/%s is not developer mode device (%s)", device, interface,
				usb_moded_interface);
	return false;
}

static enum usb_moded_status_t set_usb_moded_status(
			struct usb_moded_service_data *data)
{
	bool found = false;
	enum usb_moded_status_t i;

	DBG("");

	if (!data)
		return USB_MODED_NOT_SET;

	/* Skip internal state, start from first usb moded state */
	for (i = USB_MODED_UNDEFINED; usb_moded_entries[i]; i++) {
		if (!g_strcmp0(data->mode, usb_moded_entries[i])) {
			usb_moded_status = i;
			found = true;
			break;
		}
	}

	if (!found) {
		if (usb_moded_status == USB_MODED_DEVELOPER_MODE)
			DBG("developer mode not ready yet, network %d "
						"dhcp server %d", data->network,
						data->dhcp_server);
		else
			DBG("unknown usb-moded status %s", data->mode);

		usb_moded_status = USB_MODED_UNKNOWN;
		goto out;
	}

	/*
	 * If in developer mode and the network and dhcp server
	 * are up and there is interface set, change interface
	 */
	if (usb_moded_status == USB_MODED_DEVELOPER_MODE && data->interface &&
				*(data->interface) && data->network == 1 &&
				data->dhcp_server == 1)
		set_developer_mode_interface(data->interface);

out:
	DBG("mode:%s => %d:%s, interface: %s", data->mode, usb_moded_status,
				usb_moded_status_to_str(),
				usb_moded_interface);

	return usb_moded_status;
}

static void reset_pending_call(bool cancel)
{
	if (!pending_call)
		return;

	if (cancel)
		dbus_pending_call_cancel(pending_call);

	dbus_pending_call_unref(pending_call);

	pending_call = NULL;
}

static void pending_devices_remove1(gpointer user_data)
{
	struct connman_device *device = user_data;

	DBG("");

	if (device)
		connman_device_unref(device);
}

static bool pending_devices_remove(struct connman_device *device)
{
	const char *interface;

	DBG("");

	if (!pending_devices || !device)
		return false;

	interface = connman_device_get_string(device, "Interface");

	if (!interface) {
		DBG("no interface for device %p", device);
		return false;
	}

	DBG("remove device %d %s %s", connman_device_get_index(device),
				connman_device_get_ident(device), interface);

	return g_hash_table_remove(pending_devices, interface);
}

static bool pending_devices_add(struct connman_device *device)
{
	const char *interface;

	DBG("");

	if (!pending_devices || !device) {
		DBG("hash table unset or no device");
		return false;
	}

	interface = connman_device_get_string(device, "Interface");

	DBG("add device %d %s %s", connman_device_get_index(device),
				connman_device_get_ident(device), interface);

	/* Interfaces are unique, second notification should not replace old */
	if (g_hash_table_contains(pending_devices, interface)) {
		DBG("interface %s already exists", interface);
		return false;
	}

	return g_hash_table_replace(pending_devices, g_strdup(interface),
				connman_device_ref(device));

}

static struct connman_device *pending_devices_find_by_interface(
			const char *interface)
{
	return g_hash_table_lookup(pending_devices, interface);
}

/* DBus service state callbacks */
static void usb_moded_connect(DBusConnection *conn, void *user_data)
{
	usb_moded_service_state = USB_MODED_SERVICE_CONNECT;
}

static void usb_moded_disconnect(DBusConnection *conn, void *user_data)
{
	/* Usb-moded is gone, cancel and reset pending call. */
	reset_pending_call(true);

	usb_moded_service_state = USB_MODED_SERVICE_DISCONNECT;
}

static void send_notify(struct connman_device *device, bool on)
{
	if (!is_developer_mode_device(device)) {
		DBG("not developer mode device %p", device);
		return;
	}

	connman_device_status_notify(device, on, NOT_MANAGED);

	/* Reset the developer mode interface interface goes down */
	if (!on && usb_moded_status != USB_MODED_DEVELOPER_MODE) {
		g_free(usb_moded_interface);
		usb_moded_interface = NULL;
		DBG("developer mode interface reset");
	}

	/* Reset usb mode query and cancel if query exists */
	reset_pending_call(true);
}

static bool parse_usb_moded_message(DBusMessage *msg,
			struct usb_moded_service_data *data)
{
	const char *key = NULL;
	const char *signature = DBUS_TYPE_ARRAY_AS_STRING
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING;

	DBG("");

	if (!msg || !data)
		return false;

	if (!dbus_message_has_signature(msg, signature)) {
		connman_error("usb-moded message signature \"%s\" "
					"does not match expected \"%s\"",
					dbus_message_get_signature(msg),
					signature);
		return false;
	}

	DBusMessageIter iter, array, dict, variant;

	if (!dbus_message_iter_init(msg, &iter))
		return false;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_next(&iter);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&array, &dict);
		dbus_message_iter_next(&array);

		if (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_STRING)
			continue;

		dbus_message_iter_get_basic(&dict, &key);
		dbus_message_iter_next(&dict);

		if (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_VARIANT)
			continue;

		dbus_message_iter_recurse(&dict, &variant);
		dbus_message_iter_next(&dict);

		switch(dbus_message_iter_get_arg_type(&variant)) {
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "mode_name"))
				dbus_message_iter_get_basic(&variant,
							&data->mode);

			if (g_str_equal(key, "network_interface"))
				dbus_message_iter_get_basic(&variant,
							&data->interface);

			break;
		case DBUS_TYPE_INT32:
			if (g_str_equal(key, "network"))
				dbus_message_iter_get_basic(&variant,
							&data->network);

			if (g_str_equal(key, "dhcp_server"))
				dbus_message_iter_get_basic(&variant,
							&data->dhcp_server);

			break;
		default:
			break;
		}
	}

	if (data->mode && data->interface)
		return true;

	return false;
}

static void get_usb_moded_state_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = NULL;
	DBusError error;
	struct usb_moded_service_data data = { 0 };
	struct connman_device *device;
	int index;

	DBG("");

	/*
	 * A theoretical chance that call notify is called without receiving a
	 * reply. No change must be done, just return.
	 */
	if (!dbus_pending_call_get_completed(call)) {
		DBG("pending call notify called but no reply received yet");
		return;
	}

	reply = dbus_pending_call_steal_reply(call);

	if (!reply) {
		DBG("NULL reply received from D-Bus");
		goto done;
	}

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		if (!g_strcmp0(error.name, DBUS_ERROR_SERVICE_UNKNOWN)) {
			DBG("usb-moded not running");
			usb_moded_disconnect(NULL, NULL);
		}

		connman_error("%s: %s", error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (!parse_usb_moded_message(reply, &data)) {
		DBG("failed to parse reply");
		goto done;
	}

	DBG("contents: mode: %s interface: %s network: %d dhcp_server: %d",
				data.mode, data.interface, data.network,
				data.dhcp_server);

	if (set_usb_moded_status(&data) != USB_MODED_DEVELOPER_MODE) {
		DBG("not in developer mode, is %s", usb_moded_status_to_str());
		goto done;
	}

	/*
	 * Check that this device with the interface still exists, it may be
	 * that message from usb moded arrives late and the network interface
	 * has already been put down.
	 */
	index = connman_inet_ifindex(data.interface);
	if (index < 0) {
		DBG("interface %s not up", data.interface);
		goto done;
	}

	/* Get a pending device, if no such device exists yet do nothing */
	device = pending_devices_find_by_interface(data.interface);

	if (!device || (index != connman_device_get_index(device))) {
		DBG("no device for interface %d/%s", index, data.interface);
		goto done;
	}

	send_notify(device, true);

done:
	/* Remove and reset query, no need to cancel as reply is received */
	reset_pending_call(false);

	if (reply)
		dbus_message_unref(reply);
}

static int usb_mode_query_state()
{
	DBusMessage *msg = NULL;
	gint rval = -EINVAL;

	DBG("");

	if (pending_call) {
		DBG("query already pending");
		return -EALREADY;
	}

	if (usb_moded_service_state == USB_MODED_SERVICE_DISCONNECT) {
		DBG("usb-moded not present, query not made");
		return -EHOSTDOWN;
	}

	msg = dbus_message_new_method_call(USB_MODE_SERVICE, USB_MODE_OBJECT,
				USB_MODE_INTERFACE, USB_MODE_TARGET_CONFIG_GET);

	if (!msg) {
		DBG("D-Bus method call creation failed");
		rval = -ENOMEM;
		goto error;
	}

	if (!g_dbus_send_message_with_reply(connection, msg,
				&pending_call, -1)) {
		connman_error("Cannot call %s on D-Bus service %s",
					USB_MODE_TARGET_CONFIG_GET,
					USB_MODE_SERVICE);
		rval = -ECONNREFUSED;
		goto error;
	}

	if (!pending_call) {
		connman_error("set pending call failed");
		goto error;
	}

	if (!dbus_pending_call_set_notify(pending_call,
				get_usb_moded_state_reply, NULL, NULL)) {
		connman_error("set notify to pending call failed");
		goto error;
	}

	rval = -EINPROGRESS;

out:
	if (msg)
		dbus_message_unref(msg);

	return rval;

error:
	/* Reset usb mode pending call, cancel call if set. */
	reset_pending_call(true);

	goto out;
}

static gboolean usb_moded_signal(DBusConnection *conn, DBusMessage *message,
			void *user_data)
{
	struct usb_moded_service_data data = { 0 };
	struct connman_device *device;
	int index;

	DBG("");

	if (!parse_usb_moded_message(message, &data)) {
		DBG("failed to parse signal");
		return TRUE;
	}

	/*
	 * If the signal defines developer mode and there is already a pending
	 * call waiting for reply, use the device information to send a notify
	 * and cancel+reset pending call afterwards.
	 */
	if (set_usb_moded_status(&data) == USB_MODED_DEVELOPER_MODE) {
		index = connman_inet_ifindex(data.interface);
		if (index < 0) {
			DBG("interface %s not up", data.interface);
			return TRUE;
		}

		device = pending_devices_find_by_interface(data.interface);

		if (!device || (index != connman_device_get_index(device))) {
			DBG("no device for interface %d/%s", index,
						data.interface);
			return TRUE;
		}

		DBG("interface %s present, notifying", data.interface);
		send_notify(device, true);
	}

	/* Cancel and reset pending call if it was running */
	reset_pending_call(true);

	return TRUE;
}

static int check_usb_moded_status(struct connman_device *device)
{
	DBG("%p", device);

	switch (usb_moded_status) {
	/*
	 * If the mode was not set query mode from usb moded. In case of failure
	 * in getting state ignore this netlink notification. State query is
	 * sent over D-Bus and if the received status is developer mode then
	 * connman_device_status_notify() is called (with true value) for this
	 * device.
	 */
	case USB_MODED_NOT_SET:
		DBG("querying mode");
		return usb_mode_query_state();
	case USB_MODED_DEVELOPER_MODE:
		DBG("in developer mode"); // Ok mode, continue
		return USB_MODED_DEVELOPER_MODE;
	default:
		DBG("in non-supported mode %d:%s", usb_moded_status,
					usb_moded_status_to_str());
		return -EINVAL;
	}
}

static bool check_device(struct connman_device *device)
{
	/* Exclude these devices as developer mode devices */
	switch (connman_device_get_type(device)) {
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_CELLULAR:
	case CONNMAN_DEVICE_TYPE_GPS:
	case CONNMAN_DEVICE_TYPE_WIFI:
		return false;
	default:
		return true;
	}
}

static void developer_mode_newlink(unsigned short type, int index,
			unsigned flags, unsigned change)
{
	struct connman_device *device;

	DBG("index %d change %u", index, change);

	/*
	 * Device must be up and running. Also L1 must be set up since with
	 * usb tethering, both usb interface and tethering (bridge) interfaces
	 * are up but only tethering has IP address set
	 */
	if ((flags & (IFF_UP | IFF_RUNNING | IFF_LOWER_UP)) !=
				(IFF_UP | IFF_RUNNING | IFF_LOWER_UP)) {
		DBG("device %d not up/running/ready yet", index);
		return;
	}

	device = connman_device_find_by_index(index);

	if (!device) {
		DBG("no device for index %d", index);
		return;
	}

	if (!check_device(device)) {
		DBG("not supported device %p", device);
		return;
	}

	if (!pending_devices_add(device))
		DBG("cannot add pending device %p", device);

	/*
	 * Status check is necessary only when enabling. Notify if in developer
	 * mode. Interface is up requires that query is made.
	 */
	if (check_usb_moded_status(device) == USB_MODED_DEVELOPER_MODE)
		send_notify(device, true);
}

static void developer_mode_dellink(unsigned short type, int index,
			unsigned flags, unsigned change)
{
	struct connman_device *device;

	DBG("index %d change %u", index, change);

	device = connman_device_find_by_index(index);
	if (!device) {
		DBG("no device for index %d", index);
		return;
	}

	if (!check_device(device)) {
		DBG("not supported device %p", device);
		return;
	}

	/* Notify is sent if interface matches */
	send_notify(device, false);

	/* Interface down, remove device, not needed anymore */
	if (!pending_devices_remove(device))
		DBG("cannot remove device %p", device);
}

/*
 * Listen for rtnl events as ipconfig_changed is triggered only by services
 * having changed ifconfig. For other devices kernel netlink messages are used.
 * Priority must be higher than with device.c, since the interface name in case
 * of dellink() must be retrieved from it. It may be that inet.c cannot get the
 * interface name as the device has already been removed. Higher priority than
 * device.c rtnl notify guarantees that the interface name is not removed before
 * notification is processed.
 */
static struct connman_rtnl developer_mode_rtnl = {
	.name		= "developer_mode_plugin",
	.priority	= CONNMAN_RTNL_PRIORITY_LOW,
	.newlink	= developer_mode_newlink,
	.dellink	= developer_mode_dellink,
};

static int usb_moded_service_watch = 0;
static int usb_moded_signal_watch = 0;

static int sailfish_developer_mode_init(void)
{
	int err;

	DBG("");

	usb_moded_status = USB_MODED_NOT_SET;

	connection = connman_dbus_get_connection();
	pending_devices = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, pending_devices_remove1);

	usb_moded_service_watch = g_dbus_add_service_watch(connection,
				USB_MODE_SERVICE, usb_moded_connect,
				usb_moded_disconnect, NULL, NULL);

	usb_moded_signal_watch = g_dbus_add_signal_watch(connection,
				USB_MODE_SERVICE, USB_MODE_OBJECT,
				USB_MODE_INTERFACE,
				USB_MODE_TARGET_CONFIG_SIGNAL_NAME,
				usb_moded_signal, NULL, NULL);

	err = connman_rtnl_register(&developer_mode_rtnl);
	if (err < 0)
		DBG("cannot register rtnl watch");

	return err;
}

static void sailfish_developer_mode_exit(void)
{
	DBG("");

	connman_rtnl_unregister(&developer_mode_rtnl);

	if (usb_moded_service_watch)
		g_dbus_remove_watch(connection, usb_moded_service_watch);

	if (usb_moded_signal_watch)
		g_dbus_remove_watch(connection, usb_moded_signal_watch);

	reset_pending_call(true);

	dbus_connection_unref(connection);

	g_free(usb_moded_interface);
	usb_moded_interface = NULL;

	if (pending_devices)
		g_hash_table_destroy(pending_devices);
}

CONNMAN_PLUGIN_DEFINE(sailfish_developer_mode, "Sailfish developer mode plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		sailfish_developer_mode_init, sailfish_developer_mode_exit)
