/*
 *  ConnMan developer mode plugin unit tests
 *
 *  Copyright (C) 2019 Jolla Ltd. All rights reserved.
 *  Contact: jussi.laakkonen@jolla.com
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

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"

#include "src/connman.h"

extern struct connman_plugin_desc __connman_builtin_sailfish_developer_mode;

enum dbus_config_t {
	DBUS_CONFIG_UNSET = 0x0000,
	DBUS_WATCH_ADD_FAIL = 0x0001,
	DBUS_WATCH_REM_FAIL = 0x0002,
	DBUS_SEND_MESSAGE_FAIL = 0x0004,
	DBUS_PENDING_CALL_NULL = 0x0008,
	DBUS_PENDING_CALL_COMPLETED_FAIL = 0x0010,
	DBUS_SET_NOTIFY_FAIL = 0x0020
};

enum dbus_config_t dbus_config = DBUS_CONFIG_UNSET;

void set_dbus_config(enum dbus_config_t type)
{
	if (type & DBUS_WATCH_ADD_FAIL)
		DBG("DBUS_WATCH_ADD_FAIL");

	if (type & DBUS_WATCH_REM_FAIL)
		DBG("DBUS_WATCH_REM_FAIL");

	if (type & DBUS_SEND_MESSAGE_FAIL)
		DBG("DBUS_SEND_MESSAGE_FAIL");

	if (type & DBUS_PENDING_CALL_NULL)
		DBG("DBUS_PENDING_CALL_NULL");

	if (type & DBUS_PENDING_CALL_COMPLETED_FAIL)
		DBG("DBUS_PENDING_CALL_COMPLETED_FAIL");

	if (type & DBUS_SET_NOTIFY_FAIL)
		DBG("DBUS_SET_NOTIFY_FAIL");

	dbus_config = type;
}

// DBus dummies
GDBusWatchFunction connect_function = NULL;
GDBusWatchFunction disconnect_function = NULL;
GDBusSignalFunction signal_function = NULL;
static int service_watch_id = 13;
static int signal_watch_id = 42;

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy)
{
	DBG("");

	g_assert_null(connection);
	g_assert(connect);
	g_assert(disconnect);

	connect_function = connect;
	disconnect_function = disconnect;

	return service_watch_id;
}

guint g_dbus_add_signal_watch(DBusConnection *connection,
				const char *sender, const char *path,
				const char *interface, const char *member,
				GDBusSignalFunction function, void *user_data,
				GDBusDestroyFunction destroy)
{
	DBG("");

	g_assert_null(connection);
	g_assert(function);

	if (dbus_config & DBUS_WATCH_ADD_FAIL)
		return -1;

	signal_function = function;

	return signal_watch_id;
}

gboolean g_dbus_remove_watch(DBusConnection *connection, guint tag)
{
	DBG("");
	
	g_assert_null(connection);

	/* No signal was set */
	if (dbus_config & DBUS_WATCH_ADD_FAIL)
		return TRUE;

	g_assert(tag == signal_watch_id || tag == service_watch_id);
	
	signal_function = NULL;
	
	if (dbus_config & DBUS_WATCH_REM_FAIL)
		return FALSE;

	return TRUE;
}

#define PENDING_FAKE_POINTER (0x6E78B)

static DBusPendingCall *pending_call = NULL;
static DBusMessage *sent_message = NULL;

gboolean g_dbus_send_message_with_reply(DBusConnection *connection,
					DBusMessage *message,
					DBusPendingCall **call, int timeout)
{
	DBG("%p %p", connection, message);

	if (dbus_config & DBUS_SEND_MESSAGE_FAIL)
		return FALSE;

	if (dbus_config & DBUS_PENDING_CALL_NULL)
		return TRUE;

	if (!pending_call)
		pending_call = (DBusPendingCall*)PENDING_FAKE_POINTER;

	*call = pending_call;
	sent_message = dbus_message_ref(message);

	return TRUE;
}

DBusConnection *connman_dbus_get_connection(void)
{
	DBG("");

	return NULL;
}

void dbus_connection_unref(DBusConnection *connection)
{
	DBG("%p", connection);

	g_assert_null(connection); // Should be NULL in tests
}

DBusPendingCall *notify_pending = NULL;
DBusPendingCallNotifyFunction notify_function = NULL;

dbus_bool_t dbus_pending_call_set_notify(DBusPendingCall *pending,
			DBusPendingCallNotifyFunction function, void *user_data,
			DBusFreeFunction free_user_data)
{
	DBG("%p %p %p", pending, function, user_data);

	g_assert(pending == pending_call);
	g_assert(function);
	g_assert_null(user_data);

	if (dbus_config & DBUS_SET_NOTIFY_FAIL)
		return FALSE;

	notify_pending = pending;
	notify_function = function;

	return TRUE;
}

void dbus_pending_call_cancel(DBusPendingCall *pending) {
	g_assert(pending);
	g_assert(pending == pending_call);
}

struct usb_moded_data {
	const char *mode_name;
	const char *mode_module;
	int appsync;
	int network;
	int mass_storage;
	const char *network_interface;
	int nat;
	int dhcp_server;
	const char *connman_tethering;
};

static struct usb_moded_data usb_moded_data = {
	.mode_name = NULL,
	.mode_module = "not_used",
	.appsync = 0,
	.network = 0,
	.mass_storage = 0,
	.network_interface = NULL,
	.nat = 0,
	.dhcp_server = 0,
	.connman_tethering = "not_used",
};

/* This part is adapted from usb-moded changes in src/usb_moded-dbus.c */
static void test_dbus_append_int_value(DBusMessageIter *iter, const char *key,
			int val)
{
	DBusMessageIter entry, variant;

	g_assert(iter);
	g_assert(key);

	g_assert(dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, 0,
				&entry));
	g_assert(dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
				&key));
	g_assert(dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
				DBUS_TYPE_INT32_AS_STRING, &variant));

	dbus_int32_t arg = val;

	g_assert(dbus_message_iter_append_basic(&variant, DBUS_TYPE_INT32,
				&arg));
	g_assert(dbus_message_iter_close_container(&entry, &variant));
	g_assert(dbus_message_iter_close_container(iter, &entry));
}

static void test_dbus_append_str_value(DBusMessageIter *iter, const char *key,
			const char *val)
{
	DBusMessageIter entry, variant;
	
	g_assert(iter);
	g_assert(key);
	g_assert(val);

	g_assert(dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY, 0,
				&entry));

	g_assert(dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
				&key));

	g_assert(dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
				DBUS_TYPE_STRING_AS_STRING, &variant));

	const char *arg = val ?: "";

	g_assert(dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING,
		&arg));
	g_assert(dbus_message_iter_close_container(&entry, &variant));
	g_assert(dbus_message_iter_close_container(iter, &entry));
}

enum usb_moded_ignore_t {
	IGNORE_UNSET = 			0x0000,
	IGNORE_MODE_NAME =		0x0001,
	IGNORE_MODE_MODULE =		0x0002,
	IGNORE_APPSYNC =		0x0004,
	IGNORE_NETWORK =		0x0008,
	IGNORE_MASS_STORAGE =		0x0010,
	IGNORE_NETWORK_INTERFACE =	0x0020,
	IGNORE_NAT =			0x0040,
	IGNORE_DHCP_SERVER =		0x0080,
	IGNORE_CONNMAN_TETHERING =	0x0100,
};

static enum usb_moded_ignore_t usb_moded_ignore = IGNORE_UNSET;

static void set_usb_moded_ignore(enum usb_moded_ignore_t ignore)
{
	usb_moded_ignore = ignore;

	if (usb_moded_ignore & IGNORE_MODE_NAME)
		DBG("mode_name");

	if (usb_moded_ignore & IGNORE_MODE_MODULE)
		DBG("mode_module");

	if (usb_moded_ignore & IGNORE_APPSYNC)
		DBG("appsync");

	if (usb_moded_ignore & IGNORE_NETWORK)
		DBG("network");

	if (usb_moded_ignore & IGNORE_MASS_STORAGE)
		DBG("mass_storage");

	if (usb_moded_ignore & IGNORE_NETWORK_INTERFACE)
		DBG("network_interface");

	if (usb_moded_ignore & IGNORE_NAT)
		DBG("nat");

	if (usb_moded_ignore & IGNORE_DHCP_SERVER)
		DBG("dhcp_server");

	if (usb_moded_ignore & IGNORE_CONNMAN_TETHERING)
		DBG("connman_tethering");
}

static void test_dbus_append_mode_details(DBusMessage *msg,
			struct usb_moded_data *data)
{
	DBusMessageIter body, dict;

	DBG("");

	g_assert(msg);
	g_assert(data);

	dbus_message_iter_init_append(msg, &body);

	g_assert(dbus_message_iter_open_container(&body,
				DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
				&dict));

	if (!(usb_moded_ignore & IGNORE_MODE_NAME))
		test_dbus_append_str_value(&dict, "mode_name", data->mode_name);

	if (!(usb_moded_ignore & IGNORE_MODE_MODULE))
		test_dbus_append_str_value(&dict, "mode_module",
					data->mode_module);

	if (!(usb_moded_ignore & IGNORE_APPSYNC))
		test_dbus_append_int_value(&dict, "appsync", data->appsync);

	if (!(usb_moded_ignore & IGNORE_NETWORK))
		test_dbus_append_int_value(&dict, "network", data->network);

	if (!(usb_moded_ignore & IGNORE_MASS_STORAGE))
		test_dbus_append_int_value(&dict, "mass_storage",
					data->mass_storage);

	if (!(usb_moded_ignore & IGNORE_NETWORK_INTERFACE))
		test_dbus_append_str_value(&dict, "network_interface",
					data->network_interface);

	if (!(usb_moded_ignore & IGNORE_NAT))
		test_dbus_append_int_value(&dict, "nat", data->nat);

	if (!(usb_moded_ignore & IGNORE_DHCP_SERVER))
		test_dbus_append_int_value(&dict, "dhcp_server",
					data->dhcp_server);

	if (!(usb_moded_ignore & IGNORE_CONNMAN_TETHERING))
		test_dbus_append_str_value(&dict, "connman_tethering",
					data->connman_tethering);

	g_assert(dbus_message_iter_close_container(&body, &dict));
}

enum dbus_reply_type_t {
	DBUS_MESSAGE = 0,
	DBUS_MESSAGE_INVALID,
	DBUS_MESSAGE_INT,
	DBUS_MESSAGE_DEVMODE_FAIL1,
	DBUS_MESSAGE_DEVMODE_FAIL2,
	DBUS_MESSAGE_DEVMODE_FAIL3,
	DBUS_MESSAGE_FAILED,
	DBUS_MESSAGE_SERVICE_UNKNOWN,
	DBUS_MESSAGE_NULL
};

static enum dbus_reply_type_t dbus_reply_type = DBUS_MESSAGE;

static void set_dbus_reply_type(enum dbus_reply_type_t type)
{
	dbus_reply_type = type;
}

DBusMessage *dbus_pending_call_steal_reply(DBusPendingCall *pending)
{
	DBusMessage *msg = NULL;
	DBusMessageIter iter;
	const char *developer_mode = "developer_mode";
	const char *invalid = "connection_sharing";
	const char *error = "test error message";
	int value = 123;

	DBG("");

	g_assert(sent_message);
	dbus_message_set_serial(sent_message, 123456);

	switch (dbus_reply_type) {
	case DBUS_MESSAGE:
		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
		usb_moded_data.mode_name = developer_mode;
		usb_moded_data.network = 1;
		usb_moded_data.dhcp_server = 1;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_INVALID:
		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
		usb_moded_data.mode_name = invalid;
		usb_moded_data.network = 1;
		usb_moded_data.dhcp_server = 1;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_INT:
		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
		dbus_message_iter_init_append(msg, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &value);
		break;
	case DBUS_MESSAGE_DEVMODE_FAIL1:
		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
		usb_moded_data.mode_name = invalid;
		usb_moded_data.network = 0;
		usb_moded_data.dhcp_server = 1;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_DEVMODE_FAIL2:
		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
		usb_moded_data.mode_name = invalid;
		usb_moded_data.network = 1;
		usb_moded_data.dhcp_server = 0;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_DEVMODE_FAIL3:
		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
		usb_moded_data.mode_name = invalid;
		usb_moded_data.network = 0;
		usb_moded_data.dhcp_server = 0;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_SERVICE_UNKNOWN:
		msg = dbus_message_new_error(sent_message,
					DBUS_ERROR_SERVICE_UNKNOWN, error);
		break;
	case DBUS_MESSAGE_FAILED:
		msg = dbus_message_new_error(sent_message, DBUS_ERROR_FAILED,
					error);
		break;
	case DBUS_MESSAGE_NULL:
		return NULL;
	}
	
	g_assert(msg);

	dbus_message_unref(sent_message);
	sent_message = NULL;

	return msg;
}

void dbus_pending_call_unref(DBusPendingCall *pending)
{
	DBG("%p", pending);

	g_assert(pending);
	g_assert(pending == pending_call);
	pending = NULL;
	pending_call = NULL;
}

dbus_bool_t dbus_pending_call_get_completed(DBusPendingCall *pending)
{
	DBG("%p", pending);

	g_assert(pending);
	g_assert(pending == pending_call);

	if (dbus_config & DBUS_PENDING_CALL_COMPLETED_FAIL)
		return FALSE;

	return TRUE;
}

// device dummies

#include <net/if.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

struct connman_device {
	int index;
	enum connman_device_type type;
	const char *ident;
	const char *ifname;
	int refcount;
};

static struct connman_device test_device1 = {
	.index = 100,
	.type = CONNMAN_DEVICE_TYPE_GADGET,
	.ident = "gadget123",
	.ifname = "rndis0",
	.refcount = 0,
};

static struct connman_device test_device2 = {
	.index = 101,
	.type = CONNMAN_DEVICE_TYPE_UNKNOWN,
	.ident = "unknown456",
	.ifname = "rndis0",
	.refcount = 0,
};

static struct connman_device test_device3 = {
	.index = 102,
	.type = CONNMAN_DEVICE_TYPE_GADGET,
	.ident = "gadget789",
	.ifname = "rndis0",
	.refcount = 0,
};

static struct connman_device test_device4 = {
	.index = 103,
	.type = CONNMAN_DEVICE_TYPE_ETHERNET,
	.ident = "ethernet321",
	.ifname = "rndis1",
	.refcount = 0,
};


struct connman_device *connman_device_find_by_index(int index)
{
	switch (index) {
	case 100:
		return &test_device1;
	case 101:
		return &test_device2;
	case 103:
		return &test_device4;
	default:
		return NULL;
	}
}

int connman_device_get_index(struct connman_device *device)
{
	return device->index;
}

const char *connman_device_get_ident(struct connman_device *device)
{
	return device ? device->ident : NULL;
}

const char *connman_device_get_string(struct connman_device *device,
							const char *key)
{
	if (device && !g_strcmp0(key, "Interface"))
		return device->ifname;

	return NULL;
}

enum connman_device_type connman_device_get_type(struct connman_device *device)
{
	return device ? device->type : 0;
}

struct connman_device *connman_device_ref_debug(struct connman_device *device,
				const char *file, int line, const char *caller)
{
	g_assert(device);

	DBG("%p ref %d by %s:%d:%s()", device, device->refcount + 1, file, line,
				caller);

	__sync_fetch_and_add(&device->refcount, 1);

	return device;
}

void connman_device_unref_debug(struct connman_device *device,
				const char *file, int line, const char *caller)
{
	g_assert(device);

	DBG("%p ref %d by %s:%d:%s()", device, device->refcount - 1, file, line,
				caller);

	__sync_fetch_and_sub(&device->refcount, 1);

	g_assert_cmpint(device->refcount, >=, 0);
}

// Notification recording
enum device_notify_status { NOTIFY_UNSET = 0, NOTIFY_TRUE, NOTIFY_FALSE };

static struct connman_device *notify_device = NULL;
static enum device_notify_status notify_status = NOTIFY_UNSET;

void connman_device_status_notify(struct connman_device *device, bool status,
			bool managed)
{
	DBG("%p %s", device, status ? "on" : "off");

	notify_device = device;
	notify_status = status ? NOTIFY_TRUE : NOTIFY_FALSE;
	g_assert(managed == false);
}

// rtnl dummies
static struct connman_rtnl *rtnl_notifier = NULL;
static bool rtnl_on = true;

int connman_rtnl_register(struct connman_rtnl *rtnl)
{
	DBG("");

	g_assert(rtnl);

	if (!rtnl_on)
		return -ENOENT;

	if (!g_strcmp0(rtnl->name, "developer_mode_plugin"))
		rtnl_notifier = rtnl;

	return 0;
}

void connman_rtnl_unregister(struct connman_rtnl *rtnl)
{
	DBG("");

	g_assert(rtnl);

	rtnl_notifier = NULL;
}

// inet dummies
char *connman_inet_ifname(int index)
{
	struct connman_device *dev;

	dev = connman_device_find_by_index(index);

	if (!dev)
		return NULL;

	return g_strdup(dev->ifname);
}

int test_interface_index = -1;

int connman_inet_ifindex(const char *ifname)
{
	if (!g_strcmp0(ifname, usb_moded_data.network_interface))
		return test_interface_index;

	return -1;
}

// End of dummies

static void set_test_interface(struct connman_device *device)
{
	g_assert(device);

	usb_moded_data.network_interface = device->ifname;
	test_interface_index = device->index;
}

// Rtnl on/off
static void rtnl_device_on(int index, unsigned flags)
{
	g_assert(rtnl_notifier);

	if (rtnl_notifier->newlink)
		rtnl_notifier->newlink(0, index, flags, 0);
}

static void rtnl_device_off(int index, unsigned flags)
{
	g_assert(rtnl_notifier);

	if (rtnl_notifier->dellink)
		rtnl_notifier->dellink(0, index, flags, 0);
}

// Notify

static void reset_notify()
{
	notify_device = NULL;
	notify_status = NOTIFY_UNSET;
}

// Dbus messaging

void call_dbus_pending_notify()
{
	DBG("%p %p", notify_pending, notify_function);

	g_assert(notify_function);
	g_assert(notify_pending);

	notify_function(notify_pending, NULL);
}

void reset_dbus_pending_notify()
{
	notify_function = NULL;
	notify_pending = NULL;
}

void reset_messages()
{
	set_dbus_reply_type(DBUS_MESSAGE);

	if (sent_message)
		dbus_message_unref(sent_message);

	sent_message = NULL;
	pending_call = NULL;
}

void send_dbus_connect()
{
	g_assert(connect_function);
	connect_function(NULL, NULL);
}

void send_dbus_disconnect()
{
	g_assert(disconnect_function);
	disconnect_function(NULL, NULL);
}

void send_dbus_signal(const char *mode)
{
	DBusMessage *msg = NULL;
	DBusMessageIter iter;
	int value = 456;
	
	DBG("");

	g_assert(signal_function);

	msg = dbus_message_new(DBUS_MESSAGE_TYPE_SIGNAL);

	dbus_message_iter_init_append(msg, &iter);

	switch (dbus_reply_type) {
	case DBUS_MESSAGE_INT:
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &value);
		break;
	case DBUS_MESSAGE_DEVMODE_FAIL1:
		usb_moded_data.mode_name = mode;
		usb_moded_data.network = 0;
		usb_moded_data.dhcp_server = 1;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_DEVMODE_FAIL2:
		usb_moded_data.mode_name = mode;
		usb_moded_data.network = 1;
		usb_moded_data.dhcp_server = 0;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	case DBUS_MESSAGE_DEVMODE_FAIL3:
		usb_moded_data.mode_name = mode;
		usb_moded_data.network = 0;
		usb_moded_data.dhcp_server = 0;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	default:
		usb_moded_data.mode_name = mode;
		usb_moded_data.network = 1;
		usb_moded_data.dhcp_server = 1;
		test_dbus_append_mode_details(msg, &usb_moded_data);
		break;
	}

	signal_function(NULL, msg, NULL);

	dbus_message_unref(msg);
}

void reset_test(void)
{
	reset_notify();
	reset_dbus_pending_notify();
	reset_messages();
	set_dbus_config(DBUS_CONFIG_UNSET);
	set_dbus_reply_type(DBUS_MESSAGE);
	test_interface_index = -1;
	set_usb_moded_ignore(IGNORE_UNSET);
	rtnl_on = true;
}

/* Device enabling, all status changes and react to D-Bus reply */
static void developer_mode_plugin_test_rtnl0()
{
	reset_test();
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP);

	/* No query has been made or notify done*/
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING);

	/* No query has been made or notify done*/
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	/* usb moded is unset */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	
	/* Query has been made */
	g_assert(sent_message);
	
	/* Send D-Bus reply */
	set_test_interface(&test_device1);
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	
	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	reset_dbus_pending_notify();

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Signal is received before device is enabled */
static void developer_mode_plugin_test_rtnl1()
{
	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	send_dbus_signal("developer_mode");

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* No query has been made but notify is done, no reference is kept */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Another notify about interface should create no actions */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* No query has been made but notify is done, no reference is kept */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* No signal received, query usb moded status */
static void developer_mode_plugin_test_rtnl2()
{
	DBusMessage *msg_old = NULL;

	reset_test();
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	/* usb moded status is being queried */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Query has been made */
	g_assert(sent_message);
	msg_old = sent_message;

	/* usb moded status is not queried for the second time, no new ref */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert(sent_message == msg_old);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	set_test_interface(&test_device1);
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	reset_dbus_pending_notify();

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Tests the notification off without active device.*/
static void developer_mode_plugin_test_rtnl3()
{
	reset_test();
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING);

	/* No query has been made or notify done*/
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	/* If the device is valid, remove notification is sent */
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);
	
	/* If the device is valid, remove notification is sent */
	set_test_interface(&test_device1);
	send_dbus_signal("developer_mode");
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Device is put up, usb moded goes down and comes back up with signal */
static void developer_mode_plugin_test_rtnl4()
{
	DBusMessage *old_msg;

	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* Query has been made but no notify is done, reference is kept */
	g_assert(sent_message);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	old_msg = sent_message;

	/* No new query has been made, reference is not released */
	send_dbus_disconnect();
	g_assert(sent_message == old_msg);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Device goes down and comes back up, no new query, no notify */
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	/* Back on */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(sent_message == old_msg);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Off */
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	dbus_message_unref(sent_message);
	sent_message = old_msg = NULL;
	reset_notify();

	/* No new query or notify after connect */
	send_dbus_connect();
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);

	/* Signal received, the device is brought up, notified and released */
	send_dbus_signal("developer_mode");
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Device is put up, usb moded goes down and comes back up with signal */
static void developer_mode_plugin_test_rtnl5()
{
	DBusMessage *old_msg;

	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* Query has been made but no notify is done, reference is kept */
	g_assert(sent_message);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	old_msg = sent_message;

	/*
	 * No new query has been made and reference is released, no notify sent.
	 */
	send_dbus_disconnect();
	g_assert(sent_message == old_msg);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	g_assert(notify_status == NOTIFY_UNSET);

	dbus_message_unref(sent_message);
	sent_message = old_msg = NULL;
	reset_notify();

	/* No new query or notify after connect */
	send_dbus_connect();
	g_assert_null(sent_message);
	g_assert(notify_status == NOTIFY_UNSET);
	reset_notify();

	/* Signal received, the device is brought up, notified and released */
	send_dbus_signal("developer_mode");
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Notify off works as normal, notification is sent and dev released */
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	/* Another on call works as normal */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);


	__connman_builtin_sailfish_developer_mode.exit();
}

/* Device is put up, and signal comes, device is notified */
static void developer_mode_plugin_test_rtnl6()
{
	DBusMessage *old_msg;

	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* Query has been made, no notify is done, reference is kept */
	g_assert(sent_message);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	old_msg = sent_message;

	/* A device with same interface is not added and creates no query */
	test_device2.type = test_device1.type;
	rtnl_device_on(test_device2.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(sent_message == old_msg);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	g_assert_cmpint(test_device2.refcount, ==, 0);

	/* Another notification from different device4 creates no new query */
	rtnl_device_on(test_device4.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(sent_message == old_msg);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	g_assert_cmpint(test_device4.refcount, ==, 1);

	/* After receiving signal notify is sent, notify is done */
	send_dbus_signal("developer_mode");
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Off creates nothing new */
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);
	g_assert_cmpint(test_device2.refcount, ==, 0);
	g_assert_cmpint(test_device4.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device2.refcount, ==, 0);
	g_assert_cmpint(test_device4.refcount, ==, 0);
}

/*
 * Device1 is put up and down and device4 with different interface comes up,
 * with a late down notification signal (undefined) after which correct signal
 * (developer_mode) is sent.
 */
static void developer_mode_plugin_test_rtnl7()
{
	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* Query has been made, no notify is done, reference is kept */
	g_assert(sent_message);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Notify with device1 interface */
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	reset_dbus_pending_notify();

	/* Off creates nothing new */
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);
	reset_dbus_pending_notify();
	reset_notify();

	/*
	 * Another notification from different device without usb-moded signal
	 * in between.
	 */
	set_test_interface(&test_device4);
	rtnl_device_on(test_device4.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* No new message */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device4.refcount, ==, 1);

	/* Late signal from usb-moded creates no new message or notify */
	send_dbus_signal("undefined");
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);

	/* Notify with device4 interface */
	send_dbus_signal("developer_mode");
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device4);
	g_assert_cmpint(test_device4.refcount, ==, 1);

	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device4.refcount, ==, 0);
}

/*
 * Device comes up, gets developer mode reply , gets signal undefined and
 * device is notified to be off
 */
static void developer_mode_plugin_test_rtnl8()
{
	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* Query has been made, no notify is done, reference is kept */
	g_assert(sent_message);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Notify with device1 interface */
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	reset_dbus_pending_notify();
	reset_notify();

	/* Away from developer mode and device goes off */
	send_dbus_signal("undefined");
	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_FALSE);
	g_assert(notify_device == &test_device1);
	g_assert_cmpint(test_device1.refcount, ==, 0);
	reset_dbus_pending_notify();
	reset_notify();

	__connman_builtin_sailfish_developer_mode.exit();
}


/*
 * Tests devices with invalid type (test_device2) and no device set in device.c
 * (test_device3).
 */
static void developer_mode_plugin_test_rtnl_fail0()
{
	reset_test();
	set_test_interface(&test_device3);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	send_dbus_signal("developer_mode");

	/* Device 3 is valid but no device found */
	rtnl_device_on(test_device3.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);

	/* No query has been made or notify done*/
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device3.refcount, ==, 0);

	rtnl_device_off(test_device3.index, 0);
	g_assert(notify_status == NOTIFY_UNSET);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Test with usb moded in invalid state for developer mode */
static void developer_mode_plugin_test_rtnl_fail1()
{
	const char *signals[] = {"undefined", "ask", "busy", "abd_mode",
				"diag_mode", "connection_sharing", "host_mode",
				"mtp_mode", "mass_storage", "pc_suite",
				"charging_only", "charging_only_fallback",
				"dedicated_charger", "garbage", NULL};
	int i = 0;

	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	for (i = 0; signals[i]; i++) {
		send_dbus_signal(signals[i]);
	
		rtnl_device_on(test_device1.index,
					IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
		g_assert(notify_status == NOTIFY_UNSET);
		g_assert_cmpint(test_device1.refcount, ==, 1);
	
		/* No query is made */
		g_assert_null(sent_message);
		g_assert_null(pending_call);

		rtnl_device_off(test_device1.index, 0);
		g_assert_cmpint(test_device1.refcount, ==, 0);
		reset_notify();
	}

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Query usb moded status and get invalid result */
static void developer_mode_plugin_test_rtnl_fail2()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_reply_type(DBUS_MESSAGE_INVALID);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	/* usb moded status is being queried */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Query has been made */
	g_assert(sent_message);

	set_test_interface(&test_device1);
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);

	__connman_builtin_sailfish_developer_mode.exit();
	
	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Interface "lost" before reply and signal is processed */
static void developer_mode_plugin_test_rtnl_fail3()
{
	int index;

	reset_test();
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	/* usb moded status is being queried */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Query has been made */
	g_assert(sent_message);

	/* Change index so no result is provided */
	index = test_device1.index;
	test_device1.index = -1;

	set_test_interface(&test_device1);
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* No new query has been made */
	g_assert_null(sent_message);
	g_assert_null(pending_call);

	/* signal received but invalid interface still */
	send_dbus_signal("developer_mode");
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	test_device1.index = index;

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Initialization fails as rtnl registration fails */
static void developer_mode_plugin_test_rtnl_fail4()
{
	reset_test();
	rtnl_on = false;

	g_assert(__connman_builtin_sailfish_developer_mode.init() != 0);
	__connman_builtin_sailfish_developer_mode.exit();

}

/* Generic failed message */
static void developer_mode_plugin_test_dbus_error0()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_reply_type(DBUS_MESSAGE_FAILED);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	
	/* Query has been made */
	g_assert(sent_message);

	/* Error is sent, no new queries are made */
	call_dbus_pending_notify();
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Invalid message signature */
static void developer_mode_plugin_test_dbus_error1()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_reply_type(DBUS_MESSAGE_INT);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	
	/* Query has been made */
	g_assert(sent_message);

	/* Invalid signature in message, no new query is made */
	call_dbus_pending_notify();
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Invalid signal and invalid signature */
static void developer_mode_plugin_test_dbus_error2()
{
	reset_test();
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	/* Set invalid signal signature */
	set_dbus_reply_type(DBUS_MESSAGE_INT);
	set_test_interface(&test_device1);
	send_dbus_signal("");

	__connman_builtin_sailfish_developer_mode.exit();
}

/* Message sending fails */
static void developer_mode_plugin_test_dbus_error3()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_config(DBUS_SEND_MESSAGE_FAIL);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	/* Sending fails, no query or notification */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_null(notify_pending);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Pending call is NULL */
static void developer_mode_plugin_test_dbus_error4()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_config(DBUS_PENDING_CALL_NULL);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);
	
	/* Pending call null, no query or notification */
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_null(notify_pending);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Setting notify fails */
static void developer_mode_plugin_test_dbus_error5()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_config(DBUS_SET_NOTIFY_FAIL);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	/* Cannot set notify, no notification but query is done*/
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert(sent_message);
	g_assert_null(pending_call);
	g_assert_null(notify_pending);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Setting and removing signal fails */
static void developer_mode_plugin_test_dbus_error6()
{
	set_dbus_config(DBUS_WATCH_ADD_FAIL);

	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);
	g_assert_null(signal_function);
	__connman_builtin_sailfish_developer_mode.exit();
	
	set_dbus_config(DBUS_WATCH_REM_FAIL);
	
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);
	g_assert(signal_function);
	__connman_builtin_sailfish_developer_mode.exit();
}

/* Call not completed */
static void developer_mode_plugin_test_dbus_error7()
{
	DBusMessage *old_msg;

	reset_test();
	set_dbus_config(DBUS_PENDING_CALL_COMPLETED_FAIL);
	set_test_interface(&test_device1);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	
	/* Query has been made */
	g_assert(sent_message);
	g_assert(pending_call);
	old_msg = sent_message;

	/* Pending call completed fails, no new query */
	call_dbus_pending_notify();
	g_assert(sent_message == old_msg);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Let pending call to complete, notification is done */
	set_dbus_config(DBUS_CONFIG_UNSET);
	call_dbus_pending_notify();
	g_assert(notify_status == NOTIFY_TRUE);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* NULL message */
static void developer_mode_plugin_test_dbus_error8()
{
	DBusMessage *old_msg;

	reset_test();
	set_test_interface(&test_device1);
	set_dbus_reply_type(DBUS_MESSAGE_NULL);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	
	/* Query has been made */
	g_assert(sent_message);
	old_msg = sent_message;

	/* NULL message is sent, no new query is done */
	call_dbus_pending_notify();
	g_assert(sent_message == old_msg);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);

	/* Last test, reset messages (free mem) */
	reset_messages();
}

/* Msg and signal with all fail type messages */
static void developer_mode_plugin_test_dbus_error9()
{
	enum dbus_reply_type_t type;

	reset_test();
	set_test_interface(&test_device1);

	for (type = DBUS_MESSAGE_DEVMODE_FAIL1;
				type <= DBUS_MESSAGE_DEVMODE_FAIL3; type++) {
		set_dbus_reply_type(type);
		g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

		rtnl_device_on(test_device1.index,
					IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
		g_assert(notify_status == NOTIFY_UNSET);
		g_assert_cmpint(test_device1.refcount, ==, 1);

		/* Query has been made */
		g_assert(sent_message);

		/* Error is sent, no new queries are made */
		call_dbus_pending_notify();
		g_assert_null(sent_message);
		g_assert_null(pending_call);
		g_assert_cmpint(test_device1.refcount, ==, 1);

		rtnl_device_off(test_device1.index, 0);
		g_assert(notify_status == NOTIFY_UNSET);
		g_assert_cmpint(test_device1.refcount, ==, 0);

		/* Invalid signal, no query */
		send_dbus_signal("developer_mode");
		rtnl_device_on(test_device1.index,
					IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
		g_assert(notify_status == NOTIFY_UNSET);
		g_assert_cmpint(test_device1.refcount, ==, 1);
		g_assert_null(sent_message);
		g_assert_null(pending_call);

		__connman_builtin_sailfish_developer_mode.exit();

		g_assert_cmpint(test_device1.refcount, ==, 0);
	}
}

/* Missing mode */
static void developer_mode_plugin_test_dbus_error10()
{
	reset_test();
	set_test_interface(&test_device1);
	set_usb_moded_ignore(IGNORE_MODE_NAME);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Query has been made */
	g_assert(sent_message);

	/* Error with message, no new queries are made */
	call_dbus_pending_notify();
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	/*
	 * Invalid signal, new query is made because reply & signal parsing have
	 * failed
	 */
	send_dbus_signal("developer_mode");
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	g_assert(sent_message);
	g_assert(pending_call);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Missing network interface */
static void developer_mode_plugin_test_dbus_error11()
{
	reset_test();
	set_test_interface(&test_device1);
	set_usb_moded_ignore(IGNORE_NETWORK_INTERFACE);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Query has been made */
	g_assert(sent_message);

	/* Error is sent, no new queries are made */
	call_dbus_pending_notify();
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	rtnl_device_off(test_device1.index, 0);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 0);

	/*
	 * Invalid signal, new query is made because parsing of reply & signal
	 * have failed
	 */
	send_dbus_signal("developer_mode");
	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);
	g_assert(sent_message);
	g_assert(pending_call);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

/* Service unknown message */
static void developer_mode_plugin_test_dbus_error12()
{
	reset_test();
	set_test_interface(&test_device1);
	set_dbus_reply_type(DBUS_MESSAGE_SERVICE_UNKNOWN);
	g_assert(__connman_builtin_sailfish_developer_mode.init() == 0);

	rtnl_device_on(test_device1.index, IFF_UP|IFF_RUNNING|IFF_LOWER_UP);
	g_assert(notify_status == NOTIFY_UNSET);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	/* Query has been made */
	g_assert(sent_message);

	/* Service unknown error is sent, no new queries are made */
	call_dbus_pending_notify();
	g_assert_null(sent_message);
	g_assert_null(pending_call);
	g_assert_cmpint(test_device1.refcount, ==, 1);

	__connman_builtin_sailfish_developer_mode.exit();

	g_assert_cmpint(test_device1.refcount, ==, 0);
}

static gchar *option_debug = NULL;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

int main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func("/developer_mode_plugin/test_rtnl0",
				developer_mode_plugin_test_rtnl0);
	g_test_add_func("/developer_mode_plugin/test_rtnl1",
				developer_mode_plugin_test_rtnl1);
	g_test_add_func("/developer_mode_plugin/test_rtnl2",
				developer_mode_plugin_test_rtnl2);
	g_test_add_func("/developer_mode_plugin/test_rtnl3",
				developer_mode_plugin_test_rtnl3);
	g_test_add_func("/developer_mode_plugin/test_rtnl4",
				developer_mode_plugin_test_rtnl4);
	g_test_add_func("/developer_mode_plugin/test_rtnl5",
				developer_mode_plugin_test_rtnl5);
	g_test_add_func("/developer_mode_plugin/test_rtnl6",
				developer_mode_plugin_test_rtnl6);
	g_test_add_func("/developer_mode_plugin/test_rtnl7",
				developer_mode_plugin_test_rtnl7);
	g_test_add_func("/developer_mode_plugin/test_rtnl8",
				developer_mode_plugin_test_rtnl8);
	g_test_add_func("/developer_mode_plugin/test_rtnl_fail0",
				developer_mode_plugin_test_rtnl_fail0);
	g_test_add_func("/developer_mode_plugin/test_rtnl_fail1",
				developer_mode_plugin_test_rtnl_fail1);
	g_test_add_func("/developer_mode_plugin/test_rtnl_fail2",
				developer_mode_plugin_test_rtnl_fail2);
	g_test_add_func("/developer_mode_plugin/test_rtnl_fail3",
				developer_mode_plugin_test_rtnl_fail3);
	g_test_add_func("/developer_mode_plugin/test_rtnl_fail4",
				developer_mode_plugin_test_rtnl_fail4);
	g_test_add_func("/developer_mode_plugin/test_dbus_error0",
				developer_mode_plugin_test_dbus_error0);
	g_test_add_func("/developer_mode_plugin/test_dbus_error1",
				developer_mode_plugin_test_dbus_error1);
	g_test_add_func("/developer_mode_plugin/test_dbus_error2",
				developer_mode_plugin_test_dbus_error2);
	g_test_add_func("/developer_mode_plugin/test_dbus_error3",
				developer_mode_plugin_test_dbus_error3);
	g_test_add_func("/developer_mode_plugin/test_dbus_error4",
				developer_mode_plugin_test_dbus_error4);
	g_test_add_func("/developer_mode_plugin/test_dbus_error5",
				developer_mode_plugin_test_dbus_error5);
	g_test_add_func("/developer_mode_plugin/test_dbus_error6",
				developer_mode_plugin_test_dbus_error6);
	g_test_add_func("/developer_mode_plugin/test_dbus_error7",
				developer_mode_plugin_test_dbus_error7);
	g_test_add_func("/developer_mode_plugin/test_dbus_error8",
				developer_mode_plugin_test_dbus_error8);
	g_test_add_func("/developer_mode_plugin/test_dbus_error9",
				developer_mode_plugin_test_dbus_error9);
	g_test_add_func("/developer_mode_plugin/test_dbus_error10",
				developer_mode_plugin_test_dbus_error10);
	g_test_add_func("/developer_mode_plugin/test_dbus_error11",
				developer_mode_plugin_test_dbus_error11);
	g_test_add_func("/developer_mode_plugin/test_dbus_error12",
				developer_mode_plugin_test_dbus_error12);

	return g_test_run();
}

