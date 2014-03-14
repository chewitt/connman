/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014  jolla Ltd.
 *  Contact: Aaron McCarthy <aaron.mccarthy@jollamobile.com>
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

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/technology.h>
#include <connman/device.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define HYBRIS_SERVICE "com.jollamobile.gps"
#define HYBRIS_DEVICE_PATH "/com/jollamobile/gps/Device"
#define HYBRIS_DEVICE_INTERFACE "com.jollamobile.gps.Device"
#define FREEDESKTOP_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define FREEDESKTOP_PROPERTIES_SET "Set"
#define PROPERTY_CHANGED "PropertyChanged"
#define POWERED_NAME "Powered"

#define TIMEOUT 60000

static DBusConnection *connection;

static struct connman_device *hybris_gps_device;

static void powered_reply(DBusPendingCall *call, void *user_data)
{
    (void)user_data;

    DBG("");

    DBusMessage *reply = dbus_pending_call_steal_reply(call);

    dbus_message_unref(reply);
    dbus_pending_call_unref(call);
}

static int change_powered(DBusConnection *conn, dbus_bool_t powered)
{
    DBG("");

    DBusMessage *message = dbus_message_new_method_call(HYBRIS_SERVICE, HYBRIS_DEVICE_PATH,
                                                        FREEDESKTOP_PROPERTIES_INTERFACE,
                                                        FREEDESKTOP_PROPERTIES_SET);
    if (message == NULL)
        return -ENOMEM;

    dbus_message_set_auto_start(message, FALSE);

    DBusMessageIter iter;
    dbus_message_iter_init_append(message, &iter);

    const char *string = HYBRIS_DEVICE_INTERFACE;
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &string);
    string = POWERED_NAME;
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &string);

    DBusMessageIter value;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, DBUS_TYPE_BOOLEAN_AS_STRING, &value);
    dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &powered);
    dbus_message_iter_close_container(&iter, &value);

    DBusPendingCall *call;
    if (dbus_connection_send_with_reply(conn, message, &call, TIMEOUT) == FALSE) {
        connman_error("Failed to change Powered property");
        dbus_message_unref(message);
        return -EINVAL;
    }

    if (call == NULL) {
        connman_error("D-Bus connection not available");
        dbus_message_unref(message);
        return -EINVAL;
    }

    dbus_pending_call_set_notify(call, powered_reply, 0, 0);

    dbus_message_unref(message);

    return -EINPROGRESS;
}

static int hybris_gps_enable(struct connman_device *device)
{
    (void)device;

    DBG("");

    if (connman_device_get_string(hybris_gps_device, "Path") == NULL) {
        connman_device_set_powered(hybris_gps_device, TRUE);
        return 0;
    }

    return change_powered(connection, TRUE);
}

static int hybris_gps_disable(struct connman_device *device)
{
    (void)device;

    DBG("");

    if (connman_device_get_string(hybris_gps_device, "Path") == NULL) {
        connman_device_set_powered(hybris_gps_device, FALSE);
        return 0;
    }

    return change_powered(connection, FALSE);
}

static int hybris_gps_probe(struct connman_device *device)
{
    (void)device;

    DBG("");

    return 0;
}

static void hybris_gps_remove(struct connman_device *device)
{
    (void)device;

    DBG("");
}

static struct connman_device_driver device_driver = {
    .name = "gps",
    .type = CONNMAN_DEVICE_TYPE_GPS,
    .probe = hybris_gps_probe,
    .remove = hybris_gps_remove,
    .enable = hybris_gps_enable,
    .disable = hybris_gps_disable
};

static int hybris_gps_tech_probe(struct connman_technology *technology)
{
    (void)technology;

    DBG("");

    return 0;
}

static void hybris_gps_tech_remove(struct connman_technology *technology)
{
    (void)technology;

    DBG("");
}

static struct connman_technology_driver tech_driver = {
    .name = "gps",
    .type = CONNMAN_SERVICE_TYPE_GPS,
    .probe = hybris_gps_tech_probe,
    .remove = hybris_gps_tech_remove,
};

static void hybris_gps_connect(DBusConnection *conn, void *user_data)
{
    (void)user_data;

    DBG("");

    connman_device_set_string(hybris_gps_device, "Path", HYBRIS_DEVICE_PATH);

    change_powered(conn, connman_device_get_powered(hybris_gps_device));
}

static void hybris_gps_disconnect(DBusConnection *conn, void *user_data)
{
    (void)conn;
    (void)user_data;

    DBG("");

    connman_device_set_string(hybris_gps_device, "Path", NULL);
}

static gboolean device_changed(DBusConnection *conn, DBusMessage *message, void *user_data)
{
    (void)conn;
    (void)user_data;

    DBG("");

    DBusMessageIter iter;
    if (dbus_message_iter_init(message, &iter) == FALSE)
        return TRUE;

    const char *property;
    dbus_message_iter_get_basic(&iter, &property);
    dbus_message_iter_next(&iter);

    DBusMessageIter value;
    dbus_message_iter_recurse(&iter, &value);

    if (g_str_equal(property, POWERED_NAME) == TRUE) {
        dbus_bool_t powered;
        dbus_message_iter_get_basic(&value, &powered);
        connman_device_set_powered(hybris_gps_device, powered);
    }

    return TRUE;
}

static guint watch;
static guint device_watch;

static int hybris_gps_init()
{
    DBG("");

    connection = connman_dbus_get_connection();
    if (connection == NULL) {
        connman_warn("Failed to get dbus connection");
        return -EIO;
    }

    watch = g_dbus_add_service_watch(connection, HYBRIS_SERVICE, hybris_gps_connect,
                                     hybris_gps_disconnect, NULL, NULL);
    if (watch == 0) {
        connman_warn("Failed to add hybris service watcher");
        dbus_connection_unref(connection);
        return -EIO;
    }

    device_watch = g_dbus_add_signal_watch(connection, HYBRIS_SERVICE, HYBRIS_DEVICE_PATH,
                                           HYBRIS_DEVICE_INTERFACE, PROPERTY_CHANGED,
                                           device_changed, NULL, NULL);
    if (device_watch == 0) {
        connman_warn("Failed to add hybris device property changed signal watcher");
        g_dbus_remove_watch(connection, watch);
        dbus_connection_unref(connection);
        return -EIO;
    }

    if (connman_technology_driver_register(&tech_driver) < 0) {
        connman_warn("Failed to initialize technology for Hybris GPS");
        g_dbus_remove_watch(connection, device_watch);
        g_dbus_remove_watch(connection, watch);
        dbus_connection_unref(connection);
        return -EIO;
    }

    if (connman_device_driver_register(&device_driver) < 0) {
        connman_warn("Failed to initialize device driver for " HYBRIS_SERVICE);
        connman_technology_driver_unregister(&tech_driver);
        g_dbus_remove_watch(connection, device_watch);
        g_dbus_remove_watch(connection, watch);
        dbus_connection_unref(connection);
        return -EIO;
    }

    hybris_gps_device = connman_device_create("gps", CONNMAN_DEVICE_TYPE_GPS);
    if (hybris_gps_device == NULL) {
        connman_warn("Failed to creat GPS device");
        return -ENODEV;
    }

    if (connman_device_register(hybris_gps_device) < 0) {
        connman_warn("Failed to register GPS device");
        connman_device_unref(hybris_gps_device);
        hybris_gps_device = NULL;
        return -EIO;
    }

    return 0;
}

static void hybris_gps_exit()
{
    DBG("");

    if (hybris_gps_device != NULL) {
        connman_device_unregister(hybris_gps_device);
        connman_device_unref(hybris_gps_device);
        hybris_gps_device = NULL;
    }

    connman_device_driver_unregister(&device_driver);
    connman_technology_driver_unregister(&tech_driver);
}

CONNMAN_PLUGIN_DEFINE(hybris_gps, "Hybris GPS", VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
                      hybris_gps_init, hybris_gps_exit)
