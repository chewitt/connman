/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd.
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/technology.h>
#include <connman/device.h>
#include <connman/dbus.h>
#include <connman/log.h>

/* The connman-jollagps plugin allows Flight Mode to toggle GPS powered/enablement */

static struct connman_device *jolla_gps_device;

static int jolla_gps_enable(struct connman_device *device)
{
    (void)device;

    DBG("");

    connman_device_set_powered(jolla_gps_device, TRUE);
    return 0;
}

static int jolla_gps_disable(struct connman_device *device)
{
    (void)device;

    DBG("");

    connman_device_set_powered(jolla_gps_device, FALSE);
    return 0;
}

static int jolla_gps_probe(struct connman_device *device)
{
    (void)device;

    DBG("");

    return 0;
}

static void jolla_gps_remove(struct connman_device *device)
{
    (void)device;

    DBG("");
}

static struct connman_device_driver device_driver = {
    .name = "gps",
    .type = CONNMAN_DEVICE_TYPE_GPS,
    .probe = jolla_gps_probe,
    .remove = jolla_gps_remove,
    .enable = jolla_gps_enable,
    .disable = jolla_gps_disable
};

static int jolla_gps_tech_probe(struct connman_technology *technology)
{
    (void)technology;

    DBG("");

    return 0;
}

static void jolla_gps_tech_remove(struct connman_technology *technology)
{
    (void)technology;

    DBG("");
}

static struct connman_technology_driver tech_driver = {
    .name = "gps",
    .type = CONNMAN_SERVICE_TYPE_GPS,
    .probe = jolla_gps_tech_probe,
    .remove = jolla_gps_tech_remove,
};

static int jolla_gps_init()
{
    DBG("");

    if (connman_technology_driver_register(&tech_driver) < 0) {
        connman_warn("Failed to initialize technology for Jolla GPS");
        return -EIO;
    }

    if (connman_device_driver_register(&device_driver) < 0) {
        connman_warn("Failed to initialize device driver for Jolla GPS");
        connman_technology_driver_unregister(&tech_driver);
        return -EIO;
    }

    jolla_gps_device = connman_device_create("gps", CONNMAN_DEVICE_TYPE_GPS);
    if (jolla_gps_device == NULL) {
        connman_warn("Failed to create GPS device");
        return -ENODEV;
    }

    if (connman_device_register(jolla_gps_device) < 0) {
        connman_warn("Failed to register GPS device");
        connman_device_unref(jolla_gps_device);
        jolla_gps_device = NULL;
        return -EIO;
    }

    return 0;
}

static void jolla_gps_exit()
{
    DBG("");

    if (jolla_gps_device != NULL) {
        connman_device_unregister(jolla_gps_device);
        connman_device_unref(jolla_gps_device);
        jolla_gps_device = NULL;
    }

    connman_device_driver_unregister(&device_driver);
    connman_technology_driver_unregister(&tech_driver);
}

CONNMAN_PLUGIN_DEFINE(jolla_gps, "Jolla GPS", VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
                      jolla_gps_init, jolla_gps_exit)
