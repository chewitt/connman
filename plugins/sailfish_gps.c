/*
 *  Connection Manager
 *
 *  Copyright (C) 2014-2017 Jolla Ltd.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <errno.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/technology.h>
#include <connman/device.h>
#include <connman/log.h>

/* This plugin allows Flight Mode to toggle GPS powered/enablement */

static struct connman_device *sailfish_gps_device;

static int sailfish_gps_enable(struct connman_device *device)
{
	(void)device;

	DBG("");

	connman_device_set_powered(sailfish_gps_device, TRUE);
	return 0;
}

static int sailfish_gps_disable(struct connman_device *device)
{
	(void)device;

	DBG("");

	connman_device_set_powered(sailfish_gps_device, FALSE);
	return 0;
}

static int sailfish_gps_probe(struct connman_device *device)
{
	(void)device;

	DBG("");

	return 0;
}

static void sailfish_gps_remove(struct connman_device *device)
{
	(void)device;

	DBG("");
}

static struct connman_device_driver device_driver = {
	.name = "gps",
	.type = CONNMAN_DEVICE_TYPE_GPS,
	.probe = sailfish_gps_probe,
	.remove = sailfish_gps_remove,
	.enable = sailfish_gps_enable,
	.disable = sailfish_gps_disable
};

static int sailfish_gps_tech_probe(struct connman_technology *technology)
{
	(void)technology;

	DBG("");

	return 0;
}

static void sailfish_gps_tech_remove(struct connman_technology *technology)
{
	(void)technology;

	DBG("");
}

static struct connman_technology_driver tech_driver = {
	.name = "gps",
	.type = CONNMAN_SERVICE_TYPE_GPS,
	.probe = sailfish_gps_tech_probe,
	.remove = sailfish_gps_tech_remove,
};

static int sailfish_gps_init()
{
	DBG("");

	/* These calls never actually fail */
	connman_technology_driver_register(&tech_driver);
	connman_device_driver_register(&device_driver);
	sailfish_gps_device = connman_device_create(device_driver.name,
						device_driver.type);

	/* This one may, in theory */
	if (connman_device_register(sailfish_gps_device) < 0) {
		connman_warn("Failed to register GPS device");
		connman_device_unref(sailfish_gps_device);
		sailfish_gps_device = NULL;
		return -EIO;
	}

	return 0;
}

static void sailfish_gps_exit()
{
	DBG("");

	if (sailfish_gps_device) {
		connman_device_unregister(sailfish_gps_device);
		connman_device_unref(sailfish_gps_device);
		sailfish_gps_device = NULL;
	}

	connman_device_driver_unregister(&device_driver);
	connman_technology_driver_unregister(&tech_driver);
}

CONNMAN_PLUGIN_DEFINE(sailfish_gps, "Sailfish GPS", VERSION,
				CONNMAN_PLUGIN_PRIORITY_DEFAULT,
				sailfish_gps_init, sailfish_gps_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
