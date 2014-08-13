/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd.
 *  Contact: Hannu Mallat <hannu.mallat@jollamobile.com>
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

/*
 * Ensure that rfkill is set to desired state on startup for
 * Bluetooth, even before bluetooth legacy driver figures out BT
 * adapter presence via BlueZ D-Bus API.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "connman.h"

#define BLUETOOTH_RFKILL_IDENT "bluetooth_rfkill"

static struct connman_device *bt_device = NULL;

#define BT_DEVICE 0

static int bluetooth_rfkill_device_probe(struct connman_device *device)
{
	struct hci_dev_info dev_info;
	int fd = -1;
	int r = 0;

	DBG("device %p", device);

	fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (fd < 0) {
		DBG("Cannot open BT socket: %s(%d)", strerror(errno), errno);
		r = -errno;
		goto out;
	}

	memset(&dev_info, 0, sizeof(dev_info));
	dev_info.dev_id = BT_DEVICE;
	if (ioctl(fd, HCIGETDEVINFO, &dev_info) < 0) {
		DBG("Cannot get BT info: %s(%d)", strerror(errno), errno);
		r = -errno;
		goto out;
	}

	if (ioctl(fd, HCIDEVUP, dev_info.dev_id) < 0) {
		DBG("Cannot raise BT dev %d: %s(%d)", dev_info.dev_id,
					strerror(errno), errno);
		if (errno != ERFKILL && errno != EALREADY) {
			r = -errno;
			goto out;
		}
	}

	DBG("Probe done.");

out:
	if (fd >= 0)
		close(fd);

	return r;
}

static void bluetooth_rfkill_device_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int bluetooth_rfkill_device_enable(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}

static int bluetooth_rfkill_device_disable(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}

static struct connman_device_driver dev_driver = {
	.name = "bluetooth_rfkill",
	.type = CONNMAN_DEVICE_TYPE_BLUETOOTH,
	.probe = bluetooth_rfkill_device_probe,
	.remove = bluetooth_rfkill_device_remove,
	.enable = bluetooth_rfkill_device_enable,
	.disable = bluetooth_rfkill_device_disable
};

static int bluetooth_rfkill_tech_probe(struct connman_technology *technology)
{
	DBG("technology %p", technology);
	__connman_rfkill_block(CONNMAN_SERVICE_TYPE_BLUETOOTH, TRUE);
	return 0;
}

static void bluetooth_rfkill_tech_remove(struct connman_technology *technology)
{
	DBG("technology %p", technology);
}

static struct connman_technology_driver tech_driver = {
	.name = "bluetooth_rfkill",
	.type = CONNMAN_SERVICE_TYPE_BLUETOOTH,
	.probe = bluetooth_rfkill_tech_probe,
	.remove = bluetooth_rfkill_tech_remove,
};

static int jolla_rfkill_init(void)
{
	int err;

	DBG("Initializing dummy device for BT rfkill.");

	err = connman_device_driver_register(&dev_driver);
	if (err < 0)
		return err;

	err = connman_technology_driver_register(&tech_driver);
	if (err < 0) {
		connman_device_driver_unregister(&dev_driver);
		return err;
	}

	/* Force loading of BT settings and applying BT rfkill */
	bt_device = connman_device_create("bluetooth_rfkill",
					CONNMAN_DEVICE_TYPE_BLUETOOTH);
	if (bt_device != NULL) {
		connman_device_set_ident(bt_device, BLUETOOTH_RFKILL_IDENT);
		if (connman_device_register(bt_device) < 0) {
                       connman_device_unref(bt_device);
                       connman_technology_driver_unregister(&tech_driver);
                       connman_device_driver_unregister(&dev_driver);
                       return err;
               }
       }

	return 0;
}

static void jolla_rfkill_exit(void)
{
	DBG("");

	if (bt_device != NULL) {
		connman_device_unregister(bt_device);
		connman_device_unref(bt_device);
		bt_device = NULL;
	}

	connman_technology_driver_unregister(&tech_driver);
	connman_device_driver_unregister(&dev_driver);
}

CONNMAN_PLUGIN_DEFINE(jolla_rfkill, "Jolla rfkill", VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
                      jolla_rfkill_init, jolla_rfkill_exit)
