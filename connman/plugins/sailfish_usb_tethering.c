/*
 *  Connection Manager
 *
 *  Copyright (C) 2015-2017 Jolla Ltd. All rights reserved.
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "connman.h"

#include <errno.h>

static GSList *sailfish_usb_list = NULL;

struct sailfish_usb_device {
	struct connman_device *device;
	struct connman_technology *tech;
	int index;
	char *name;
	unsigned flags;
	unsigned int watch;
	bool enabled;
	bool tethering;
};

struct sailfish_usb_tethering {
	struct connman_technology *tech;
	const char *bridge;
	bool done;
};

static void sailfish_usb_device_free(struct sailfish_usb_device *usb)
{
	if (usb) {
		connman_device_set_data(usb->device, NULL);
		g_free(usb->name);
		g_free(usb);
	}
}

static struct sailfish_usb_device *sailfish_usb_device_for_index(int index)
{
	GSList *l;

	for (l = sailfish_usb_list; l;  l = g_slist_next(l)) {
		struct sailfish_usb_device *usb = l->data;

		if (usb->index == index)
			return usb;
	}

	DBG("no device for index %d!", index);
	return NULL;
}

static int sailfish_usb_device_probe(struct connman_device *device)
{
	struct sailfish_usb_device *usb = g_new0(struct sailfish_usb_device,1);

	usb->device = device;
	usb->index = connman_device_get_index(device);
	DBG("device %p index %d", device, usb->index);
	sailfish_usb_list = g_slist_append(sailfish_usb_list, usb);
	connman_device_set_data(device, usb);
	connman_device_set_powered(usb->device, true);
	return 0;
}

static void sailfish_usb_device_remove(struct connman_device *device)
{
	struct sailfish_usb_device *usb = connman_device_get_data(device);
	GSList *l = g_slist_find(sailfish_usb_list, usb);

	DBG("device %p usb %p link %p", device, usb, l);
	if (l) {
		sailfish_usb_list = g_slist_delete_link(sailfish_usb_list, l);
		sailfish_usb_device_free(usb);
	}
}

static int sailfish_usb_device_enable(struct connman_device *device)
{
	struct sailfish_usb_device *usb = connman_device_get_data(device);

	DBG("device %p usb %p", device, usb);
	usb->enabled = true;
	return 0;
}

static int sailfish_usb_device_disable(struct connman_device *device)
{
	struct sailfish_usb_device *usb = connman_device_get_data(device);

	DBG("device %p usb %p", device, usb);
	usb->enabled = false;
	return 0;
}

static struct connman_device_driver sailfish_usb_device_driver = {
	.name		= "network",
	.type		= CONNMAN_DEVICE_TYPE_GADGET,
	.probe		= sailfish_usb_device_probe,
	.remove		= sailfish_usb_device_remove,
	.enable		= sailfish_usb_device_enable,
	.disable	= sailfish_usb_device_disable,
};

static void sailfish_usb_tech_add_interface(struct connman_technology *tech,
			int index, const char *name, const char *ident)
{
	struct sailfish_usb_device *usb;

	DBG("index %d name %s ident %s", index, name, ident);
	usb = sailfish_usb_device_for_index(index);
	if (usb) {
		g_free(usb->name);
		usb->name = g_strdup(name);
		usb->tech = tech;
		__connman_device_enable(usb->device);
	}
}

static void sailfish_usb_tech_remove_interface(struct connman_technology *tech,
								int index)
{
	struct sailfish_usb_device *usb;

	DBG("index %d", index);
	usb = sailfish_usb_device_for_index(index);
	if (usb && usb->tech == tech) {
		usb->tech = NULL;
		usb->tethering = false;
	}
}

static void sailfish_usb_tethering_on(gpointer data, gpointer user_data)
{
	struct sailfish_usb_device *usb = data;
	struct sailfish_usb_tethering *tethering = user_data;

	DBG("name %s index %d bridge %s enabled %d", usb->name, usb->index,
					tethering->bridge, usb->enabled);

	if (usb->enabled && usb->tech == tethering->tech) {
		if (!tethering->done) {
			// Notify tethering code before adding the first
			// device to the bridge
			tethering->done = true;
			connman_technology_tethering_notify(tethering->tech,
									true);
		}

		usb->tethering = true;
		connman_inet_ifup(usb->index);
		connman_inet_add_to_bridge(usb->index, tethering->bridge);
	}
}

static void sailfish_usb_tethering_off(gpointer data, gpointer user_data)
{
	struct sailfish_usb_device *usb = data;
	struct sailfish_usb_tethering *tethering = user_data;

	DBG("name %s index %d bridge %s tethering %d", usb->name, usb->index,
					tethering->bridge, usb->tethering);

	if (usb->tethering && usb->tech == tethering->tech) {
		// Tethering code will be notified after the last device
		// is removed from the bridge
		tethering->done = true;
		usb->tethering = false;
		connman_inet_remove_from_bridge(usb->index, tethering->bridge);
		connman_inet_ifdown(usb->index);
	}
}

static int sailfish_usb_tech_set_tethering(struct connman_technology *tech,
				const char *ident, const char *passphrase,
				const char *bridge, bool enabled)
{
	struct sailfish_usb_tethering tethering;
	DBG("bridge %s enabled %d", bridge, enabled);

	tethering.tech = tech;
	tethering.bridge = bridge;
	tethering.done = false;
	if (enabled) {
		g_slist_foreach(sailfish_usb_list, sailfish_usb_tethering_on,
								&tethering);
	} else {
		g_slist_foreach(sailfish_usb_list, sailfish_usb_tethering_off,
								&tethering);
		if (tethering.done)
			connman_technology_tethering_notify(tech, false);
	}

	return tethering.done ? 0 : (-ENODEV);
}

static int sailfish_usb_tech_probe(struct connman_technology *tech)
{
	DBG("%p", tech);
	return 0;
}

static void sailfish_usb_tech_remove(struct connman_technology *tech)
{
	GSList *l;

	DBG("%p", tech);
	for (l = sailfish_usb_list; l;  l = g_slist_next(l)) {
		struct sailfish_usb_device *usb = l->data;

		if (usb->tech == tech) {
			usb->tech = NULL;
			usb->tethering = false;
		}
	}
}

static struct connman_technology_driver sailfish_usb_tech_driver = {
	.name			= "usb_tethering",
	.type			= CONNMAN_SERVICE_TYPE_GADGET,
	.probe			= sailfish_usb_tech_probe,
	.remove			= sailfish_usb_tech_remove,
	.add_interface		= sailfish_usb_tech_add_interface,
	.remove_interface	= sailfish_usb_tech_remove_interface,
	.set_tethering		= sailfish_usb_tech_set_tethering,
};

static int sailfish_usb_tethering_init(void)
{
	int err;

	if (__connman_plugin_enabled("gadget")) {
		connman_info("No USB tethering since gadget plugin is enabled");
		return (-EOPNOTSUPP);
	}

	DBG("");
	err = connman_technology_driver_register(&sailfish_usb_tech_driver);

	if (err < 0)
		return err;

	return connman_device_driver_register(&sailfish_usb_device_driver);
}

static void sailfish_usb_device_free1(gpointer user_data)
{
	sailfish_usb_device_free(user_data);
}

static void sailfish_usb_tethering_exit()
{
	DBG("");
	connman_technology_driver_unregister(&sailfish_usb_tech_driver);
	connman_device_driver_unregister(&sailfish_usb_device_driver);

	if (sailfish_usb_list) {
		g_slist_free_full(sailfish_usb_list,
					sailfish_usb_device_free1);
		sailfish_usb_list = NULL;
	}
}

CONNMAN_PLUGIN_DEFINE(sailfish_usb_tethering, "Sailfish USB tethering plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		sailfish_usb_tethering_init, sailfish_usb_tethering_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
