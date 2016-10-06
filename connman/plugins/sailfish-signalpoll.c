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

#include <mce_display.h>
#include <mce_log.h>

#include <gutil_misc.h>
#include <gutil_log.h>

enum signalpoll_display_events {
	DISPLAY_EVENT_VALID,
	DISPLAY_EVENT_STATE,
	DISPLAY_EVENT_COUNT
};

static GSList *poll_services;
static guint signalpoll_timer;
static MceDisplay *display;
static gulong display_event_id[DISPLAY_EVENT_COUNT];

#define POLL_INTERVAL_SECS (2)

static gboolean signalpoll_display_on(void)
{
	return display && display->valid &&
				display->state != MCE_DISPLAY_STATE_OFF;
}

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
	if (signalpoll_display_on() && poll_services) {
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

static void signalpoll_display_cb(MceDisplay *display, void *user_data)
{
	signalpoll_update();
}

static void signalpoll_clean_services(gpointer service)
{
	connman_service_unref(service);
}

static void signalpoll_mce_debug_notify(struct connman_debug_desc *desc)
{
	mce_log.level = (desc->flags & CONNMAN_DEBUG_FLAG_PRINT) ?
		GLOG_LEVEL_VERBOSE : GLOG_LEVEL_INHERIT;
}

static struct connman_debug_desc mce_debug CONNMAN_DEBUG_ATTR = {
	.name                   = "mce",
	.flags                  = CONNMAN_DEBUG_FLAG_DEFAULT,
	.notify                 = signalpoll_mce_debug_notify
};

static struct connman_notifier signalpoll_notifier = {
	.name                   = "signalpoll",
	.priority               = CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.service_state_changed  = signalpoll_service_state_changed,
	.service_remove         = signalpoll_remove_poll_service
};

static int signalpoll_init()
{
	DBG("");
	display = mce_display_new();
	display_event_id[DISPLAY_EVENT_VALID] =
		mce_display_add_valid_changed_handler(display,
				signalpoll_display_cb, NULL);
	display_event_id[DISPLAY_EVENT_STATE] =
		mce_display_add_state_changed_handler(display,
				signalpoll_display_cb, NULL);

	connman_notifier_register(&signalpoll_notifier);
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
	connman_notifier_unregister(&signalpoll_notifier);
	gutil_disconnect_handlers(display, display_event_id,
							DISPLAY_EVENT_COUNT);
	mce_display_unref(display);
	display = NULL;
}

CONNMAN_PLUGIN_DEFINE(sailfish_signalpoll, "Signal poll plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, signalpoll_init, signalpoll_exit)
