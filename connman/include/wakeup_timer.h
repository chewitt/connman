/*
 *  Connection Manager
 *
 *  Copyright (C) 2014-2016 Jolla Ltd. All rights reserved.
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
 */

#ifndef __CONNMAN_WAKEUP_TIMER_H
#define __CONNMAN_WAKEUP_TIMER_H

#include <glib.h>

G_BEGIN_DECLS

struct connman_wakeup_timer {
	const char *name;
	guint (*timeout_add) (gint priority,
				guint interval,
				GSourceFunc function,
				gpointer data,
				GDestroyNotify notify);
	guint (*timeout_add_seconds) (gint priority,
					guint interval,
					GSourceFunc function,
					gpointer data,
					GDestroyNotify notify);
};

int connman_wakeup_timer_register(const struct connman_wakeup_timer *timer);
void connman_wakeup_timer_unregister(const struct connman_wakeup_timer *timer);

guint connman_wakeup_timer_add(guint interval,
				GSourceFunc function,
				gpointer data);
guint connman_wakeup_timer_add_full(gint priority,
					guint interval,
					GSourceFunc function,
					gpointer data,
					GDestroyNotify notify);
guint connman_wakeup_timer_add_seconds(guint interval,
					GSourceFunc function,
					gpointer data);
guint connman_wakeup_timer_add_seconds_full(gint priority,
					guint interval,
					GSourceFunc function,
					gpointer data,
					GDestroyNotify notify);

G_END_DECLS

#endif /* __CONNMAN_WAKEUP_TIMER_H */
