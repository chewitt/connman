/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd. All rights reserved.
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

#ifndef __CONNMAN_WAKEUP_TIMER_H
#define __CONNMAN_WAKEUP_TIMER_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

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

int connman_wakeup_timer_register(struct connman_wakeup_timer *wakeup_timer);
void connman_wakeup_timer_unregister(struct connman_wakeup_timer *t);

int connman_wakeup_timer(gint priority,
				guint interval,
				GSourceFunc function,
				gpointer data,
				GDestroyNotify notify);
int connman_wakeup_timer_seconds(gint priority,
					guint interval,
					GSourceFunc function,
					gpointer data,
					GDestroyNotify notify);


#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_WAKEUP_TIMER_H */
