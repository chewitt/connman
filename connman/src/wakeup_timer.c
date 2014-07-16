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

#include <errno.h>

#include "wakeup_timer.h"

static struct connman_wakeup_timer *timer = NULL;

int connman_wakeup_timer_register(struct connman_wakeup_timer *t)
{
	if (!t)
		return -EINVAL;

	if (timer)
		return -EALREADY;

	timer = t;

	return 0;
}

void connman_wakeup_timer_unregister(struct connman_wakeup_timer *t)
{
	if (timer && t && g_strcmp0(timer->name, t->name) == 0)
		timer = NULL;
}

int connman_wakeup_timer(gint priority,
				guint interval,
				GSourceFunc function,
				gpointer data,
				GDestroyNotify notify)
{
	if (!timer)
		return g_timeout_add_full(priority, interval, function,
						data, notify);
	else
		return (timer->timeout_add)(priority, interval, function, data,
						notify);
}

int connman_wakeup_timer_seconds(gint priority,
					guint interval,
					GSourceFunc function,
					gpointer data,
					GDestroyNotify notify)
{
	if (!timer)
		return g_timeout_add_seconds_full(priority, interval, function,
							data, notify);
	else
		return (timer->timeout_add_seconds)(priority, interval,
							function, data,	notify);
}
