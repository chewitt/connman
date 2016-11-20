/*
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
 */

#include <errno.h>

#include "wakeup_timer.h"

static const struct connman_wakeup_timer *timer = NULL;

int connman_wakeup_timer_register(const struct connman_wakeup_timer *t)
{
	if (!t)
		return -EINVAL;

	if (timer)
		return -EALREADY;

	timer = t;

	return 0;
}

void connman_wakeup_timer_unregister(const struct connman_wakeup_timer *t)
{
	if (timer && t && g_strcmp0(timer->name, t->name) == 0)
		timer = NULL;
}

guint connman_wakeup_timer_add(guint interval,
				GSourceFunc function,
				gpointer data)
{
	return connman_wakeup_timer_add_full(G_PRIORITY_DEFAULT,
					interval, function, data, NULL);
}

guint connman_wakeup_timer_add_full(gint priority,
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

guint connman_wakeup_timer_add_seconds(guint interval,
					GSourceFunc function,
					gpointer data)
{
	return connman_wakeup_timer_add_seconds_full(G_PRIORITY_DEFAULT,
					interval, function, data, NULL);
}

guint connman_wakeup_timer_add_seconds_full(gint priority,
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
