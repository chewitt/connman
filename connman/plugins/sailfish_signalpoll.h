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

#ifndef __SAILFISH_SIGNALPOLL_H
#define __SAILFISH_SIGNALPOLL_H

#include <gsupplicant_types.h>

typedef struct signalpoll_priv SignalPollPriv;

typedef struct signalpoll {
	GObject object;
	SignalPollPriv* priv;
	guint average;
} SignalPoll;

typedef guint (*signalpoll_rssi_to_strength_func)(int rssi);
typedef void (*signalpoll_event_func)(struct signalpoll *poll, void *data);

struct signalpoll *signalpoll_new(GSupplicantInterface *iface,
					signalpoll_rssi_to_strength_func fn);
struct signalpoll *signalpoll_ref(struct signalpoll *poll);
void signalpoll_unref(struct signalpoll *poll);
gulong signalpoll_add_average_changed_handler(struct signalpoll *poll,
					signalpoll_event_func fn, void *data);

void signalpoll_remove_handler(struct signalpoll *poll, gulong id);

#endif /* __SAILFISH_SIGNALPOLL_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
