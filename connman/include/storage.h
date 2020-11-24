/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_STORAGE_H
#define __CONNMAN_STORAGE_H

#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

gchar **connman_storage_get_services();
GKeyFile *connman_storage_load_service(const char *service_id);

const char *connman_storage_dir(void);
const char *connman_storage_vpn_dir(void);
const char *connman_storage_user_dir(void);
const char *connman_storage_user_vpn_dir(void);
const char *connman_storage_dir_for(const char *service_id);

void connman_storage_update_finalize_cb(
				void (*cb) (uid_t uid, void *user_data),
				void *user_data);
bool connman_storage_user_change_in_progress();

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_STORAGE_H */
