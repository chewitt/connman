/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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

#include <errno.h>
#include <string.h>

#include "connman.h"

int __connman_login_manager_init()
{
	if (!connman_setting_get_bool("EnableLoginManager"))
		return -EOPNOTSUPP;

#ifdef SYSTEMD
	int err;

	err = __systemd_login_init();
	if (err)
		connman_warn("cannot initialize systemd login manager (%s)",
					strerror(-err));

	return err;
#endif

	return 0;
}

void __connman_login_manager_cleanup()
{
	if (!connman_setting_get_bool("EnableLoginManager"))
		return;

#ifdef SYSTEMD
	__systemd_login_cleanup();
#endif
}
