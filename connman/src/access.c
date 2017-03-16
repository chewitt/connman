/*
 *  Connection Manager
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
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

#include <connman/access.h>
#include <connman/log.h>

#include <errno.h>
#include <string.h>

struct connman_access_service_policy {
	struct connman_access_service_policy_impl *impl;
	const struct connman_access_driver *driver;
};

#define DRIVER_NAME_SEPARATOR     ':'
#define DRIVER_NAME_SEPARATOR_STR ":"

static GSList *access_drivers;
static char *access_default_service_policy;

static void connman_access_driver_update_default_service_policy()
{
	g_free(access_default_service_policy);
	access_default_service_policy = NULL;

	if (access_drivers) {
		const struct connman_access_driver *default_driver =
			access_drivers->data;

		if (default_driver->default_service_policy) {
			access_default_service_policy =
				g_strconcat(default_driver->name,
					DRIVER_NAME_SEPARATOR_STR,
					default_driver->default_service_policy,
					NULL);
		}
	}
}

int connman_access_driver_register(const struct connman_access_driver *drv)
{
	if (!drv || !drv->name)
		return -EINVAL;

	if (g_slist_find(access_drivers, drv))
		return -EALREADY;

	/*
	 * If there were multiple drivers we would have to sort them somehow.
	 * For now let the last one to become the default.
	 */
	DBG("\"%s\"", drv->name);
	access_drivers = g_slist_prepend(access_drivers, (void*)drv);
	connman_access_driver_update_default_service_policy();
	return 0;
}

void connman_access_driver_unregister(const struct connman_access_driver *drv)
{
	if (g_slist_find(access_drivers, drv)) {
		DBG("\"%s\"", drv->name);
		access_drivers = g_slist_remove(access_drivers, drv);
		connman_access_driver_update_default_service_policy();
	}
}

const char *connman_access_default_service_policy()
{
	return access_default_service_policy;
}

struct connman_access_service_policy *connman_access_service_policy_create(
							const char *spec)
{
	const struct connman_access_driver *driver = NULL;
	struct connman_access_service_policy *p = NULL;

	if (access_drivers) {
		if (spec) {
			/*
			 * The policy spec starts with the driver name
			 * followed by :
			 */
			GSList *l = access_drivers;
			const char *name = spec;
			const char *sep = strchr(spec, DRIVER_NAME_SEPARATOR);
			gsize len;

			if (sep) {
				/* Skip the separator */
				len = sep - spec;
				spec = sep + 1;
			} else {
				/* Default policy of the specified driver */
				len = strlen(spec);
				spec = NULL;
			}

			while (l) {
				const struct connman_access_driver *d =
								l->data;

				if (!strncmp(d->name, name, len) &&
							!d->name[len]) {
					driver = d;
					break;
				}
				l = l->next;
			}

			if (!driver) {
				DBG("no such access driver: %.*s", len, name);
			}

		} else {
			driver = access_drivers->data;
		}
	}

	if (driver && driver->service_policy_create) {
		struct connman_access_service_policy_impl *impl =
			driver->service_policy_create(spec);

		if (impl) {
			p = g_slice_new(struct connman_access_service_policy);
			p->impl = impl;
			p->driver = driver;
		}
	}

	return p;
}

void connman_access_service_policy_free(
			struct connman_access_service_policy *p)
{
	if (p) {
		if (p->driver->service_policy_free)
			p->driver->service_policy_free(p->impl);

		g_slice_free(struct connman_access_service_policy, p);
	}
}

enum connman_access connman_access_service_get_property(
		struct connman_access_service_policy *p, const char *sender,
		const char *name, enum connman_access default_access)
{
	if (p && p->driver->service_get_property)
		return p->driver->service_get_property(p->impl, sender, name,
							default_access);

	return default_access;
}

enum connman_access connman_access_service_set_property(
		struct connman_access_service_policy *p, const char *sender,
		const char *name, enum connman_access default_access)
{
	if (p && p->driver->service_set_property)
		return p->driver->service_set_property(p->impl, sender, name,
							default_access);

	return default_access;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
