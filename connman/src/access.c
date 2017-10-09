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

#include "connman.h"

#include <errno.h>
#include <string.h>

struct connman_access_manager_policy {
	struct connman_access_manager_policy_impl *impl;
	const struct connman_access_driver *driver;
};

struct connman_access_service_policy {
	struct connman_access_service_policy_impl *impl;
	const struct connman_access_driver *driver;
};

struct connman_access_tech_policy {
	struct connman_access_tech_policy_impl *impl;
	const struct connman_access_driver *driver;
};

#define DRIVER_NAME_SEPARATOR     ':'
#define DRIVER_NAME_SEPARATOR_STR ":"

static GSList *access_drivers;
static char *access_default_service_policy_str;
struct connman_access_service_policy *access_default_service_policy;

static const struct connman_access_driver *access_get_driver
			(const char *full_spec, const char **spec_part)
{
	const struct connman_access_driver *driver = NULL;
	const char *spec = full_spec;

	if (access_drivers) {
		if (spec && spec[0]) {
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
				DBG("no such access driver: %.*s", (int)len,
									name);
			}

		} else {
			driver = access_drivers->data;
		}
	}

	if (driver) {
		*spec_part = spec;
		return driver;
	} else {
		*spec_part = NULL;
		return NULL;
	}
}


/* Service */
static struct connman_access_service_policy *access_service_policy_new
		(const struct connman_access_driver *driver, const char *spec)
{
	if (driver && driver->service_policy_create) {
		struct connman_access_service_policy_impl *impl =
			driver->service_policy_create(spec);

		if (impl) {
			struct connman_access_service_policy *p;

			p = g_slice_new(struct connman_access_service_policy);
			p->impl = impl;
			p->driver = driver;
			return p;
		}
	}
	return NULL;
}

static void access_driver_update_default_service_policy(void)
{
	g_free(access_default_service_policy_str);
	access_default_service_policy_str = NULL;

	__connman_access_service_policy_free(access_default_service_policy);
	access_default_service_policy = NULL;

	if (access_drivers) {
		/* Default driver: */
		const struct connman_access_driver *driver =
			access_drivers->data;

		if (driver->default_service_policy) {
			access_default_service_policy_str =
				g_strconcat(driver->name,
					DRIVER_NAME_SEPARATOR_STR,
					driver->default_service_policy,
					NULL);
			access_default_service_policy =
				access_service_policy_new(driver,
					driver->default_service_policy);
			DBG("\"%s\"", access_default_service_policy_str);
			return;
		}
	}

	DBG("no default service policy");
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
	access_driver_update_default_service_policy();
	return 0;
}

void connman_access_driver_unregister(const struct connman_access_driver *drv)
{
	if (g_slist_find(access_drivers, drv)) {
		DBG("\"%s\"", drv->name);
		access_drivers = g_slist_remove(access_drivers, drv);
		access_driver_update_default_service_policy();
	}
}

const char *__connman_access_default_service_policy_str(void)
{
	return access_default_service_policy_str;
}

bool __connman_access_is_default_service_policy
			(struct connman_access_service_policy *policy)
{
	return __connman_access_service_policy_equal(policy,
					access_default_service_policy);
}

struct connman_access_service_policy *__connman_access_service_policy_create
							(const char *spec)
{
	/*
	 * NB: access_service_policy_new() gets the spec updated by
	 * connman_access_get_driver()
	 */
	const struct connman_access_driver *driver =
		access_get_driver(spec, &spec);

       return access_service_policy_new(driver, spec);
}

void __connman_access_service_policy_free
				(struct connman_access_service_policy *p)
{
	if (p) {
		if (p->driver->service_policy_free)
			p->driver->service_policy_free(p->impl);

		g_slice_free(struct connman_access_service_policy, p);
	}
}

bool __connman_access_service_policy_equal
			(const struct connman_access_service_policy *p1,
				const struct connman_access_service_policy *p2)
{
	if (p1 == p2) {
		return TRUE;
	} else if (!p1 || !p2) {
		return FALSE;
	} else if (p1->driver != p2->driver) {
		return FALSE;
	} else {
		const struct connman_access_driver *driver = p1->driver;

		return driver->service_policy_equal &&
			driver->service_policy_equal(p1->impl, p2->impl);
	}
}

enum connman_access __connman_access_service_policy_check
		(const struct connman_access_service_policy *p,
			enum connman_access_service_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	if (p && p->driver->service_policy_check)
		return p->driver->service_policy_check(p->impl,
					method, arg, sender, default_access);

	return default_access;
}

/* Manager */
struct connman_access_manager_policy *__connman_access_manager_policy_create
							(const char *spec)
{
	struct connman_access_manager_policy *p = NULL;
	const struct connman_access_driver *driver =
		access_get_driver(spec, &spec);

	if (driver && driver->manager_policy_create) {
		struct connman_access_manager_policy_impl *impl =
			driver->manager_policy_create(spec);

		if (impl) {
			p = g_slice_new(struct connman_access_manager_policy);
			p->impl = impl;
			p->driver = driver;
		}
	}

	return p;
}

void __connman_access_manager_policy_free
				(struct connman_access_manager_policy *p)
{
	if (p) {
		if (p->driver->manager_policy_free)
			p->driver->manager_policy_free(p->impl);

		g_slice_free(struct connman_access_manager_policy, p);
	}
}

enum connman_access __connman_access_manager_policy_check
		(const struct connman_access_manager_policy *p,
			enum connman_access_manager_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	if (p && p->driver->manager_policy_check)
		return p->driver->manager_policy_check(p->impl,
					method, arg, sender, default_access);

	return default_access;
}

/* Technology */
struct connman_access_tech_policy *__connman_access_tech_policy_create
							(const char *spec)
{
	struct connman_access_tech_policy *p = NULL;
	const struct connman_access_driver *driver =
		access_get_driver(spec, &spec);

	if (driver && driver->tech_policy_create) {
		struct connman_access_tech_policy_impl *impl =
			driver->tech_policy_create(spec);

		if (impl) {
			p = g_slice_new(struct connman_access_tech_policy);
			p->impl = impl;
			p->driver = driver;
		}
	}

	return p;
}

void __connman_access_tech_policy_free(struct connman_access_tech_policy *p)
{
	if (p) {
		if (p->driver->tech_policy_free)
			p->driver->tech_policy_free(p->impl);

		g_slice_free(struct connman_access_tech_policy, p);
	}
}

enum connman_access __connman_access_tech_set_property
		(const struct connman_access_tech_policy *p, const char *name,
			const char *sender, enum connman_access default_access)
{
	if (p && p->driver->tech_set_property)
		return p->driver->tech_set_property(p->impl, name, sender,
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
