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

#ifndef __CONNMAN_ACCESS_H
#define __CONNMAN_ACCESS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum connman_access {
	CONNMAN_ACCESS_DENY,
	CONNMAN_ACCESS_ALLOW
};

/* For convenience of the implementation, these should be non-zero */
enum connman_access_service_methods {
	CONNMAN_ACCESS_SERVICE_GET_PROPERTY = 1,
	CONNMAN_ACCESS_SERVICE_SET_PROPERTY,
	CONNMAN_ACCESS_SERVICE_CLEAR_PROPERTY,
	CONNMAN_ACCESS_SERVICE_CONNECT,
	CONNMAN_ACCESS_SERVICE_DISCONNECT,
	CONNMAN_ACCESS_SERVICE_REMOVE,
	CONNMAN_ACCESS_SERVICE_RESET_COUNTERS
};

enum connman_access_manager_methods {
	CONNMAN_ACCESS_MANAGER_GET_PROPERTY = 1,
	CONNMAN_ACCESS_MANAGER_SET_PROPERTY,
	CONNMAN_ACCESS_MANAGER_CREATE_SERVICE
};

struct connman_access_service_policy;
struct connman_access_service_policy_impl;
struct connman_access_tech_policy;
struct connman_access_tech_policy_impl;
struct connman_access_manager_policy;
struct connman_access_manager_policy_impl;

struct connman_access_driver {
	const char *name;
	const char *default_service_policy;

	/* Service */
	struct connman_access_service_policy_impl *(*service_policy_create)
		(const char *spec);
	void (*service_policy_free)
		(struct connman_access_service_policy_impl *policy);
	bool (*service_policy_equal)
		(const struct connman_access_service_policy_impl *p1,
			const struct connman_access_service_policy_impl *p2);
	enum connman_access (*service_policy_check)
		(const struct connman_access_service_policy_impl *policy,
			enum connman_access_service_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access);

	/* Manager */
	struct connman_access_manager_policy_impl *(*manager_policy_create)
		(const char *spec);
	void (*manager_policy_free)
		(struct connman_access_manager_policy_impl *policy);
	enum connman_access (*manager_policy_check)
		(const struct connman_access_manager_policy_impl *policy,
			enum connman_access_manager_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access);

	/* Technology */
	struct connman_access_tech_policy_impl *(*tech_policy_create)
		(const char *spec);
	void (*tech_policy_free)
		(struct connman_access_tech_policy_impl *policy);
	enum connman_access (*tech_set_property)
		(const struct connman_access_tech_policy_impl *policy,
			const char *name, const char *sender,
			enum connman_access default_access);
};

int connman_access_driver_register(const struct connman_access_driver *d);
void connman_access_driver_unregister(const struct connman_access_driver *d);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_ACCESS_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
