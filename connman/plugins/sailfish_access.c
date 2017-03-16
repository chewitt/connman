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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/access.h>

#include <dbusaccess_peer.h>
#include <dbusaccess_policy.h>

#include <gutil_idlepool.h>
#include <gutil_log.h>

struct connman_access_service_policy_impl {
	int ref_count;
	char *spec;
	DAPolicy *impl;
};

enum sailfish_service_access_action {
	SERVICE_ACCESS_GET_PROPERTY = 1,
	SERVICE_ACCESS_SET_PROPERTY
};

#define SERVICE_ACCESS_BUS DA_BUS_SYSTEM
#define DRIVER_NAME "sailfish"

/* We assume that these match each other an we don't have to convert */
G_STATIC_ASSERT((DA_ACCESS)CONNMAN_ACCESS_DENY == DA_ACCESS_DENY);
G_STATIC_ASSERT((DA_ACCESS)CONNMAN_ACCESS_ALLOW == DA_ACCESS_ALLOW);

static GHashTable *service_policies;
static GUtilIdlePool* service_policies_pool;

static const char *service_policy_default =
	DA_POLICY_VERSION ";group(privileged)=allow";
static const DA_ACTION service_policy_actions [] = {
        { "get", SERVICE_ACCESS_GET_PROPERTY, 1 },
        { "set", SERVICE_ACCESS_SET_PROPERTY, 1 },
        { NULL }
    };

static void sailfish_access_service_policy_free(
			struct connman_access_service_policy_impl *p)
{
	GASSERT(p->ref_count > 0);
	if (!--(p->ref_count)) {
		if (service_policies) {
			g_hash_table_remove(service_policies, p->spec);
		}
		g_free(p->spec);
		da_policy_unref(p->impl);
		g_slice_free(struct connman_access_service_policy_impl, p);
	}
}

static void sailfish_access_service_policy_unref(gpointer data)
{
	sailfish_access_service_policy_free(data);
}

static struct connman_access_service_policy_impl *
		sailfish_access_service_policy_create(const char *spec)
{
	struct connman_access_service_policy_impl *p = NULL;

	if (!spec || !spec[0]) {
		/* Empty policy = use default */
		spec = service_policy_default;
	}

	if (service_policies) {
		p = g_hash_table_lookup(service_policies, spec);
	}

	if (p) {
		/* Re-using the existing policy */
		p->ref_count++;
	} else {
		/* Parse the policy string */
		DAPolicy *impl = da_policy_new_full(spec,
						service_policy_actions);

		if (impl) {
			/* String is usable */
			p = g_slice_new0(struct
				connman_access_service_policy_impl);

			p->ref_count = 1;
			p->impl = impl;
			p->spec = g_strdup(spec);
			if (service_policies) {
				g_hash_table_replace(service_policies,
								p->spec, p);
			}

			/*
			 * It's quite common that identical policies
			 * are being created in a loop and immediately
			 * get freed without even being used. Adding an
			 * extra reference to the idle pool saves us from
			 * having to actually allocate a bunch of identical
			 * objects.
			 */
			if (service_policies_pool) {
				p->ref_count++;
				gutil_idle_pool_add(service_policies_pool, p,
					sailfish_access_service_policy_unref);
			}
		} else {
			DBG("invalid spec \"%s\"", spec);
		}
	}

	return p;
}

static enum connman_access sailfish_access_service_check(
	struct connman_access_service_policy_impl *policy,
	const char *sender, enum sailfish_service_access_action action,
	const char *name, enum connman_access default_access)
{
	/* Don't unref this one: */
	DAPeer* peer = da_peer_get(SERVICE_ACCESS_BUS, sender);

	return peer ? (enum connman_access)da_policy_check(policy->impl,
		&peer->cred, action, name, (DA_ACCESS)default_access) :
		default_access;
}

static enum connman_access sailfish_access_service_get_property(
			struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return sailfish_access_service_check(policy, sender,
			SERVICE_ACCESS_GET_PROPERTY, name, default_access);
}

static enum connman_access sailfish_access_service_set_property(
			struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return sailfish_access_service_check(policy, sender,
			SERVICE_ACCESS_SET_PROPERTY, name, default_access);
}

static const struct connman_access_driver sailfish_connman_access_driver = {
	.name                  = DRIVER_NAME,
	.service_policy_create = sailfish_access_service_policy_create,
	.service_policy_free   = sailfish_access_service_policy_free,
	.service_get_property  = sailfish_access_service_get_property,
	.service_set_property  = sailfish_access_service_set_property
};

static int sailfish_access_init()
{
	int ret;
	DBG("");

	ret = connman_access_driver_register(&sailfish_connman_access_driver);
	if (ret == 0) {
		service_policies = g_hash_table_new(g_str_hash, g_str_equal);
		service_policies_pool = gutil_idle_pool_new();
	}
	return ret;
}

static void sailfish_access_exit()
{
	DBG("");
	connman_access_driver_unregister(&sailfish_connman_access_driver);
	da_peer_flush(SERVICE_ACCESS_BUS, NULL);
	gutil_idle_pool_unref(service_policies_pool);
	service_policies_pool = NULL;
	if (service_policies) {
		g_hash_table_destroy(service_policies);
		service_policies = NULL;
	}
}

CONNMAN_PLUGIN_DEFINE(sailfish_access, "Sailfish access control", VERSION,
			CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			sailfish_access_init, sailfish_access_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
