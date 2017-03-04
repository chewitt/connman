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
#include <errno.h>

#include <dbusaccess_peer.h>
#include <dbusaccess_policy.h>
#include <gutil_idlepool.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"

#define DRIVER "sailfish"
#define SPEC_BAD "bad"
#define SPEC_DENY "deny"
#define SPEC_ALLOW "allow"

struct da_policy {
	int ref_count;
	gboolean allow;
};

static int policy_count;
static GUtilIdlePool* peer_pool;

extern struct connman_plugin_desc __connman_builtin_sailfish_access;

/*==========================================================================*
 * Stubs
 *==========================================================================*/

DAPolicy *da_policy_new_full(const char *spec, const DA_ACTION *actions)
{
	if (!g_strcmp0(spec, SPEC_BAD)) {
		return NULL;
	} else {
		DAPolicy *p = g_new0(DAPolicy, 1);
		p->ref_count = 1;
		p->allow = !g_strcmp0(spec, SPEC_ALLOW);
		policy_count++;
		return p;
	}
}

DAPolicy *da_policy_ref(DAPolicy *p)
{
	if (p) {
		g_atomic_int_inc(&p->ref_count);
	}
	return p;
}

void da_policy_unref(DAPolicy *p)
{
	if (p) {
		if (g_atomic_int_dec_and_test(&p->ref_count)) {
			policy_count--;
			g_free(p);
		}
	}
}

DA_ACCESS da_policy_check(DAPolicy *p, const DACred *cred, guint action,
				const char *arg, DA_ACCESS default_access)
{
	return p->allow ? DA_ACCESS_ALLOW : DA_ACCESS_DENY;
}

DAPeer* da_peer_get(DA_BUS bus, const char* name)
{
	if (name) {
		gsize len = strlen(name);
		DAPeer *peer = g_malloc0(sizeof(DAPeer) + len + 1);
		char *buf = (char*)(peer + 1);
		strcpy(buf, name);
		peer->name = buf;
		gutil_idle_pool_add(peer_pool, peer, g_free);
		return peer;
	} else {
		return NULL;
	}
}

void da_peer_flush(DA_BUS bus, const char* name)
{
	gutil_idle_pool_drain(peer_pool);
}

/*==========================================================================*
 * Tests
 *==========================================================================*/

static void test_sailfish_access_register()
{
	g_assert(__connman_builtin_sailfish_access.init() == 0);
	g_assert(__connman_builtin_sailfish_access.init() == -EALREADY);
	__connman_builtin_sailfish_access.exit();
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_badspec()
{
	g_assert(__connman_builtin_sailfish_access.init() == 0);
	g_assert(!connman_access_service_policy_create(DRIVER ":" SPEC_BAD));
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_latefree()
{
	struct connman_access_service_policy *p;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	p = connman_access_service_policy_create(NULL);
	g_assert(p);

	/*
	 * This is not right to call connman_access_service_policy_free()
	 * after the plugin the been terminated but it will still work.
	 */
	__connman_builtin_sailfish_access.exit();
	connman_access_service_policy_free(p);
}

static void test_sailfish_access_cache()
{
	struct connman_access_service_policy *p1;
	struct connman_access_service_policy *p2;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	p1 = connman_access_service_policy_create(DRIVER);
	p2 = connman_access_service_policy_create(DRIVER);
	g_assert(p1);
	g_assert(p2);
	/* The policy implementation is reused */
	g_assert(policy_count == 1);
	connman_access_service_policy_free(p1);
	connman_access_service_policy_free(p2);
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_allow()
{
	struct connman_access_service_policy *p;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	p = connman_access_service_policy_create(DRIVER ":" SPEC_ALLOW);
	g_assert(p);
	g_assert(connman_access_service_get_property(p, "x", "foo",
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_service_set_property(p, NULL, "foo",
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	connman_access_service_policy_free(p);
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_deny()
{
	struct connman_access_service_policy *p;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	p = connman_access_service_policy_create(DRIVER ":" SPEC_DENY);
	g_assert(p);
	g_assert(connman_access_service_get_property(p, "x", "foo",
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(connman_access_service_set_property(p, NULL, "foo",
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	connman_access_service_policy_free(p);
	__connman_builtin_sailfish_access.exit();
}

#define PREFIX "/sailfish_access/"

int main(int argc, char *argv[])
{
	int ret;
	peer_pool = gutil_idle_pool_new();
	g_test_init(&argc, &argv, NULL);
	g_test_add_func(PREFIX "register", test_sailfish_access_register);
	g_test_add_func(PREFIX "badspec", test_sailfish_access_badspec);
	g_test_add_func(PREFIX "latefree", test_sailfish_access_latefree);
	g_test_add_func(PREFIX "cache", test_sailfish_access_cache);
	g_test_add_func(PREFIX "allow", test_sailfish_access_allow);
	g_test_add_func(PREFIX "deny", test_sailfish_access_deny);
	ret = g_test_run();
	gutil_idle_pool_unref(peer_pool);
	return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
