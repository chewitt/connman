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

#include "src/connman.h"

#include <errno.h>

#include <dbusaccess_peer.h>
#include <dbusaccess_policy.h>
#include <dbusaccess_system.h>

#include <gutil_idlepool.h>
#include <gutil_log.h>

#define DRIVER "sailfish"
#define SPEC_BAD "bad"
#define SPEC_DENY DA_POLICY_VERSION ";*=deny"
#define SPEC_ALLOW DA_POLICY_VERSION ";*=allow"
#define SPEC_DENY_CLEAR DA_POLICY_VERSION ";*=allow;ClearProperty(*)=deny"

static GUtilIdlePool* peer_pool;

extern struct connman_plugin_desc __connman_builtin_sailfish_access;

/*==========================================================================*
 * Stubs
 *==========================================================================*/

DAPeer* da_peer_get(DA_BUS bus, const char* name)
{
	if (name) {
		gsize len = strlen(name);
		DAPeer *peer = g_malloc0(sizeof(DAPeer) + len + 1);
		char *buf = (char*)(peer + 1);
		strcpy(buf, name);
		peer->name = buf;
		gutil_idle_pool_add(peer_pool, peer, g_free);
		if (strcmp(name, "root")) {
			peer->cred.euid = 1;
			peer->cred.egid = 1;
		}
		return peer;
	} else {
		return NULL;
	}
}

void da_peer_flush(DA_BUS bus, const char* name)
{
	gutil_idle_pool_drain(peer_pool);
}

/*
 * The build environment doesn't necessarily have these users and groups.
 * And yet, sailfish access plugin depends on those.
 */

int da_system_uid(const char* user)
{
	if (!g_strcmp0(user, "nemo")) {
		return 100000;
	} else {
		return -1;
	}
}

int da_system_gid(const char* group)
{
	if (!g_strcmp0(group, "privileged")) {
		return 996;
	} else {
		return -1;
	}
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
	g_assert(!__connman_access_service_policy_create(DRIVER ":" SPEC_BAD));
	g_assert(!__connman_access_tech_policy_create(DRIVER ":" SPEC_BAD));
	g_assert(!__connman_access_manager_policy_create(DRIVER ":" SPEC_BAD));
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_default()
{
	struct connman_access_service_policy *sp;
	struct connman_access_manager_policy *mp;
	struct connman_access_tech_policy *tp;

	g_assert(__connman_builtin_sailfish_access.init() == 0);

	sp = __connman_access_service_policy_create(NULL);
	mp = __connman_access_manager_policy_create(NULL);
	tp = __connman_access_tech_policy_create(NULL);
	g_assert(sp);
	g_assert(mp);
	g_assert(tp);
	g_assert(__connman_access_is_default_service_policy(sp));
	__connman_access_service_policy_free(sp);
	__connman_access_manager_policy_free(mp);
	__connman_access_tech_policy_free(tp);

	sp = __connman_access_service_policy_create("");
	mp = __connman_access_manager_policy_create("");
	tp = __connman_access_tech_policy_create("");
	g_assert(sp);
	g_assert(mp);
	g_assert(tp);
	g_assert(__connman_access_is_default_service_policy(sp));
	__connman_access_service_policy_free(sp);
	__connman_access_manager_policy_free(mp);
	__connman_access_tech_policy_free(tp);

	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_latefree()
{
	struct connman_access_service_policy *p;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	p = __connman_access_service_policy_create(NULL);
	g_assert(p);

	/*
	 * This is not right to call __connman_access_service_policy_free()
	 * after the plugin the been terminated but it will still work.
	 */
	__connman_builtin_sailfish_access.exit();
	__connman_access_service_policy_free(p);
}

static void test_sailfish_access_cache()
{
	struct connman_access_service_policy *p1;
	struct connman_access_service_policy *p2;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	p1 = __connman_access_service_policy_create(DRIVER);
	p2 = __connman_access_service_policy_create(DRIVER);
	g_assert(p1);
	g_assert(p2);
	/* The policy implementation is reused */
	__connman_access_service_policy_free(p1);
	__connman_access_service_policy_free(p2);
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_allow()
{
	struct connman_access_service_policy *sp;
	struct connman_access_manager_policy *mp;
	struct connman_access_tech_policy *tp;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	sp = __connman_access_service_policy_create(DRIVER ":" SPEC_ALLOW);
	mp = __connman_access_manager_policy_create(DRIVER ":" SPEC_ALLOW);
	tp = __connman_access_tech_policy_create(DRIVER ":" SPEC_ALLOW);
	g_assert(sp);
	g_assert(mp);
	g_assert(tp);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_GET_PROPERTY, "foo", "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_SET_PROPERTY, "foo", NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_manager_policy_check(mp,
			CONNMAN_ACCESS_MANAGER_GET_PROPERTY, "foo", "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_manager_policy_check(mp,
			CONNMAN_ACCESS_MANAGER_SET_PROPERTY, "foo", NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_tech_set_property(tp, "foo", "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_tech_set_property(tp, "foo", NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	__connman_access_service_policy_free(sp);
	__connman_access_manager_policy_free(mp);
	__connman_access_tech_policy_free(tp);
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_deny()
{
	struct connman_access_service_policy *sp;
	struct connman_access_manager_policy *mp;
	struct connman_access_tech_policy *tp;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	sp = __connman_access_service_policy_create(DRIVER ":" SPEC_DENY);
	mp = __connman_access_manager_policy_create(DRIVER ":" SPEC_DENY);
	tp = __connman_access_tech_policy_create(DRIVER ":" SPEC_DENY);
	g_assert(sp);
	g_assert(mp);
	g_assert(tp);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_GET_PROPERTY, "foo", "x",
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_SET_PROPERTY, "foo", NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_manager_policy_check(mp,
			CONNMAN_ACCESS_MANAGER_GET_PROPERTY, "foo", "x",
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_manager_policy_check(mp,
			CONNMAN_ACCESS_MANAGER_SET_PROPERTY, "foo", NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_tech_set_property(tp, "foo", "x",
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_tech_set_property(tp, "foo", NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	__connman_access_service_policy_free(sp);
	__connman_access_manager_policy_free(mp);
	__connman_access_tech_policy_free(tp);
	__connman_builtin_sailfish_access.exit();
}

static void test_sailfish_access_deny_clear()
{
	struct connman_access_service_policy *sp;

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	sp = __connman_access_service_policy_create(DRIVER ":" SPEC_DENY_CLEAR);
	g_assert(sp);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_GET_PROPERTY, "foo", "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_SET_PROPERTY, "foo", "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_CLEAR_PROPERTY, "Error", "x",
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_CONNECT, NULL, "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_DISCONNECT, NULL, "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_REMOVE, NULL, "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(sp,
			CONNMAN_ACCESS_SERVICE_RESET_COUNTERS, NULL, "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	/* Even if the action is unknown, it's still allowed because
	 * everything is allowed, except for ClearProperty */
	g_assert(__connman_access_service_policy_check(sp, -1, NULL, "x",
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	__connman_access_service_policy_free(sp);
	__connman_builtin_sailfish_access.exit();
}

#define PREFIX "/sailfish_access/"

int main(int argc, char *argv[])
{
	int ret;
	peer_pool = gutil_idle_pool_new();
	g_test_init(&argc, &argv, NULL);
	gutil_log_timestamp = FALSE;
	gutil_log_default.level = g_test_verbose() ?
		GLOG_LEVEL_VERBOSE : GLOG_LEVEL_NONE;
	__connman_log_init(argv[0], g_test_verbose() ? "*" : NULL,
		FALSE, FALSE, "connman", CONNMAN_VERSION);

	g_test_add_func(PREFIX "register", test_sailfish_access_register);
	g_test_add_func(PREFIX "badspec", test_sailfish_access_badspec);
	g_test_add_func(PREFIX "default", test_sailfish_access_default);
	g_test_add_func(PREFIX "latefree", test_sailfish_access_latefree);
	g_test_add_func(PREFIX "cache", test_sailfish_access_cache);
	g_test_add_func(PREFIX "allow", test_sailfish_access_allow);
	g_test_add_func(PREFIX "deny", test_sailfish_access_deny);
	g_test_add_func(PREFIX "deny_clear", test_sailfish_access_deny_clear);

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
