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

#include <gutil_log.h>

struct connman_access_service_policy_impl {
	char *spec;
};

struct connman_access_manager_policy_impl {
	int unused;
};

struct connman_access_tech_policy_impl {
	int unused;
};

static const struct connman_access_driver test_inval;

static struct connman_access_service_policy_impl *test_service_policy_create
		(const char *spec)
{
	struct connman_access_service_policy_impl *impl =
		g_new0(struct connman_access_service_policy_impl, 1);

	impl->spec = g_strdup(spec);
	return impl;
}

static void test_service_policy_free
		(struct connman_access_service_policy_impl *policy)
{
	g_free(policy->spec);
	g_free(policy);
}

static bool test_service_policy_equal
		(const struct connman_access_service_policy_impl *p1,
			 const struct connman_access_service_policy_impl *p2)
{
	return !g_strcmp0(p1->spec, p2->spec);
}

static struct connman_access_manager_policy_impl *test_manager_policy_create
		(const char *spec)
{
	return g_new0(struct connman_access_manager_policy_impl, 1);
}

static void test_manager_policy_free
		(struct connman_access_manager_policy_impl *policy)
{
	g_free(policy);
}

static struct connman_access_tech_policy_impl *test_tech_policy_create
		(const char *spec)
{
	return g_new0(struct connman_access_tech_policy_impl, 1);
}

static void test_tech_policy_free
		(struct connman_access_tech_policy_impl *policy)
{
	g_free(policy);
}

/*==========================================================================*
 * Test driver 1
 *==========================================================================*/

static enum connman_access test1_service_policy_check
		(const struct connman_access_service_policy_impl *policy,
			enum connman_access_service_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

static enum connman_access test1_manager_policy_check
		(const struct connman_access_manager_policy_impl *policy,
			enum connman_access_manager_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

static enum connman_access test1_tech_set_property
		(const struct connman_access_tech_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

static const struct connman_access_driver test1_driver = {
	.name = "test1",
	.default_service_policy = "allow",
	.service_policy_create = test_service_policy_create,
	.service_policy_free = test_service_policy_free,
	.service_policy_equal = test_service_policy_equal,
	.service_policy_check = test1_service_policy_check,
	.manager_policy_create = test_manager_policy_create,
	.manager_policy_free = test_manager_policy_free,
	.manager_policy_check = test1_manager_policy_check,
	.tech_policy_create = test_tech_policy_create,
	.tech_policy_free = test_tech_policy_free,
	.tech_set_property = test1_tech_set_property
};

/*==========================================================================*
 * Test driver 2
 *==========================================================================*/

static enum connman_access test2_service_policy_check
		(const struct connman_access_service_policy_impl *policy,
			enum connman_access_service_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_DENY;
}

static enum connman_access test2_manager_policy_check
		(const struct connman_access_manager_policy_impl *policy,
			enum connman_access_manager_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_DENY;
}

static enum connman_access test2_tech_set_property
		(const struct connman_access_tech_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_DENY;
}

static const struct connman_access_driver test2_driver = {
	.name = "test2",
	.default_service_policy = "deny",
	.service_policy_create = test_service_policy_create,
	.service_policy_free = test_service_policy_free,
	.service_policy_equal = test_service_policy_equal,
	.service_policy_check = test2_service_policy_check,
	.manager_policy_create = test_manager_policy_create,
	.manager_policy_free = test_manager_policy_free,
	.manager_policy_check = test2_manager_policy_check,
	.tech_policy_create = test_tech_policy_create,
	.tech_policy_free = test_tech_policy_free,
	.tech_set_property = test2_tech_set_property
};

/*==========================================================================*
 * Test driver 3
 *==========================================================================*/

static enum connman_access test3_service_policy_check
		(const struct connman_access_service_policy_impl *policy,
			enum connman_access_service_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	return default_access;
}

static enum connman_access test3_manager_policy_check
		(const struct connman_access_manager_policy_impl *policy,
			enum connman_access_manager_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access)
{
	return default_access;
}

static enum connman_access test3_tech_set_property
		(const struct connman_access_tech_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return default_access;
}

static const struct connman_access_driver test3_driver = {
	.name = "test3",
	.service_policy_check = test3_service_policy_check,
	.manager_policy_check = test3_manager_policy_check,
	.tech_set_property = test3_tech_set_property
};

/*==========================================================================*
 * Test driver 4
 *==========================================================================*/

static struct connman_access_service_policy_impl *test4_service_policy_create
		(const char *spec)
{
	return NULL;
}

static struct connman_access_manager_policy_impl *test4_manager_policy_create
		(const char *spec)
{
	return NULL;
}

static struct connman_access_tech_policy_impl *test4_tech_policy_create
		(const char *spec)
{
	return NULL;
}

static const struct connman_access_driver test4_driver = {
	.name = "test4",
	.service_policy_create = test4_service_policy_create,
	.service_policy_check = test3_service_policy_check,
	.manager_policy_create = test4_manager_policy_create,
	.tech_policy_create = test4_tech_policy_create,
	.tech_set_property = test3_tech_set_property
};

/*==========================================================================*
 * Test driver 5
 *==========================================================================*/

static struct connman_access_service_policy_impl *test5_service_policy_create
		(const char *spec)
{
	static struct connman_access_service_policy_impl impl;
	return &impl;
}

static struct connman_access_manager_policy_impl *test5_manager_policy_create
		(const char *spec)
{
	static struct connman_access_manager_policy_impl impl;
	return &impl;
}

static struct connman_access_tech_policy_impl *test5_tech_policy_create
		(const char *spec)
{
	static struct connman_access_tech_policy_impl impl;
	return &impl;
}

static const struct connman_access_driver test5_driver = {
	.name = "test5",
	.service_policy_create = test5_service_policy_create,
	.manager_policy_create = test5_manager_policy_create,
	.tech_policy_create = test5_tech_policy_create
};

/*==========================================================================*
 * Test driver 6
 *==========================================================================*/

static const struct connman_access_driver test6_driver = {
	.name = "test6",
	.service_policy_create = test_service_policy_create,
	.service_policy_free = test_service_policy_free
};

/*==========================================================================*
 * Tests
 *==========================================================================*/

static void test_access_register()
{
	g_assert(connman_access_driver_register(NULL) == -EINVAL);
	g_assert(connman_access_driver_register(&test_inval) == -EINVAL);
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test1_driver) == -EALREADY);
	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(NULL);
}

static void test_access_default_policy()
{
	const char* s1 = "test1:allow";
	const char* s2 = "test2:deny";

	struct connman_access_service_policy *p1;
	struct connman_access_service_policy *p2;

	g_assert(!__connman_access_default_service_policy_str());
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(!g_strcmp0(s1,__connman_access_default_service_policy_str()));

	p1 = __connman_access_service_policy_create(s1);
	g_assert(__connman_access_is_default_service_policy(p1));

	g_assert(connman_access_driver_register(&test2_driver) == 0);
	g_assert(!g_strcmp0(s2,__connman_access_default_service_policy_str()));

	p2 = __connman_access_service_policy_create(s2);
	g_assert(!__connman_access_is_default_service_policy(p1));
	g_assert(__connman_access_is_default_service_policy(p2));

	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!__connman_access_default_service_policy_str());
	g_assert(!__connman_access_is_default_service_policy(p1));
	g_assert(!__connman_access_is_default_service_policy(p2));

	__connman_access_service_policy_free(p1);
	__connman_access_service_policy_free(p2);

	connman_access_driver_unregister(&test3_driver);
	g_assert(!g_strcmp0(s2,__connman_access_default_service_policy_str()));

	connman_access_driver_unregister(&test2_driver);
	g_assert(!g_strcmp0(s1,__connman_access_default_service_policy_str()));

	connman_access_driver_unregister(&test1_driver);
	g_assert(!__connman_access_default_service_policy_str());
}

static void test_access_service_policy()
{
	struct connman_access_service_policy *policy;

	g_assert(!__connman_access_service_policy_create(NULL));
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test2_driver) == 0);

	/* test3_driver has no service_policy_create callback */
	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!__connman_access_service_policy_create(NULL));
	connman_access_driver_unregister(&test3_driver);

	/* test4_driver has service_policy_create which returns NULL */
	g_assert(connman_access_driver_register(&test4_driver) == 0);
	g_assert(!__connman_access_service_policy_create(NULL));
	connman_access_driver_unregister(&test4_driver);

	/*
	 * test5_driver has service_policy_create but no service_policy_free.
	 * It also has no service_get/set_property callbacks.
	 */
	g_assert(connman_access_driver_register(&test5_driver) == 0);
	policy = __connman_access_service_policy_create(NULL);
	g_assert(policy);
	g_assert(__connman_access_service_policy_check(policy,
			CONNMAN_ACCESS_SERVICE_GET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(policy,
			CONNMAN_ACCESS_SERVICE_GET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	__connman_access_service_policy_free(policy);
	connman_access_driver_unregister(&test5_driver);

	/* Invalid driver name */
	g_assert(!__connman_access_service_policy_create("test:"));

	/* test1_driver allows everything */
	policy = __connman_access_service_policy_create("test1:whatever");
	g_assert(__connman_access_service_policy_check(policy,
			CONNMAN_ACCESS_SERVICE_SET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	__connman_access_service_policy_free(policy);

	/* test2_driver (last one, i.e. default) disallows everything */
	policy = __connman_access_service_policy_create("test2");
	g_assert(__connman_access_service_policy_check(policy,
			CONNMAN_ACCESS_SERVICE_CLEAR_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	__connman_access_service_policy_free(policy);

	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test2_driver);

	/* It's OK to delete NULL */
	__connman_access_service_policy_free(NULL);

	/* or to pass NULL policy */
	g_assert(__connman_access_service_policy_check(NULL,
			CONNMAN_ACCESS_SERVICE_CONNECT, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(NULL,
			CONNMAN_ACCESS_SERVICE_DISCONNECT, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	g_assert(__connman_access_service_policy_check(NULL,
			CONNMAN_ACCESS_SERVICE_REMOVE, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_service_policy_check(NULL,
			CONNMAN_ACCESS_SERVICE_RESET_COUNTERS, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);

	/* Invalid policy */
	g_assert(__connman_access_service_policy_check(NULL,
			(enum connman_access_service_methods)-1, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
}

static void test_access_policy_equal()
{
	struct connman_access_service_policy *p1;
	struct connman_access_service_policy *p21;
	struct connman_access_service_policy *p22;
	struct connman_access_service_policy *p23;
	struct connman_access_service_policy *p61;
	struct connman_access_service_policy *p62;

	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test2_driver) == 0);
	g_assert(connman_access_driver_register(&test6_driver) == 0);

	p1 = __connman_access_service_policy_create("test1:foo");
	p21 = __connman_access_service_policy_create("test2:foo");
	p22 = __connman_access_service_policy_create("test2:foo");
	p23 = __connman_access_service_policy_create("test2:bar");
	p61 = __connman_access_service_policy_create("test6:");
	p62 = __connman_access_service_policy_create("test6:");

	g_assert(p1);
	g_assert(p21);
	g_assert(p22);
	g_assert(p23);
	g_assert(p61);
	g_assert(p62);

	g_assert(__connman_access_service_policy_equal(NULL, NULL));
	g_assert(__connman_access_service_policy_equal(p1, p1));
	g_assert(!__connman_access_service_policy_equal(p1, NULL));
	g_assert(!__connman_access_service_policy_equal(NULL, p1));
	g_assert(!__connman_access_service_policy_equal(p1, p21));
	g_assert(!__connman_access_service_policy_equal(p21, p23));
	g_assert(__connman_access_service_policy_equal(p21, p22));

	/* test6_driver has no service_policy_equal callback */
	g_assert(__connman_access_service_policy_equal(p61, p61));
	g_assert(!__connman_access_service_policy_equal(p61, p62));

	__connman_access_service_policy_free(p1);
	__connman_access_service_policy_free(p21);
	__connman_access_service_policy_free(p22);
	__connman_access_service_policy_free(p23);
	__connman_access_service_policy_free(p61);
	__connman_access_service_policy_free(p62);

	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test2_driver);
	connman_access_driver_unregister(&test6_driver);
}

static void test_access_manager_policy()
{
	struct connman_access_manager_policy *policy;

	g_assert(!__connman_access_manager_policy_create(NULL));
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test2_driver) == 0);

	/* test3_driver has no manager_policy_create callback */
	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!__connman_access_manager_policy_create(NULL));
	connman_access_driver_unregister(&test3_driver);

	/* test4_driver has manager_policy_create which returns NULL */
	g_assert(connman_access_driver_register(&test4_driver) == 0);
	g_assert(!__connman_access_manager_policy_create(NULL));
	connman_access_driver_unregister(&test4_driver);

	/*
	 * test5_driver has manager_policy_create but no manager_policy_free.
	 * It also has no manager_get/set_property callbacks.
	 */
	g_assert(connman_access_driver_register(&test5_driver) == 0);
	policy = __connman_access_manager_policy_create(NULL);
	g_assert(policy);
	g_assert(__connman_access_manager_policy_check(policy,
			CONNMAN_ACCESS_MANAGER_GET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_manager_policy_check(policy,
			CONNMAN_ACCESS_MANAGER_GET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	__connman_access_manager_policy_free(policy);
	connman_access_driver_unregister(&test5_driver);

	/* Invalid driver name */
	g_assert(!__connman_access_manager_policy_create("test:"));

	/* test1_driver allows everything */
	policy = __connman_access_manager_policy_create("test1:whatever");
	g_assert(__connman_access_manager_policy_check(policy,
			CONNMAN_ACCESS_MANAGER_GET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	__connman_access_manager_policy_free(policy);

	/* test2_driver (last one, i.e. default) disallows everything */
	policy = __connman_access_manager_policy_create("test2");
	g_assert(__connman_access_manager_policy_check(policy,
			CONNMAN_ACCESS_MANAGER_SET_PROPERTY, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	__connman_access_manager_policy_free(policy);

	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test2_driver);

	/* It's OK to delete NULL */
	__connman_access_manager_policy_free(NULL);

	/* or to pass NULL policy */
	g_assert(__connman_access_manager_policy_check(NULL,
			CONNMAN_ACCESS_MANAGER_CREATE_SERVICE, NULL, NULL,
			CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_manager_policy_check(NULL,
			CONNMAN_ACCESS_MANAGER_CREATE_SERVICE, NULL, NULL,
			CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
}

static void test_access_tech_policy()
{
	struct connman_access_tech_policy *policy;

	g_assert(!__connman_access_tech_policy_create(NULL));
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test2_driver) == 0);

	/* test3_driver has no tech_policy_create callback */
	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!__connman_access_tech_policy_create(NULL));
	connman_access_driver_unregister(&test3_driver);

	/* test4_driver has tech_policy_create which returns NULL */
	g_assert(connman_access_driver_register(&test4_driver) == 0);
	g_assert(!__connman_access_tech_policy_create(NULL));
	connman_access_driver_unregister(&test4_driver);

	/*
	 * test5_driver has tech_policy_create but no tech_policy_free.
	 * It also has no tech_get/set_property callbacks.
	 */
	g_assert(connman_access_driver_register(&test5_driver) == 0);
	policy = __connman_access_tech_policy_create(NULL);
	g_assert(policy);
	g_assert(__connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	__connman_access_tech_policy_free(policy);
	connman_access_driver_unregister(&test5_driver);

	/* Invalid driver name */
	g_assert(!__connman_access_tech_policy_create("test:"));

	/* test1_driver allows everything */
	policy = __connman_access_tech_policy_create("test1:whatever");
	g_assert(__connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	__connman_access_tech_policy_free(policy);

	/* test2_driver (last one, i.e. default) disallows everything */
	policy = __connman_access_tech_policy_create("test2");
	g_assert(__connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	__connman_access_tech_policy_free(policy);

	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test2_driver);

	/* It's OK to delete NULL */
	__connman_access_tech_policy_free(NULL);

	/* or to pass NULL policy */
	g_assert(__connman_access_tech_set_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(__connman_access_tech_set_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
}

#define PREFIX "/access/"

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	gutil_log_timestamp = FALSE;
	gutil_log_default.level = g_test_verbose() ?
		GLOG_LEVEL_VERBOSE : GLOG_LEVEL_NONE;
	__connman_log_init(argv[0], g_test_verbose() ? "*" : NULL,
			FALSE, FALSE, "connman", CONNMAN_VERSION);

	g_test_add_func(PREFIX "register", test_access_register);
	g_test_add_func(PREFIX "default_policy", test_access_default_policy);
	g_test_add_func(PREFIX "service_policy", test_access_service_policy);
	g_test_add_func(PREFIX "policy_equal", test_access_policy_equal);
	g_test_add_func(PREFIX "manager_policy", test_access_manager_policy);
	g_test_add_func(PREFIX "tech_policy", test_access_tech_policy);
	return g_test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
