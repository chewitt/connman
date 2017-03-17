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

struct connman_access_service_policy_impl {
	int unused;
};

struct connman_access_tech_policy_impl {
	int unused;
};

static const struct connman_access_driver test_inval;

static struct connman_access_service_policy_impl *test_service_policy_create
		(const char *spec)
{
	return g_new0(struct connman_access_service_policy_impl, 1);
}

static void test_service_policy_free
		(struct connman_access_service_policy_impl *policy)
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

static enum connman_access test1_service_get_property
		(struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

static enum connman_access test1_service_set_property
		(struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

static enum connman_access test1_tech_set_property
		(struct connman_access_tech_policy_impl *policy,
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
	.service_get_property = test1_service_get_property,
	.service_set_property = test1_service_set_property,
	.tech_policy_create = test_tech_policy_create,
	.tech_policy_free = test_tech_policy_free,
	.tech_set_property = test1_tech_set_property
};

/*==========================================================================*
 * Test driver 2
 *==========================================================================*/

static enum connman_access test2_service_get_property
		(struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_DENY;
}

static enum connman_access test2_service_set_property
		(struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return CONNMAN_ACCESS_DENY;
}

static enum connman_access test2_tech_set_property
		(struct connman_access_tech_policy_impl *policy,
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
	.service_get_property = test2_service_get_property,
	.service_set_property = test2_service_set_property,
	.tech_policy_create = test_tech_policy_create,
	.tech_policy_free = test_tech_policy_free,
	.tech_set_property = test2_tech_set_property
};

/*==========================================================================*
 * Test driver 3
 *==========================================================================*/

static enum connman_access test3_service_get_property
		(struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return default_access;
}

static enum connman_access test3_service_set_property
		(struct connman_access_service_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return default_access;
}

static enum connman_access test3_tech_set_property
		(struct connman_access_tech_policy_impl *policy,
			const char *sender, const char *name,
			enum connman_access default_access)
{
	return default_access;
}

static const struct connman_access_driver test3_driver = {
	.name = "test3",
	.service_get_property = test3_service_get_property,
	.service_set_property = test3_service_set_property,
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

static struct connman_access_tech_policy_impl *test4_tech_policy_create
		(const char *spec)
{
	return NULL;
}

static const struct connman_access_driver test4_driver = {
	.name = "test4",
	.service_policy_create = test4_service_policy_create,
	.service_get_property = test3_service_get_property,
	.service_set_property = test3_service_set_property,
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

static struct connman_access_tech_policy_impl *test5_tech_policy_create
		(const char *spec)
{
	static struct connman_access_tech_policy_impl impl;
	return &impl;
}

static const struct connman_access_driver test5_driver = {
	.name = "test5",
	.service_policy_create = test5_service_policy_create,
	.tech_policy_create = test5_tech_policy_create
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
	const char* def1 = "test1:allow";
	const char* def2 = "test2:deny";

	g_assert(!connman_access_default_service_policy());
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(!g_strcmp0(def1, connman_access_default_service_policy()));

	g_assert(connman_access_driver_register(&test2_driver) == 0);
	g_assert(!g_strcmp0(def2, connman_access_default_service_policy()));

	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!connman_access_default_service_policy());

	connman_access_driver_unregister(&test3_driver);
	g_assert(!g_strcmp0(def2, connman_access_default_service_policy()));

	connman_access_driver_unregister(&test2_driver);
	g_assert(!g_strcmp0(def1, connman_access_default_service_policy()));

	connman_access_driver_unregister(&test1_driver);
	g_assert(!connman_access_default_service_policy());
}

static void test_access_service_policy()
{
	struct connman_access_service_policy *policy;

	g_assert(!connman_access_service_policy_create(NULL));
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test2_driver) == 0);

	/* test3_driver has no service_policy_create callback */
	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!connman_access_service_policy_create(NULL));
	connman_access_driver_unregister(&test3_driver);

	/* test4_driver has service_policy_create which returns NULL */
	g_assert(connman_access_driver_register(&test4_driver) == 0);
	g_assert(!connman_access_service_policy_create(NULL));
	connman_access_driver_unregister(&test4_driver);

	/*
	 * test5_driver has service_policy_create but no service_policy_free.
	 * It also has no service_get/set_property callbacks.
	 */
	g_assert(connman_access_driver_register(&test5_driver) == 0);
	policy = connman_access_service_policy_create(NULL);
	g_assert(policy);
	g_assert(connman_access_service_get_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_service_get_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	g_assert(connman_access_service_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_service_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	connman_access_service_policy_free(policy);
	connman_access_driver_unregister(&test5_driver);

	/* Invalid driver name */
	g_assert(!connman_access_service_policy_create("test:"));

	/* test1_driver allows everything */
	policy = connman_access_service_policy_create("test1:whatever");
	g_assert(connman_access_service_get_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_service_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	connman_access_service_policy_free(policy);

	/* test2_driver (last one, i.e. default) disallows everything */
	policy = connman_access_service_policy_create("test2");
	g_assert(connman_access_service_get_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	g_assert(connman_access_service_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	connman_access_service_policy_free(policy);

	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test2_driver);

	/* It's OK to delete NULL */
	connman_access_service_policy_free(NULL);

	/* or to pass NULL policy */
	g_assert(connman_access_service_get_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_service_get_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	g_assert(connman_access_service_set_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_service_set_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
}

static void test_access_tech_policy()
{
	struct connman_access_tech_policy *policy;

	g_assert(!connman_access_tech_policy_create(NULL));
	g_assert(connman_access_driver_register(&test1_driver) == 0);
	g_assert(connman_access_driver_register(&test2_driver) == 0);

	/* test3_driver has no tech_policy_create callback */
	g_assert(connman_access_driver_register(&test3_driver) == 0);
	g_assert(!connman_access_tech_policy_create(NULL));
	connman_access_driver_unregister(&test3_driver);

	/* test4_driver has tech_policy_create which returns NULL */
	g_assert(connman_access_driver_register(&test4_driver) == 0);
	g_assert(!connman_access_tech_policy_create(NULL));
	connman_access_driver_unregister(&test4_driver);

	/*
	 * test5_driver has tech_policy_create but no tech_policy_free.
	 * It also has no tech_get/set_property callbacks.
	 */
	g_assert(connman_access_driver_register(&test5_driver) == 0);
	policy = connman_access_tech_policy_create(NULL);
	g_assert(policy);
	g_assert(connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
	connman_access_tech_policy_free(policy);
	connman_access_driver_unregister(&test5_driver);

	/* Invalid driver name */
	g_assert(!connman_access_tech_policy_create("test:"));

	/* test1_driver allows everything */
	policy = connman_access_tech_policy_create("test1:whatever");
	g_assert(connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_ALLOW);
	connman_access_tech_policy_free(policy);

	/* test2_driver (last one, i.e. default) disallows everything */
	policy = connman_access_tech_policy_create("test2");
	g_assert(connman_access_tech_set_property(policy, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_DENY);
	connman_access_tech_policy_free(policy);

	connman_access_driver_unregister(&test1_driver);
	connman_access_driver_unregister(&test2_driver);

	/* It's OK to delete NULL */
	connman_access_tech_policy_free(NULL);

	/* or to pass NULL policy */
	g_assert(connman_access_tech_set_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_ALLOW) == CONNMAN_ACCESS_ALLOW);
	g_assert(connman_access_tech_set_property(NULL, NULL, NULL,
				CONNMAN_ACCESS_DENY) == CONNMAN_ACCESS_DENY);
}

#define PREFIX "/access/"

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func(PREFIX "register", test_access_register);
	g_test_add_func(PREFIX "default_policy", test_access_default_policy);
	g_test_add_func(PREFIX "service_policy", test_access_service_policy);
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
