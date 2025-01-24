/*
 *  Connection Manager
 *
 *  Copyright (C) 2019 Jolla Ltd. All rights reserved.
 *  Contact: David Llewellyn-Jones <david.llewellyn-jones@jolla.com>
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
#include "vpn/vpn.h"

#include <errno.h>

#include <gutil_log.h>

/*==========================================================================*
 * Test driver 1
 *==========================================================================*/

static enum vpn_access test1_policy_check (const char *sender,
					  enum vpn_access_method method,
					  const char *arg)
{
	return VPN_ACCESS_ALLOW;
}

static const struct vpn_access_plugin test1_driver = {
	.name = "test1",
	.priority = VPN_ACCESS_PRIORITY_LOW,

	.vpn_policy_check = test1_policy_check
};

/*==========================================================================*
 * Test driver 2
 *==========================================================================*/

static enum vpn_access test2_policy_check (const char *sender,
					  enum vpn_access_method method,
					  const char *arg)
{
	return VPN_ACCESS_DENY;
}

static const struct vpn_access_plugin test2_driver = {
	.name = "test2",
	.priority = VPN_ACCESS_PRIORITY_DEFAULT,

	.vpn_policy_check = test2_policy_check
};

/*==========================================================================*
 * Test driver 3
 *==========================================================================*/

static enum vpn_access test3_policy_check (const char *sender,
					  enum vpn_access_method method,
					  const char *arg)
{
	return VPN_ACCESS_DONT_CARE;
}

static const struct vpn_access_plugin test3_driver = {
	.name = "test3",
	.priority = VPN_ACCESS_PRIORITY_HIGH,

	.vpn_policy_check = test3_policy_check
};

/*==========================================================================*
 * Tests
 *==========================================================================*/

static void test_access_policy_allow()
{
	g_assert(vpn_access_plugin_register(&test1_driver) == 0);

	g_assert(__vpn_access_policy_check("sender",
					   VPN_ACCESS_CONNECTION_GET_PROPERTIES,
					   "arg", TRUE));
	g_assert(__vpn_access_policy_check("sender",
					   VPN_ACCESS_MANAGER_CREATE,
					   "arg", TRUE));

	vpn_access_plugin_unregister(&test1_driver);
}

static void test_access_policy_deny()
{
	g_assert(vpn_access_plugin_register(&test2_driver) == 0);

	g_assert(!__vpn_access_policy_check("sender",
					    VPN_ACCESS_CONNECTION_SET_PROPERTY,
					    "arg", TRUE));
	g_assert(!__vpn_access_policy_check("sender",
					    VPN_ACCESS_MANAGER_GET_CONNECTIONS,
					    "arg", TRUE));

	vpn_access_plugin_unregister(&test2_driver);
}

static void test_access_policy_default()
{
	g_assert(vpn_access_plugin_register(&test3_driver) == 0);

	g_assert(__vpn_access_policy_check("sender",
					   VPN_ACCESS_CONNECTION_DISCONNECT,
					   "arg", TRUE));
	g_assert(!__vpn_access_policy_check("sender",
					    VPN_ACCESS_MANAGER_REGISTER_AGENT,
					    "arg", FALSE));

	vpn_access_plugin_unregister(&test3_driver);
}

static void test_access_policy_priority()
{
	g_assert(vpn_access_plugin_register(&test1_driver) == 0);
	g_assert(vpn_access_plugin_register(&test2_driver) == 0);
	g_assert(vpn_access_plugin_register(&test3_driver) == 0);

	g_assert(!__vpn_access_policy_check("sender",
					    VPN_ACCESS_CONNECTION_SET_PROPERTY,
					    "arg", TRUE));
	g_assert(!__vpn_access_policy_check("sender",
					    VPN_ACCESS_MANAGER_GET_CONNECTIONS,
					    "arg", TRUE));

	vpn_access_plugin_unregister(&test2_driver);

	g_assert(__vpn_access_policy_check("sender",
					   VPN_ACCESS_CONNECTION_SET_PROPERTY,
					   "arg", TRUE));
	g_assert(__vpn_access_policy_check("sender",
					   VPN_ACCESS_MANAGER_GET_CONNECTIONS,
					   "arg", TRUE));

	vpn_access_plugin_unregister(&test1_driver);

	g_assert(__vpn_access_policy_check("sender",
					   VPN_ACCESS_CONNECTION_SET_PROPERTY,
					   "arg", TRUE));
	g_assert(!__vpn_access_policy_check("sender",
					    VPN_ACCESS_MANAGER_GET_CONNECTIONS,
					    "arg", FALSE));

	vpn_access_plugin_unregister(&test3_driver);
}

#define PREFIX "/vpn_access/"

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	gutil_log_timestamp = FALSE;
	gutil_log_default.level = g_test_verbose() ?
		GLOG_LEVEL_VERBOSE : GLOG_LEVEL_NONE;
	__connman_log_init(argv[0], g_test_verbose() ? "*" : NULL,
			FALSE, FALSE, "connman", CONNMAN_VERSION);

	g_test_add_func(PREFIX "access_policy_allow",
			test_access_policy_allow);
	g_test_add_func(PREFIX "access_policy_deny",
			test_access_policy_deny);
	g_test_add_func(PREFIX "access_policy_default",
			test_access_policy_default);
	g_test_add_func(PREFIX "access_policy_priority",
			test_access_policy_priority);
	return g_test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
