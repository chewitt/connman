/*
 *  Connection Manager
 *
 *  Copyright (C) 2019-2020 Jolla Ltd. All rights reserved.
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

#include <dbusaccess_peer.h>
#include <dbusaccess_policy.h>
#include <dbusaccess_system.h>

#include <gutil_idlepool.h>
#include <gutil_log.h>

static GUtilIdlePool* peer_pool;

extern struct connman_plugin_desc __connman_builtin_sailfish_access;
extern const char *sailfish_access_config_file;

#define TMP_DIR_TEMPLATE "test-sailfish_access-XXXXXX"
#define ROOT_SENDER ":1.100"
#define PRIVILEGED_SENDER ":1.200"
#define NON_PRIVILEGED_SENDER ":1.300"
#define INVALID_SENDER ":1.400"

#define NEMO_UID (100000)
#define NEMO_GID (100000)
#define PRIVILEGED_GID (996)

/*==========================================================================*
 * Stubs
 *==========================================================================*/

DAPeer *da_peer_get(DA_BUS bus, const char *name)
{
	if (name && g_strcmp0(name, INVALID_SENDER)) {
		gsize len = strlen(name);
		DAPeer *peer = g_malloc0(sizeof(DAPeer) + len + 1);
		char *buf = (char*)(peer + 1);
		strcpy(buf, name);
		peer->name = buf;
		gutil_idle_pool_add(peer_pool, peer, g_free);
		if (!strcmp(name, PRIVILEGED_SENDER)) {
			peer->cred.euid = NEMO_UID;
			peer->cred.egid = PRIVILEGED_GID;
		} else if (strcmp(name, ROOT_SENDER)) {
			peer->cred.euid = NEMO_UID;
			peer->cred.egid = NEMO_GID;
		}
		return peer;
	} else {
		return NULL;
	}
}

void da_peer_flush(DA_BUS bus, const char *name)
{
	gutil_idle_pool_drain(peer_pool);
}

/*
 * The build environment doesn't necessarily have these users and groups.
 * And yet, sailfish access plugin depends on those.
 */

int da_system_uid(const char *user)
{
	if (!g_strcmp0(user, "nemo"))
		return NEMO_UID;
	else
		return -1;
}

int da_system_gid(const char *group)
{
	if (!g_strcmp0(group, "privileged"))
		return PRIVILEGED_GID;
	else
		return -1;
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

static void test_sailfish_access_default()
{
	const char *default_config_file = sailfish_access_config_file;

	sailfish_access_config_file = "/no such file";
	g_assert(__connman_builtin_sailfish_access.init() == 0);

	/* root and privileged are allowed to access properties */
	g_assert(__vpn_access_policy_check(ROOT_SENDER,
					   VPN_ACCESS_CONNECTION_GET_PROPERTIES,
					   "", TRUE));
	g_assert(__vpn_access_policy_check(PRIVILEGED_SENDER,
					   VPN_ACCESS_CONNECTION_GET_PROPERTIES,
					   "", TRUE));

	/* Non-privileged and unknown users are not */
	g_assert(!__vpn_access_policy_check(NON_PRIVILEGED_SENDER,
					   VPN_ACCESS_CONNECTION_GET_PROPERTIES,
					   "", TRUE));
	g_assert(!__vpn_access_policy_check(INVALID_SENDER,
					   VPN_ACCESS_CONNECTION_GET_PROPERTIES,
					   "", TRUE));

	/* Unknown methods are allowed */
	g_assert(__vpn_access_policy_check(NON_PRIVILEGED_SENDER,
					   VPN_ACCESS_METHOD_COUNT,
					   "", TRUE));

	__connman_builtin_sailfish_access.exit();

	/* Restore the defaults */
	sailfish_access_config_file = default_config_file;
}

struct test_config_data {
	gboolean allowed;
	const char *sender;
	enum vpn_access_method method;
	const char * arg;
	gboolean default_access;
	const char *config;
};

static const struct test_config_data config_tests [] = {
	{
		TRUE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_CONNECTION_GET_PROPERTIES,
		"", FALSE,
		"[net.connman.vpn.Connection]\n"
		"GetProperties = " DA_POLICY_VERSION "; * = allow \n"
	},{
		FALSE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_CONNECTION_GET_PROPERTIES,
		"", FALSE,
		"[net.connman.vpn.Connection]\n"
		"GetProperties = " DA_POLICY_VERSION "; * = allow \n"
		"=========" /* Invalid key file */
	},{
		FALSE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_CONNECTION_SET_PROPERTY,
		"", FALSE,
		"[Common]\n"
		"DefaultAccess = " DA_POLICY_VERSION "; * = allow \n"
		"[net.connman.vpn.Connection]\n"
		"SetProperty = " DA_POLICY_VERSION "; * = deny; "
		"group(privileged) = allow\n"
	},{
		TRUE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_CONNECTION_CLEAR_PROPERTY,
		"", TRUE,
		"[Common]\n"
		"DefaultAccess = " DA_POLICY_VERSION "; * = allow \n"
		"[net.connman.vpn.Connection]\n"
		"SetProperty = " DA_POLICY_VERSION "; * = deny; "
		"group(privileged) = allow \n"
	},{
		TRUE, PRIVILEGED_SENDER,
		VPN_ACCESS_CONNECTION_CONNECT,
		"", TRUE,
		"[Common]\n"
		"DefaultAccess = " DA_POLICY_VERSION "; * = deny \n"
		"[net.connman.vpn.Connection]\n"
		"Connect = " DA_POLICY_VERSION "; * = deny; "
		"group(privileged) = allow \n"
	},{
		TRUE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_CONNECTION_DISCONNECT,
		"", TRUE,
		"[Common]\n"
		"DefaultAccess = " DA_POLICY_VERSION "; * = allow \n"
		"[net.connman.vpn.Connection]\n"
		"* = invalid"
	},{
		FALSE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_MANAGER_CREATE,
		"", TRUE,
		"[Common]\n"
		"DefaultAccess = " DA_POLICY_VERSION "; * = allow \n"
		"[net.connman.vpn.Manager]\n"
		"* = " DA_POLICY_VERSION "; * = deny \n" /* <= Applied */
	},{
		TRUE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_MANAGER_REMOVE,
		"", TRUE,
		"[Common]\n" /* DefaultAccess gets applied */
		"DefaultAccess = " DA_POLICY_VERSION "; * = allow \n"
		"[net.connman.vpn.Connection]\n"
		"* = " DA_POLICY_VERSION "; * = deny \n"
	},{
		TRUE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_MANAGER_GET_CONNECTIONS,
		"", TRUE,
		"[net.connman.vpn.Manager]\n"
		"* = " DA_POLICY_VERSION "; * = allow \n" /* <= Applied */
		"GetConnections = invalid \n"
	},{
		FALSE, PRIVILEGED_SENDER,
		VPN_ACCESS_MANAGER_GET_CONNECTIONS,
		"", TRUE,
		"[net.connman.vpn.Manager]\n"
		"* = " DA_POLICY_VERSION "; * = allow \n"
		"GetConnections = " DA_POLICY_VERSION "; "
		"* = deny \n"  /* <= Applied */
	},{
		TRUE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_STORAGE_CHANGE_USER,
		"", TRUE,
		"[net.connman.vpn.Storage]\n"
		"* = " DA_POLICY_VERSION "; * = allow \n" /* <= Applied */
		"ChangeUser = invalid \n"
	},{
		FALSE, PRIVILEGED_SENDER,
		VPN_ACCESS_STORAGE_CHANGE_USER,
		"", TRUE,
		"[net.connman.vpn.Storage]\n"
		"* = " DA_POLICY_VERSION "; * = allow \n"
		"ChangeUser = " DA_POLICY_VERSION "; "
		"* = deny \n"  /* <= Applied */
	},{
		FALSE, NON_PRIVILEGED_SENDER,
		VPN_ACCESS_STORAGE_CHANGE_USER,
		"", FALSE,
		"[Common]\n"
		"DefaultAccess = " DA_POLICY_VERSION "; * = allow \n"
		"[net.connman.vpn.Storage]\n"
		"ChangeUser = " DA_POLICY_VERSION "; * = deny; "
		"group(privileged) = allow\n"
	}
};

static void test_config(gconstpointer test_data)
{
	const struct test_config_data *test = test_data;
	const char *default_config_file = sailfish_access_config_file;
	char *dir = g_dir_make_tmp(TMP_DIR_TEMPLATE, NULL);
	char *file = g_strconcat(dir, "/test.conf", NULL);

	/* Write temporary config file */
	sailfish_access_config_file = file;
	g_assert(g_file_set_contents(file, test->config, -1, NULL));

	g_assert(__connman_builtin_sailfish_access.init() == 0);
	g_assert(__vpn_access_policy_check(test->sender, test->method,
					   test->arg, test->default_access)
		 == test->allowed);
	__connman_builtin_sailfish_access.exit();

	/* Restore the defaults */
	sailfish_access_config_file = default_config_file;

	remove(file);
	remove(dir);

	g_free(file);
	g_free(dir);
}


#define PREFIX "/sailfish_vpn_access/"

int main(int argc, char *argv[])
{
	int i, ret;
	peer_pool = gutil_idle_pool_new();
	g_test_init(&argc, &argv, NULL);
	gutil_log_timestamp = FALSE;
	gutil_log_default.level = g_test_verbose() ?
		GLOG_LEVEL_VERBOSE : GLOG_LEVEL_NONE;
	__connman_log_init(argv[0], g_test_verbose() ? "*" : NULL,
		FALSE, FALSE, "connman", CONNMAN_VERSION);

	g_test_add_func(PREFIX "register", test_sailfish_access_register);
	g_test_add_func(PREFIX "default", test_sailfish_access_default);
	for (i = 0; i < G_N_ELEMENTS(config_tests); i++) {
		char* name = g_strdup_printf("%s/config/%d", PREFIX, i + 1);
		const struct test_config_data *test = config_tests + i;

		g_test_add_data_func(name, test, test_config);
		g_free(name);
	}
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
