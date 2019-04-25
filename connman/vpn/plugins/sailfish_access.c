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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <vpn/access.h>

#include <dbusaccess_peer.h>
#include <dbusaccess_policy.h>

#include <gutil_idlepool.h>
#include <gutil_log.h>

#define CONNMAN_BUS DA_BUS_SYSTEM
#define DRIVER_NAME "sailfish"
#define COMMON_GROUP "Common"
#define DEFAULT_POLICY "DefaultAccess"
#define DEFAULT_INTF_POLICY "*"

GPtrArray *active_policy;

const char *sailfish_access_config_file = "/etc/connman/vpn-dbus-access.conf";
static const char *default_access_policy = DA_POLICY_VERSION "; "
	"* = deny; "
	"group(privileged) = allow";

/*
 * Configuration is loaded from /etc/connman/vpn-dbus-access.conf
 * If configuration is missing, default access rules are used.
 * Syntax goes like this:
 *
 * [Common]
 * DefaultAccess = <default rules for all controlled interfaces/methods>
 *
 * [InterfaceX]
 * * = <default access rules for all methods in this interface>
 * MethodY = <access rule for this method>
 */

/* We assume that these match each other and we don't have to convert */
G_STATIC_ASSERT((DA_ACCESS)VPN_ACCESS_DENY == DA_ACCESS_DENY);
G_STATIC_ASSERT((DA_ACCESS)VPN_ACCESS_ALLOW == DA_ACCESS_ALLOW);

static void sailfish_access_policy_free(gpointer user_data)
{
	da_policy_unref((DAPolicy *)user_data);
}

static void sailfish_access_load_config_intf(GKeyFile *config,
					     DAPolicy *default_policy)
{
	int i;
	GPtrArray *default_policies = g_ptr_array_new_with_free_func(
				sailfish_access_policy_free);

	/* Load the default policy for each interface */
	for (i = 0; i < VPN_ACCESS_INTF_COUNT; i++) {
		DAPolicy *default_intf_policy = NULL;
		const char *group = vpn_access_intf_name(i);
		char *spec = g_key_file_get_string(config, group,
						   DEFAULT_INTF_POLICY, NULL);

		/* Parse the default policy for this interface */
		if (spec) {
			default_intf_policy = da_policy_new(spec);
			if (!default_intf_policy)
				DBG("Failed to parse default %s rule \"%s\"",
				    group, spec);

			g_free(spec);
		}

		if (!default_intf_policy)
			default_intf_policy = da_policy_ref(default_policy);

		g_ptr_array_add(default_policies, default_intf_policy);
	}

	/* Parse individual policies for each method */
	for (i = 0; i < VPN_ACCESS_METHOD_COUNT; i++) {
		DAPolicy *policy = NULL;
		const char *method = vpn_access_method_name(i);
		enum vpn_access_intf intf = vpn_access_intf_from_method(i);
		const char *group = vpn_access_intf_name(intf);
		char *spec = g_key_file_get_string(config, group, method, NULL);

		if (spec) {
			policy = da_policy_new(spec);
			if (!policy)
				DBG("Failed to parse %s.%s rule \"%s\"",
							group, method, spec);

			g_free(spec);
		}

		if (!policy)
			policy = da_policy_ref(g_ptr_array_index(
						       default_policies, intf));

		g_ptr_array_add(active_policy, policy);
	}

	g_ptr_array_free(default_policies, TRUE);
}

static void sailfish_access_load_config()
{
	GKeyFile *config = g_key_file_new();
	char *default_policy_spec;
	DAPolicy *default_policy;

	/*
	 * Try to load config file, in case of error just make sure
	 * that it config is empty.
	 */
	if (g_file_test(sailfish_access_config_file, G_FILE_TEST_IS_REGULAR)) {
		if (g_key_file_load_from_file(config,
					sailfish_access_config_file,
					G_KEY_FILE_NONE, NULL)) {
			DBG("Loading D-Bus access rules from %s",
						sailfish_access_config_file);
		} else {
			g_key_file_unref(config);
			config = g_key_file_new();
		}
	}

	default_policy_spec = g_key_file_get_string(config, COMMON_GROUP,
						DEFAULT_POLICY, NULL);
	default_policy = da_policy_new(default_policy_spec);

	if (!default_policy) {
		DBG("Failed to parse common default D-Bus policy \"%s\"",
		    default_policy_spec);
		default_policy = da_policy_new(default_access_policy);
		if (!default_policy)
			DBG("Failed to parse fallback default D-Bus policy "
			    "\"%s\"", default_access_policy);
	}

	sailfish_access_load_config_intf(config, default_policy);

	da_policy_unref(default_policy);
	g_free(default_policy_spec);
	g_key_file_unref(config);
}

static enum vpn_access sailfish_access_policy_check(const char *sender,
					    enum vpn_access_method method,
					    const char *arg)
{
	if (active_policy && method >= 0 && method < active_policy->len) {
		DAPeer *peer = da_peer_get(CONNMAN_BUS, sender);

		if (peer)
			/* This cast is gated by the compile time asserts
			 * at the head of this file */
			return (enum vpn_access)da_policy_check(
				       g_ptr_array_index(active_policy, method),
				       &peer->cred, 0, arg, DA_ACCESS_ALLOW);
		else
			/*
			 * Deny access to unknown peers. Those are
			 * already gone from the bus and won't be
			 * able to receive our reply anyway.
			 */
			return VPN_ACCESS_DENY;
	}
	return VPN_ACCESS_DONT_CARE;
}

static const struct vpn_access_plugin sailfish_vpn_access_driver = {
	.name                         = DRIVER_NAME,
	.priority                     = VPN_ACCESS_PRIORITY_DEFAULT,

	/* Connection and Manager */
	.vpn_policy_check             = sailfish_access_policy_check
};

static int sailfish_access_init()
{
	int ret;
	DBG("");

	ret = vpn_access_plugin_register(&sailfish_vpn_access_driver);
	if (ret == 0) {
		active_policy = g_ptr_array_new_with_free_func
				(sailfish_access_policy_free);

		sailfish_access_load_config();
	}
	return ret;
}

static void sailfish_access_exit()
{
	DBG("");
	vpn_access_plugin_unregister(&sailfish_vpn_access_driver);
	da_peer_flush(CONNMAN_BUS, NULL);
	if (active_policy) {
		g_ptr_array_free(active_policy, TRUE);
		active_policy = NULL;
	}
}

CONNMAN_PLUGIN_DEFINE(sailfish_access, "Sailfish access control", VERSION,
			CONNMAN_PLUGIN_PRIORITY_HIGH - 1,
			sailfish_access_init, sailfish_access_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
