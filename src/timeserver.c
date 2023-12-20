/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <glib.h>
#include <stdlib.h>
#include <gweb/gresolv.h>
#include <netdb.h>
#include <sys/time.h>

#include "connman.h"

#define TS_RECHECK_INTERVAL     7200

/**
 *  A strong (that is, uses #connman_service_{ref,unref}) reference to
 *  the network service currently used for time of day synchronization.
 *
 */
static struct connman_service *ts_service;
static GSList *timeservers_list = NULL;
static GSList *ts_list = NULL;
static char *ts_current = NULL;
static int ts_recheck_id = 0;
static int ts_backoff_id = 0;
static bool ts_is_synced = false;

static GResolv *resolv = NULL;
static int resolv_id = 0;

static void sync_next(void);
static void ts_set_nameservers(const struct connman_service *service);

static void resolv_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static void ntp_callback(bool success, void *user_data)
{
	dbus_uint64_t timestamp;
	struct timeval tv;

	DBG("success %d", success);

	__connman_timeserver_set_synced(success);
	if (!success) {
		sync_next();
		return;
	}

	if (gettimeofday(&tv, NULL) < 0) {
		connman_warn("Failed to get current time");
	}

	timestamp = tv.tv_sec;
	connman_dbus_property_changed_basic(
					CONNMAN_MANAGER_PATH,
					CONNMAN_CLOCK_INTERFACE, "Time",
					DBUS_TYPE_UINT64, &timestamp);
}

static void save_timeservers(char **servers)
{
	GKeyFile *keyfile;
	int cnt;

	keyfile = __connman_storage_load_global();
	if (!keyfile)
		keyfile = g_key_file_new();

	for (cnt = 0; servers && servers[cnt]; cnt++);

	g_key_file_set_string_list(keyfile, "global", "Timeservers",
			   (const gchar **)servers, cnt);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);
}

static char **load_timeservers(void)
{
	GKeyFile *keyfile;
	char **servers = NULL;

	keyfile = __connman_storage_load_global();
	if (!keyfile)
		return NULL;

	servers = g_key_file_get_string_list(keyfile, "global",
						"Timeservers", NULL, NULL);

	g_key_file_free(keyfile);

	return servers;
}

static void resolv_result(GResolvResultStatus status, char **results,
				gpointer user_data)
{
	int i;

	DBG("status %d", status);

	if (status == G_RESOLV_RESULT_STATUS_SUCCESS) {
		if (results) {
			/* prepend the results in reverse order */

			for (i = 0; results[i]; i++)
				/* count */;
			i--;

			for (; i >= 0; i--) {
				DBG("result[%d]: %s", i, results[i]);

				ts_list = __connman_timeserver_add_list(
					ts_list, results[i]);
			}
		}
	}

	sync_next();
}

/*
 * Once the timeserver list (timeserver_list) is created, we start
 * querying the servers one by one. If resolving fails on one of them,
 * we move to the next one. The user can enter either an IP address or
 * a URL for the timeserver. We only resolve the URLs. Once we have an
 * IP for the NTP server, we start querying it for time corrections.
 */
static void timeserver_sync_start(void)
{
	GSList *list;

	for (list = timeservers_list; list; list = list->next) {
		char *timeserver = list->data;

		ts_list = g_slist_prepend(ts_list, g_strdup(timeserver));
	}
	ts_list = g_slist_reverse(ts_list);

	sync_next();
}

static gboolean timeserver_sync_restart(gpointer user_data)
{
	timeserver_sync_start();
	ts_backoff_id = 0;

	return FALSE;
}

/*
 * Select the next time server from the working list (ts_list) because
 * for some reason the first time server in the list didn't work. If
 * none of the server did work we start over with the first server
 * with a backoff.
 */
static void sync_next(void)
{
	if (ts_current) {
		g_free(ts_current);
		ts_current = NULL;
	}

	__connman_ntp_stop();
	ts_set_nameservers(ts_service);

	while (ts_list) {
		ts_current = ts_list->data;
		ts_list = g_slist_delete_link(ts_list, ts_list);

		/* if it's an IP, directly query it. */
		if (connman_inet_check_ipaddress(ts_current) > 0) {
			DBG("Using timeserver %s", ts_current);
			__connman_ntp_start(ts_current, ntp_callback, NULL);
			return;
		}

		DBG("Resolving timeserver %s", ts_current);
		resolv_id = g_resolv_lookup_hostname(resolv, ts_current,
						resolv_result, NULL);
		return;
	}

	DBG("No timeserver could be used, restart probing in 5 seconds");
	ts_backoff_id = g_timeout_add_seconds(5, timeserver_sync_restart, NULL);
}

GSList *__connman_timeserver_add_list(GSList *server_list,
		const char *timeserver)
{
	GSList *list = server_list;

	if (!timeserver)
		return server_list;

	while (list) {
		char *existing_server = list->data;
		if (strcmp(timeserver, existing_server) == 0)
			return server_list;
		list = g_slist_next(list);
	}
	return g_slist_prepend(server_list, g_strdup(timeserver));
}

/*
 * __connman_timeserver_get_all function creates the timeserver
 * list which will be used to determine NTP server for time corrections.
 * The service settings take priority over the global timeservers.
 */
GSList *__connman_timeserver_get_all(const struct connman_service *service)
{
	GSList *list = NULL;
	const struct connman_network *network;
	char **timeservers;
	const char * const *service_ts;
	const char * const *service_ts_config;
	const char *service_gw;
	char **fallback_ts;
	int index, i;

	if (__connman_clock_timeupdates() == TIME_UPDATES_MANUAL)
		return NULL;

	service_ts_config = connman_service_get_timeservers_config(service);

	/* First add Service Timeservers.Configuration to the list */
	for (i = 0; service_ts_config && service_ts_config[i];
			i++)
		list = __connman_timeserver_add_list(list,
				service_ts_config[i]);

	service_ts = connman_service_get_timeservers(service);

	/* Then add Service Timeservers via DHCP to the list */
	for (i = 0; service_ts && service_ts[i]; i++)
		list = __connman_timeserver_add_list(list, service_ts[i]);

	/*
	 * Then add Service Gateway to the list, if UseGatewaysAsTimeservers
	 * configuration option is set to true.
	 */
	if (connman_setting_get_bool("UseGatewaysAsTimeservers")) {
		network = __connman_service_get_network((struct connman_service *)service);
		if (network) {
			index = connman_network_get_index(network);
			service_gw = __connman_ipconfig_get_gateway_from_index(index,
				CONNMAN_IPCONFIG_TYPE_ALL);

			if (service_gw)
				list = __connman_timeserver_add_list(list, service_gw);
		}
	}

	/* Then add Global Timeservers to the list */
	timeservers = load_timeservers();

	for (i = 0; timeservers && timeservers[i]; i++)
		list = __connman_timeserver_add_list(list, timeservers[i]);

	g_strfreev(timeservers);

	fallback_ts = connman_setting_get_string_list("FallbackTimeservers");

	/* Lastly add the fallback servers */
	for (i = 0; fallback_ts && fallback_ts[i]; i++)
		list = __connman_timeserver_add_list(list, fallback_ts[i]);

	return g_slist_reverse(list);
}

static gboolean ts_recheck(gpointer user_data)
{
	struct connman_service *service;
	GSList *ts;

	ts = __connman_timeserver_get_all(connman_service_get_default());

	if (!ts) {
		DBG("timeservers disabled");

		return TRUE;
	}

	if (g_strcmp0(ts_current, ts->data) != 0) {
		DBG("current %s preferred %s", ts_current, (char *)ts->data);

		g_slist_free_full(ts, g_free);

		service = connman_service_get_default();
		__connman_timeserver_sync(service,
				CONNMAN_TIMESERVER_SYNC_REASON_TS_CHANGE);

		return FALSE;
	}

	DBG("");

	g_slist_free_full(ts, g_free);

	return TRUE;
}

static void ts_recheck_disable(void)
{
	if (ts_recheck_id == 0)
		return;

	g_source_remove(ts_recheck_id);
	ts_recheck_id = 0;

	if (ts_backoff_id) {
		g_source_remove(ts_backoff_id);
		ts_backoff_id = 0;
	}

	if (ts_current) {
		g_free(ts_current);
		ts_current = NULL;
	}
}

static void ts_recheck_enable(void)
{
	if (ts_recheck_id > 0)
		return;

	ts_recheck_id = g_timeout_add_seconds(TS_RECHECK_INTERVAL, ts_recheck,
			NULL);
}

static int ts_setup_resolv(struct connman_service *service)
{
	int i;

	i = __connman_service_get_index(service);
	if (i < 0)
		return -EINVAL;

	if (resolv) {
		g_resolv_unref(resolv);
		resolv = NULL;
	}

	resolv = g_resolv_new(i);
	if (!resolv)
		return -ENOMEM;

	if (getenv("CONNMAN_RESOLV_DEBUG"))
		g_resolv_set_debug(resolv, resolv_debug, "RESOLV");

	return 0;
}


static void ts_set_nameservers(const struct connman_service *service)
{
	char **nameservers;
	int i;

	if (resolv_id > 0)
		g_resolv_cancel_lookup(resolv, resolv_id);

	g_resolv_flush_nameservers(resolv);

	nameservers = connman_service_get_nameservers(service);
	if (nameservers) {
		for (i = 0; nameservers[i]; i++)
			g_resolv_add_nameserver(resolv, nameservers[i], 53, 0);

		g_strfreev(nameservers);
	}
}

/**
 *  @brief
 *    Reset internal time of day synchronization state and initiate
 *    time of day synchronization with the specified network service.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           object for which a time of day
 *                           synchronization with time services should
 *                           be initiated. Name and time servers from
 *                           this service will be used for time of day
 *                           synchronization.
 *
 *  @sa __connman_timeserver_sync
 *  @sa __connman_timeserver_conf_update
 *  @sa __connman_timeserver_system_set
 *
 */
static void ts_reset(struct connman_service *service)
{
	DBG("service %p (%s)",
		service, connman_service_get_identifier(service));

	if (!resolv)
		return;

	__connman_timeserver_set_synced(false);

	/*
	 * Before we start creating the new timeserver list we must stop
	 * any ongoing ntp query and server resolution.
	 */

	__connman_ntp_stop();

	ts_recheck_disable();

	ts_set_nameservers(service);

	g_slist_free_full(timeservers_list, g_free);

	g_slist_free_full(ts_list, g_free);
	ts_list = NULL;

	timeservers_list = __connman_timeserver_get_all(service);

	__connman_service_timeserver_changed(service, timeservers_list);

	if (!timeservers_list) {
		DBG("No timeservers set.");
		return;
	}

	ts_recheck_enable();

	if (ts_service) {
		connman_service_unref(ts_service);
		ts_service = NULL;
	}

	if (service) {
		connman_service_ref(service);
		ts_service = service;
	}

	timeserver_sync_start();
}

static const char *timeserver_sync_reason2string(
			enum connman_timeserver_sync_reason reason)
{
	switch (reason) {
	case CONNMAN_TIMESERVER_SYNC_REASON_START:
		return "start";
	case CONNMAN_TIMESERVER_SYNC_REASON_ADDRESS_UPDATE:
		return "address update";
	case CONNMAN_TIMESERVER_SYNC_REASON_STATE_UPDATE:
		return "state update";
	case CONNMAN_TIMESERVER_SYNC_REASON_TS_CHANGE:
		return "timeserver change";
	}

	return "unknown";
}

/**
 *  @brief
 *    Initiate a time of day synchronization with time services.
 *
 *  This initiates a time of day synchronization with time services
 *  for the specified network service for the provided reason.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           object for which a time of day
 *                           synchronization with time services should
 *                           be initiated.
 *  @param[in]      reason   The reason for the time of day
 *                           synchronizization request.
 *
 */
void __connman_timeserver_sync(struct connman_service *service,
			enum connman_timeserver_sync_reason reason)
{
	DBG("service %p (%s) reason %d (%s)",
		service, connman_service_get_identifier(service),
		reason, timeserver_sync_reason2string(reason));

	if (!service)
		return;

	switch (reason) {
	case CONNMAN_TIMESERVER_SYNC_REASON_START:
	case CONNMAN_TIMESERVER_SYNC_REASON_STATE_UPDATE:
		if (ts_service == service)
			return;
		break;
	case CONNMAN_TIMESERVER_SYNC_REASON_ADDRESS_UPDATE:
	case CONNMAN_TIMESERVER_SYNC_REASON_TS_CHANGE:
		if (ts_service != service)
			return;
		break;
	default:
		return;
	}

	ts_reset(service);
}

void __connman_timeserver_conf_update(struct connman_service *service)
{
	if (!service || (ts_service && ts_service != service))
		return;

	ts_reset(service);
}


bool __connman_timeserver_is_synced(void)
{
	return ts_is_synced;
}

void __connman_timeserver_set_synced(bool status)
{
	dbus_bool_t is_synced;

	if (ts_is_synced == status)
		return;

	ts_is_synced = status;
	is_synced = status;
	connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
				CONNMAN_CLOCK_INTERFACE, "TimeserverSynced",
				DBUS_TYPE_BOOLEAN, &is_synced);
}

static int timeserver_start(struct connman_service *service)
{
	int rv;

	DBG("service %p", service);

	/* get rid of the old resolver */
	rv = ts_setup_resolv(service);
	if (rv)
		return rv;

	ts_set_nameservers(service);

	__connman_timeserver_sync(service,
			CONNMAN_TIMESERVER_SYNC_REASON_START);

	return 0;
}

static void timeserver_stop(void)
{
	DBG(" ");

	if (ts_service) {
		connman_service_unref(ts_service);
		ts_service = NULL;
	}

	if (resolv) {
		g_resolv_unref(resolv);
		resolv = NULL;
	}

	g_slist_free_full(timeservers_list, g_free);
	timeservers_list = NULL;

	g_slist_free_full(ts_list, g_free);
	ts_list = NULL;

	__connman_ntp_stop();

	ts_recheck_disable();
}

int __connman_timeserver_system_set(char **servers)
{
	struct connman_service *service;

	save_timeservers(servers);

	service = connman_service_get_default();
	if (service)
		ts_reset(service);

	return 0;
}

char **__connman_timeserver_system_get()
{
	char **servers;

	servers = load_timeservers();
	return servers;
}

static void default_changed(struct connman_service *default_service)
{
	if (default_service)
		timeserver_start(default_service);
	else
		timeserver_stop();
}

static const struct connman_notifier timeserver_notifier = {
	.name			= "timeserver",
	.default_changed	= default_changed,
};

int __connman_timeserver_init(void)
{
	DBG("");

	connman_notifier_register(&timeserver_notifier);

	return 0;
}

void __connman_timeserver_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&timeserver_notifier);
}
