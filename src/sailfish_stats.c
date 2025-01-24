/*
 *  Connection Manager
 *
 *  Copyright (C) 2016-2019 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2016-2019 Slava Monich <slava.monich@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include "sailfish_datacounters.h"

#include "connman.h"

#include <gutil_timenotify.h>
#include <gutil_idlepool.h>

#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/if.h>

struct connman_stats {
	struct connman_service *service;
	struct datacounter *counter;
	struct datacounter_dbus *counter_dbus;
	struct datacounters_dbus *counters_dbus;
	gboolean active;
	int index;
	guint link_watch_id;
	GSList *history_list;
	GSList *history_dbus_list;
	gulong cutoff_id;
};

#define STATS_NAME_HOME     "home"
#define STATS_NAME_ROAMING  "roaming"

static GUtilIdlePool *stats_idle_pool;
static GUtilTimeNotify *stats_time_notify;

#define stats_name(roaming) ((roaming) ? STATS_NAME_ROAMING : STATS_NAME_HOME)

static const char* stats_obsolete[] = { "data", "history" };

static const struct datahistory_type datahistory_types[] = {
	{ datahistory_memory_get_type, "second", {1, TIME_UNIT_SECOND}, 2000 },
	{ datahistory_memory_get_type, "minute", {1, TIME_UNIT_MINUTE}, 2000 },
	{ datahistory_file_get_type, "hour", {1, TIME_UNIT_HOUR}, 720 },
	{ datahistory_file_get_type, "day", {1, TIME_UNIT_DAY}, 365 },
	{ datahistory_file_get_type, "month", {1, TIME_UNIT_MONTH}, 240 }
};

static void stats_cutoff_update(struct connman_stats *stats)
{
	__connman_service_set_disabled(stats->service,
			stats->counter->cutoff_state == CUTOFF_ACTIVATED);
}

static void stats_cutoff_event(struct datacounter *counter,
			enum datacounter_property property, void *arg)
{
	stats_cutoff_update((struct connman_stats *)arg);
}

/** Deletes the leftovers from the older versions of connman */
static void stats_delete_obsolete_files(const char *dir)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(stats_obsolete); i++) {
		char *path = g_build_filename(dir, stats_obsolete[i], NULL);

		if (unlink(path) < 0) {
			if (errno != ENOENT) {
				connman_error("error deleting %s: %s",
						path, strerror(errno));
			}
		} else {
			DBG("deleted %s", path);
		}
		g_free(path);
	}
}

static void stats_update_interval_add(void *list_data, void *user_data)
{
	struct datahistory *history = list_data;

	/* Zero interval is ignored */
	__connman_rtnl_update_interval_add(history->update_interval);
}

static void stats_update_interval_remove(void *list_data, void *user_data)
{
	struct datahistory *history = list_data;

	/* Zero interval is ignored */
	__connman_rtnl_update_interval_remove(history->update_interval);
}

static void stats_set_active(struct connman_stats *stats, gboolean active)
{
	if (stats->active != active) {
		if (stats->active) {
			g_slist_foreach(stats->history_list,
					stats_update_interval_remove, NULL);
		}
		stats->active = active;
		if (stats->active) {
			g_slist_foreach(stats->history_list,
					stats_update_interval_add, NULL);
		} else {
			/* Carrier went off */
			__connman_stats_set_index(stats, -1);
		}
	}
}

static void stats_newlink(unsigned int flags, unsigned int change, void *data)
{
	stats_set_active(data, (flags & IFF_LOWER_UP) != 0);
}

static void stats_free_history(gpointer data)
{
	datahistory_unref(data);
}

static void stats_free_history_dbus(gpointer data)
{
	datahistory_dbus_free(data);
}

static struct connman_stats *stats_new(struct connman_service *service,
							const char *name)
{
	int i;
	const char *histories[G_N_ELEMENTS(datahistory_types)+1];
	const char *ident = connman_service_get_identifier(service);
	struct connman_stats *stats = g_new0(struct connman_stats, 1);
	struct datacounters *counters = datacounters_new(ident);

	/* It's safe to keep the pointer to struct connman_service - this
	 * stats thing it owned by the service and will be deleteed before
	 * the service itself gets deleted */
	stats->service = service;

	/*
	 * The datacounters objects are shared by home/roaming counters.
	 * Also, internally they create objects that are shared by all
	 * datacounters objects. Keeping references to these objects for
	 * a short while (until the next idle loop) can save quite a few
	 * CPU cycles if stats are created/destroyed in the loop.
	 */
	gutil_idle_pool_add_object_ref(stats_idle_pool, counters);

	/*
	 * We have to register the "parent" object first and then its
	 * children with gdbus. If we do it the other way around, gdbus
	 * breaks and may access deallocated memory.
	 */
	stats->counters_dbus = datacounters_dbus_new(counters);
	stats->counter = datacounters_get_counter(counters, name);
	gutil_idle_pool_add_object_ref(stats_idle_pool, stats->counter);
	for (i = 0; i < G_N_ELEMENTS(datahistory_types); i++) {
		histories[i] = datahistory_types[i].name;
	}
	histories[i] = NULL;
	stats->counter_dbus = datacounter_dbus_new(stats->counter, histories);

	/* N.B. datahistory_dbus keeps a reference to datahistory */
	for (i = 0; i < G_N_ELEMENTS(datahistory_types); i++) {
		struct datahistory *h = datahistory_new(stats->counter,
						datahistory_types + i);

		stats->history_list = g_slist_append(stats->history_list, h);
		stats->history_dbus_list =
			g_slist_append(stats->history_dbus_list,
					datahistory_dbus_new(h));
	}

	/* Update the service state and watch for changes */
	stats_cutoff_update(stats);
	stats->cutoff_id = datacounter_add_property_handler(stats->counter,
		DATACOUNTER_PROPERTY_CUTOFF_STATE, stats_cutoff_event, stats);

	datacounters_unref(counters);
	return stats;
}

struct connman_stats *__connman_stats_new(struct connman_service *service,
							gboolean roaming)
{
	const char *ident = connman_service_get_identifier(service);
	char *dir = g_build_filename(connman_storage_dir_for(ident), ident,
				NULL);

	DBG("%s %d", ident, roaming);

	/*
	 * The directory gets created when the service is saved.
	 * Until then it should never become connected, no data
	 * should be transferred and therefore no statistics or
	 * history needs to be stored. We only check the directory
	 * to see if there are any stale files there to delete.
	 */
	if (g_file_test(dir, G_FILE_TEST_IS_DIR)) {
		stats_delete_obsolete_files(dir);
	}

	g_free(dir);
	return stats_new(service, stats_name(roaming));
}

struct connman_stats *__connman_stats_new_existing(
			struct connman_service *service, gboolean roaming)
{
	return __connman_stats_new(service, roaming);
}

void __connman_stats_free(struct connman_stats *stats)
{
	if (G_LIKELY(stats)) {
		if (stats->link_watch_id) {
			connman_rtnl_remove_watch(stats->link_watch_id);
		}
		if (stats->active) {
			g_slist_foreach(stats->history_list,
					stats_update_interval_remove, NULL);
		}
		g_slist_free_full(stats->history_list, stats_free_history);
		g_slist_free_full(stats->history_dbus_list,
						stats_free_history_dbus);
		datacounters_dbus_free(stats->counters_dbus);
		datacounter_dbus_free(stats->counter_dbus);
		datacounter_remove_handler(stats->counter, stats->cutoff_id);
		datacounter_unref(stats->counter);
		g_free(stats);
	}
}

void __connman_stats_reset(struct connman_stats *stats)
{
	if (G_LIKELY(stats)) {
		datacounter_reset(stats->counter);
	}
}

void __connman_stats_set_index(struct connman_stats *stats, int index)
{
	if (G_LIKELY(stats) && stats->index != index) {
		if (stats->link_watch_id) {
			connman_rtnl_remove_watch(stats->link_watch_id);
		}
		stats->index = index;
		if (index >= 0) {
			/*
			 * connman_rtnl_add_newlink_watch() calls
			 * stats_newlink() right away but only if
			 * interface flags are not all zeros. They
			 * should be non-zero because this function
			 * is called from service_lower_up(), meaning
			 * that at least IFF_LOWER_UP flag must be set.
			 *
			 * In other words, this call not only starts
			 * watching interface flags but also updates
			 * the current state, turning on interface
			 * update notifications if necessary.
			 */
			stats->link_watch_id =
				connman_rtnl_add_newlink_watch(index,
							stats_newlink, stats);
		} else {
			stats->link_watch_id = 0;
			stats_set_active(stats, FALSE);
		}
	}
}

void __connman_stats_rebase(struct connman_stats *stats,
				const struct connman_stats_data *data)
{
	if (G_LIKELY(stats)) {
		datacounter_rebase(stats->counter, data);
	}
}

gboolean __connman_stats_update(struct connman_stats *stats,
				const struct connman_stats_data *data)
{
	return G_LIKELY(stats) && datacounter_update(stats->counter, data);
}

void __connman_stats_get(struct connman_stats *stats,
				struct connman_stats_data *data)
{
	if (G_LIKELY(data)) {
		if (G_LIKELY(stats)) {
			*data = *stats->counter->value;
		} else {
			memset(data, 0, sizeof(*data));
		}
	}
}

void __connman_stats_read(const char *ident, gboolean roaming,
				struct connman_stats_data *data)
{
	datacounter_file_load(ident, stats_name(roaming), data);
}

void __connman_stats_clear(const char *ident, gboolean roaming)
{
	datacounter_file_clear(ident, stats_name(roaming));
}

int __connman_stats_init(void)
{
	/*
	 * For some unidentified reason, timerfd_settime sometimes fails
	 * with EINVAL. Since GUtilTimeNotify object is actually a singleton
	 * (which exists as long as it's being used), keeping its instance
	 * around guarantees that only one instance is created, ever. So far
	 * it looks like timerfd_settime never fails the first time, which
	 * kind of solves the problem with random timerfd_settime failures.
	 */
	stats_time_notify = gutil_time_notify_new();
	stats_idle_pool = gutil_idle_pool_new();
	return 0;
}

void __connman_stats_cleanup(void)
{
	gutil_time_notify_unref(stats_time_notify);
	gutil_idle_pool_unref(stats_idle_pool);
	stats_time_notify = NULL;
	stats_idle_pool = NULL;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
