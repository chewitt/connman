/*
 *  ConnMan storage unit tests
 *
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
 *  Contact: jussi.laakkonen@jolla.com
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

#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include <syslog.h>

#include "src/connman.h"

#define TEST_PREFIX "/systemd_login"

enum sd_session_state {
	SD_SESSION_STATE_IDLE = 0,
	SD_SESSION_STATE_UNKNOWN,
	SD_SESSION_STATE_INIT,
	SD_SESSION_STATE_OFFLINE,
	SD_SESSION_STATE_LINGERING,
	SD_SESSION_STATE_OPENING,
	SD_SESSION_STATE_ONLINE,
	SD_SESSION_STATE_ACTIVE,
	SD_SESSION_STATE_CLOSING,
	SD_SESSION_STATE_NULL,
};

typedef struct sd_login_monitor {
	int fd;
	char *seat;
	char *session;
	enum sd_session_state state;
	uid_t uid;
	bool is_remote;
	bool is_ready;
	int is_ready_timeouts;
} sd_login_monitor;

static sd_login_monitor *monitor = NULL;

static char *state2string(enum sd_session_state state)
{
	switch (state) {
	case SD_SESSION_STATE_UNKNOWN:
		return g_strdup("unknown");
	case SD_SESSION_STATE_INIT:
		/* fall through */
	case SD_SESSION_STATE_OFFLINE:
		return g_strdup("offline");
	case SD_SESSION_STATE_LINGERING:
		return g_strdup("lingering");
	case SD_SESSION_STATE_OPENING:
		return g_strdup("opening");
	case SD_SESSION_STATE_ONLINE:
		return g_strdup("online");
	case SD_SESSION_STATE_ACTIVE:
		return g_strdup("active");
	case SD_SESSION_STATE_CLOSING:
		return g_strdup("closing");
	default:
		return NULL;
	}
}

/* systemd login stubs */

/* Return active session and user of seat */
int sd_seat_get_active(const char *seat, char **session, uid_t *uid)
{
	DBG("");

	if (!monitor)
		return -1;

	if (!monitor->is_ready) {
		if (!monitor->is_ready_timeouts--)
			monitor->is_ready = true;
		else
			DBG("ready timeout, left %d", monitor->is_ready_timeouts);

		return -ENOENT;
	}

	if (g_strcmp0(monitor->seat, seat))
		return -1;

	DBG("%s session %s uid %u", monitor->seat, monitor->session,
				monitor->uid);

	*session = g_strdup(monitor->session);
	*uid = monitor->uid;

	return 0;
}

/* Return 1 if the session is remote. */
int sd_session_is_remote(const char *session)
{
	if (!monitor)
		return -1;

	g_assert(session);

	DBG("%s", monitor->is_remote ? "true" : "false");

	return monitor->is_remote;
}

/* Get state from UID. Possible states: offline, lingering, online, active, closing */
int sd_uid_get_state(uid_t uid, char **state)
{
	char *temp_state;

	DBG("");

	if (!monitor)
		return -1;

	g_assert(state);
	g_assert_cmpint((int)uid, ==, (int)monitor->uid);
	temp_state = state2string(monitor->state);

	DBG("state for %u is %d:%s", monitor->uid, monitor->state, temp_state);

	if (monitor->state == SD_SESSION_STATE_NULL) {
		g_free(temp_state);
		return -1;
	}

	*state = temp_state;

	return 0;
}

bool monitor_on = true;

int sd_login_monitor_new(const char *category, sd_login_monitor** ret)
{
	DBG("");

	g_assert(ret);
	g_assert_cmpstr(category, ==, "session");

	if (!monitor_on) {
		DBG("monitor set to fail");
		return -1;
	}

	if (!monitor) {
		monitor = g_new0(struct sd_login_monitor, 1);
		g_assert(monitor);

		monitor->fd = socket(AF_UNIX, SOCK_STREAM, 0);
		monitor->seat = g_strdup("seat0");
		monitor->session = g_strdup("c0");
		monitor->state = SD_SESSION_STATE_INIT;
		monitor->is_ready = true;
	}

	*ret = monitor;

	return 0;
}

/* Destroys the passed monitor. Returns NULL. */
sd_login_monitor* sd_login_monitor_unref(sd_login_monitor *m)
{
	DBG("");

	g_assert(m == monitor);
	g_assert_cmpint(monitor->state, >, SD_SESSION_STATE_IDLE);

	if (monitor->fd >= 0)
		close(monitor->fd);

	g_free(monitor->seat);
	g_free(monitor->session);

	g_free(monitor);
	monitor = NULL;

	return monitor;
}

/* Flushes the monitor */
int sd_login_monitor_flush(sd_login_monitor *m)
{
	DBG("");

	g_assert(m == monitor);
	g_assert_cmpint(monitor->state, >, SD_SESSION_STATE_IDLE);

	return m ? 0 : 1;
}

/* Get FD from monitor */
int sd_login_monitor_get_fd(sd_login_monitor *m)
{
	DBG("");

	g_assert(m == monitor);
	g_assert_cmpint(monitor->state, >, SD_SESSION_STATE_IDLE);

	DBG("return fd %d", m->fd);

	return m ? m->fd : -1;
}

/* END of systemd login stubs */

/* storage.c stubs and necessary bits */

static uid_t storage_uid = 0;
static int storage_change_user_err1 = -EINPROGRESS;
static int storage_change_user_err2 = 0;
static connman_storage_change_user_result_cb_t storage_cb = NULL;
static int storage_delayed_call_count = 0;
static guint delayed_cb_id = 0;

static void storage_initialize(int err1, int err2)
{
	storage_uid = 0;
	storage_change_user_err1 = err1;
	storage_change_user_err2 = err2;
	delayed_cb_id = 0;
}

struct cb_data {
	int err;
	uid_t uid;
	connman_storage_change_user_result_cb_t cb;
	void *user_cb_data;
};

static gboolean delayed_cb(gpointer user_data)
{
	struct cb_data *data = user_data;

	DBG("");

	data->cb(storage_uid, storage_change_user_err2, data->user_cb_data);

	if (storage_delayed_call_count) {
		DBG("delay another call");
		storage_delayed_call_count--;
		return G_SOURCE_CONTINUE;
	}

	g_free(data);
	delayed_cb_id = 0;

	return G_SOURCE_REMOVE;
}

int __connman_storage_change_user(uid_t uid,
			connman_storage_change_user_result_cb_t cb,
			void *user_cb_data, bool prepare_only)
{
	struct cb_data *data;

	if (uid == storage_uid)
		return -EALREADY;

	g_assert(cb);
	g_assert(user_cb_data);

	if (!storage_change_user_err2)
		storage_uid = uid;

	storage_cb = cb;

	if (prepare_only)
		cb(storage_uid, storage_change_user_err1, user_cb_data);

	if (storage_change_user_err1 != -EINPROGRESS)
		goto out;

	data = g_new0(struct cb_data, 1);
	data->err = storage_change_user_err2;
	data->uid = storage_uid;
	data->cb = cb;
	data->user_cb_data = user_cb_data;

	delayed_cb_id = g_timeout_add_full(G_PRIORITY_HIGH, 50, delayed_cb,
				data, NULL);

	DBG("add cb id %u", delayed_cb_id);

out:
	return storage_change_user_err1;
}

bool __connman_technology_disable_all(void)
{
	return true;
}

/* END STORAGE STUB */

/* notifier stubs */

int connman_notifier_register(struct connman_notifier *notifier)
{
	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	return;
}

static void monitor_initialize(uid_t uid, enum sd_session_state initial_state,
			const char *seat, int expected_return)
{
	g_assert_null(monitor);
	g_assert_cmpint(sd_login_monitor_new("session", &monitor), ==,
				expected_return);

	if (expected_return == -1)
		return;

	monitor->uid = uid;

	if (initial_state != SD_SESSION_STATE_IDLE)
		monitor->state = initial_state;

	if (seat) {
		if (monitor->seat)
			g_free(monitor->seat);

		monitor->seat = g_strdup(seat);
	}
}

static void monitor_set_session(const char *session)
{
	if (!monitor)
		return;

	if (monitor->session)
		g_free(monitor->session);

	monitor->session = g_strdup(session);
}

static char *last_err_log = NULL;
static char *last_warn_log = NULL;
static char *last_info_log = NULL;

static void test_connman_log_hook(const struct connman_debug_desc *desc,
				int priority, const char *format, va_list va)
{
	/* connman is only using these four priorities: */
	switch (priority) {
	case LOG_ERR:
		if (last_err_log)
			g_free(last_err_log);

		last_err_log = g_strdup_vprintf(format, va);
		break;
	case LOG_WARNING:
		if (last_warn_log)
			g_free(last_warn_log);

		last_warn_log = g_strdup_vprintf(format, va);
		break;
	case LOG_INFO:
		if (last_info_log)
			g_free(last_info_log);

		last_info_log = g_strdup_vprintf(format, va);
		break;
	case LOG_DEBUG:
		break;
	default:
		break;
	}
}

static void test_connman_log_hook_clean()
{
	g_free(last_err_log);
	last_err_log = NULL;

	g_free(last_warn_log);
	last_warn_log = NULL;

	g_free(last_info_log);
	last_info_log = NULL;
}

/* Total wait of 0.120s */
#define MAIN_LOOP_ITERATIONS_DEFAULT 6000
/* Total wait of 0.300s */
#define MAIN_LOOP_ITERATIONS_MED 15000
/* Total wait of 0.600s */
#define MAIN_LOOP_ITERATIONS_LONG 30000
#define MAIN_LOOP_SLEEP_USEC 20

static unsigned int iterate_main_context(GMainContext *context,
			gboolean may_block, unsigned int limit,
			unsigned int max_events)
{
	unsigned int counter = 0;
	unsigned int events = 0;
	bool event_recorded = false;

	g_assert(context);
	g_assert_true(g_main_context_acquire(context));

	DBG("");

	if (!limit)
		limit = MAIN_LOOP_ITERATIONS_DEFAULT;

	while (counter < limit && events < max_events) {
		if (g_main_context_pending(context)) {
			events++;
			DBG("event #%u @ iteration %u", events, counter);

			/*
			 * Main context iteration is not set to wait, dispatch
			 * here.
			 */
			if (!may_block)
				g_main_context_dispatch(context);

			event_recorded = true;
		}

		/* If iteration fails to dispatch do that manually. */
		if (!g_main_context_iteration(context, may_block)) {
			g_main_context_dispatch(context);
		/*
		 * If the g_main_context_pending() already recorded an event
		 * skip it here to avoid double.
		 */
		} else if (!event_recorded) {
			events++;
			DBG("event #%u @ iteration %u", events, counter);
		}

		usleep(MAIN_LOOP_SLEEP_USEC);

		counter++;
		event_recorded = false;
	}

	g_main_context_release(context);

	DBG("%u events", events);

	return events;
}

/* No user change, uid = 0 */
static void systemd_login_test_basic1()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, 0, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);
	g_assert_cmpint(__systemd_login_init(), ==, -EALREADY);

	/*
	 * With expected + 1 events wait for that no additional events are
	 * dispatched
	 */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
}

/* No user change, uid is set but in wrong state */
static void systemd_login_test_basic2()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, 0, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
}

/* User change with uid 1000 set to active */
static void systemd_login_test_basic3()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 2), ==, 1);
	g_assert_cmpint(delayed_cb_id, ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_cmpstr(last_info_log, ==, "user changed to 1000");

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/* User change with uid 1000 set to be active but already set */
static void systemd_login_test_basic4()
{
	GMainLoop *mainloop;

	storage_initialize(-EALREADY, 0);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);
	g_assert_cmpstr(last_info_log, ==, "user already set to 1000");

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/* User change with uid 1000 set to be remote and online (e.g., ssh)*/
static void systemd_login_test_basic5()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_ONLINE, NULL, 0);
	monitor->is_remote = true;

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/* User change with uid 1000 set to be lingering */
static void systemd_login_test_basic6()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_LINGERING, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/* User change with uid 1000 set to be opening */
static void systemd_login_test_basic7()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_OPENING, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
}

/* User change with uid 1000 set to closing */
static void systemd_login_test_basic8()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_CLOSING, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
}

/* User change with uid 1000 set to be online */
static void systemd_login_test_basic9()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_ONLINE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);
	
	g_main_loop_unref(mainloop);
}

/* Monitor first reports once that it is not ready then succeeds */
static void systemd_login_test_basic10()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	/* Simulate the case when session is not ready yet */
	monitor->is_ready = false;
	monitor->is_ready_timeouts = 2;

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
			TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_loop_unref(mainloop);
}

static unsigned int poll_events = 0;

gint poll_func(GPollFD *ufds, guint nfsd, gint timeout)
{
	int events = 0;
	int i;

	for (i = 0; i < nfsd; i++) {
		if (ufds[i].fd == monitor->fd) {
			if (ufds[i].events & G_IO_IN && poll_events) {
				ufds[i].revents |= G_IO_IN;
				events++;
				poll_events--;

				DBG("systemd login fd, set G_IO_IN event "
							"(%d left)",
							poll_events);
			}
		}
	}

	return events;
}

/* User change with uid 1000 coming from systemd login after start */
static void systemd_login_test_full1()
{
	GMainLoop *mainloop;
	GMainContext *context;
	GPollFunc orig_func;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(0, 0, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);
	context = g_main_loop_get_context(mainloop);

	orig_func = g_main_context_get_poll_func(context);
	g_main_context_set_poll_func(context, poll_func);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	monitor->uid = 1000;
	monitor->state = SD_SESSION_STATE_ACTIVE;
	poll_events = 1;

	g_assert_cmpint(iterate_main_context(context, FALSE,
				MAIN_LOOP_ITERATIONS_MED, 4), ==, 3);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_cmpstr(last_info_log, ==, "user changed to 1000");

	__systemd_login_cleanup();
	g_assert_null(monitor);
	g_assert_cmpint(delayed_cb_id, ==, 0);

	g_main_context_set_poll_func(context, orig_func);
	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/*
 * No initial user change, and the delayed check is initialized twice and
 * after that the user change is done via systemd login.
 */
static void systemd_login_test_full2()
{
	GMainLoop *mainloop;
	GMainContext *context;
	GPollFunc orig_func;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(0, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);
	context = g_main_loop_get_context(mainloop);

	orig_func = g_main_context_get_poll_func(context);
	g_main_context_set_poll_func(context, poll_func);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	monitor->uid = 1000;
	monitor->state = SD_SESSION_STATE_ACTIVE;
	poll_events = 3;

	g_assert_cmpint(iterate_main_context(context, FALSE,
				MAIN_LOOP_ITERATIONS_MED, 5), ==, 4);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_cmpstr(last_info_log, ==, "user changed to 1000");

	__systemd_login_cleanup();
	g_assert_null(monitor);
	g_assert_cmpint(delayed_cb_id, ==, 0);

	g_main_context_set_poll_func(context, orig_func);
	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/*
 * User is set to 1000 at start and same notification is coming from systemd
 * login causing no user change.
 */
static void systemd_login_test_full3()
{
	GMainLoop *mainloop;
	GMainContext *context;
	GPollFunc orig_func;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);
	context = g_main_loop_get_context(mainloop);

	orig_func = g_main_context_get_poll_func(context);
	g_main_context_set_poll_func(context, poll_func);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	/* Get the initial check reply */
	g_assert_cmpint(iterate_main_context(context, FALSE,
				MAIN_LOOP_ITERATIONS_MED, 2), ==, 1);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_cmpstr(last_info_log, ==, "user changed to 1000");
	test_connman_log_hook_clean();

	storage_initialize(-EALREADY, 0);
	poll_events = 1;

	/* Get the already enabled reply */
	g_assert_cmpint(iterate_main_context(context, FALSE,
				MAIN_LOOP_ITERATIONS_MED, 3), ==, 2);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_context_set_poll_func(context, orig_func);
	g_main_loop_unref(mainloop);
}

/*
 * Start with user 0, then change to 1000 with systemd login notify, and then
 * to 1001. Do additional callback at the end from storage.
 */
static void systemd_login_test_full4()
{
	GMainLoop *mainloop;
	GMainContext *context;
	GPollFunc orig_func;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(0, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);
	context = g_main_loop_get_context(mainloop);

	orig_func = g_main_context_get_poll_func(context);
	g_main_context_set_poll_func(context, poll_func);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	monitor->uid = 1000;
	poll_events = 1;

	/* Get reply to first change */
	g_assert_cmpint(iterate_main_context(context, FALSE,
				MAIN_LOOP_ITERATIONS_MED, 4), ==, 3);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_cmpstr(last_info_log, ==, "user changed to 1000");

	monitor->uid = 1001;
	poll_events = 1;
	storage_delayed_call_count = 1;

	/* Get reply to second change */
	g_assert_cmpint(iterate_main_context(context, FALSE,
				MAIN_LOOP_ITERATIONS_MED, 5), ==, 4);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_cmpstr(last_info_log, ==, "user changed to 1001");

	__systemd_login_cleanup();
	g_assert_null(monitor);

	g_main_context_set_poll_func(context, orig_func);
	g_main_loop_unref(mainloop);
	test_connman_log_hook_clean();
}

/* Invalid seat */
static void systemd_login_test_error1()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, 0, "seat1", 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_cmpstr(last_warn_log, ==,
				"err -1 failed to get active session and/or "
				"user for seat seat0");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* Session NULL */
static void systemd_login_test_error2()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, 0, NULL, 0);
	monitor_set_session(NULL);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* State returns NULL */
static void systemd_login_test_error3()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_NULL, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 0, 1), ==, 0);

	g_assert_null(last_err_log);
	g_assert_cmpstr(last_warn_log, ==,
				"err -1 failed to get state for uid 1000 "
				"session c0");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* Unknown state */
static void systemd_login_test_error4()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(1000, SD_SESSION_STATE_UNKNOWN, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 0, 1), ==, 0);
	g_assert_null(last_err_log);
	g_assert_cmpstr(last_warn_log, ==, "unknown sd_login state unknown");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* User change reports error */
static void systemd_login_test_error5()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, -EINVAL);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, MAIN_LOOP_ITERATIONS_MED, 2), ==, 1);
	g_assert_cmpint(delayed_cb_id, ==, 0);

	g_assert_null(last_err_log);
	g_assert_cmpstr(last_warn_log, ==,
			"changed to different user 0 than requested (1000)");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* User change reports timeout */
static void systemd_login_test_error6()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, -ETIMEDOUT);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 0, 3), ==, 2);
	g_assert_cmpint(delayed_cb_id, ==, 0);

	g_assert_null(last_err_log);
	g_assert_null(last_warn_log);
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* User change reports not found */
static void systemd_login_test_error7()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, -ENOENT);
	monitor_initialize(1000, SD_SESSION_STATE_ACTIVE, NULL, 0);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, 0);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 0, 2), ==, 1);
	g_assert_cmpint(delayed_cb_id, ==, 0);

	g_assert_null(last_err_log);
	g_assert_cmpstr(last_warn_log, ==,
			"changed to different user 0 than requested (1000)");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* Initial systemd connection fails */
static void systemd_login_test_error8()
{
	GMainLoop *mainloop;

	monitor_on = false;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(0, 0, NULL, -1);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, -EINPROGRESS);

	monitor_on = true;
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, MAIN_LOOP_ITERATIONS_LONG, 2), ==, 1);

	g_assert_true(g_str_has_prefix(last_err_log,
				"failed to init systemd login monitor -1"));
	g_assert_cmpstr(last_warn_log, ==,
				"failed to initialize login monitor");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);

	if (monitor)
		sd_login_monitor_unref(monitor);

	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* Faulty socket on systemd */
static void systemd_login_test_error9()
{
	GMainLoop *mainloop;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(0, 0, NULL, 0);

	if (monitor->fd > 0)
		close(monitor->fd);

	monitor->fd = -1;

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, -EINPROGRESS);

	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, MAIN_LOOP_ITERATIONS_LONG, 2), ==, 1);

	g_assert_cmpstr(last_err_log, ==,
				"cannot init connection to systemd logind");
	g_assert_cmpstr(last_warn_log, ==, "failed to initialize io channel");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);
	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

/* Initial systemd connection fails and monitor is closed before main loop */
static void systemd_login_test_error10()
{
	GMainLoop *mainloop;

	monitor_on = false;

	storage_initialize(-EINPROGRESS, 0);
	monitor_initialize(0, 0, NULL, -1);

	mainloop = g_main_loop_new(NULL, FALSE);

	g_assert_cmpint(__systemd_login_init(), ==, -EINPROGRESS);

	monitor_on = true;
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				TRUE, 1, 2), ==, 1);

	g_assert_true(g_str_has_prefix(last_err_log,
				"failed to init systemd login monitor -1"));
	g_assert_cmpstr(last_warn_log, ==,
				"failed to initialize login monitor");
	g_assert_null(last_info_log);

	__systemd_login_cleanup();
	g_main_loop_unref(mainloop);

	if (monitor)
		sd_login_monitor_unref(monitor);

	g_assert_null(monitor);
	test_connman_log_hook_clean();
}

static gchar *option_debug = NULL;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

int main(int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else {
			g_printerr("An unknown error occurred\n");
		}

		return 1;
	}

	g_option_context_free(context);

	connman_log_hook = test_connman_log_hook;
	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func(TEST_PREFIX "/test_basic1",
				systemd_login_test_basic1);
	g_test_add_func(TEST_PREFIX "/test_basic2",
				systemd_login_test_basic2);
	g_test_add_func(TEST_PREFIX "/test_basic3",
				systemd_login_test_basic3);
	g_test_add_func(TEST_PREFIX "/test_basic4",
				systemd_login_test_basic4);
	g_test_add_func(TEST_PREFIX "/test_basic5",
				systemd_login_test_basic5);
	g_test_add_func(TEST_PREFIX "/test_basic6",
				systemd_login_test_basic6);
	g_test_add_func(TEST_PREFIX "/test_basic7",
				systemd_login_test_basic7);
	g_test_add_func(TEST_PREFIX "/test_basic8",
				systemd_login_test_basic8);
	g_test_add_func(TEST_PREFIX "/test_basic9",
				systemd_login_test_basic9);
	g_test_add_func(TEST_PREFIX "/test_basic10",
				systemd_login_test_basic10);
	g_test_add_func(TEST_PREFIX "/test_full1",
				systemd_login_test_full1);
	g_test_add_func(TEST_PREFIX "/test_full2",
				systemd_login_test_full2);
	g_test_add_func(TEST_PREFIX "/test_full3",
				systemd_login_test_full3);
	g_test_add_func(TEST_PREFIX "/test_full4",
				systemd_login_test_full4);
	g_test_add_func(TEST_PREFIX "/test_error1",
				systemd_login_test_error1);
	g_test_add_func(TEST_PREFIX "/test_error2",
				systemd_login_test_error2);
	g_test_add_func(TEST_PREFIX "/test_error3",
				systemd_login_test_error3);
	g_test_add_func(TEST_PREFIX "/test_error4",
				systemd_login_test_error4);
	g_test_add_func(TEST_PREFIX "/test_error5",
				systemd_login_test_error5);
	g_test_add_func(TEST_PREFIX "/test_error6",
				systemd_login_test_error6);
	g_test_add_func(TEST_PREFIX "/test_error7",
				systemd_login_test_error7);
	g_test_add_func(TEST_PREFIX "/test_error8",
				systemd_login_test_error8);
	g_test_add_func(TEST_PREFIX "/test_error9",
				systemd_login_test_error9);
	g_test_add_func(TEST_PREFIX "/test_error10",
				systemd_login_test_error10);

	return g_test_run();
}
