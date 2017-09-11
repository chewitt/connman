/*
 *  Connection Manager
 *
 *  Copyright (C) 2014-2017 Jolla Ltd. All rights reserved.
 *  Contact: Hannu Mallat <hannu.mallat@jollamobile.com>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include <iphbd/libiphb.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"
#include "wakeup_timer.h"

#include "../src/connman.h"

#define CHUNK 4
#define MAX_COUNT 100
#define MAX_DELAY 20
#define TEST_TIMEOUT_SEC (30)

static GMainLoop *main_loop = NULL;
static guint test_timeout_id = 0;

extern struct connman_plugin_desc __connman_builtin_sailfish_wakeup_timer;

/*==========================================================================*
 * Stub IPHB calls to allow unit testing in development environment
 *==========================================================================*/

struct iphb_stub {
	int pipe_fd[2]; /* Pipe to nowhere */
};

iphb_t iphb_open(int *dummy)
{
	struct iphb_stub *stub = g_new0(struct iphb_stub, 1);

	g_assert(pipe(stub->pipe_fd) == 0);
	return stub;
}

int iphb_get_fd(iphb_t iphbh)
{
	struct iphb_stub *stub = iphbh;

	return stub->pipe_fd[0];
}

time_t iphb_wait2(iphb_t iphbh, unsigned mintime, unsigned maxtime,
			int must_wait, int resume)
{
	return 0;
}

int iphb_discard_wakeups(iphb_t iphbh)
{
	return 0;
}

iphb_t iphb_close(iphb_t iphbh)
{
	struct iphb_stub *stub = iphbh;

	close(stub->pipe_fd[0]);
	close(stub->pipe_fd[1]);
	g_free(stub);

	return NULL;
}

/*==========================================================================*
 * Code shared by all tests
 *==========================================================================*/

struct connman_wakeup_timer dummy_timer = {"Dummy", NULL, NULL};

static gboolean test_timeout_cb(gpointer user_data)
{
	connman_error("Timeout!");
	g_main_loop_quit(main_loop);
	test_timeout_id = 0;

	return G_SOURCE_REMOVE;
}

static void test_common_init()
{
	__connman_log_init("test-sailfish-wakeup-timer",
				g_test_verbose() ? "*" : NULL,
				FALSE, FALSE,
				"test-sailfish-wakeup-timer", "1");
	g_assert(connman_wakeup_timer_register(NULL) == (-EINVAL));
	g_assert(__connman_builtin_sailfish_wakeup_timer.init() == 0);
	g_assert(__connman_builtin_sailfish_wakeup_timer.init() == (-EALREADY));
	g_assert(connman_wakeup_timer_register(&dummy_timer) == (-EALREADY));

	main_loop = g_main_loop_new(NULL, FALSE);
	test_timeout_id = g_timeout_add_seconds(TEST_TIMEOUT_SEC,
						test_timeout_cb, NULL);
}

static void test_common_deinit()
{
	connman_wakeup_timer_unregister(NULL);
	connman_wakeup_timer_unregister(&dummy_timer);
	__connman_builtin_sailfish_wakeup_timer.exit();
	__connman_builtin_sailfish_wakeup_timer.exit();
	__connman_log_cleanup(FALSE);
	g_main_loop_unref(main_loop);
	g_assert(test_timeout_id);
	g_source_remove(test_timeout_id);
	test_timeout_id = 0;
	main_loop = NULL;
}

/*==========================================================================*
 * create-timeout-within-callback
 *==========================================================================*/

struct create_timeout_within_callback_data {
	guint timeouts_scheduled;
	guint timeouts_handled;
	guint timeouts_destroyed;
};

static void create_timeout_within_callback_notify(gpointer user_data)
{
	struct create_timeout_within_callback_data *data = user_data;

	data->timeouts_destroyed++;
}

static gboolean create_timeout_within_callback_cb(gpointer user_data)
{
	struct create_timeout_within_callback_data *data = user_data;
	int i;

	DBG("scheduled %d, handled %d", data->timeouts_scheduled,
						data->timeouts_handled);

	for (i = 0; i < CHUNK && data->timeouts_scheduled < MAX_COUNT; i++) {
		data->timeouts_scheduled++;
		g_assert(connman_wakeup_timer_add_full(G_PRIORITY_DEFAULT,
				g_test_rand_int_range(0, MAX_DELAY),
				create_timeout_within_callback_cb,
				user_data,
				create_timeout_within_callback_notify));
	}

	data->timeouts_handled++;
	if (data->timeouts_handled == MAX_COUNT) {
		DBG("Done, let's quit");
		g_main_loop_quit(main_loop);
	}

	return G_SOURCE_REMOVE;
}

static gboolean create_timeout_within_callback_seed(gpointer user_data)
{
	struct create_timeout_within_callback_data *data = user_data;
	int i;

	for (i = 0; i < CHUNK && data->timeouts_scheduled < MAX_COUNT; i++) {
		data->timeouts_scheduled++;
		g_assert(connman_wakeup_timer_add_full(G_PRIORITY_DEFAULT,
				g_test_rand_int_range(0, MAX_DELAY),
				create_timeout_within_callback_cb,
				user_data,
				create_timeout_within_callback_notify));
	}

	return G_SOURCE_REMOVE;
}

static void test_create_timeout_within_callback(void)
{
	struct create_timeout_within_callback_data data = {0};

	/* This one will schedule the regular glib callback */
	connman_wakeup_timer_add(0, create_timeout_within_callback_seed, &data);

	test_common_init();

	g_main_loop_run(main_loop);

	g_assert(data.timeouts_destroyed == data.timeouts_scheduled);
	test_common_deinit();
}

/*==========================================================================*
 * cancel-timeout-within-callback
 *==========================================================================*/

struct cancel_timeout_within_callback_data {
	guint timeout_to_cancel;
};

static gboolean cancel_timeout_done_cb(gpointer user_data)
{
	DBG("Done!");
	g_main_loop_quit(main_loop);
	return G_SOURCE_REMOVE;
}

static gboolean cancel_timeout_cb(gpointer user_data)
{
	struct cancel_timeout_within_callback_data *data = user_data;

	DBG("");
	g_assert(data->timeout_to_cancel);
	g_source_remove(data->timeout_to_cancel);
	data->timeout_to_cancel = 0;

	return G_SOURCE_REMOVE;
}

static gboolean cancelled_timeout_cb(gpointer user_data)
{
	g_assert(FALSE);
	return G_SOURCE_REMOVE;
}

static gboolean cancel_timeout_within_callback_go(gpointer user_data)
{
	struct cancel_timeout_within_callback_data *data = user_data;
	
	g_assert(connman_wakeup_timer_add(0, cancel_timeout_cb, user_data));

	data->timeout_to_cancel = connman_wakeup_timer_add(0,
					cancelled_timeout_cb, user_data);
	
	g_assert(connman_wakeup_timer_add(0, cancel_timeout_done_cb,
					user_data));

	return G_SOURCE_REMOVE;
}

static void test_cancel_timeout_within_callback(void)
{
	struct cancel_timeout_within_callback_data data = {0};

	/* This one will schedule the regular glib callback */
	connman_wakeup_timer_add(0, cancel_timeout_within_callback_go, &data);

	test_common_init();

	g_main_loop_run(main_loop);

	g_assert(!data.timeout_to_cancel);
	test_common_deinit();
}

/*==========================================================================*
 * timeout-order
 *==========================================================================*/

struct timeout_order_data {
	guint next_order;
	guint repeat_count;
};

struct timeout_order_param {
	struct timeout_order_data *data;
	guint order;
};

static gboolean timeout_order_done(gpointer user_data)
{
	DBG("Done, let's quit");
	g_main_loop_quit(main_loop);

	return G_SOURCE_REMOVE;
}

static gboolean timeout_repeat_cb(gpointer user_data)
{
	struct timeout_order_data *data = user_data;

	DBG("%u", data->repeat_count);
	data->repeat_count++;

	return G_SOURCE_CONTINUE;
}

static gboolean timeout_order_cb(gpointer user_data)
{
	struct timeout_order_param *param = user_data;

	DBG("%u", param->order);
	g_assert(param->order == param->data->next_order);
	param->data->next_order++;

	return G_SOURCE_REMOVE;
}

static guint timeout_order_submit(struct timeout_order_data *data,
						guint order, guint ms)
{
	struct timeout_order_param *param =
		g_new0(struct timeout_order_param, 1);

	param->data = data;
	param->order = order;

	return connman_wakeup_timer_add_full(G_PRIORITY_DEFAULT, ms,
					timeout_order_cb, param, g_free);
}

static gboolean timeout_order_start(gpointer user_data)
{
	struct timeout_order_data *data = user_data;
	int i;

	/* Schedule repeated timer. It will be destroyed by
	 * sailfish_wakeup_timer_exit */
	connman_wakeup_timer_add(1, timeout_repeat_cb, data);

	/* This one won't run */
	g_source_remove(connman_wakeup_timer_add_seconds(0,
						timeout_order_done, data));

	for (i = 0; i < 5; i++) {
		timeout_order_submit(data, i, i);
	}

	/* This one will stop the test */
	connman_wakeup_timer_add(i, timeout_order_done, data);

	return G_SOURCE_REMOVE;
}

static void test_timeout_order(void)
{
	struct timeout_order_data data = {0};

	/* This one will schedule the regular glib callback */
	connman_wakeup_timer_add_seconds(0, timeout_order_start, &data);

	test_common_init();

	g_main_loop_run(main_loop);

	g_assert(data.next_order == 5);
	g_assert(data.repeat_count > 1);

	test_common_deinit();
}

#define TEST_(name) "/wakeup-timer/" name

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func(TEST_("create-timeout-within-callback"),
			test_create_timeout_within_callback);
	g_test_add_func(TEST_("cancel-timeout-within-callback"),
			test_cancel_timeout_within_callback);
	g_test_add_func(TEST_("timeout-order"), test_timeout_order);

	return g_test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
