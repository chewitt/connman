/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd. All rights reserved.
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
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"
#include "wakeup_timer.h"

#define CHUNK 4
#define MAX_COUNT 100
#define MAX_DELAY 20

static GMainLoop *main_loop = NULL;

extern struct connman_plugin_desc __connman_builtin_jolla_wakeup_timer;

extern int __connman_log_init(const char *program, const char *debug,
			gboolean detach, gboolean backtrace,
			const char *program_name, const char *program_version);

static unsigned int timeouts_scheduled;
static unsigned int timeouts_handled;

static gboolean create_timeout_within_callback_cb(gpointer user_data)
{
	int i;

	DBG("scheduled %d, handled %d", timeouts_scheduled, timeouts_handled);

	for (i = 0; i < CHUNK && timeouts_scheduled < MAX_COUNT; i++) {
		timeouts_scheduled++;
		connman_wakeup_timer(G_PRIORITY_DEFAULT,
				g_test_rand_int_range(0, MAX_DELAY),
				create_timeout_within_callback_cb,
				NULL,
				NULL);
	}

	timeouts_handled++;
	if (timeouts_handled == MAX_COUNT) {
		DBG("Done, let's quit");
		g_main_loop_quit(main_loop);
	}

	return FALSE;
}

static gboolean create_timeout_within_callback_seed(gpointer user_data)
{
	int i;

	for (i = 0; i < CHUNK && timeouts_scheduled < MAX_COUNT; i++) {
		timeouts_scheduled++;
		connman_wakeup_timer(G_PRIORITY_DEFAULT,
				g_test_rand_int_range(0, MAX_DELAY),
				create_timeout_within_callback_cb,
				NULL,
				NULL);
	}

	return FALSE;
}

static void create_timeout_within_callback(void)
{
	timeouts_scheduled = 0;
	timeouts_handled = 0;

	main_loop = g_main_loop_new(NULL, FALSE);
	__connman_log_init("test-jolla-wakeup-timer",
				g_test_verbose() ? "*" : NULL,
				FALSE, FALSE,
				"test-jolla-wakeup-timer", "1");
	(__connman_builtin_jolla_wakeup_timer.init)();

	g_timeout_add(0, create_timeout_within_callback_seed, NULL);
	g_main_loop_run(main_loop);

	(__connman_builtin_jolla_wakeup_timer.exit)();
	g_main_loop_unref(main_loop);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/wakeup-timer/create-timeout-within-callback",
			create_timeout_within_callback);

	return g_test_run();
}
