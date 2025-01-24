/*
 *  Connection Manager
 *
 *  Copyright (C) 2016-2018 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2016-2018 Slava Monich <slava.monich@jolla.com>
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

#include <gutil_strv.h>

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TEST_SUITE "datacounters"
#define TEST_(t) "/" TEST_SUITE "/" t

static const char *test_ident = "test";
static const char *test_ident2 = "test2";
static const char *test_counter = "home";
static const char *test_counter2 = "roaming";
static char *test_tmp_dir = "home";
static gint64 time_override_utc = 0;

GDateTime *test_time_now()
{
	return time_override_utc ?
		g_date_time_new_from_unix_utc(time_override_utc) :
		g_date_time_new_now_utc();
}

static char *test_service_dir()
{
	return g_strconcat(STORAGEDIR, "/", test_ident, NULL);
}

static char *test_counter_file()
{
	return g_strconcat(STORAGEDIR, "/", test_ident, "/stats.",
						test_counter, NULL);
}

static char *test_counter_file2()
{
	return g_strconcat(STORAGEDIR, "/", test_ident, "/stats.",
						test_counter2, NULL);
}

static void test_remove_counter_file()
{
	char *file = test_counter_file();

	remove(file);
	g_free(file);
}

static void test_remove_counter_file2()
{
	char *file = test_counter_file2();

	remove(file);
	g_free(file);
}

static void test_remove_counter_files()
{
	test_remove_counter_file();
	test_remove_counter_file2();
}

/* ==== /datacounters/null ==== */

static void test_datacounters_null()
{
	struct datacounters *counters;

	/* API calls should survive all kinds of NULL arguments */
	g_assert(!datacounters_new(NULL));
	g_assert(!datacounters_ref(NULL));
	datacounters_unref(NULL);
	g_assert(!datacounters_get_counter(NULL, NULL));
	g_assert(!datacounters_get_counter(NULL, test_counter));
	datacounters_reset_all_counters(NULL);
	g_assert(!datacounters_add_counters_handler(NULL, NULL, NULL));
	datacounters_remove_handler(NULL, 0);
	datacounters_remove_handlers(NULL, NULL, 0);

	/* Create and immediately deallocate the second one */
	counters = datacounters_new(test_ident);
	datacounters_unref(datacounters_new(test_ident2));

	/* NULL arguments other that the object pointer */
	datacounters_remove_handler(counters, 0);
	g_assert(!datacounters_get_counter(counters, NULL));
	g_assert(!datacounters_add_counters_handler(counters, NULL, NULL));
	datacounters_remove_handler(counters, 0);
	datacounters_remove_handlers(counters, NULL, 0);
	datacounters_unref(counters);
}

/* ==== /datacounters/basic ==== */

static void test_datacounters_cb(struct datacounters *counters, void *arg)
{
	int *count = arg;

	(*count)++;
}

static void test_datacounters_basic_reset_cb(struct datacounter *dc, void *arg)
{
	int *count = arg;

	(*count)++;
}

static void test_datacounters_basic()
{
	int reset_count = 0;
	int counters_changed_count = 0;
	struct datacounters *c = datacounters_new(test_ident);
	gulong dcid, cid = datacounters_add_counters_handler(c,
			test_datacounters_cb, &counters_changed_count);
	struct datacounter *dc = datacounters_get_counter(c, test_counter);
	struct datacounter *dc2 = datacounters_get_counter(c, test_counter2);

	/* Both datacounters_new calls actually return the same object */
	g_assert(datacounters_new(test_ident) == c);
	datacounters_unref(c);

	/* Only two counters should have been created */
	g_assert(counters_changed_count == 2);
	counters_changed_count = 0;

	/* Same goes for datacounters_get_counter */
	g_assert(datacounters_get_counter(c, test_counter) == dc);
	datacounter_unref(dc);

	/* Reset all counters (actually only one) */
	dcid = datacounter_add_reset_handler(dc,
			test_datacounters_basic_reset_cb, &reset_count);
	datacounters_reset_all_counters(c);
	datacounter_remove_handler(dc, dcid);
	g_assert(reset_count == 1);
	reset_count = 0;

	datacounters_remove_handler(c, cid);
	datacounters_unref(c);
	datacounter_unref(dc);
	datacounter_unref(dc2);
	test_remove_counter_files();
}

/* Common */

static void test_init(const char *pname)
{
	char *template = g_strconcat(pname, "_XXXXXX", NULL);
	char *service_dir;

	test_tmp_dir = g_dir_make_tmp(template, NULL);

	__connman_log_init(pname, g_test_verbose() ? "*" : NULL, FALSE, FALSE,
						pname, CONNMAN_VERSION);
	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_tmp_dir, ".local", 0755,
								0644), ==, 0);

	service_dir = test_service_dir();
	mkdir(STORAGEDIR, 0755);
	mkdir(service_dir, 0755);

	g_free(service_dir);
	g_free(template);
}

static void test_cleanup()
{
	char *service_dir = test_service_dir();

	test_remove_counter_files();
	remove(service_dir);
	remove(STORAGEDIR);
	remove(test_tmp_dir);

	__connman_log_cleanup(FALSE);
	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	g_free(service_dir);
	g_free(test_tmp_dir);
	test_tmp_dir = NULL;
}

int main(int argc, char *argv[])
{
	int ret;
	char *pname = g_path_get_basename(argv[0]);

	g_test_init(&argc, &argv, NULL);
	test_init(pname);
	g_test_add_func(TEST_("null"), test_datacounters_null);
	g_test_add_func(TEST_("basic"), test_datacounters_basic);
	ret = g_test_run();
	test_cleanup();
	g_free(pname);
	return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
