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
#include "test_timenotify.h"

#include "connman.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TEST_SUITE "datacounter"
#define TEST_(t) "/" TEST_SUITE "/" t
#define TEST_TIMEOUT_SEC (30)

static const char *test_ident = "test";
static const char *test_counter = "home";
static char *test_tmp_dir;
static gint64 time_override_utc;

struct datacounter_file_contents_v1 {
	guint32 version;
	guint32 reserved;
	struct connman_stats_data total;
} __attribute__((packed));

struct test_loop {
	GMainLoop *loop;
	guint timeout_id;
};

#define ASSERT_DATA_EQUAL(data1,data2)  do { \
	g_assert((data1).rx_packets == (data2).rx_packets); \
	g_assert((data1).tx_packets == (data2).tx_packets); \
	g_assert((data1).rx_bytes == (data2).rx_bytes);     \
	g_assert((data1).tx_bytes == (data2).tx_bytes);     \
	g_assert((data1).rx_errors == (data2).rx_errors);   \
	g_assert((data1).tx_errors == (data2).tx_errors);   \
	g_assert((data1).rx_dropped == (data2).rx_dropped); \
	g_assert((data1).tx_dropped == (data2).tx_dropped); \
} while (false)

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

static void test_remove_counter_file()
{
	char *file = test_counter_file();

	remove(file);
	g_free(file);
}

static struct datacounter *test_counter_new()
{
	return datacounter_new(test_ident, test_counter);
}

static gboolean test_loop_quit(gpointer user_data)
{
	struct test_loop *test = user_data;

	DBG("timeout");
	test->timeout_id = 0;
	g_main_loop_quit(test->loop);
	return G_SOURCE_REMOVE;
}

static void test_loop_init(struct test_loop *test)
{
	test->loop = g_main_loop_new(NULL, FALSE);
	test->timeout_id = g_timeout_add_seconds(TEST_TIMEOUT_SEC,
						test_loop_quit, test);
}

static void test_loop_destroy(struct test_loop *test)
{
	if (test->timeout_id) {
		g_source_remove(test->timeout_id);
		test->timeout_id = 0;
	}
	if (test->loop) {
		g_main_loop_unref(test->loop);
		test->loop = NULL;
	}
}

static void test_datacounter_loop_quit_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	g_main_loop_quit(arg);
}

/* ==== /datacounter/null ==== */

static void test_datacounter_null()
{
	struct datacounter *dc;

	/* API calls should survive all kinds of NULL arguments */
	g_assert(!datacounter_ref(NULL));
	datacounter_unref(NULL);
	datacounter_reset(NULL);
	datacounter_reset_baseline(NULL);
	datacounter_rebase(NULL, NULL);
	datacounter_update(NULL, NULL);
	g_assert(!datacounter_reset_time(NULL));
	g_assert(!datacounter_baseline_reset_time(NULL));
	g_assert(!datacounter_data_warning(NULL));
	datacounter_set_data_warning(NULL, 0);
	g_assert(!datacounter_data_limit(NULL));
	datacounter_set_data_limit(NULL, 0);
	datacounter_set_time_limit(NULL, NULL);
	datacounter_set_time_limit_enabled(NULL, TRUE);
	g_assert(!datacounter_time_limit_enabled(NULL));
	g_assert(!datacounter_cutoff_enabled(NULL));
	datacounter_set_cutoff_enabled(NULL, FALSE);
	g_assert(!datacounter_autoreset_enabled(NULL));
	datacounter_set_autoreset_enabled(NULL, FALSE);
	datacounter_set_autoreset(NULL, NULL);
	g_assert(!datacounter_format_time(NULL, NULL));
	g_assert(!datacounter_format_time_now(NULL));
	g_assert(!datacounter_add_reset_handler(NULL, NULL, NULL));
	g_assert(!datacounter_add_update_handler(NULL, NULL, NULL));
	g_assert(!datacounter_add_property_handler(NULL,
				DATACOUNTER_PROPERTY_ANY, NULL, NULL));
	datacounter_remove_handler(NULL, 0);
	datacounter_remove_handlers(NULL, NULL, 0);

	/* NULL arguments other that the object pointer */
	dc = test_counter_new();
	datacounter_remove_handler(dc, 0);
	datacounter_set_autoreset(dc, NULL);
	datacounter_set_time_limit(dc, NULL);
	g_assert(!datacounter_add_reset_handler(dc, NULL, NULL));
	g_assert(!datacounter_add_update_handler(dc, NULL, NULL));
	g_assert(!datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_ANY, NULL, NULL));
	datacounter_remove_handler(dc, 0);
	datacounter_remove_handlers(dc, NULL, 0);
	datacounter_unref(dc);
}

/* ==== /datacounter/basic ==== */

static void test_datacounter_basic_reset_cb(struct datacounter *dc, void *arg)
{
	int *count = arg;

	(*count)++;
}

static void test_datacounter_basic_update_cb(struct datacounter *counter,
	const struct connman_stats_data *change, GDateTime *time, void *arg)
{
	int *count = arg;

	(*count)++;
}

static void test_datacounter_basic()
{
	struct datacounter_timer autoreset;
	struct connman_stats_data data, data2;
	struct datacounter *dc;
	char *file = test_counter_file();
	int reset_count = 0, update_count = 0;
	const char *tstr;
	const char *strnow;
	GDateTime *t;
	gulong id[2];

	/* Test how datacounters_validate_timer handles invalid values. */
	memset(&autoreset, 0, sizeof(autoreset));
	autoreset.unit = TIME_UNITS;
	autoreset.at[TIME_UNIT_SECOND] = 60;
	autoreset.at[TIME_UNIT_HOUR] = 24;
	autoreset.at[TIME_UNIT_MONTH] = 13;
	datacounters_validate_timer(&autoreset);
	g_assert(autoreset.value == 1);
	g_assert(autoreset.unit == TIME_UNIT_DEFAULT);
	g_assert(autoreset.at[TIME_UNIT_SECOND] == 59);
	g_assert(autoreset.at[TIME_UNIT_MINUTE] == 0);
	g_assert(autoreset.at[TIME_UNIT_HOUR] == 23);
	g_assert(autoreset.at[TIME_UNIT_DAY] == 1);
	/* Month gets reset to the minimum value */
	g_assert(autoreset.at[TIME_UNIT_MONTH] == 1);

	autoreset.unit = -1;
	autoreset.at[TIME_UNIT_MONTH] = 0;
	datacounters_validate_timer(&autoreset);
	g_assert(autoreset.unit == TIME_UNIT_DEFAULT);
	g_assert(autoreset.at[TIME_UNIT_MONTH] == 1);

	/* Create a counter and save it */
	dc = test_counter_new();
	id[0] = datacounter_add_reset_handler(dc,
			test_datacounter_basic_reset_cb, &reset_count);
	id[1] = datacounter_add_update_handler(dc,
			test_datacounter_basic_update_cb, &update_count);
	datacounter_reset(dc);
	datacounter_reset_baseline(dc);
	datacounter_rebase(dc, NULL);
	memset(&data, 0, sizeof(data));
	data.rx_packets = data.tx_packets = 1;
	data.rx_bytes = 2048;
	data.tx_bytes = 4096;
	datacounter_update(dc, &data);
	datacounter_reset_baseline(dc);

	/* Assert that callbacks have been invoked */
	datacounter_remove_handlers(dc, id, G_N_ELEMENTS(id));
	g_assert(reset_count == 1);
	g_assert(update_count == 1);

	/* Time formatting (strings are deallocated later by dc) */
	g_assert(!datacounter_format_time(dc, NULL));
	t = g_date_time_new_from_unix_utc(0);
	tstr = datacounter_format_time(dc, t);
	g_date_time_unref(t);
	DBG("%s", tstr);
	g_assert(!strcmp(tstr, "1970-01-01 00:00:00 +0000"));

	time_override_utc = 60;
	t = datacounters_time_now();
	tstr = datacounter_format_time(dc, t);
	strnow = datacounter_format_time_now(dc);
	g_date_time_unref(t);
	DBG("%s", tstr);
	g_assert(!strcmp(tstr, "1970-01-01 00:01:00 +0000"));
	g_assert(!strcmp(tstr, strnow));
	time_override_utc = 0;

	/* Test extra ref/unref */
	datacounter_ref(dc);
	datacounter_unref(dc);
	datacounter_unref(dc);

	/* This one should read the file we have just written */
	dc = test_counter_new();
	ASSERT_DATA_EQUAL((*dc->value), data);
	datacounter_rebase(dc, &data);
	datacounter_unref(dc);

	/* Load the same file with datacounter_file_load */
	g_assert(datacounter_file_load(test_ident, test_counter, &data2));
	ASSERT_DATA_EQUAL(data2, data);

	/* Clear it and expect to load zeros from there */
	datacounter_file_clear(test_ident, test_counter);
	g_assert(datacounter_file_load(test_ident, test_counter, &data2));
	g_assert(!data2.rx_packets);
	g_assert(!data2.tx_packets);
	g_assert(!data2.rx_bytes);
	g_assert(!data2.tx_bytes);
	g_assert(!data2.rx_errors);
	g_assert(!data2.tx_errors);
	g_assert(!data2.rx_dropped);
	g_assert(!data2.tx_dropped);

	/* Remove the file */
	remove(file);

	/* Now we should fail to load it */
	g_assert(!datacounter_file_load(test_ident, test_counter, &data));
	g_assert(!data.rx_packets);
	g_assert(!data.tx_packets);
	g_assert(!data.rx_bytes);
	g_assert(!data.tx_bytes);
	g_assert(!data.rx_errors);
	g_assert(!data.tx_errors);
	g_assert(!data.rx_dropped);
	g_assert(!data.tx_dropped);

	/* This does nothing, just improves branch coverage */
	datacounter_file_clear(test_ident, test_counter);
	g_free(file);
}

/* ==== /datacounter/nodir ==== */

static void test_datacounter_nodir()
{
	char *dir = test_service_dir();
	struct datacounter *dc;

	/* Remove the service dir */
	test_remove_counter_file();
	remove(dir);

	/*
	 * datacounter fails to save the file. Not sure that this is the
	 * right behavior but it is what it is.
	 */
	dc = test_counter_new();
	datacounter_reset(dc);
	datacounter_unref(dc);
	g_assert(!datacounter_file_load(test_ident, test_counter, NULL));

	/* Undo the damage */
	mkdir(dir, 0755);
	g_free(dir);
}

/* ==== /datacounter/badfile ==== */

static void test_datacounter_badfile()
{
	char *file = test_counter_file();
	struct datacounter *dc;
	struct datacounter_file_contents_v1 v1;
	struct datacounter_file_contents_v1 *ptr;
	gchar *contents;
	gsize length;

	/* Invalid contents */
	memset(&v1, 0, sizeof(v1));
	g_assert(g_file_set_contents(file, (void*)&v1, sizeof(v1), NULL));
	g_assert(!datacounter_file_load(test_ident, test_counter, NULL));

	/* Short file */
	g_assert(g_file_set_contents(file, (void*)&v1, sizeof(v1)-1, NULL));
	g_assert(!datacounter_file_load(test_ident, test_counter, NULL));

	/* Create the new file */
	remove(file);
	dc = test_counter_new();
	datacounter_reset(dc);
	datacounter_unref(dc);

	/* Increment the version and it should fail to load */
	g_assert(g_file_get_contents(file, &contents, &length, NULL));
	g_assert(length > sizeof(*ptr));
	ptr = (void*)contents;
	ptr->version++;
	g_assert(g_file_set_contents(file, contents, length, NULL));
	g_assert(!datacounter_file_load(test_ident, test_counter, NULL));
	g_free(contents);

	/* Undo the damage */
	remove(file);
	g_free(file);
}

/* ==== /datacounter/oldfile ==== */

static void test_datacounter_oldfile()
{
	char *file = test_counter_file();
	struct datacounter_file_contents_v1 v1;
	struct datacounter *dc;

	/* Write file in the old format */
	memset(&v1, 0, sizeof(v1));
	v1.version = 1;
	v1.total.rx_packets = 2;
	v1.total.tx_packets = 3;
	v1.total.rx_bytes = 4;
	v1.total.tx_bytes = 5;
	v1.total.rx_errors = 6;
	v1.total.tx_errors = 7;
	v1.total.rx_dropped = 8;
	v1.total.tx_dropped = 9;
	g_assert(g_file_set_contents(file, (void*)&v1, sizeof(v1), NULL));

	/* Stop the time and load it back */
	time_override_utc = datacounters_now();
	dc = test_counter_new();
	g_assert(!datacounter_reset_time(dc));
	g_assert(!datacounter_data_warning(dc));
	g_assert(!datacounter_data_limit(dc));
	g_assert(!datacounter_time_limit_enabled(dc));
	g_assert(!datacounter_cutoff_enabled(dc));
	g_assert(!datacounter_autoreset_enabled(dc));
	g_assert(datacounter_baseline_reset_time(dc) == time_override_utc);
	ASSERT_DATA_EQUAL((*dc->value), v1.total);
	datacounter_unref(dc);

	/* Undo the damage */
	time_override_utc = 0;
	remove(file);
	g_free(file);
}

/* ==== /datacounter/baseline ==== */

static void test_datacounter_baseline_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	(*count)++;
}

static void test_datacounter_baseline_value_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_BASELINE);
	(*count)++;
}

static void test_datacounter_baseline_reset_time_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_BASELINE_RESET_TIME);
	(*count)++;
}

static void test_datacounter_baseline()
{
	struct connman_stats_data data;
	struct datacounter *dc;
	int property_changed = 0;
	int baseline_value_changed = 0;
	int baseline_reset_time_changed = 0;
	gulong ids[3];

	time_override_utc = datacounters_now();
	memset(&data, 0, sizeof(data));

	/* Create a counter update it and reset the baseline */
	dc = test_counter_new();
	datacounter_reset(dc);
	datacounter_rebase(dc, &data);
	datacounter_reset_baseline(dc);

	/* Register the handlers, update, change time and reset again */
	ids[0] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_ANY,
				test_datacounter_baseline_cb,
				&property_changed);
	ids[1] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_BASELINE,
				test_datacounter_baseline_value_cb,
				&baseline_value_changed);
	ids[2] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_BASELINE_RESET_TIME,
				test_datacounter_baseline_reset_time_cb,
				&baseline_reset_time_changed);
	time_override_utc++;
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);
	datacounter_update(dc, &data); /* to improve branch coverage */
	datacounter_reset_baseline(dc);

	/*
	 * Validate the number of times callbacks have been invoked.
	 * The following changes should have occured: value, baseline
	 * and baseline reset time. So the "catch all" handler should
	 * be invoked 3 times, specific handlers - one time each.
	 */
	g_assert(property_changed == 3);
	g_assert(baseline_value_changed == 1);
	g_assert(baseline_reset_time_changed == 1);

	property_changed = 0;
	baseline_value_changed = 0;
	baseline_reset_time_changed = 0;

	/*
	 * This reset should cause 4 property changes: value, baseline,
	 * reset time and baseline reset time.
	 */
	time_override_utc++;
	datacounter_reset(dc);
	g_assert(property_changed == 4);
	g_assert(baseline_value_changed == 1);
	g_assert(baseline_reset_time_changed == 1);

	property_changed = 0;
	baseline_value_changed = 0;
	baseline_reset_time_changed = 0;

	/* And another reset - no changes at all */
	datacounter_reset(dc);
	g_assert(!property_changed);
	g_assert(!baseline_value_changed);
	g_assert(!baseline_reset_time_changed);

	/* Remove the handlers and do it again, counters shouldn't change */
	datacounter_remove_handlers(dc, ids, G_N_ELEMENTS(ids));
	time_override_utc++;
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);
	datacounter_reset_baseline(dc);
	g_assert(!property_changed);
	g_assert(!baseline_value_changed);
	g_assert(!baseline_reset_time_changed);

	/* Done */
	datacounter_unref(dc);

	/* Undo the damage */
	time_override_utc = 0;
	test_remove_counter_file();
}

/* ==== /datacounter/autoreset ==== */

static void test_datacounter_autoreset_any_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	DBG("%d", property);
	(*count)++;
}

static void test_datacounter_autoreset_enabled_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_AUTORESET_ENABLED);
	(*count)++;
}

static void test_datacounter_autoreset_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_AUTORESET);
	(*count)++;
}

static void test_datacounter_autoreset()
{
	struct datacounter *dc;
	struct connman_stats_data data;
	int property_changed = 0;
	int autoreset_enabled_changed = 0;
	int autoreset_changed = 0;
	struct datacounter_timer autoreset;
	GUtilTimeNotify *time_notify = test_time_notify_new();
	struct test_loop test;
	gulong ids[3], loop_quit_id;

	time_override_utc = datacounters_now()-1;
	memset(&data, 0, sizeof(data));
	memset(&autoreset, 0, sizeof(autoreset));
	autoreset.unit = TIME_UNIT_YEAR;

	/* Create a counter update it and reset everything */
	dc = test_counter_new();
	datacounter_reset(dc);
	datacounter_rebase(dc, &data);
	datacounter_reset_baseline(dc);
	datacounter_set_autoreset_enabled(dc, FALSE);
	datacounter_set_autoreset(dc, &autoreset);
	autoreset = *dc->autoreset;

	/* Register the handlers, enable autoreset */
	ids[0] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_ANY,
				test_datacounter_autoreset_any_cb,
				&property_changed);
	ids[1] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_AUTORESET_ENABLED,
				test_datacounter_autoreset_enabled_cb,
				&autoreset_enabled_changed);
	ids[2] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_AUTORESET,
				test_datacounter_autoreset_cb,
				&autoreset_changed);

	autoreset.unit = TIME_UNIT_SECOND;
	datacounter_set_autoreset(dc, &autoreset);
	datacounter_set_autoreset(dc, &autoreset);
	datacounter_set_autoreset_enabled(dc, TRUE);
	g_assert(datacounter_autoreset_enabled(dc));
	g_assert(property_changed == 2);
	g_assert(autoreset_enabled_changed == 1);
	g_assert(autoreset_changed == 1);

	property_changed = 0;
	autoreset_enabled_changed = 0;
	autoreset_changed = 0;

	/* Simulate system time change. Baseline gets reset */
	time_override_utc++;
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);
	test_time_notify_signal(time_notify);
	g_assert(!memcmp(dc->baseline, &data, sizeof(data)));
	g_assert(property_changed == 3); /* value, baseline and reset time */
	property_changed = 0;

	/* Disable autoreset (twice), count the notifications (one) */
	datacounter_set_autoreset_enabled(dc, FALSE);
	datacounter_set_autoreset_enabled(dc, FALSE);
	g_assert(!datacounter_autoreset_enabled(dc));
	g_assert(property_changed == 1);
	g_assert(autoreset_enabled_changed == 1);
	g_assert(!autoreset_changed);

	property_changed = 0;
	autoreset_enabled_changed = 0;

	/*
	 * Make sure that autoreset actually happens in 1 sec. We quit
	 * the loop when PROPERTY_BASELINE_RESET_TIME changes meaning
	 * that autoreset has happened.
	 */
	time_override_utc = 0;
	test_time_notify_signal(time_notify);
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	property_changed = 0;
	datacounter_update(dc, &data);
	datacounter_set_autoreset_enabled(dc, TRUE);
	test_loop_init(&test);
	loop_quit_id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_BASELINE_RESET_TIME,
				test_datacounter_loop_quit_cb, test.loop);
	g_main_loop_run(test.loop);

	/*
	 * 4 property changes happen before we quit the loop:
	 *
	 * 1. DATACOUNTER_PROPERTY_VALUE
	 * 2. DATACOUNTER_PROPERTY_AUTORESET_ENABLED
	 * 3. DATACOUNTER_PROPERTY_BASELINE
	 * 4. DATACOUNTER_PROPERTY_BASELINE_RESET_TIME
	 */
	g_assert(test.timeout_id);
	g_assert(property_changed >= 4);
	datacounter_remove_handler(dc, loop_quit_id);
	test_loop_destroy(&test);

	/* Done */
	datacounter_remove_handlers(dc, ids, G_N_ELEMENTS(ids));
	datacounter_unref(dc);
	test_time_notify_unref(time_notify);

	/* Undo the damage */
	time_override_utc = 0;
	test_remove_counter_file();
}

/* ==== /datacounter/autoreset2 ==== */

static const struct test_autoreset2 {
	guint u1[TIME_UNITS];
	guint u2[TIME_UNITS];
	struct datacounter_timer config;
	gint64 step1;
	gint64 step2;
} tests_autoreset2 [] = {
	{
		{0, 0, 0, 1, 1, 2016},
		{1, 0, 0, 1, 1, 2016},
		{1, TIME_UNIT_SECOND, {0}},
		0, 1
	},{
		{0, 0, 0, 1, 1, 2016},
		{0, 1, 0, 1, 1, 2016},
		{1, TIME_UNIT_MINUTE, {0}},
		59, 1
	},{
		{0, 0, 0, 1, 1, 2016},
		{2, 0, 0, 1, 1, 2016},
		{1, TIME_UNIT_MINUTE, {2}},
		1, 1
	},{
		{0, 0, 0, 1, 2, 2016},
		{1, 0, 0, 29, 2, 2016},
		{1, TIME_UNIT_MONTH, {0, 0, 0, 31}},
		2419199 /* 28 days - 1 sec*/,  2
	},{
		{0, 0, 0, 31, 1, 2016},
		{0, 0, 5, 29, 2, 2016},
		{1, TIME_UNIT_MONTH, {0, 0, 5, 30}},
		2523599 /* 29 days + 5 hours - 1 sec*/,  1
	}
};

static void test_datacounter_autoreset2_reset_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_BASELINE_RESET_TIME);
	(*count)++;
}

static void test_datacounter_autoreset2(gconstpointer test_data)
{
	const struct test_autoreset2 *test = test_data;
	GTimeZone *utc = g_time_zone_new_utc();
	GTimeZone *local = g_time_zone_new_local();
	struct datacounter *dc;
	guint units[TIME_UNITS];
	int reset_count = 0;
	gulong id;
	GDateTime *t1 = datacounters_time_from_units(local, test->u1);
	GDateTime *utc1 = g_date_time_to_timezone(t1, utc);
	GDateTime *t2;
	GDateTime *utc2;

	time_override_utc = g_date_time_to_unix(utc1);

	dc = test_counter_new();
	DBG("%s", datacounter_format_time(dc, utc1));

	datacounter_set_autoreset_enabled(dc, FALSE);
	datacounter_set_autoreset(dc, &test->config);
	datacounter_reset(dc);
	id = datacounter_add_property_handler(dc, DATACOUNTER_PROPERTY_BASELINE_RESET_TIME,
				test_datacounter_autoreset2_reset_cb, &reset_count);

	/* Move the time ahead. Nothing happens */
	time_override_utc += test->step1;
	datacounter_set_autoreset_enabled(dc, FALSE);
	datacounter_set_autoreset_enabled(dc, TRUE);
	g_assert(!reset_count);

	/* Move the time ahead again. Now reset should happen */
	time_override_utc += test->step2;
	datacounter_set_autoreset_enabled(dc, FALSE);
	datacounter_set_autoreset_enabled(dc, TRUE);
	g_assert(reset_count == 1);

		/* Make sure autoreset has happened at the right time */
	utc2 = g_date_time_new_from_unix_utc(datacounter_baseline_reset_time(dc));
	t2 = g_date_time_to_timezone(utc2, local);
	datacounters_time_to_units(units, t2);
	g_assert(!memcmp(units, test->u2, sizeof(units)));

	/* Done with this test */
	datacounter_remove_handler(dc, id);
	datacounter_unref(dc);
	g_date_time_unref(t1);
	g_date_time_unref(t2);
	g_date_time_unref(utc1);
	g_date_time_unref(utc2);
	test_remove_counter_file();

	g_time_zone_unref(utc);
	g_time_zone_unref(local);

	/* Undo the damage */
	time_override_utc = 0;
}

/* ==== /datacounter/autoreset3 ==== */

static void test_datacounter_autoreset3()
{
	struct datacounter *dc;
	struct datacounter_timer autoreset;
	struct test_loop test;
	gulong loop_quit_id;

	/* Schedule autoreset in 1 sec. */
	memset(&autoreset, 0, sizeof(autoreset));
	autoreset.value = 1;
	autoreset.unit = TIME_UNIT_SECOND;

	/* Create a counter and destroy it (to test all code branches) */
	dc = test_counter_new();
	datacounter_set_autoreset(dc, &autoreset);
	datacounter_set_autoreset_enabled(dc, TRUE);
	datacounter_unref(dc);

	/* This one we will actually exercise */
	test_remove_counter_file();
	dc = test_counter_new();

	/*
	 * Schedule autoreset. Enable/disable it twice to check
	 * for memory leaks.
	 */
	datacounter_set_autoreset(dc, &autoreset);
	datacounter_set_autoreset_enabled(dc, TRUE);
	datacounter_set_autoreset_enabled(dc, FALSE);
	datacounter_set_autoreset_enabled(dc, TRUE);

	/* Run the event loop */
	test_loop_init(&test);
	loop_quit_id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_BASELINE_RESET_TIME,
				test_datacounter_loop_quit_cb, test.loop);
	g_main_loop_run(test.loop);
	g_assert(test.timeout_id);
	test_loop_destroy(&test);

	/* Done */
	datacounter_remove_handler(dc, loop_quit_id);
	datacounter_unref(dc);
	test_remove_counter_file();
}

/* ==== /datacounter/save ==== */

static gboolean test_datacounter_save_loop_quit_cb(gpointer loop)
{
	g_main_loop_quit(loop);
	return G_SOURCE_CONTINUE;
}

static void test_datacounter_save()
{
	struct datacounter *dc;
	struct connman_stats_data data, data2, data_file;
	struct test_loop test;
	guint id;

	test_remove_counter_file();
	memset(&data, 0, sizeof(data));

	dc = test_counter_new();

	/* At this point even the smallest change will be saved right away */
	data.rx_packets++;
	data.rx_bytes += 1;
	datacounter_update(dc, &data);

	/* Verify the save */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data);

	/* This ia a major change, but we will have to wait */
	data2 = data;
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);

	/* Validate that the content of the file didn't change */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data2);

	/* Run the event loop */
	test_loop_init(&test);
	id = g_timeout_add_seconds(STATS_SHORT_WRITE_PERIOD_SEC + 1,
			test_datacounter_save_loop_quit_cb, test.loop);
	g_main_loop_run(test.loop);
	g_source_remove(id);
	test_loop_destroy(&test);

	/* Verify the save (by now it should have been saved) */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data);

	/*
	 * Short write timeout has expired, now significant changes
	 * get saved right away
	 */
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);

	/* Verify the save */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data);

	/* Insignificant change will get saved after long timeout */
	data2 = data;
	data.rx_packets++;
	data.rx_bytes += 1;
	datacounter_update(dc, &data);
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data2);

	/* Run the (short) event loop */
	test_loop_init(&test);
	id = g_timeout_add_seconds(STATS_SHORT_WRITE_PERIOD_SEC + 1,
			test_datacounter_save_loop_quit_cb, test.loop);
	g_main_loop_run(test.loop);
	g_source_remove(id);
	test_loop_destroy(&test);

	/* Data still shouldn't be saved */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data2);

	/* Run another (long) event loop */
	test_loop_init(&test);
	id = g_timeout_add_seconds(STATS_LONG_WRITE_PERIOD_SEC + 1,
			test_datacounter_save_loop_quit_cb, test.loop);
	g_main_loop_run(test.loop);
	g_source_remove(id);
	test_loop_destroy(&test);

	/* Verify the save (by now it should have been saved) */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data);

	/* At this point even the smallest change will be saved right away */
	data.rx_packets++;
	data.rx_bytes += 1;
	datacounter_update(dc, &data);

	/* Verify the save */
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data);

	/* Now insignificant changes don't get saved */
	data2 = data;
	data.rx_packets++;
	data.rx_bytes += 1;
	datacounter_update(dc, &data);
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data2);

	/* But they do get saved when we destroy the object */
	datacounter_unref(dc);
	g_assert(datacounter_file_load(test_ident, test_counter, &data_file));
	ASSERT_DATA_EQUAL(data_file, data);

	/* Undo the damage */
	test_remove_counter_file();
}

/* ==== /datacounter/limit ==== */

static void test_datacounter_limit_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_DATA_LIMIT);
	(*count)++;
}

static void test_datacounter_limit()
{
	struct datacounter *dc;
	const guint64 limit = 1024;
	int limit_changed = 0;
	gulong id;

	dc = test_counter_new();
	datacounter_set_data_limit(dc, 0);
	id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_DATA_LIMIT,
				test_datacounter_limit_cb,
				&limit_changed);
	/*
	 * Even though we set the limit twice the handler should only
	 * be invoked once because the second time it's the same value.
	 */
	datacounter_set_data_limit(dc, limit);
	datacounter_set_data_limit(dc, limit);
	g_assert(limit_changed == 1);
	g_assert(datacounter_data_limit(dc) == limit);

	/* Done */
	datacounter_remove_handler(dc, id);
	datacounter_unref(dc);

	/* Undo the damage */
	test_remove_counter_file();
}

/* ==== /datacounter/warning ==== */

static void test_datacounter_warning_cutoff_state_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_CUTOFF_STATE);
	(*count)++;
}

static void test_datacounter_warning_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_DATA_WARNING);
	(*count)++;
}

static void test_datacounter_warning()
{
	struct datacounter *dc;
	const guint64 warning = 1024;
	struct connman_stats_data data;
	int warning_changed = 0;
	int state_changed = 0;
	gulong id[2];

	memset(&data, 0, sizeof(data));

	dc = test_counter_new();
	datacounter_set_data_warning(dc, 0);
	datacounter_set_data_limit(dc, 0);
	datacounter_set_time_limit_enabled(dc, FALSE);
	datacounter_set_cutoff_enabled(dc, TRUE);
	g_assert(dc->cutoff_state == CUTOFF_NO_LIMIT);

	id[0] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_CUTOFF_STATE,
				test_datacounter_warning_cutoff_state_cb,
				&state_changed);
	id[1] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_DATA_WARNING,
				test_datacounter_warning_cb,
				&warning_changed);
	/*
	 * Even though we set the overdraft twice the handler should only
	 * be invoked once because the second time it's the same value.
	 * The cutoff state should change to CUTOFF_BELOW_LIMIT.
	 */
	datacounter_set_data_warning(dc, warning);
	datacounter_set_data_warning(dc, warning);
	g_assert(datacounter_data_warning(dc) == warning);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(warning_changed == 1);
	g_assert(state_changed == 1);
	warning_changed = 0;
	state_changed = 0;

	/* Cross the warning boundary */
	data.rx_packets++;
	data.rx_bytes += warning;
	datacounter_update(dc, &data);
	g_assert(dc->cutoff_state == CUTOFF_WARNING);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* Done */
	datacounter_remove_handlers(dc, id, G_N_ELEMENTS(id));
	datacounter_unref(dc);

	/* Undo the damage */
	test_remove_counter_file();
}

/* ==== /datacounter/cutoff ==== */

static void test_datacounter_cutoff_enabled_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_CUTOFF_ENABLED);
	(*count)++;
}

static void test_datacounter_cutoff_state_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_CUTOFF_STATE);
	(*count)++;
}

static void test_datacounter_cutoff()
{
	struct datacounter *dc;
	struct connman_stats_data data;
	const guint64 chunk = 1024;
	const guint64 warning = chunk;
	const guint64 limit = 2*chunk;
	int state_changed = 0;
	int cutoff_enabled_changed = 0;
	gulong id;

	dc = test_counter_new();
	datacounter_reset(dc);
	datacounter_set_data_warning(dc, warning);
	datacounter_set_data_limit(dc, limit);

	/* Test the "enabled" state notification */
	datacounter_set_cutoff_enabled(dc, FALSE);
	g_assert(!datacounter_cutoff_enabled(dc));
	g_assert(dc->cutoff_state == CUTOFF_DISABLED);
	id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_CUTOFF_ENABLED,
				test_datacounter_cutoff_enabled_cb,
				&cutoff_enabled_changed);
	datacounter_set_cutoff_enabled(dc, TRUE);
	g_assert(datacounter_cutoff_enabled(dc));
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(cutoff_enabled_changed == 1);
	cutoff_enabled_changed = 0;
	datacounter_remove_handler(dc, id);

	id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_CUTOFF_STATE,
				test_datacounter_cutoff_state_cb,
				&state_changed);

	/* Receive one byte less than warning level, nothing should happen */
	memset(&data, 0, sizeof(data));
	data.rx_packets++;
	data.rx_bytes += warning - 1;
	datacounter_update(dc, &data);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(!state_changed);

	/* Transmit one more byte and we should get a warning */
	data.tx_packets++;
	data.tx_bytes += 1;
	datacounter_update(dc, &data);
	g_assert(dc->cutoff_state == CUTOFF_WARNING);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* Disable the warning */
	datacounter_set_data_warning(dc, 0);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* Make warning larger that the limit. That essentially disables it */
	datacounter_set_data_warning(dc, limit+1);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(!state_changed);

	/* Receive one byte less than the limit, nothing should happen */
	data.rx_packets++;
	data.rx_bytes += (limit - warning) - 1;
	datacounter_update(dc, &data);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(!state_changed);

	/* Transmit one more byte and we should hit the limit */
	data.tx_packets++;
	data.tx_bytes += 1;
	datacounter_update(dc, &data);
	g_assert(dc->cutoff_state == CUTOFF_ACTIVATED);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* Disable the limit, we still below the warning level */
	datacounter_set_data_limit(dc, 0);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* And warning too */
	datacounter_set_data_warning(dc, 0);
	g_assert(dc->cutoff_state == CUTOFF_NO_LIMIT);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* Finally turn it off (twice) */
	datacounter_set_cutoff_enabled(dc, FALSE);
	datacounter_set_cutoff_enabled(dc, FALSE);
	g_assert(dc->cutoff_state == CUTOFF_DISABLED);
	g_assert(state_changed == 1);
	state_changed = 0;

	/* Done */
	datacounter_remove_handler(dc, id);
	datacounter_unref(dc);

	/* Undo the damage */
	test_remove_counter_file();
}

/* ==== /datacounter/timelimit ==== */

static void test_datacounter_timelimit_enabled_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED);
	(*count)++;
}

static void test_datacounter_timelimit()
{
	struct datacounter *dc;
	struct datacounter_timer timer;
	int time_limit_enabled_changed = 0;
	gulong id;

	dc = test_counter_new();

	/* Test the "enabled" state notification */
	datacounter_set_time_limit_enabled(dc, FALSE);
	g_assert(!datacounter_time_limit_enabled(dc));
	id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED,
				test_datacounter_timelimit_enabled_cb,
				&time_limit_enabled_changed);
	datacounter_set_time_limit_enabled(dc, TRUE);
	g_assert(datacounter_time_limit_enabled(dc));
	g_assert(time_limit_enabled_changed == 1);
	time_limit_enabled_changed = 0;
	datacounter_remove_handler(dc, id);

	/* Stop the time */
	time_override_utc = datacounters_now();
	datacounter_reset(dc);

	/* Set time limit to 1 sec. */
	memset(&timer, 0, sizeof(timer));
	timer.value = 1;
	timer.unit = TIME_UNIT_SECOND;
	datacounter_set_time_limit(dc, &timer);
	datacounter_set_time_limit_enabled(dc, TRUE);
	datacounter_set_cutoff_enabled(dc, TRUE);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
	datacounter_set_time_limit_enabled(dc, FALSE);
	g_assert(dc->cutoff_state == CUTOFF_NO_LIMIT);

	/* Overshoot the limit by 1 sec, cutoff should get activated */
	time_override_utc += 2;
	datacounter_set_time_limit_enabled(dc, TRUE);
	g_assert(dc->cutoff_state == CUTOFF_ACTIVATED);

	/* Done */
	datacounter_unref(dc);

	/* Undo the damage */
	test_remove_counter_file();
	time_override_utc = 0;
}

/* ==== /datacounter/timelimit2 ==== */

static void test_datacounter_timelimit2_state_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_CUTOFF_STATE);
	(*count)++;
}

static void test_datacounter_timelimit2_enabled_cb(struct datacounter *dc,
			enum datacounter_property property, void *arg)
{
	int *count = arg;

	g_assert(property == DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED);
	(*count)++;
}

static void test_datacounter_timelimit2()
{
	static const struct time_limit2_test {
		guint u1[TIME_UNITS];
		guint u2[TIME_UNITS];
		struct datacounter_timer limit;
		gint64 step1;
		gint64 step2;
	} tests [] = {
		{
			{0, 0, 0, 1, 1, 2016},
			{1, 0, 0, 1, 1, 2016},
			{1, TIME_UNIT_SECOND, {0}},
			0, 1
		},{
			{0, 0, 0, 1, 1, 2016},
			{0, 1, 0, 1, 1, 2016},
			{1, TIME_UNIT_MINUTE, {0}},
			59, 1
		},{
			{0, 0, 0, 1, 1, 2016},
			{2, 0, 0, 1, 1, 2016},
			{1, TIME_UNIT_MINUTE, {2}},
			1, 1
		},{
			{0, 0, 0, 1, 2, 2016},
			{1, 0, 0, 29, 2, 2016},
			{1, TIME_UNIT_MONTH, {0, 0, 0, 31}},
			2419199 /* 28 days - 1 sec*/,  2
		},{
			{0, 0, 0, 31, 1, 2016},
			{0, 0, 5, 29, 2, 2016},
			{1, TIME_UNIT_MONTH, {0, 0, 5, 30}},
			2523599 /* 29 days + 5 hours - 1 sec*/,  1
		}
	};

	guint i;
	GTimeZone *utc = g_time_zone_new_utc();
	GTimeZone *local = g_time_zone_new_local();
	GUtilTimeNotify *time_notify = test_time_notify_new();

	for (i=0; i<G_N_ELEMENTS(tests); i++) {
		const struct time_limit2_test *test = tests + i;
		struct datacounter *dc;
		int state_change_count = 0;
		int enabled_change_count = 0;
		gulong id[2];
		GDateTime *t1 = datacounters_time_from_units(local, test->u1);
		GDateTime *utc1 = g_date_time_to_timezone(t1, utc);

		time_override_utc = g_date_time_to_unix(utc1);

		dc = test_counter_new();
		DBG("test #%u %s", i+1, datacounter_format_time(dc, utc1));

		datacounter_set_data_limit(dc, 0);
		datacounter_set_time_limit_enabled(dc, FALSE);
		datacounter_set_time_limit(dc, &test->limit);
		datacounter_reset(dc);
		id[0] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_CUTOFF_STATE,
				test_datacounter_timelimit2_state_cb,
				&state_change_count);
		id[1] = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_TIME_LIMIT_ENABLED,
				test_datacounter_timelimit2_enabled_cb,
				&enabled_change_count);

		/* Enable cut-off */
		g_assert(dc->cutoff_state == CUTOFF_DISABLED);
		datacounter_set_cutoff_enabled(dc, TRUE);
		g_assert(dc->cutoff_state == CUTOFF_NO_LIMIT);
		g_assert(state_change_count == 1);
		state_change_count = 0;

		/* Turn the time limit on, time is before the limit. */
		time_override_utc += test->step1;
		datacounter_set_time_limit_enabled(dc, TRUE);
		g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);
		g_assert(enabled_change_count == 1);
		g_assert(state_change_count == 1);
		enabled_change_count = 0;
		state_change_count = 0;

		/* Move the time ahead again. Now the state should change. */
		time_override_utc += test->step2;
		test_time_notify_signal(time_notify);
		g_assert(dc->cutoff_state == CUTOFF_ACTIVATED);
		g_assert(!enabled_change_count);
		g_assert(state_change_count == 1);
		state_change_count = 0;

		datacounter_set_time_limit_enabled(dc, FALSE);
		g_assert(dc->cutoff_state == CUTOFF_NO_LIMIT);
		g_assert(enabled_change_count == 1);
		g_assert(state_change_count == 1);
		enabled_change_count = 0;
		state_change_count = 0;

		/* Done with this test */
		datacounter_remove_handlers(dc, id, G_N_ELEMENTS(id));
		datacounter_unref(dc);
		g_date_time_unref(t1);
		g_date_time_unref(utc1);
		test_remove_counter_file();
	}

	/* Done */
	g_time_zone_unref(utc);
	g_time_zone_unref(local);
	test_time_notify_unref(time_notify);

	/* Undo the damage */
	time_override_utc = 0;
}

/* ==== /datacounter/timelimit3 ==== */

static void test_datacounter_timelimit3()
{
	struct datacounter *dc;
	struct datacounter_timer timer;
	struct test_loop test;
	gulong loop_quit_id;

	test_remove_counter_file();
	dc = test_counter_new();

	/* Schedule really long time limit */
	memset(&timer, 0, sizeof(timer));
	timer.value = 2;
	timer.unit = TIME_UNIT_YEAR;

	/* Enable/disable it twice to check for memory leaks. */
	datacounter_set_data_limit(dc, 0);
	datacounter_set_time_limit(dc, &timer);
	datacounter_set_time_limit_enabled(dc, TRUE);
	datacounter_set_time_limit_enabled(dc, FALSE);
	datacounter_set_time_limit_enabled(dc, TRUE);
	datacounter_set_cutoff_enabled(dc, TRUE);
	datacounter_reset(dc);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);

	/* Switch it back and forth */
	datacounter_set_time_limit_enabled(dc, FALSE);
	g_assert(dc->cutoff_state == CUTOFF_NO_LIMIT);
	datacounter_set_time_limit_enabled(dc, TRUE);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);

	/* Then reset time limit to 1 sec. */
	memset(&timer, 0, sizeof(timer));
	timer.value = 1;
	timer.unit = TIME_UNIT_SECOND;
	datacounter_set_time_limit(dc, &timer);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);

	/* Run the event loop */
	test_loop_init(&test);
	loop_quit_id = datacounter_add_property_handler(dc,
				DATACOUNTER_PROPERTY_CUTOFF_STATE,
				test_datacounter_loop_quit_cb, test.loop);
	g_main_loop_run(test.loop);
	g_assert(test.timeout_id);
	g_assert(dc->cutoff_state == CUTOFF_ACTIVATED);
	test_loop_destroy(&test);
	datacounter_remove_handler(dc, loop_quit_id);

	/* Resetting baseline resets the time limit too */
	datacounter_reset_baseline(dc);
	g_assert(dc->cutoff_state == CUTOFF_BELOW_LIMIT);

	/* This tests a few more code paths */
	timer.value = 2;
	datacounter_set_time_limit(dc, &timer);
	datacounter_reset(dc);

	/* Done */
	datacounter_unref(dc);
	test_remove_counter_file();
}

/* ==== /datacounter/wrap ==== */

static void test_datacounter_wrap()
{
	struct datacounter *dc;
	struct connman_stats_data data;

	dc = test_counter_new();
	memset(&data, 0, sizeof(data));
	datacounter_reset(dc);
	datacounter_rebase(dc, &data);
	data.rx_bytes = 0x100000001ULL;
	data.tx_bytes = 0xffffffff;
	datacounter_update(dc, &data);
	data.rx_bytes = 1;
	data.tx_bytes = 2;
	datacounter_update(dc, &data);
	g_assert(dc->value->rx_bytes == 0x100000001ULL);
	g_assert(dc->value->tx_bytes == 0x100000002ULL);

	/*
	 * This one is ignored because either all counters are 32-bit
	 * or all are 64-bit, mixing those makes no sense.
	 */
	data.rx_bytes = 2;
	data.tx_bytes = 0x100000003ULL;
	datacounter_update(dc, &data);
	g_assert(dc->value->rx_bytes == 0x100000001ULL);
	g_assert(dc->value->tx_bytes == 0x100000002ULL);

	/* Done */
	datacounter_unref(dc);

	/* Undo the damage */
	test_remove_counter_file();
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

	test_remove_counter_file();
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
	int i, ret;
	char *pname = g_path_get_basename(argv[0]);

	g_test_init(&argc, &argv, NULL);
	test_init(pname);
	g_test_add_func(TEST_("null"), test_datacounter_null);
	g_test_add_func(TEST_("basic"), test_datacounter_basic);
	g_test_add_func(TEST_("nodir"), test_datacounter_nodir);
	g_test_add_func(TEST_("badfile"), test_datacounter_badfile);
	g_test_add_func(TEST_("oldfile"), test_datacounter_oldfile);
	g_test_add_func(TEST_("baseline"), test_datacounter_baseline);
	g_test_add_func(TEST_("autoreset"), test_datacounter_autoreset);
	for (i = 0; i < G_N_ELEMENTS(tests_autoreset2); i++) {
		const struct test_autoreset2 *test = tests_autoreset2 + i;
		char* name = g_strdup_printf(TEST_("autoreset2/%d"), i + 1);

		g_test_add_data_func(name, test, test_datacounter_autoreset2);
		g_free(name);
	}
	g_test_add_func(TEST_("autoreset3"), test_datacounter_autoreset3);
	g_test_add_func(TEST_("save"), test_datacounter_save);
	g_test_add_func(TEST_("limit"), test_datacounter_limit);
	g_test_add_func(TEST_("warning"), test_datacounter_warning);
	g_test_add_func(TEST_("cutoff"), test_datacounter_cutoff);
	g_test_add_func(TEST_("timelimit"), test_datacounter_timelimit);
	g_test_add_func(TEST_("timelimit2"), test_datacounter_timelimit2);
	g_test_add_func(TEST_("timelimit3"), test_datacounter_timelimit3);
	g_test_add_func(TEST_("wrap"), test_datacounter_wrap);
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
