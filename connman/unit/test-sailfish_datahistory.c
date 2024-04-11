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
#include "sailfish_datahistory_file.h"

#include "test_timenotify.h"

#include "connman.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#define TEST_SUITE "datahistory"
#define TEST_(t) "/" TEST_SUITE "/" t
#define TEST_TIMEOUT_SEC (30)

struct test_history_file_map {
	int fd;
	int len;
	struct datahistory_file_header *header;
	struct datahistory_sample *sample;
};

static const char *test_ident = "test";
static const char *test_counter = "home";
static const char test_history[] = "file";
static char *test_tmp_dir;
static gint64 time_override_utc;

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

static char *test_history_file()
{
	return g_strconcat(STORAGEDIR, "/", test_ident, "/history.",
				test_counter, ".", test_history, NULL);
}

static gsize test_file_size(const char *file)
{
	gsize size = 0;
	struct stat st;
	if (!stat(file, &st)) {
		size = st.st_size;
	}
	return size;
}

static void test_remove_counter_file()
{
	char *file = test_counter_file();
	remove(file);
	g_free(file);
}

static void test_remove_history_file()
{
	char *file = test_history_file();
	remove(file);
	g_free(file);
}

static void test_remove_files()
{
	test_remove_counter_file();
	test_remove_history_file();
}

static int test_file_descriptor(const char *fname)
{
	char *procfd = g_strdup_printf("/proc/%u/fd", getpid());
	DIR *dir = opendir(procfd);
	int found = -1;
	if (dir) {
		struct dirent *d;
		const int bufsiz = PATH_MAX;
		char *buf = g_malloc(bufsiz);
		while ((d = readdir(dir)) != NULL) {
			if (strcmp(d->d_name, ".") != 0 &&
					strcmp(d->d_name, "..") != 0) {
				char *path = g_strconcat(procfd, "/",
							d->d_name, NULL);
				ssize_t n = readlink(path, buf, bufsiz);
				DBG("%s %.*s", path, (int)n, buf);
				g_free(path);
				if (n > 0 && n < bufsiz) {
					buf[n] = 0;

					/*
					 * Just comparing the file names
					 * doesn't work in scratchbox.
					 * g_str_has_suffix works for
					 * scratchbox as well.
					 */
					if (g_str_has_suffix(buf, fname)) {
						found = atoi(d->d_name);
						DBG("%d -> %s", found, fname);
						break;
					}
				}
			}
		}
		closedir(dir);
		g_free(buf);
	}
	g_free(procfd);
	return found;
}

static int test_history_file_descriptor()
{
	char *file = test_history_file();
	int fd = test_file_descriptor(file);
	g_free(file);
	return fd;
}

static struct datacounter *test_counter_new()
{
	return datacounter_new(test_ident, test_counter);
}

static void test_datahistory_count_cb(struct datahistory *dh, void *arg)
{
	int *count = arg;

	(*count)++;
}

static void test_history_file_map_open(struct test_history_file_map *map,
							const char *fname)
{
	char *tmp = NULL;

	if (!fname) {
		fname = tmp = test_history_file();
	}
	map->len = test_file_size(fname);
	map->fd = open(fname, O_RDWR);
	map->header = mmap(NULL, map->len, PROT_READ|PROT_WRITE, MAP_SHARED,
								map->fd, 0);
	g_assert(map->header);
	map->sample = (struct datahistory_sample *)(map->header + 1);
	g_free(tmp);
}

static void test_history_file_map_close(struct test_history_file_map *map)
{
        munmap(map->header, map->len);
	close(map->fd);
}

static struct datahistory_samples *test_copy_samples
				(const struct datahistory_samples *s)
{
	if (s) {
		int i;
		struct datahistory_samples *copy =
			g_malloc(sizeof(struct datahistory_samples) +
			sizeof(struct datahistory_sample*) * (s->count - 1) +
			sizeof(struct datahistory_sample) * s->count);
		struct datahistory_sample *storage =
			(void*)(copy->samples + s->count);

		copy->count = s->count;
		for (i = 0; i < s->count; i++) {
			copy->samples[i] = storage + i;
			storage[i] = *(s->samples[i]);
		}
		return copy;
	}
	return NULL;
}

#define test_free_samples(s) g_free(s)

/* Fake some core APIs */

static GSList *connman_rtnl_update_list;
static unsigned int connman_rtnl_update_interval;

static gint connman_rtnl_compare_interval(gconstpointer a, gconstpointer b)
{
	guint val_a = GPOINTER_TO_UINT(a);
	guint val_b = GPOINTER_TO_UINT(b);

	return (val_a > val_b) ? 1 : (val_a < val_b) ? -1 : 0;
}

unsigned int __connman_rtnl_update_interval_add(unsigned int interval)
{
	if (interval) {
		connman_rtnl_update_list =
			g_slist_insert_sorted(connman_rtnl_update_list,
					GUINT_TO_POINTER(interval),
					connman_rtnl_compare_interval);
		connman_rtnl_update_interval =
			GPOINTER_TO_UINT(connman_rtnl_update_list->data);
	}
	return connman_rtnl_update_interval;
}

unsigned int __connman_rtnl_update_interval_remove(unsigned int interval)
{
	if (interval) {
		connman_rtnl_update_list =
			g_slist_remove(connman_rtnl_update_list,
					GINT_TO_POINTER(interval));
		connman_rtnl_update_interval = connman_rtnl_update_list ?
			GPOINTER_TO_UINT(connman_rtnl_update_list->data) : 0;
	}
	return connman_rtnl_update_interval;
}

/* ==== /datahistory/null ==== */

static void test_datahistory_null()
{
	static const struct datahistory_type type = {
		datahistory_memory_get_type, "second",
		{1, TIME_UNIT_SECOND}, 100
        };
	struct datacounter *dc = test_counter_new();
	struct datahistory *dh = datahistory_new(dc, &type);

	g_assert(!datahistory_new(NULL,NULL));
	g_assert(!datahistory_new(dc,NULL));
	g_assert(!datahistory_new(NULL,&type));
	g_assert(!datahistory_ref(NULL));
	datahistory_unref(NULL);
        datahistory_clear(NULL);
        g_assert(!datahistory_persistent(NULL));
	g_assert(!datahistory_get_sample_at_interval(NULL, 0, NULL));
	g_assert(!datahistory_get_sample_at_interval(dh, 0, NULL));
        g_assert(!datahistory_get_samples(NULL, 0));
        g_assert(!datahistory_get_samples_since(NULL, 0, 0));
        g_assert(!datahistory_add_cleared_handler(dh, NULL, NULL));
        g_assert(!datahistory_add_cleared_handler(NULL, NULL, NULL));
        g_assert(!datahistory_add_start_time_handler(dh, NULL, NULL));
        g_assert(!datahistory_add_start_time_handler(NULL, NULL, NULL));
        g_assert(!datahistory_add_last_sample_handler(dh, NULL, NULL));
        g_assert(!datahistory_add_last_sample_handler(NULL, NULL, NULL));
        g_assert(!datahistory_add_sample_added_handler(dh, NULL, NULL));
        g_assert(!datahistory_add_sample_added_handler(NULL, NULL, NULL));
        datahistory_remove_handler(dh, 0);
        datahistory_remove_handler(NULL, 1);

	/* Cleanup */
	datahistory_unref(dh);
	datacounter_unref(dc);
	g_assert(!connman_rtnl_update_list);
	test_remove_files();
}

/* ==== /datahistory/ioerr ==== */

static void test_datahistory_ioerr()
{
	static const struct datahistory_type type = {
		datahistory_file_get_type, test_history,
		{1, TIME_UNIT_SECOND}, 100
        };

	char *dir = test_service_dir();
	char *hf = test_history_file();
	struct datacounter *dc;
	struct datahistory *dh;
	const struct datahistory_samples *samples;
	struct connman_stats_data data;

	time_override_utc = 1480000000; /* Nov 24 15:06:40 UTC 2016 */
	dc = test_counter_new();
	dh = datahistory_new(dc, &type);

	/* Indicate some data */
	memset(&data, 0, sizeof(data));
	data.tx_packets++;
	data.tx_bytes += 512;
	datacounter_update(dc, &data);

	time_override_utc += 2;
	data.tx_packets++;
	data.tx_bytes += 512;
	datacounter_update(dc, &data);
	samples = datahistory_get_samples(dh, 0);
	g_assert(samples && samples->count == 1);
	g_assert(g_file_test(hf, G_FILE_TEST_EXISTS));
	g_assert(test_file_size(hf) > sizeof(struct datahistory_file_header));

	/* Close the file and add more data. That creates new file */
	close(test_history_file_descriptor());
	remove(hf);
	g_assert(!g_file_test(hf, G_FILE_TEST_EXISTS));

	time_override_utc += 2;
	data.tx_packets++;
	data.tx_bytes += 512;
	datacounter_update(dc, &data);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(g_file_test(hf, G_FILE_TEST_EXISTS));
	g_assert(test_file_size(hf) == sizeof(struct datahistory_file_header));

	/* Clearing the history won't create the file */
	close(test_history_file_descriptor());
	remove(hf);
	g_assert(!g_file_test(hf, G_FILE_TEST_EXISTS));
	datacounter_reset(dc);
	g_assert(!g_file_test(hf, G_FILE_TEST_EXISTS));

	datacounter_unref(dc);
	datahistory_unref(dh);

	/* Remove the whole service dir */
	test_remove_files();
	remove(dir);

	/* No counter, no file history */
	dc = test_counter_new();
	dh = datahistory_new(dc, &type);
	g_assert(!datahistory_get_samples(dh, 0));

	datacounter_unref(dc);
	datahistory_unref(dh);

	/* Undo the damage */
	time_override_utc = 0;
	mkdir(dir, 0755);
	g_free(hf);
	g_free(dir);
}

/* ==== /datahistory/basic ==== */

static void test_datahistory_basic()
{
	static const struct datahistory_type forever = {
		datahistory_memory_get_type, "forever",
		{200, TIME_UNIT_YEAR}, 10
        };

	struct datacounter *dc;
	struct datahistory *dh;
	struct connman_stats_data data;
	struct datahistory_sample s;
	int cleared_count = 0;
	int last_sample_changed = 0;
	int start_time_changed = 0;
	gulong id[3];

	/* Stop the time */
	time_override_utc = datacounters_now();
	dc = test_counter_new();
	dh = datahistory_new(dc, &forever);

	/* 200 years is a too long time */
	g_assert(!connman_rtnl_update_list);
	datahistory_unref(datahistory_ref(dh));
	g_assert(!datahistory_persistent(dh));

	/* No handers should be invoked on reset of the empty history */
	id[0] = datahistory_add_cleared_handler(dh,
			test_datahistory_count_cb, &cleared_count);
	id[1] = datahistory_add_last_sample_handler(dh,
			test_datahistory_count_cb, &last_sample_changed);
	id[2] = datahistory_add_start_time_handler(dh,
			test_datahistory_count_cb, &start_time_changed);
	datahistory_clear(dh);
	g_assert(!cleared_count);
	g_assert(!last_sample_changed);
	g_assert(!start_time_changed);

	/* There should be no samples there */
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(!datahistory_get_samples_since(dh, time_override_utc, 0));
	g_assert(!datahistory_get_sample_at_interval(dh, 1, &s));

	/* Indicate that some data have been received */
	memset(&data, 0, sizeof(data));
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);
	g_assert(!start_time_changed);
	g_assert(last_sample_changed == 1);
	g_assert(dh->last_sample.bytes_sent == data.tx_bytes);
	g_assert(dh->last_sample.bytes_received == data.rx_bytes);
	g_assert(dh->last_sample.time == time_override_utc);
	last_sample_changed = 0;

	/* Fetch the last (current) sample */
	memset(&s, 0, sizeof(s));
	g_assert(datahistory_get_sample_at_interval(dh, 0, &s));
	g_assert(!memcmp(&s, &dh->last_sample, sizeof(s)));

	/* Then move the time ahead and clear the counter */
	time_override_utc += 1;
	datacounter_reset(dc);
	g_assert(!cleared_count);
	g_assert(last_sample_changed);
	g_assert(start_time_changed);
	last_sample_changed = 0;
	start_time_changed = 0;

	/* Cleanup */
	datahistory_remove_handlers(dh, id, G_N_ELEMENTS(id));
	datahistory_unref(dh);
	datacounter_unref(dc);
	test_remove_files();
	time_override_utc = 0;
}

/* ==== /datahistory/basic2 ==== */

static const struct test_basic2 {
	struct datahistory_type type;
	gint64 step1;
	gint64 step2;
	gint64 step3;
	guint step3_back;
} tests_basic2 [] = {
	{
		{datahistory_memory_get_type, "second",
		{1, TIME_UNIT_SECOND}, 10}, 1, 1, 1, 5
	},{
		{datahistory_file_get_type, "second",
		{1, TIME_UNIT_SECOND}, 10}, 1, 1, 1, 5
	},{
		{datahistory_memory_get_type, "hour",
		{1, TIME_UNIT_HOUR}, 20}, 3600, 7220, 3600, 11
	},{
		{datahistory_file_get_type, "hour",
		{1, TIME_UNIT_HOUR}, 20}, 3600, 7220, 3600, 11
	}
};

static void test_datahistory_basic2_sample_cb(struct datahistory *dh,
		const struct datahistory_sample *sample, void *arg)
{
	int *count = arg;
	(*count)++;
}

static void test_datahistory_basic2(gconstpointer test_data)
{
	const struct test_basic2 *test = test_data;
	struct datacounter *dc;
	struct datahistory *dh;
	const struct datahistory_samples *samples;
	struct connman_stats_data data;
	struct datahistory_sample s;
	gulong id[2];
	int last_sample_changed = 0;
	int samples_added = 0;
	const gint64 t0 = 1480000000; /* Nov 24 15:06:40 UTC 2016 */
	const gint64 t1 = t0 + test->step1;
	const gint64 t2 = t1 + test->step2;
	guint i;

	memset(&data, 0, sizeof(data));

	time_override_utc = t0;
	dc = test_counter_new();
	dh = datahistory_new(dc, &test->type);

	id[0] = datahistory_add_last_sample_handler(dh,
			test_datahistory_count_cb, &last_sample_changed);
	id[1] = datahistory_add_sample_added_handler(dh,
			test_datahistory_basic2_sample_cb, &samples_added);

	/* Indicate that some data have been transmitted */
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 2048;
	data.tx_bytes += 4096;
	datacounter_update(dc, &data);
	g_assert(last_sample_changed == 1);
	g_assert(!samples_added);
	last_sample_changed = 0;

	/* Move the time ahead and add more data */
	time_override_utc = t1;
	data.rx_packets++;
	data.tx_packets++;
	data.rx_bytes += 1048;
	data.tx_bytes += 2096;
	datacounter_update(dc, &data);
	g_assert(last_sample_changed == 1);
	g_assert(samples_added == 1);
	last_sample_changed = 0;
	samples_added = 0;

	/* And again */
	time_override_utc = t2;
	data.rx_packets++;
	data.rx_bytes += 512;
	datacounter_update(dc, &data);
	g_assert(last_sample_changed == 1);
	g_assert(samples_added == 1);
	last_sample_changed = 0;
	samples_added = 0;

	/* There should be 2 samples in the history now */
	samples = datahistory_get_samples_since(dh, t0, 0);
	g_assert(samples && samples->count == 2);

	/* This should return only one sample */
	samples = datahistory_get_samples_since(dh, t1, 0);
	g_assert(samples && samples->count == 1);

	/* And this one no samples at all */
	g_assert(!datahistory_get_samples_since(dh, t2, 0));

	/* Make sure that the history doesn't grow beyond the limit */
	for (i = 0; i < test->type.max_depth; i++) {
		time_override_utc += test->step3;
		data.rx_packets++;
		data.rx_bytes += 16*(i+1);
		datacounter_update(dc, &data);
		g_assert(last_sample_changed == 1);
		g_assert(samples_added == 1);
		last_sample_changed = 0;
		samples_added = 0;
	}

	samples = datahistory_get_samples_since(dh, t0, 0);
	g_assert(samples && samples->count == test->type.max_depth);

	samples = datahistory_get_samples_since(dh, time_override_utc -
					test->step3_back * test->step3, 0);
	g_assert(samples && samples->count == test->step3_back);

	samples = datahistory_get_samples_since(dh, time_override_utc -
					test->step3_back * test->step3,
					test->step3_back - 1);
	g_assert(samples && samples->count == test->step3_back - 1);

	samples = datahistory_get_samples_since(dh, time_override_utc -
					test->step3_back * test->step3,
					test->step3_back);
	g_assert(samples && samples->count == test->step3_back);

	samples = datahistory_get_samples_since(dh, time_override_utc -
					test->step3_back * test->step3,
					test->step3_back + 1);
	g_assert(samples && samples->count == test->step3_back);

	/* Pick individual samples from the past */
	g_assert(datahistory_get_sample_at_interval(dh, 0, &s));
	g_assert(!memcmp(&s, &dh->last_sample, sizeof(s)));

	g_assert(datahistory_get_sample_at_interval(dh, 1, &s));
	g_assert(!memcmp(&s, samples->samples[test->step3_back-1], sizeof(s)));

	g_assert(datahistory_get_sample_at_interval(dh, 2, &s));
	g_assert(!memcmp(&s, samples->samples[test->step3_back-2], sizeof(s)));

	g_assert(datahistory_get_sample_at_interval(dh,
					test->type.max_depth, &s));
	g_assert(!datahistory_get_sample_at_interval(dh,
					test->type.max_depth + 1, &s));

	/* Reset the counter and make sure that the history is gone */
	datacounter_reset(dc);
	g_assert(!datahistory_get_samples(dh, 0));

	/* Cleanup */
	datahistory_remove_handler(dh, id[0]);
	datahistory_remove_handler(dh, id[1]);
	datahistory_unref(dh);
	datacounter_unref(dc);

	time_override_utc = 0;
	test_remove_files();
}

/* ==== /datahistory/period ==== */

static const struct test_period {
	struct datahistory_type type;
	gint64 t0;
	guint nupdates;
	struct test_period_update {
		int rx_bytes;
		int tx_bytes;
		gint64 time;
		int samples_added;
	} updates[4];
	guint nsamples;
	gint64 sample_time[2];
} tests_period [] = {
	{
		{
			datahistory_memory_get_type,
			"hour",
			{1,TIME_UNIT_HOUR}, 10 
		},
		1480613400, /* Thu Dec  1 17:30:00 UTC 2016 */
		2, {
			{
				0, 1024,
				1480615020, /* Dec  1 17:57:00 */
				0
			},{
				512, 0,
				1480615260, /* Dec  1 18:01:00 */
				1
			}
		},
		1, {
			1480615200, /* Dec  1 18:00:00 */
		}
	},{
		{
			datahistory_file_get_type, test_history,
			{2, TIME_UNIT_HOUR}, 10
		},
		1480613400, /* Thu Dec  1 17:30:00 UTC 2016 */
		4, {
			{
				0, 1024,
				1480615020, /* Dec  1 17:57:00 */
				0
			},{
				512, 0,
				1480615260, /* Dec  1 18:01:00 */
				0
			},{
				512, 0,
				1480618800, /* Dec  1 19:00:00 */
				1
			},{
				0, 512,
				1480622400, /* Dec  1 20:00:00 */
				0
			}
		},
		1, {
			1480618800  /* Dec  1 19:00:00 */
		}
	}
};

static void test_datahistory_period_sample_cb(struct datahistory *dh,
		const struct datahistory_sample *sample, void *arg)
{
	int *count = arg;
	(*count)++;
}

static void test_datahistory_period(gconstpointer test_data)
{
	const struct test_period *test = test_data;
	GUtilTimeNotify *time_notify = test_time_notify_new();
	struct connman_stats_data data;
	struct datacounter *dc;
	struct datahistory *dh;
	const struct datahistory_samples *samples;
	gulong sample_added_id;
	int samples_added = 0;
	guint i;

	time_override_utc = test->t0;

	test_remove_files();
	dc = test_counter_new();
	dh = datahistory_new(dc, &test->type);

	sample_added_id = datahistory_add_sample_added_handler(dh,
			test_datahistory_period_sample_cb, &samples_added);

	/* Update the history */
	memset(&data, 0, sizeof(data));
	for (i=0; i<test->nupdates; i++) {
		const struct test_period_update *update = test->updates + i;
		time_override_utc = update->time;
		if (update->rx_bytes) {
			data.rx_packets++;
			data.rx_bytes += update->rx_bytes;
		}
		if (update->tx_bytes) {
			data.tx_packets++;
			data.tx_bytes += update->tx_bytes;
		}
		datacounter_update(dc, &data);
		if (!update->rx_bytes && !update->tx_bytes) {
			test_time_notify_signal(time_notify);
		}
		g_assert(samples_added == update->samples_added);
		samples_added = 0;
	}

	/* Check the timestampls */
	samples = datahistory_get_samples(dh, 0);
	g_assert(samples && samples->count == test->nsamples);
	for (i=0; i<samples->count; i++) {
		g_assert(samples->samples[i]->time == test->sample_time[i]);
	}

	/* Cleanup */
	datahistory_remove_handler(dh, sample_added_id);
	datahistory_unref(dh);
	datacounter_unref(dc);

	time_override_utc = 0;
	test_time_notify_unref(time_notify);
	test_remove_files();
}

/* ==== /datahistory/file ==== */

static void test_datahistory_file()
{
	static const struct datahistory_type test = {
		datahistory_file_get_type, test_history,
		{1, TIME_UNIT_SECOND}, 10
	};
	static const struct datahistory_type test2 = {
		datahistory_file_get_type, test_history,
		{1, TIME_UNIT_MINUTE}, 20
	};

	struct datacounter *dc;
	struct datahistory *dh;
	const struct datahistory_samples *s;
	struct datahistory_samples *s1;
	struct datahistory_samples *s2;
	struct connman_stats_data data;
	char *fname = test_history_file();
	guint i;

	time_override_utc = 1481822887; /* Thu Dec 15 19:28:07 EET 2016 */
	dc = test_counter_new();
	dh = datahistory_new(dc, &test);

	memset(&data, 0, sizeof(data));
	for (i=0; i<test.max_depth + 2; i++) {
		data.rx_packets++;
		data.tx_packets++;
		data.rx_bytes += 2048;
		data.tx_bytes += 4096;
		datacounter_update(dc, &data);
		time_override_utc++;
	}

	s = datahistory_get_samples(dh, 0);
	g_assert(s && s->count == test.max_depth);
	s1 = test_copy_samples(s);
	datahistory_unref(dh);

	/* Reopen the file */
	dh = datahistory_new(dc, &test);
	s = datahistory_get_samples(dh, 0);
	g_assert(s && s->count == test.max_depth);
	s2 = test_copy_samples(s);
	datahistory_unref(dh);

	g_assert(s1->count == s2->count);
	for (i=0; i<s1->count; i++) {
		g_assert(!memcmp(s1->samples[i], s2->samples[i],
						sizeof(*s2->samples[i])));
	}
	test_free_samples(s1);
	test_free_samples(s2);

	/*
	 * This should reset the file because the sample period won't match
	 */
	dh = datahistory_new(dc, &test2);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));

	/* Update the file */
	time_override_utc += 60;
	data.rx_packets++;
	data.rx_bytes += 1024;
	datacounter_update(dc, &data);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(1));

	/* Resetting the counter will clear the history file */
	datacounter_reset(dc);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));
	datahistory_unref(dh);

	/* Reopen the empty file */
	dh = datahistory_new(dc, &test2);
	g_assert(!datahistory_get_samples(dh, 0));
	datahistory_unref(dh);

	datacounter_unref(dc);
	time_override_utc = 0;
	test_remove_files();
	g_free(fname);
}

/* ==== /datahistory/validate ==== */

static void test_datahistory_validate()
{
	static const struct datahistory_type test = {
		datahistory_file_get_type, test_history,
		{1, TIME_UNIT_SECOND}, 10
	};

	static const struct datahistory_type test2 = {
		datahistory_file_get_type, test_history,
		{1, TIME_UNIT_SECOND}, 5
	};

	struct datacounter *dc;
	struct datahistory *dh;
	struct datahistory_sample sample;
	const struct datahistory_samples *s;
	struct datahistory_samples *s1;
	struct connman_stats_data data;
	char *fname = test_history_file();
	struct test_history_file_map file;
	guint i, shift;

	time_override_utc = 1481822887; /* Thu Dec 15 19:28:07 EET 2016 */
	dc = test_counter_new();
	dh = datahistory_new(dc, &test);

	memset(&data, 0, sizeof(data));
	for (i=0; i<test.max_depth + 2; i++) {
		data.rx_packets++;
		data.tx_packets++;
		data.rx_bytes += 2048;
		data.tx_bytes += 4096;
		datacounter_update(dc, &data);
		time_override_utc++;
	}

	s = datahistory_get_samples(dh, 0);
	g_assert(s && s->count == test.max_depth);
	s1 = test_copy_samples(s);
	datahistory_unref(dh);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test.max_depth));

	/* This should truncate the file */
	dh = datahistory_new(dc, &test2);
	s = datahistory_get_samples(dh, 0);
	g_assert(s && s->count == test2.max_depth);
	shift = s1->count - s->count;
	for (i = 0; i < s->count; i++) {
		g_assert(!memcmp(s1->samples[i + shift], s->samples[i],
						sizeof(*s->samples[i])));
	}
	test_free_samples(s1);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test2.max_depth));

	/* Write more data */
	for (i=0; i<test2.max_depth + 2; i++) {
		data.tx_packets++;
		data.tx_bytes += 4096;
		datacounter_update(dc, &data);
		time_override_utc++;
	}

	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test2.max_depth));
	s1 = test_copy_samples(datahistory_get_samples(dh, 0));
	datahistory_unref(dh);

	/*
	 * Now increase the maximum number of samples. The file should
	 * get normalized (the start index reset to zero) but otherwise
	 * the its content should remain the same.
	 */
	dh = datahistory_new(dc, &test);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test2.max_depth));
	s = datahistory_get_samples(dh, 0);
	g_assert(s && s->count == test2.max_depth); /* Still the same */
	for (i = 0; i < s1->count; i++) {
		g_assert(!memcmp(s1->samples[i], s->samples[i],
						sizeof(*s->samples[i])));
	}
	test_free_samples(s1);
	datahistory_unref(dh);

	/*
	 * Damage the version field of the file header
	 */
	test_history_file_map_open(&file, fname);
	file.header->version++;
	test_history_file_map_close(&file);

	/* This should reset the file because the version doesn't match */
	dh = datahistory_new(dc, &test);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));

	/* Update the file */
	time_override_utc += 60;
	data.rx_packets++;
	data.rx_bytes += 1024;
	datacounter_update(dc, &data);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(1));
	datacounter_unref(dc);

	/*
	 * Damage the total number of entries in the file header
	 */
	test_history_file_map_open(&file, fname);
	file.header->total++;
	test_history_file_map_close(&file);

	/* This should reset the file because it's broken */
	dh = datahistory_new(dc, &test);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));

	/* Update the file */
	time_override_utc += 60;
	data.rx_packets++;
	data.rx_bytes += 1024;
	datacounter_update(dc, &data);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(1));

	/*
	 * Damage the start index in the file header 
	 */
	test_history_file_map_open(&file, fname);
	file.header->start = file.header->total;
	test_history_file_map_close(&file);
 
	/* This should reset the file because it's broken */
	dh = datahistory_new(dc, &test);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));

	/* Add some data and close the file */
	for (i=0; i<test.max_depth + 3; i++) {
		data.rx_packets++;
		data.rx_bytes += 2048;
		datacounter_update(dc, &data);
		time_override_utc++;
	}

	datahistory_unref(dh);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test.max_depth));

	/*
	 * Damage the data (swap two samples)
	 */
	test_history_file_map_open(&file, fname);
	sample = file.sample[0];
	file.sample[0] = file.sample[1];
	file.sample[1] = sample;
	test_history_file_map_close(&file);

	/* This should reset the file because the data make no sense */
	dh = datahistory_new(dc, &test);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));

	datahistory_unref(dh);
	datacounter_unref(dc);
	time_override_utc = 0;
	test_remove_files();
	g_free(fname);
}

/* ==== /datahistory/mismatch ==== */

static void test_datahistory_mismatch()
{
	static const struct datahistory_type test = {
		datahistory_file_get_type, test_history,
		{1, TIME_UNIT_SECOND}, 10
	};

	struct datacounter *dc;
	struct datahistory *dh;
	const struct datahistory_samples *s;
	struct connman_stats_data data;
	char *fname = test_history_file();
	guint i;

	time_override_utc = 1481822887; /* Thu Dec 15 19:28:07 EET 2016 */
	dc = test_counter_new();
	dh = datahistory_new(dc, &test);

	memset(&data, 0, sizeof(data));
	for (i=0; i<test.max_depth + 2; i++) {
		data.rx_packets++;
		data.tx_packets++;
		data.rx_bytes += 2048;
		data.tx_bytes += 4096;
		datacounter_update(dc, &data);
		time_override_utc++;
	}

	s = datahistory_get_samples(dh, 0);
	g_assert(s && s->count == test.max_depth);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test.max_depth));
	datahistory_unref(dh);

	/*
	 * Clear the counter. That doesn't affect the history file because
	 * we have deallocated the history object.
	 */
	datacounter_reset(dc);
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(test.max_depth));

	/*
	 * Now when we re-create the history object, it should detect that
	 * the counter no longer matches the history and reset itself.
	 */
	dh = datahistory_new(dc, &test);
	g_assert(!datahistory_get_samples(dh, 0));
	g_assert(test_file_size(fname) == HISTORY_FILE_SIZE(0));
	datahistory_unref(dh);

	/* Done */
	datacounter_unref(dc);
	time_override_utc = 0;
	test_remove_files();
	g_free(fname);
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

	test_remove_files();
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
	g_test_add_func(TEST_("null"), test_datahistory_null);
	g_test_add_func(TEST_("ioerr"), test_datahistory_ioerr);
	g_test_add_func(TEST_("basic"), test_datahistory_basic);
	for (i = 0; i < G_N_ELEMENTS(tests_basic2); i++) {
		const struct test_basic2 *test = tests_basic2 + i;
		char* name = g_strdup_printf(TEST_("basic2/%d"), i + 1);

		g_test_add_data_func(name, test, test_datahistory_basic2);
		g_free(name);
	}
	for (i = 0; i < G_N_ELEMENTS(tests_period); i++) {
		const struct test_period *test = tests_period + i;
		char* name = g_strdup_printf(TEST_("period/%d"), i + 1);

		g_test_add_data_func(name, test, test_datahistory_period);
		g_free(name);
	}
	g_test_add_func(TEST_("file"), test_datahistory_file);
	g_test_add_func(TEST_("validate"), test_datahistory_validate);
	g_test_add_func(TEST_("mismatch"), test_datahistory_mismatch);
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
