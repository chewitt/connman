/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd. All rights reserved.
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

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "connman.h"

/*
 * Simplified version of stats.c
 */

#define STATS_DIR_MODE      (0755)
#define STATS_FILE_MODE     (0644)
#define STATS_FILE_VERSION  (0x01)
#define STATS_FILE_HOME     "stats.home"
#define STATS_FILE_ROAMING  "stats.roaming"

#define stats_file(roaming) ((roaming) ? STATS_FILE_ROAMING : STATS_FILE_HOME)

/*
 * To reduce the number of writes, we don't overwrite the stats files more
 * often than once in STATS_SHORT_WRITE_PERIOD_SEC seconds. If the changes are
 * insignificant (less than STATS_SIGNIFICANT_CHANGE bytes) we overwrite the
 * file after STATS_LONG_WRITE_PERIOD_SEC. If there are no changes, we don't
 * overwrite it at all, except when stats get reset or rebased.
 */
#define STATS_SIGNIFICANT_CHANGE        (1024)
#define STATS_SHORT_WRITE_PERIOD_SEC    (2)
#define STATS_LONG_WRITE_PERIOD_SEC     (30)

/* Unused files that may have been created by earlier versions of connman */
static const char* stats_obsolete[] = { "data", "history" };

struct stats_file_contents {
	uint32_t version;
	uint32_t reserved;
	struct connman_stats_data total;
} __attribute__((packed));

struct connman_stats {
	char *path;
	char *name;
	gboolean modified;
	uint64_t bytes_change;
	guint short_write_timeout_id;
	guint long_write_timeout_id;
	struct stats_file_contents contents;
	struct connman_stats_data last;
};

static void stats_save(struct connman_stats *stats);

static gboolean stats_file_read(const char *path,
					struct stats_file_contents *contents)
{
	gboolean ok = false;
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		struct stats_file_contents buf;
		ssize_t nbytes = read(fd, &buf, sizeof(buf));
		if (nbytes == sizeof(buf)) {
			if (buf.version == STATS_FILE_VERSION) {
				DBG("%s", path);
				DBG("[RX] %llu packets %llu bytes",
					buf.total.rx_packets,
					buf.total.rx_bytes);
				DBG("[TX] %llu packets %llu bytes",
					buf.total.tx_packets,
					buf.total.tx_bytes);
				*contents = buf;
				ok = true;
			} else {
				connman_error("%s: unexpected version (%u)",
					path, buf.version);
			}
		} else if (nbytes >= 0) {
			connman_error("%s: failed to read (%u bytes)",
				path, (unsigned int) nbytes);
		} else {
			connman_error("%s: %s", path, strerror(errno));
		}
		close(fd);
	}
	return ok;
}

static gboolean stats_file_write(const char *path,
				const struct stats_file_contents *contents)
{
	gboolean ok = false;
	int fd = open(path, O_RDWR | O_CREAT, STATS_FILE_MODE);
	if (fd >= 0) {
		int err = ftruncate(fd, sizeof(*contents));
		if (err >= 0) {
			ssize_t nbytes = write(fd, contents, sizeof(*contents));
			if (nbytes == sizeof(*contents)) {
				DBG("%s", path);
				ok = true;
			} else if (nbytes >= 0) {
				DBG("%s: failed to write (%u bytes)",
					path, (unsigned int) nbytes);
			} else {
				DBG("%s: %s", path, strerror(errno));
			}
		} else {
			DBG("%s: %s", path, strerror(errno));
		}
		close(fd);
	} else {
		DBG("%s: %s", path, strerror(errno));
	}
	return ok;
}

static struct connman_stats *stats_new(const char *id, const char *dir,
							const char *file)
{
	struct connman_stats *stats = g_new0(struct connman_stats, 1);

	stats->contents.version = STATS_FILE_VERSION;
	stats->path = g_strconcat(dir, "/", file, NULL);
	stats->name = g_strconcat(id, "/", file, NULL);
	return stats;
}

/** Deletes the leftovers from the old connman */
static void stats_delete_obsolete_files(const char* dir)
{
	guint i;
	for (i=0; i<G_N_ELEMENTS(stats_obsolete); i++) {
		char* path = g_strconcat(dir, "/", stats_obsolete[i], NULL);
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

/** Creates file if it doesn't exist */
struct connman_stats *__connman_stats_new(const char *ident, gboolean roaming)
{
	int err = 0;
	struct connman_stats *stats = NULL;
	char *dir = g_strconcat(STORAGEDIR, "/", ident, NULL);

	DBG("%s %d", ident, roaming);

	/* If the dir doesn't exist, create it */
	if (!g_file_test(dir, G_FILE_TEST_IS_DIR)) {
		if (mkdir(dir, STATS_DIR_MODE) < 0) {
			if (errno != EEXIST) {
				err = -errno;
			}
		}
	}

	if (!err) {
		stats = stats_new(ident, dir, stats_file(roaming));
		stats_file_read(stats->path, &stats->contents);
		stats_delete_obsolete_files(dir);
	} else {
		connman_error("failed to create %s: %s", dir, strerror(errno));
	}

	g_free(dir);
	return stats;
}

/** Returns NULL if the file doesn't exist */
struct connman_stats *__connman_stats_new_existing(const char *identifier,
							gboolean roaming)
{
	struct connman_stats *stats = NULL;
	struct stats_file_contents contents;
	const char* file = stats_file(roaming);
	char *dir = g_strconcat(STORAGEDIR, "/", identifier, NULL);
	char *path = g_strconcat(dir, "/", file, NULL);

	if (stats_file_read(path, &contents)) {
		stats = stats_new(identifier, dir, file);
		stats->contents = contents;
	}

	g_free(dir);
	g_free(path);
	return stats;
}

void __connman_stats_free(struct connman_stats *stats)
{
	if (stats) {
		DBG("%s", stats->name);

		if (stats->modified)
			stats_file_write(stats->path, &stats->contents);

                if (stats->short_write_timeout_id)
                    g_source_remove(stats->short_write_timeout_id);

                if (stats->long_write_timeout_id)
                    g_source_remove(stats->long_write_timeout_id);

		g_free(stats->path);
		g_free(stats->name);
		g_free(stats);
	}
}

static inline gboolean stats_significantly_changed(
					const struct connman_stats *stats)
{
	return stats->bytes_change >= STATS_SIGNIFICANT_CHANGE;
}

static gboolean stats_short_save_timeout(gpointer data)
{
	struct connman_stats *stats = data;

	DBG("%s", stats->name);
	stats->short_write_timeout_id = 0;
	if (stats_significantly_changed(stats))
		stats_save(stats);

	return FALSE;
}

static gboolean stats_long_save_timeout(gpointer data)
{
	struct connman_stats *stats = data;

	DBG("%s", stats->name);
	stats->long_write_timeout_id = 0;
	if (stats->modified)
		stats_save(stats);

	return FALSE;
}

static void stats_save(struct connman_stats *stats)
{
	if (stats_file_write(stats->path, &stats->contents)) {
		stats->bytes_change = 0;
		stats->modified = false;
	}

	/* Reset the timeouts */
	if (stats->short_write_timeout_id)
		g_source_remove(stats->short_write_timeout_id);

	if (stats->long_write_timeout_id)
		g_source_remove(stats->long_write_timeout_id);

	stats->short_write_timeout_id = g_timeout_add_seconds(
		STATS_SHORT_WRITE_PERIOD_SEC, stats_short_save_timeout, stats);
	stats->long_write_timeout_id = g_timeout_add_seconds(
		STATS_LONG_WRITE_PERIOD_SEC, stats_long_save_timeout, stats);
}

/* Protection against counters getting wrapped at 32-bit boundary */
#define STATS_UPPER_BITS_SHIFT (32)
#define STATS_UPPER_BITS (~((1ull << STATS_UPPER_BITS_SHIFT) - 1))
#define stats_32bit(value) (((value) & STATS_UPPER_BITS) == 0)

static inline void stats_fix32(uint64_t *newval, uint64_t oldval)
{
	if (*newval < oldval) {
		uint64_t prev = *newval;
		*newval |= (oldval & STATS_UPPER_BITS);

		if (G_UNLIKELY(*newval < oldval))
			*newval += (1ull << STATS_UPPER_BITS_SHIFT);

		DBG("0x%08llx -> 0x%llx", prev, *newval);
	}
}

void __connman_stats_update(struct connman_stats *stats,
				const struct connman_stats_data *data)
{
	struct connman_stats_data *last, *total;
	struct connman_stats_data fixed;

	if (!stats)
		return;

	last = &stats->last;
	total = &stats->contents.total;

	/* If nothing has changed, don't do anything */
	if (!memcmp(last, data, sizeof(*last)))
		return;

	if ((data->rx_packets < last->rx_packets) ||
	    (data->tx_packets < last->tx_packets) ||
	    (data->rx_bytes   < last->rx_bytes  ) ||
	    (data->tx_bytes   < last->tx_bytes  ) ||
	    (data->rx_errors  < last->rx_errors ) ||
	    (data->tx_errors  < last->tx_errors ) ||
	    (data->rx_dropped < last->rx_dropped) ||
	    (data->tx_dropped < last->tx_dropped)) {

		/*
		 * This can happen if the counter wasn't rebased after
		 * switching the network interface. However most likely
		 * it's the result of 32-bit wrap-around that occurs in
		 * (at least some versions of) 32-bit kernels. Double
		 * check that all the upper 32-bits in all counters are
		 * indeed zero.
		 */

		if (G_UNLIKELY(!stats_32bit(data->rx_packets)) ||
		    G_UNLIKELY(!stats_32bit(data->tx_packets)) ||
		    G_UNLIKELY(!stats_32bit(data->rx_bytes  )) ||
		    G_UNLIKELY(!stats_32bit(data->tx_bytes  )) ||
		    G_UNLIKELY(!stats_32bit(data->rx_errors )) ||
		    G_UNLIKELY(!stats_32bit(data->tx_errors )) ||
		    G_UNLIKELY(!stats_32bit(data->rx_dropped)) ||
		    G_UNLIKELY(!stats_32bit(data->tx_dropped))) {
			DBG("%s screwed up", stats->name);
			return;
		}

		fixed = *data;
		data = &fixed;

		stats_fix32(&fixed.rx_packets, last->rx_packets);
		stats_fix32(&fixed.tx_packets, last->tx_packets);
		stats_fix32(&fixed.rx_bytes,   last->rx_bytes  );
		stats_fix32(&fixed.tx_bytes,   last->tx_bytes  );
		stats_fix32(&fixed.rx_errors,  last->rx_errors );
		stats_fix32(&fixed.tx_errors,  last->tx_errors );
		stats_fix32(&fixed.rx_dropped, last->rx_dropped);
		stats_fix32(&fixed.tx_dropped, last->tx_dropped);
	}

	DBG("%s [RX] %llu packets %llu bytes", stats->name,
					data->rx_packets, data->rx_bytes);
	DBG("%s [TX] %llu packets %llu bytes", stats->name,
					data->tx_packets, data->tx_bytes);

	/* Update the total counters */
	total->rx_packets += (data->rx_packets - last->rx_packets);
	total->tx_packets += (data->tx_packets - last->tx_packets);
	total->rx_bytes   += (data->rx_bytes   - last->rx_bytes  );
	total->tx_bytes   += (data->tx_bytes   - last->tx_bytes  );
	total->rx_errors  += (data->rx_errors  - last->rx_errors );
	total->tx_errors  += (data->tx_errors  - last->tx_errors );
	total->rx_dropped += (data->rx_dropped - last->rx_dropped);
	total->tx_dropped += (data->tx_dropped - last->tx_dropped);

	/* Accumulate the changes */
	stats->modified = true;
	stats->bytes_change +=
		(data->rx_bytes - last->rx_bytes) +
		(data->tx_bytes - last->tx_bytes);

	/* Store the last values */
	*last = *data;

	/* Check if the changes need to be saved right away */
	if (stats_significantly_changed(stats)) {
		/* short_write_timeout_id prohibits any saves */
		if (!stats->short_write_timeout_id)
			stats_save(stats);
	} else {
		/* long_write_timeout_id prohibits insignificant saves */
		if (!stats->long_write_timeout_id)
			stats_save(stats);
	}
}

void __connman_stats_reset(struct connman_stats *stats)
{
	if (stats) {
		struct connman_stats_data* total = &stats->contents.total;

		DBG("%s", stats->name);
		memset(total, 0, sizeof(*total));
		stats_save(stats);
	}
}

void __connman_stats_rebase(struct connman_stats *stats,
				const struct connman_stats_data *data)
{
	if (stats) {
		struct connman_stats_data* last = &stats->last;

		if (data) {
			DBG("%s [RX] %llu packets %llu bytes", stats->name,
					data->rx_packets, data->rx_bytes);
			DBG("%s [TX] %llu packets %llu bytes", stats->name,
					data->tx_packets, data->tx_bytes);
			*last = *data;
		} else {
			DBG("%s", stats->name);
			memset(last, 0, sizeof(*last));
		}

		stats_save(stats);
	}
}

void __connman_stats_get(struct connman_stats *stats,
				struct connman_stats_data *data)
{
	if (stats) {
		*data = stats->contents.total;
	} else {
		bzero(data, sizeof(*data));
	}
}

int __connman_stats_init(void)
{
	return 0;
}

void __connman_stats_cleanup(void)
{
}
