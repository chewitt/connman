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
#define STATS_FILE_SIZE     sizeof(struct stats_file_contents)
#define STATS_FILE_HOME     "stats.home"
#define STATS_FILE_ROAMING  "stats.roaming"

#define stats_file(roaming) ((roaming) ? STATS_FILE_ROAMING : STATS_FILE_HOME)

/* Unused files that may have been created by earlier versions of connman */
static const char* stats_obsolete[] = { "data", "history" };

struct stats_file_contents {
	uint32_t version;
	uint32_t reserved;
	struct connman_stats_data total;
} __attribute__((packed));

struct connman_stats {
	int fd;
	char *path;
	char *name;
	struct stats_file_contents *contents;
	struct connman_stats_data last;
};

static void stats_init_contents(struct connman_stats *stats)
{
	if (stats->contents->version != STATS_FILE_VERSION) {
		DBG("%s", stats->name);
		memset(stats->contents, 0, STATS_FILE_SIZE);
		stats->contents->version = STATS_FILE_VERSION;
	}
}

static struct connman_stats *stats_file_open(const char *id, const char *dir,
					const char *file, gboolean create)
{
        const int flags = O_RDWR | O_CLOEXEC | (create ? O_CREAT : 0);
	char* path = g_strconcat(dir, "/", file, NULL);
	int fd = open(path, flags, STATS_FILE_MODE);
	if (fd >= 0) {
		int err = ftruncate(fd, STATS_FILE_SIZE);
		if (err >= 0) {
			struct connman_stats *stats;

			stats = g_new0(struct connman_stats, 1);
			stats->contents = mmap(NULL, STATS_FILE_SIZE,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			if (stats->contents != MAP_FAILED) {
				/* Success */
				DBG("%s", path);
				DBG("[RX] %llu packets %llu bytes",
					stats->contents->total.rx_packets,
					stats->contents->total.rx_bytes);
				DBG("[TX] %llu packets %llu bytes",
					stats->contents->total.tx_packets,
					stats->contents->total.tx_bytes);

				stats->fd = fd;
				stats->path = path;
				stats->name = g_strconcat(id, "/", file, NULL);
				stats_init_contents(stats);
				return stats;
			}
			connman_error("mmap %s error: %s", path,
				strerror(errno));
			g_free(stats);
		} else {
			connman_error("ftrunctate %s error: %s", path,
				strerror(errno));
		}
		close(fd);
	}
	/* Error */
	g_free(path);
	return NULL;
}

/** Deletes the leftovers from the old connman */
static void stats_delete_obsolete_files(const char* dir)
{
	int i;
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
		stats = stats_file_open(ident, dir, stats_file(roaming), true);
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
	char *dir = g_strconcat(STORAGEDIR, "/", identifier, NULL);
	struct connman_stats *stats;

	stats = stats_file_open(identifier, dir, stats_file(roaming), false);
	g_free(dir);
	return stats;
}

void __connman_stats_free(struct connman_stats *stats)
{
	if (stats) {
		DBG("%s", stats->name);
		msync(stats->contents, STATS_FILE_SIZE, MS_SYNC);
		munmap(stats->contents, STATS_FILE_SIZE);
		close(stats->fd);
		g_free(stats->path);
		g_free(stats->name);
		g_free(stats);
	}
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
	total = &stats->contents->total;

	/* If nothing has changed, avoid overwriting the last data
	 * to reduce the number of writes to the file */
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

	/* Store the last values */
	*last = *data;
}

void __connman_stats_reset(struct connman_stats *stats)
{
	if (stats) {
		struct connman_stats_data* total = &stats->contents->total;

		DBG("%s", stats->name);
		memset(total, 0, sizeof(*total));
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
	}
}

void __connman_stats_get(struct connman_stats *stats,
				struct connman_stats_data *data)
{
	if (stats) {
		*data = stats->contents->total;
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
