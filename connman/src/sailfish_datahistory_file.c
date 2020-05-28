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

#include "sailfish_datahistory_p.h"
#include "sailfish_datahistory_file.h"

#include "connman.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#define HISTORY_FILE_PREFIX "history."
#define HISTORY_FILE_VERSION (1)

/*
 * The history file layout:
 *
 * +==============================+
 * | datahistory_file_header      |
 * +==============================+
 * | datahistory_sample [0]       |
 * +------------------------------+
 * | ...                          |
 * +------------------------------+
 * | datahistory_sample [total-1] |
 * +==============================+
 *
 * The header's start field is the index of the first (oldest) sample.
 */

typedef struct datahistory_file {
	struct datahistory super;
	char *path;
	int fd;
	off_t fsize;
	guint32 start;
	guint32 total;
} DataHistoryFile;

typedef DataHistoryClass DataHistoryFileClass;
G_DEFINE_TYPE(DataHistoryFile, datahistory_file, DATAHISTORY_TYPE)
#define PARENT_CLASS datahistory_file_parent_class
#define DATAHISTORY_FILE_TYPE (datahistory_file_get_type())
#define DATAHISTORY_FILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	DATAHISTORY_FILE_TYPE, DataHistoryFile))

/*
 * The entire list of samples is allocated from a single memory block
 * like this:
 *
 * struct datahistory_samples for n samples:
 * +===========================+
 * | count                     |
 * | datahistory_sample* [0]   |
 * +===========================+
 * | datahistory_sample* [1]   | <= (list + 1) points here.
 * | ...                       | The structure is followed by (n-1) pointers.
 * | datahistory_sample* [n-1] |
 * +---------------------------+
 * | datahistory_sample [0]    | <= (list->samples + n) points here.
 * | ...                       | Here come n structures where the above
 * | datahistory_sample [n-1]  | pointers are actually pointing.
 * +---------------------------+
 */
static inline struct datahistory_sample *datahistory_file_samples_get_at(
			struct datahistory_samples *list, int total, int i)
{
	return ((struct datahistory_sample *)(list->samples + total)) + i;
}

static struct datahistory_samples *datahistory_file_samples_new
					(struct datahistory *history, int n)
{
	int i;
	struct datahistory_samples *list =
		g_malloc(sizeof(struct datahistory_samples) +
			sizeof(struct datahistory_sample*) * (n-1) +
			sizeof(struct datahistory_sample) * n);

	for (i = 0; i < n; i++) {
		list->samples[i] = datahistory_file_samples_get_at(list, n, i);
	}
	list->count = 0;
	datahistory_add_to_idle_pool(history, list, g_free);
	return list;
}

static gboolean datahistory_file_read_sample(struct datahistory_file *self,
			guint file_pos, struct datahistory_sample *ds)
{
	const off_t off = HISTORY_SAMPLE_OFFSET(file_pos);

	if (lseek(self->fd, off, SEEK_SET) == off) {
		ssize_t nbytes = read(self->fd, ds, sizeof(*ds));

		if (nbytes == sizeof(*ds)) {
			return TRUE;
		} else if (nbytes >= 0) {
			connman_error("%s: got %u bytes reading sample at %u",
				self->path, (unsigned int) nbytes, file_pos);
		} else {
			connman_error("%s: failed to read sample at %u: %s",
				self->path, file_pos, strerror(errno));
		}
	} else {
		connman_error("%s: fails to seek sample at %u: %s", self->path,
					file_pos, strerror(errno));
	}
	return FALSE;
}

static gboolean datahistory_file_read_sample_at(struct datahistory_file *self,
			guint pos, struct datahistory_sample *ds)
{
	return pos < self->total && datahistory_file_read_sample(self,
					(self->start + pos) % self->total, ds);
}

static gboolean datahistory_file_write_sample(struct datahistory_file *self,
		guint pos, const struct datahistory_sample *sample)
{
	const off_t off = HISTORY_SAMPLE_OFFSET(pos);

	if (lseek(self->fd, off, SEEK_SET) == off) {
		ssize_t nbytes = write(self->fd, sample, sizeof(*sample));
		if (nbytes == sizeof(*sample)) {
			return TRUE;
		} else if (nbytes >= 0) {
			connman_error("%s: wrote %u bytes for sample at %u",
				self->path, (unsigned int) nbytes, pos);
		} else {
			connman_error("%s: failed to write sample at %u: %s",
				self->path, pos, strerror(errno));
		}
	} else {
		connman_error("%s: fails to seek sample at %u: %s", self->path,
					pos, strerror(errno));
	}
	return FALSE;
}

/* Also updates the file size to match the header */
static gboolean datahistory_file_write_header(struct datahistory_file *self)
{
	const off_t fsize = HISTORY_FILE_SIZE(self->total);
	const struct datahistory_type *type = self->super.type;
	struct datahistory_file_header header;

	header.version = HISTORY_FILE_VERSION;
	header.total = self->total;
	header.start = self->start;
	header.period_value = type->period.value;
	header.period_unit = type->period.unit;
	header.reserved = 0;

	if (lseek(self->fd, 0, SEEK_SET) != 0) {
		connman_error("%s: fails to seek: %s", self->path,
					strerror(errno));
	} else if (ftruncate(self->fd, fsize) < 0) {
		connman_error("%s: fails to truncate: %s", self->path,
					strerror(errno));
	} else {
		ssize_t nbytes = write(self->fd, &header, sizeof(header));
		self->fsize = fsize;
		if (nbytes == sizeof(header)) {
			DBG("%s total:%u start:%u", self->path,
						self->total, self->start);
			return TRUE;
		} else if (nbytes >= 0) {
			connman_error("%s: wrote %u bytes", self->path,
						(unsigned int) nbytes);
		} else {
			connman_error("%s: write error: %s", self->path,
							strerror(errno));
		}
	}
	return FALSE;
}

/* The caller has to check that self->total >= max_depth */
static gboolean datahistory_file_normalize(struct datahistory_file *self,
							int max_depth)
{
	const gssize buflen = sizeof(struct datahistory_sample) * max_depth;
	struct datahistory_sample *buf = g_malloc(buflen);
	int i, pos = (self->start + self->total - max_depth) % self->total;
	gboolean ok = TRUE;

	for (i = 0; i < max_depth && ok; i++) {
		ok = datahistory_file_read_sample(self, pos, buf + i);
		pos = (pos + 1) % self->total;
	}

	if (ok) {
		self->start = 0;
		self->total = max_depth;
		ok = datahistory_file_write_header(self) &&
			write(self->fd, buf, buflen) == buflen;
	}

	g_free(buf);
	return ok;
}

static gboolean datahistory_file_validate_data(struct datahistory_file *self)
{
	struct datahistory_sample last;

	if (!self->total) {
		return TRUE;
	} else if (!datahistory_file_read_sample_at(self, 0, &last)) {
		return FALSE;
	} else {
		guint i;
		const guint max_depth = self->super.type->max_depth;
		const struct datahistory_sample *hs = &self->super.last_sample;

		for (i = 1; i < self->total; i++) {
			struct datahistory_sample next;

			if (datahistory_file_read_sample_at(self, i, &next) &&
				next.time > last.time  &&
				next.bytes_sent >= last.bytes_sent &&
				next.bytes_received >= last.bytes_received) {
				last = next;
			} else {
				/* The data make no sense */
				return FALSE;
			}
		}

		/* Check the last sample against the current counter */
		if (hs->time < last.time || hs->bytes_sent < last.bytes_sent ||
				hs->bytes_received < last.bytes_received) {
			return FALSE;
		}

		/* The contents of the file makes sense */
		if (self->total > max_depth) {
			/* File needs to be truncated */
			return datahistory_file_normalize(self, max_depth);
		} else if (self->total < max_depth && self->start) {
			/*
			 * The file can grow further but in that case
			 * the index of the first sample must be zero.
			 */
			return datahistory_file_normalize(self, self->total);
		} else {
			DBG("%s OK", self->path);
			return TRUE;
		}
	}
}

static gboolean datahistory_file_validate_header(struct datahistory_file *self,
				const struct datahistory_file_header *h)
{
	const struct datahistory_type *type = self->super.type;

	return (h->version == HISTORY_FILE_VERSION &&
			(guint)self->fsize == HISTORY_FILE_SIZE(h->total) &&
			(!h->total || h->start < h->total) &&
			h->period_value == type->period.value &&
			h->period_unit == type->period.unit);
}

static gboolean datahistory_file_validate(struct datahistory_file *self)
{
	if (lseek(self->fd, 0, SEEK_SET) == 0) {
		struct datahistory_file_header h;
		ssize_t nbytes = read(self->fd, &h, sizeof(h));

		if (nbytes == sizeof(h)) {
			if (datahistory_file_validate_header(self, &h)) {
				DBG("%s: %u entries, starting at %u",
					self->path, h.total, h.start);
				self->total = h.total;
				self->start = h.start;
				if (datahistory_file_validate_data(self)) {
					return TRUE;
				}
			}
			connman_error("History file %s is broken", self->path);
		}
	}
	return FALSE;
}

static gboolean datahistory_file_reset(struct datahistory_file *self)
{
	self->total = 0;
	self->start = 0;
	return datahistory_file_write_header(self);
}

static void datahistory_file_remove(struct datahistory_file *self)
{
	if (self->fd >= 0) {
		close(self->fd);
		self->fd = -1;
		self->fsize = 0;
		self->total = 0;
		self->start = 0;
	}
	remove(self->path);
}

static void datahistory_file_open(struct datahistory_file *self)
{
	self->fd = open(self->path, O_RDWR | O_CREAT, STORAGE_FILE_MODE);
	if (self->fd >= 0) {
		self->fsize = lseek(self->fd, 0, SEEK_END);
		if (self->fsize >= 0) {
			if (datahistory_file_validate(self) ||
					datahistory_file_reset(self)) {
				return;
			}
		} else {
			connman_error("Failed to query size of %s: %s",
				self->path, strerror(errno));
		}
		datahistory_file_remove(self);
	} else {
		connman_error("Failed to create %s: %s", self->path,
							strerror(errno));
	}
}

static gboolean datahistory_file_ensure_open(struct datahistory_file *self)
{
	if (self->fd < 0) {
		datahistory_file_open(self);
	}
	return self->fd >= 0;
}

static void datahistory_file_finish_init(struct datahistory *history)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);
	const char *ident;

	ident = history->counter->ident;
	self->path = g_strconcat(connman_storage_dir_for(ident),
			G_DIR_SEPARATOR_S, ident, G_DIR_SEPARATOR_S,
			HISTORY_FILE_PREFIX, history->counter->name, ".",
			history->type->name, NULL);
	DBG("%s", self->path);
}

static gboolean datahistory_file_is_empty(struct datahistory *history)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);

	return !datahistory_file_ensure_open(self) || !self->total;
}

static void datahistory_file_clear(struct datahistory *history)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);

	if (self->fd >= 0) {
		if (!datahistory_file_reset(self)) {
			datahistory_file_remove(self);
		}
	}
}

static void datahistory_file_push_sample(struct datahistory *history,
				const struct datahistory_sample *ds)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);

	if (datahistory_file_ensure_open(self)) {
		if (!self->start && self->total < history->type->max_depth) {

			/*
			 * The file can grow. The new sample gets written
			 * the end of the file.
			 */
			const guint pos = self->total;
			self->total++;

			/*
			 * We have to write header first because that also
			 * adjusts the file size.
			 */
			if (!datahistory_file_write_header(self) ||
					!datahistory_file_write_sample(self,
							pos, ds)) {
				datahistory_file_remove(self);
			}
		} else if (self->total > 0) {
			/* The new sample replaces the oldest sample */
			const guint pos = self->start;
			self->start = (self->start + 1) % self->total;
			if (!datahistory_file_write_sample(self, pos, ds) ||
				!datahistory_file_write_header(self)) {
				datahistory_file_remove(self);
			}
		}
	}
}

/* The caller has checked that self->total > 0 */
static int datahistory_file_get_sample_not_later_than
			(struct datahistory_file *self, gint64 max_time,
					struct datahistory_sample *ds)
{
	int low, high;

	/* Check the latest sample */
	if (!datahistory_file_read_sample_at(self, self->total - 1, ds)) {
		datahistory_file_remove(self);
		return -1;
	} else if (ds->time <= max_time) {
		/* That's it */
		return self->total - 1;
	}

	/* Check the oldest sample */
	if (!datahistory_file_read_sample_at(self, 0, ds)) {
		datahistory_file_remove(self);
		return -1;
	} else if (ds->time > max_time) {
		/* The requested time is too far back in the past */
		return -1;
	} else if (ds->time == max_time) {
		/* Exact match */
		return 0;
	}

	/* We have to search */
	low = 0;
	high = self->total - 1;

	/*
	 * At the end of the loop the lower index is pointing to the
	 * oldest sample which has time <= max_time
	 */
	while (low < high) {
		const int mid = (low + high + 1)/2;
		struct datahistory_sample current;

		if (!datahistory_file_read_sample_at(self, mid, &current)) {
			datahistory_file_remove(self);
			return -1;
		}
		if (current.time < max_time) {
			/* That could be it */
			*ds = current;
			low = mid;
		} else if (current.time > max_time) {
			/* That's definitely not it */
			high = mid - 1;
		} else {
			/* Exact match */
			*ds = current;
			return mid;
		}
	}

	/* 'low' is the index of the sample that we have been looking for */
	return low;
}

static gboolean datahistory_file_get_sample_at(struct datahistory *history,
			gint64 max, struct datahistory_sample *sample)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);

	return datahistory_file_ensure_open(self) && self->total &&
		datahistory_file_get_sample_not_later_than(self, max, sample) >= 0;
}

static const struct datahistory_samples *datahistory_file_get_samples(
				struct datahistory *history, int maxcount)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);

	if (datahistory_file_ensure_open(self) && self->total) {
		const int n = (maxcount > 0 && (guint)maxcount < self->total) ?
			maxcount : (int)self->total;
		struct datahistory_samples *list =
			datahistory_file_samples_new(history, n);
		int i, pos = (self->start + self->total - n) % self->total;

		for (i = 0; i < n; i++) {
			struct datahistory_sample *ds =
				datahistory_file_samples_get_at(list, n,
								list->count);

			if (datahistory_file_read_sample(self, pos, ds)) {
				list->count++;
			}
			pos = (pos + 1) % self->total;
		}
		return list;
	} else {
		return NULL;
	}
}

static const struct datahistory_samples *datahistory_file_get_samples_since(
		struct datahistory *history, gint64 since, int maxcount)
{
	struct datahistory_file *self = DATAHISTORY_FILE(history);
	struct datahistory_sample ds;
	int pos, count;

	if (!datahistory_file_ensure_open(self) || !self->total) {
		/* We can't open the file or it's empty */
		return NULL;
	}

	/* Check the oldest time (to see if we need all samples) */
	if (!datahistory_file_read_sample(self, self->start, &ds)) {
		datahistory_file_remove(self);
		return NULL;
	} else if (ds.time > since) {
		/* All samples fall within the requested range */
		return datahistory_file_get_samples(history, self->total);
	}

	pos = datahistory_file_get_sample_not_later_than(self, since, &ds);

	/* We need the next one */
	if (pos >= 0) {
		if ((guint)pos == (self->total - 1)) {
			/* Nothing within the requested range */
			return NULL;
		}
		pos++;
	}

	count = self->total - pos;
	return datahistory_file_get_samples(history, (maxcount <= 0) ?
					count : MIN(count, maxcount));
}

static void datahistory_file_init(struct datahistory_file *self)
{
	self->fd = -1;
}

static void datahistory_file_finalize(GObject *object)
{
	struct datahistory_file *self = DATAHISTORY_FILE(object);

	if (self->fd >= 0) {
		close(self->fd);
	}
	g_free(self->path);
	G_OBJECT_CLASS(PARENT_CLASS)->finalize(object);
}

static void datahistory_file_class_init(DataHistoryFileClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	klass->persistent = TRUE;
	klass->finish_init = datahistory_file_finish_init;
	klass->is_empty = datahistory_file_is_empty;
	klass->clear = datahistory_file_clear;
	klass->push_sample = datahistory_file_push_sample;
	klass->get_sample_at = datahistory_file_get_sample_at;
	klass->get_samples = datahistory_file_get_samples;
	klass->get_samples_since = datahistory_file_get_samples_since;
	object_class->finalize = datahistory_file_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
