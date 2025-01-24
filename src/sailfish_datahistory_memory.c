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

#include "sailfish_datahistory_p.h"

#include "connman.h"

#include <gutil_ring.h>

typedef struct datahistory_memory {
	struct datahistory super;
	GUtilRing *buffer;
} DataHistoryMemory;

typedef DataHistoryClass DataHistoryMemoryClass;
G_DEFINE_TYPE(DataHistoryMemory, datahistory_memory, DATAHISTORY_TYPE)
#define PARENT_CLASS datahistory_memory_parent_class
#define DATAHISTORY_MEMORY_TYPE (datahistory_memory_get_type())
#define DATAHISTORY_MEMORY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	DATAHISTORY_MEMORY_TYPE, DataHistoryMemory))

static void datahistory_memory_free_sample(gpointer data)
{
	g_slice_free(struct datahistory_sample, data);
}

static void datahistory_memory_finish_init(struct datahistory *history)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(history);

	self->buffer = gutil_ring_new_full(0, history->type->max_depth,
					datahistory_memory_free_sample);
}

static gboolean datahistory_memory_is_empty(struct datahistory *history)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(history);

	return !gutil_ring_size(self->buffer);
}

static void datahistory_memory_clear(struct datahistory *history)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(history);

	gutil_ring_clear(self->buffer);
}

static void datahistory_memory_push_sample(struct datahistory *history,
				const struct datahistory_sample *sample)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(history);
	struct datahistory_sample *new_sample;
	int n;

	if (gutil_ring_can_put(self->buffer, 1)) {
		/* Ring buffer isn't full yet, allocate a new sample */
		new_sample = g_slice_dup(struct datahistory_sample, sample);
	} else {
		/* Reuse the sample which we are about to drop */
		new_sample = gutil_ring_get(self->buffer);
		*new_sample = *sample;
	}

	/* Samples are supposed to be sorted */
	n = gutil_ring_size(self->buffer);
	if (n > 0) {
		const struct datahistory_sample *latest =
			gutil_ring_data_at(self->buffer, n-1);

		if (new_sample->time <= latest->time) {
			new_sample->time = latest->time + 1;
		}
	}

	/* At this point there must be at least one slot available */
	gutil_ring_put(self->buffer, new_sample);
}

static const struct datahistory_sample *
		datahistory_memory_get_sample_not_later_than
		(struct datahistory_memory *self, gint64 max_time, int *pos)
{
	const struct datahistory_sample *sample;
	const int n = gutil_ring_size(self->buffer);

	if (n <= 0) {
		/* Empty history */
		return NULL;
	}

	/* Check the latest sample */
	sample = gutil_ring_data_at(self->buffer, n - 1);
	if (sample->time <= max_time) {
		*pos = n - 1;
	} else {
		/* Now check the oldest sample */
		sample = gutil_ring_data_at(self->buffer, 0);
		if (sample->time > max_time) {
			/* Oops, we are looking too far back */
			return NULL;
		}

		/* Check for exact match */
		*pos = 0;
		if (sample->time != max_time) {
			int low = 0, high = n - 1;

			/*
			 * We can use binary search since samples
			 * are supposed to be sorted. At the end of
			 * the loop the sample is pointing to the
			 * one we are looking for.
			 */
			while (low < high) {
				const int mid = (low + high + 1)/2;
				const struct datahistory_sample *current =
					gutil_ring_data_at(self->buffer, mid);

				if (current->time < max_time) {
					/* That could be it */
					sample = current;
					low = mid;
					*pos = mid;
				} else if (current->time > max_time) {
					/* That's definitely not it */
					high = mid - 1;
				} else {
					/* Exact match */
					sample = current;
					*pos = mid;
					break;
				}
			}
		}
	}

	return sample;
}

static gboolean datahistory_memory_get_sample_at(struct datahistory *history,
				gint64 max, struct datahistory_sample *sample)
{
	int pos;
	const struct datahistory_sample *found =
		datahistory_memory_get_sample_not_later_than
				(DATAHISTORY_MEMORY(history), max, &pos);

	if (found) {
		*sample = *found;
		return TRUE;
	}
	return FALSE;
}

static const struct datahistory_samples *datahistory_memory_get_samples(
				struct datahistory *history, int maxcount)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(history);
	const int total = gutil_ring_size(self->buffer);
	const int n = (maxcount > 0 && maxcount < total) ? maxcount : total;

	if (n > 0) {
		/* The actual samples are owned by the ring buffer */
		struct datahistory_samples *out =
			g_malloc(sizeof(struct datahistory_samples) +
				sizeof(struct datahistory_sample*) * (n - 1));
		int i;

		for (i = 0; i < n; i++) {
			out->samples[i] = gutil_ring_data_at(self->buffer,
							total - n + i);
		}
		out->count = n;
		datahistory_add_to_idle_pool(history, out, g_free);
		return out;
	}
	return NULL;
}

static const struct datahistory_samples *datahistory_memory_get_samples_since(
		struct datahistory *history, gint64 since, int maxcount)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(history);
	const int n = gutil_ring_size(self->buffer);

	if (n > 0) {
		int pos;
		const struct datahistory_sample *sample =
			gutil_ring_data_at(self->buffer, 0);

		if (sample->time > since) {
			/* All samples fall within the requested range */
			return datahistory_memory_get_samples(history,
				(maxcount <= 0) ? n : MIN(n, maxcount));
		}

		sample = datahistory_memory_get_sample_not_later_than
							(self, since, &pos);

		/* We need the next one */
		if (sample) {
			if (pos == (n - 1)) {
				/* Nothing within the requested range */
				return NULL;
			}
			sample = gutil_ring_data_at(self->buffer, ++pos);
		}

		if (sample) {
			const int count = n - pos;

			return datahistory_memory_get_samples(history,
				(maxcount <= 0) ? count : MIN(count,maxcount));
		}
	}
	return NULL;
}

static void datahistory_memory_init(struct datahistory_memory *self)
{
}

static void datahistory_memory_finalize(GObject *object)
{
	struct datahistory_memory *self = DATAHISTORY_MEMORY(object);

	gutil_ring_unref(self->buffer);
	G_OBJECT_CLASS(PARENT_CLASS)->finalize(object);
}

static void datahistory_memory_class_init(DataHistoryMemoryClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	klass->finish_init = datahistory_memory_finish_init;
	klass->is_empty = datahistory_memory_is_empty;
	klass->clear = datahistory_memory_clear;
	klass->push_sample = datahistory_memory_push_sample;
	klass->get_sample_at = datahistory_memory_get_sample_at;
	klass->get_samples = datahistory_memory_get_samples;
	klass->get_samples_since = datahistory_memory_get_samples_since;
	object_class->finalize = datahistory_memory_finalize;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
