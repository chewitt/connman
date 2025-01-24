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

#ifndef SAILFISH_DATAHISTORY_PRIVATE_H
#define SAILFISH_DATAHISTORY_PRIVATE_H

/* Internal header file for use by DataHistory implementations */

#include "sailfish_datacounters.h"

typedef struct datahistory DataHistory;
typedef struct datahistory_class {
	GObjectClass parent;
	gboolean persistent;
	void (*finish_init)(struct datahistory *history);
	gboolean (*is_empty)(struct datahistory *history);
	void (*clear)(struct datahistory *history);
	void (*push_sample)(struct datahistory *history,
				const struct datahistory_sample *sample);
	gboolean (*get_sample_at)(struct datahistory *history, gint64 max_time,
				struct datahistory_sample *sample);
	const struct datahistory_samples *(*get_samples)
		(struct datahistory *history, int max_count);
	const struct datahistory_samples *(*get_samples_since)
		(struct datahistory *history, gint64 since, int max_count);
} DataHistoryClass;

GType datahistory_get_type(void);
#define DATAHISTORY_TYPE (datahistory_get_type())

#endif /* SAILFISH_DATAHISTORY_PRIVATE_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
