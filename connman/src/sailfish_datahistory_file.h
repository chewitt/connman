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

#ifndef SAILFISH_DATAHISTORY_FILE_H
#define SAILFISH_DATAHISTORY_FILE_H

/*
 * Internal header file shared by file based DataHistory implementation
 * and the unit test.
 */

#include <glib.h>

struct datahistory_file_header {
	guint32 version;
	guint32 total;
	guint32 start;
	guint32 period_value;
	guint32 period_unit;
	guint32 reserved;
} __attribute__((packed));

#define HISTORY_FILE_SIZE(total) HISTORY_SAMPLE_OFFSET(total)
#define HISTORY_SAMPLE_OFFSET(index) (\
	sizeof(struct datahistory_file_header) + \
	sizeof(struct datahistory_sample) * index)

#endif /* SAILFISH_DATAHISTORY_FILE_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
