/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_LOG_H
#define __CONNMAN_LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:log
 * @title: Logging premitives
 * @short_description: Functions for logging error and debug information
 */

void connman_info(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void connman_warn(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void connman_error(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void connman_debug(const char *format, ...)
				__attribute__((format(printf, 1, 2)));

#define connman_warn_once(fmt, arg...) do {		\
	static bool printed;				\
	if (!printed) {					\
		connman_warn(fmt, ## arg);		\
		printed = true;				\
	}						\
} while (0)

#define CONNMAN_DEBUG_ALIGN 8
#define CONNMAN_DEBUG_ATTR \
	__attribute__((used, section("__debug"), aligned(CONNMAN_DEBUG_ALIGN)))

struct connman_debug_desc {
	const char *name;
	const char *file;
#define CONNMAN_DEBUG_FLAG_DEFAULT (0)
#define CONNMAN_DEBUG_FLAG_PRINT   (1 << 0)
#define CONNMAN_DEBUG_FLAG_ALIAS   (1 << 1)
#define CONNMAN_DEBUG_FLAG_HIDE_NAME (1 << 2)
	unsigned int flags;
	void (*notify)(struct connman_debug_desc* desc);
} __attribute__((aligned(CONNMAN_DEBUG_ALIGN)));

#define CONNMAN_DEBUG_DEFINE(name) \
	static struct connman_debug_desc __debug_alias_ ## name \
	CONNMAN_DEBUG_ATTR = { \
		#name, __FILE__, CONNMAN_DEBUG_FLAG_ALIAS \
	};

/**
 * DBG:
 * @fmt: format string
 * @arg...: list of arguments
 *
 * Simple macro around connman_debug() which also include the function
 * name it is called in.
 */
#define DBG(fmt, arg...) do { \
	static struct connman_debug_desc __connman_debug_desc \
	CONNMAN_DEBUG_ATTR = { \
		.file = __FILE__, .flags = CONNMAN_DEBUG_FLAG_DEFAULT, \
	}; \
	if (__connman_debug_desc.flags & CONNMAN_DEBUG_FLAG_PRINT) \
		connman_log(&__connman_debug_desc, "%s() " fmt, \
					 __FUNCTION__ , ## arg); \
} while (0)

void connman_log(const struct connman_debug_desc *desc, const char *fmt, ...)
				__attribute__((format(printf, 2, 3)));

typedef void (*connman_log_hook_cb_t)(const struct connman_debug_desc *desc,
			int priority, const char *format, va_list va);

extern connman_log_hook_cb_t connman_log_hook;
extern struct connman_debug_desc __start___debug[];
extern struct connman_debug_desc __stop___debug[];

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_LOG_H */
