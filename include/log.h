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

/**
 *  Debug-level logging descriptor that may be used to control debug
 *  output on a per-file or -symbol basis.
 */
struct connman_debug_desc {
	const char *name;
	const char *file;
#define CONNMAN_DEBUG_FLAG_DEFAULT (0)
#define CONNMAN_DEBUG_FLAG_PRINT   (1 << 0)
#define CONNMAN_DEBUG_FLAG_ALIAS   (1 << 1)
	unsigned int flags;
} __attribute__((aligned(8)));

/**
 *  @def CONNMAN_DEBUG_DESC_INSTANTIATE(symbol, _name, _file, _flags)
 *
 *  @brief
 *    Convenience preprocessor macro for declaring and instantiating an
 *    instance of #connmand_debug_desc.
 *
 *  @param[in]  symbol   The name of the #connman_debug_desc instance
 *                       to instantiate.
 *  @param[in]  _name    An optional pointer to an immutable null-
 *                       terminated C string containing the name of
 *                       the #connman_debug_desc- controlled symbol.
 *  @param[in]  _file    A pointer to an immutable null-terminated C
 *                       string containing the name of the
 *                       #connman_debug_desc-controlled source file.
 *  @param[in]  _flags   Flags that control the interpretation and
 *                       behavior of the instantiated
 *                       #connman_debug_desc instance.
 *
 */
#define CONNMAN_DEBUG_DESC_INSTANTIATE(symbol, _name, _file, _flags) \
	static struct connman_debug_desc symbol \
	__attribute__((used, section("__debug"), aligned(8))) = { \
		.name = _name, .file = _file, .flags = _flags \
	}

/**
 *  @def CONNMAN_DEBUG_ALIAS(suffix)
 *
 *  @brief
 *    Convenience preprocessor macro for declaring and instantiating
 *    an alias (see #CONNMAN_DEBUG_FLAG_ALIAS) instance of
 *    #connmand_debug_desc.
 *
 *  @param[in]  suffix  The suffix to concatenate to the name of the
 *                      #connman_debug_desc alias instance to
 *                      instantiate.
 *
 */
#define CONNMAN_DEBUG_ALIAS(suffix) \
	CONNMAN_DEBUG_DESC_INSTANTIATE(__debug_alias_##suffix, \
		#suffix, \
		__FILE__, \
		CONNMAN_DEBUG_FLAG_ALIAS)

/**
 *  @def DBG(fmt, arg...)
 *
 *  @brief
 *    Convenience preprocessor macro for declaring an instance of
 *    #connmand_debug_desc for controlling an invocation of
 *    #connman_debug with it that includes both the file and function
 *    name the macro was invoked in.
 *
 *  This instantiates a scoped-instance of #connmand_debug_desc and
 *  then, if that instance has its #CONNMAN_DEBUG_FLAG_PRINT flag
 *  asserted, invokes a call to #connman_debug with the format:
 *
 *    "<file>:<function>() <fmt> ..."
 *
 *  where <file> is the preprocessor symbol __FILE__, <function> is
 *  the preprocessor symbol __func__, <fmt> is from @a fmt, and
 *  '...' is from @a 'arg...'.
 *
 *  @param[in]  fmt      A pointer to an immutable null-terminated C
 *                       string container the log message, consisting
 *                       of a printf-style format string composed of
 *                       zero or more output conversion directives.
 *  @param[in]  arg...   A variadic argument list, where each
 *                       argument corresponds with its peer output
 *                       conversion directive in @a fmt.
 *
 *  @sa connman_debug
 *
 */
#define DBG(fmt, arg...) do { \
	CONNMAN_DEBUG_DESC_INSTANTIATE(__connman_debug_desc, \
		0, \
		__FILE__, \
		CONNMAN_DEBUG_FLAG_DEFAULT); \
		if (__connman_debug_desc.flags & CONNMAN_DEBUG_FLAG_PRINT) \
			connman_debug("%s:%s() " fmt, \
					__FILE__, __func__, ##arg); \
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_LOG_H */
