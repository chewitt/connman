/*
 *
 *  Web service library with GLib integration
 *
 *  Copyright (C) 2009-2012  Intel Corporation. All rights reserved.
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

#ifndef __G_WEB_H
#define __G_WEB_H

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  Hypertext Transfer Protocol (HTTP) Status Code mnemonics.
 *
 *  From <https://www.iana.org/assignments/http-status-codes/
 *  http-status-codes.xhtml>
 */
enum GWebStatusCode {
	GWEB_HTTP_STATUS_CODE_UNKNOWN = 000,
	GWEB_HTTP_STATUS_CODE_CONTINUE = 100,
	GWEB_HTTP_STATUS_CODE_SWITCHING_PROTOCOLS = 101,
	GWEB_HTTP_STATUS_CODE_PROCESSING = 102,
	GWEB_HTTP_STATUS_CODE_EARLY_HINTS = 103,
	GWEB_HTTP_STATUS_CODE_OK = 200,
	GWEB_HTTP_STATUS_CODE_CREATED = 201,
	GWEB_HTTP_STATUS_CODE_ACCEPTED = 202,
	GWEB_HTTP_STATUS_CODE_NON_AUTHORITATIVE_INFORMATION = 203,
	GWEB_HTTP_STATUS_CODE_NO_CONTENT = 204,
	GWEB_HTTP_STATUS_CODE_RESET_CONTENT = 205,
	GWEB_HTTP_STATUS_CODE_PARTIAL_CONTENT = 206,
	GWEB_HTTP_STATUS_CODE_MULTI_STATUS = 207,
	GWEB_HTTP_STATUS_CODE_ALREADY_REPORTED = 208,
	GWEB_HTTP_STATUS_CODE_IM_USED = 226,
	GWEB_HTTP_STATUS_CODE_MULTIPLE_CHOICES = 300,
	GWEB_HTTP_STATUS_CODE_MOVED_PERMANENTLY = 301,
	GWEB_HTTP_STATUS_CODE_FOUND = 302,
	GWEB_HTTP_STATUS_CODE_SEE_OTHER = 303,
	GWEB_HTTP_STATUS_CODE_NOT_MODIFIED = 304,
	GWEB_HTTP_STATUS_CODE_USE_PROXY = 305,
	GWEB_HTTP_STATUS_CODE_TEMPORARY_REDIRECT = 307,
	GWEB_HTTP_STATUS_CODE_PERMANENT_REDIRECT = 308,
	GWEB_HTTP_STATUS_CODE_BAD_REQUEST = 400,
	GWEB_HTTP_STATUS_CODE_UNAUTHORIZED = 401,
	GWEB_HTTP_STATUS_CODE_PAYMENT_REQUIRED = 402,
	GWEB_HTTP_STATUS_CODE_FORBIDDEN = 403,
	GWEB_HTTP_STATUS_CODE_NOT_FOUND = 404,
	GWEB_HTTP_STATUS_CODE_METHOD_NOT_ALLOWED = 405,
	GWEB_HTTP_STATUS_CODE_NOT_ACCEPTABLE = 406,
	GWEB_HTTP_STATUS_CODE_PROXY_AUTHENTICATION_REQUIRED = 407,
	GWEB_HTTP_STATUS_CODE_REQUEST_TIMEOUT = 408,
	GWEB_HTTP_STATUS_CODE_CONFLICT = 409,
	GWEB_HTTP_STATUS_CODE_GONE = 410,
	GWEB_HTTP_STATUS_CODE_LENGTH_REQUIRED = 411,
	GWEB_HTTP_STATUS_CODE_PRECONDITION_FAILED = 412,
	GWEB_HTTP_STATUS_CODE_CONTENT_TOO_LARGE = 413,
	GWEB_HTTP_STATUS_CODE_URI_TOO_LONG = 414,
	GWEB_HTTP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE = 415,
	GWEB_HTTP_STATUS_CODE_RANGE_NOT_SATISFIABLE = 416,
	GWEB_HTTP_STATUS_CODE_EXPECTATION_FAILED = 417,
	GWEB_HTTP_STATUS_CODE_MISDIRECTED_REQUEST = 421,
	GWEB_HTTP_STATUS_CODE_UNPROCESSABLE_CONTENT = 422,
	GWEB_HTTP_STATUS_CODE_LOCKED = 423,
	GWEB_HTTP_STATUS_CODE_FAILED_DEPENDENCY = 424,
	GWEB_HTTP_STATUS_CODE_TOO_EARLY = 425,
	GWEB_HTTP_STATUS_CODE_UPGRADE_REQUIRED = 426,
	GWEB_HTTP_STATUS_CODE_PRECONDITION_REQUIRED = 428,
	GWEB_HTTP_STATUS_CODE_TOO_MANY_REQUESTS = 429,
	GWEB_HTTP_STATUS_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
	GWEB_HTTP_STATUS_CODE_UNAVAILABLE_FOR_LEGAL_REASONS = 451,
	GWEB_HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR = 500,
	GWEB_HTTP_STATUS_CODE_NOT_IMPLEMENTED = 501,
	GWEB_HTTP_STATUS_CODE_BAD_GATEWAY = 502,
	GWEB_HTTP_STATUS_CODE_SERVICE_UNAVAILABLE = 503,
	GWEB_HTTP_STATUS_CODE_GATEWAY_TIMEOUT = 504,
	GWEB_HTTP_STATUS_CODE_HTTP_VERSION_NOT_SUPPORTED = 505,
	GWEB_HTTP_STATUS_CODE_VARIANT_ALSO_NEGOTIATES = 506,
	GWEB_HTTP_STATUS_CODE_INSUFFICIENT_STORAGE = 507,
	GWEB_HTTP_STATUS_CODE_LOOP_DETECTED = 508,
	GWEB_HTTP_STATUS_CODE_NETWORK_AUTHENTICATION_REQUIRED = 511
};

struct _GWeb;
struct _GWebResult;
struct _GWebParser;

typedef struct _GWeb GWeb;
typedef struct _GWebResult GWebResult;
typedef struct _GWebParser GWebParser;

typedef bool (*GWebResultFunc)(GWebResult *result, gpointer user_data);

typedef bool (*GWebRouteFunc)(const char *addr, int ai_family,
		int if_index, gpointer user_data);

typedef bool (*GWebInputFunc)(const guint8 **data, gsize *length,
							gpointer user_data);

typedef void (*GWebDebugFunc)(const char *str, gpointer user_data);

GWeb *g_web_new(int index);

GWeb *g_web_ref(GWeb *web);
void g_web_unref(GWeb *web);

void g_web_set_debug(GWeb *web, GWebDebugFunc func, gpointer user_data);

bool g_web_supports_tls(void);

bool g_web_set_proxy(GWeb *web, const char *proxy);

bool g_web_set_address_family(GWeb *web, int family);

bool g_web_add_nameserver(GWeb *web, const char *address);

bool g_web_set_accept(GWeb *web, const char *format, ...)
				__attribute__((format(printf, 2, 3)));
bool g_web_set_user_agent(GWeb *web, const char *format, ...)
				__attribute__((format(printf, 2, 3)));
bool g_web_set_ua_profile(GWeb *web, const char *profile);

bool g_web_set_http_version(GWeb *web, const char *version);

void g_web_set_connect_timeout(GWeb *web, guint timeout_ms);
guint g_web_get_connect_timeout(const GWeb *web);

void g_web_set_close_connection(GWeb *web, bool enabled);
bool g_web_get_close_connection(GWeb *web);

guint g_web_request_get(GWeb *web, const char *url,
				GWebResultFunc func, GWebRouteFunc route,
				gpointer user_data, int *err);
guint g_web_request_post(GWeb *web, const char *url,
				const char *type, GWebInputFunc input,
				GWebResultFunc func, gpointer user_data,
				int *err);
guint g_web_request_post_file(GWeb *web, const char *url,
				const char *type, const char *file,
				GWebResultFunc func, gpointer user_data,
				int *err);

bool g_web_cancel_request(GWeb *web, guint id);

guint16 g_web_result_get_status(GWebResult *result);

bool g_web_result_get_header(GWebResult *result,
				const char *header, const char **value);
bool g_web_result_has_headers(const GWebResult *result,
				guint *count);
bool g_web_result_get_chunk(GWebResult *result,
				const guint8 **chunk, gsize *length);

typedef void (*GWebParserFunc)(const char *str, gpointer user_data);

GWebParser *g_web_parser_new(const char *begin, const char *end,
				GWebParserFunc func, gpointer user_data);

GWebParser *g_web_parser_ref(GWebParser *parser);
void g_web_parser_unref(GWebParser *parser);

void g_web_parser_feed_data(GWebParser *parser,
				const guint8 *data, gsize length);
void g_web_parser_end_data(GWebParser *parser);

#ifdef __cplusplus
}
#endif

#endif /* __G_WEB_H */
