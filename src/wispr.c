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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>

#include <gweb/gweb.h>

#include "connman.h"
#include "agent.h"

struct connman_wispr_message {
	bool has_error;
	const char *current_element;
	int message_type;
	int response_code;
	char *login_url;
	char *abort_login_url;
	char *logoff_url;
	char *access_procedure;
	char *access_location;
	char *location_name;
};

enum connman_wispr_result {
	CONNMAN_WISPR_RESULT_UNKNOWN = 0,
	CONNMAN_WISPR_RESULT_LOGIN   = 1,
	CONNMAN_WISPR_RESULT_ONLINE  = 2,
	CONNMAN_WISPR_RESULT_FAILED  = 3,
};

struct wispr_route {
	char *address;
	int if_index;
};

struct connman_wispr_portal_context {
	int refcount;
	struct connman_service *service;
	enum connman_ipconfig_type type;
	struct connman_wispr_portal *wispr_portal;

	/* Portal/WISPr common */
	GWeb *web;
	unsigned int token;
	guint request_id;

	const char *status_url;

	char *redirect_url;

	/* WISPr specific */
	GWebParser *wispr_parser;
	struct connman_wispr_message wispr_msg;

	char *wispr_username;
	char *wispr_password;
	char *wispr_formdata;

	enum connman_wispr_result wispr_result;

	GSList *route_list;

	guint timeout;
};

struct connman_wispr_portal {
	struct connman_wispr_portal_context *ipv4_context;
	struct connman_wispr_portal_context *ipv6_context;
};

static bool wispr_portal_web_result(GWebResult *result, gpointer user_data);

static GHashTable *wispr_portal_hash = NULL;

#define wispr_portal_context_ref(wp_context) \
	wispr_portal_context_ref_debug(wp_context, __FILE__, __LINE__, __func__)
#define wispr_portal_context_unref(wp_context) \
	wispr_portal_context_unref_debug(wp_context, __FILE__, __LINE__, __func__)

static void connman_wispr_message_init(struct connman_wispr_message *msg)
{
	msg->has_error = false;
	msg->current_element = NULL;

	msg->message_type = -1;
	msg->response_code = -1;

	g_free(msg->login_url);
	msg->login_url = NULL;

	g_free(msg->abort_login_url);
	msg->abort_login_url = NULL;

	g_free(msg->logoff_url);
	msg->logoff_url = NULL;

	g_free(msg->access_procedure);
	msg->access_procedure = NULL;

	g_free(msg->access_location);
	msg->access_location = NULL;

	g_free(msg->location_name);
	msg->location_name = NULL;
}

static void free_wispr_routes(struct connman_wispr_portal_context *wp_context)
{
	DBG("wp_context %p", wp_context);

	while (wp_context->route_list) {
		if (!wp_context->route_list->data)
			continue;

		struct wispr_route *route = wp_context->route_list->data;

		DBG("free route to %s if %d type %d", route->address,
				route->if_index, wp_context->type);

		switch (wp_context->type) {
		case CONNMAN_IPCONFIG_TYPE_IPV4:
			connman_inet_del_host_route(route->if_index,
					route->address);
			break;
		case CONNMAN_IPCONFIG_TYPE_IPV6:
			connman_inet_del_ipv6_host_route(route->if_index,
					route->address);
			break;
		case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		case CONNMAN_IPCONFIG_TYPE_ALL:
			break;
		}

		g_free(route->address);
		g_free(route);

		wp_context->route_list =
			g_slist_delete_link(wp_context->route_list,
					wp_context->route_list);
	}
}

static void free_connman_wispr_portal_context(
		struct connman_wispr_portal_context *wp_context)
{
	if (wp_context->wispr_portal) {
		if (wp_context->wispr_portal->ipv4_context == wp_context)
			wp_context->wispr_portal->ipv4_context = NULL;

		if (wp_context->wispr_portal->ipv6_context == wp_context)
			wp_context->wispr_portal->ipv6_context = NULL;
	}

	if (wp_context->token > 0)
		connman_proxy_lookup_cancel(wp_context->token);

	if (wp_context->request_id > 0)
		g_web_cancel_request(wp_context->web, wp_context->request_id);

	if (wp_context->timeout > 0)
		g_source_remove(wp_context->timeout);

	if (wp_context->web)
		g_web_unref(wp_context->web);

	g_free(wp_context->redirect_url);

	if (wp_context->wispr_parser)
		g_web_parser_unref(wp_context->wispr_parser);

	connman_wispr_message_init(&wp_context->wispr_msg);

	g_free(wp_context->wispr_username);
	g_free(wp_context->wispr_password);
	g_free(wp_context->wispr_formdata);

	free_wispr_routes(wp_context);

	connman_service_unref(wp_context->service);

	g_free(wp_context);
}

static struct connman_wispr_portal_context *
wispr_portal_context_ref_debug(struct connman_wispr_portal_context *wp_context,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", wp_context,
		wp_context->refcount + 1, file, line, caller);

	__sync_fetch_and_add(&wp_context->refcount, 1);

	return wp_context;
}

static void wispr_portal_context_unref_debug(
		struct connman_wispr_portal_context *wp_context,
		const char *file, int line, const char *caller)
{
	if (!wp_context)
		return;

	DBG("%p ref %d by %s:%d:%s()", wp_context,
		wp_context->refcount - 1, file, line, caller);

	if (__sync_fetch_and_sub(&wp_context->refcount, 1) != 1)
		return;

	free_connman_wispr_portal_context(wp_context);
}

static struct connman_wispr_portal_context *create_wispr_portal_context(void)
{
	return wispr_portal_context_ref(
		g_new0(struct connman_wispr_portal_context, 1));
}

static void free_connman_wispr_portal(gpointer data)
{
	struct connman_wispr_portal *wispr_portal = data;

	DBG("");

	if (!wispr_portal)
		return;

	wispr_portal_context_unref(wispr_portal->ipv4_context);
	wispr_portal_context_unref(wispr_portal->ipv6_context);

	g_free(wispr_portal);
}

#ifdef DEAD_CODE
static const char *message_type_to_string(int message_type)
{
	switch (message_type) {
	case 100:
		return "Initial redirect message";
	case 110:
		return "Proxy notification";
	case 120:
		return "Authentication notification";
	case 130:
		return "Logoff notification";
	case 140:
		return "Response to Authentication Poll";
	case 150:
		return "Response to Abort Login";
	}

	return NULL;
}
#endif

#ifdef DEAD_CODE
static const char *response_code_to_string(int response_code)
{
	switch (response_code) {
	case 0:
		return "No error";
	case 50:
		return "Login succeeded";
	case 100:
		return "Login failed";
	case 102:
		return "RADIUS server error/timeout";
	case 105:
		return "RADIUS server not enabled";
	case 150:
		return "Logoff succeeded";
	case 151:
		return "Login aborted";
	case 200:
		return "Proxy detection/repeat operation";
	case 201:
		return "Authentication pending";
	case 204:
		return "Walled garden check";
	case 255:
		return "Access gateway internal error";
	}

	return NULL;
}
#endif

static struct {
	const char *str;
	enum {
		WISPR_ELEMENT_NONE              = 0,
		WISPR_ELEMENT_ACCESS_PROCEDURE  = 1,
		WISPR_ELEMENT_ACCESS_LOCATION   = 2,
		WISPR_ELEMENT_LOCATION_NAME     = 3,
		WISPR_ELEMENT_LOGIN_URL         = 4,
		WISPR_ELEMENT_ABORT_LOGIN_URL   = 5,
		WISPR_ELEMENT_MESSAGE_TYPE      = 6,
		WISPR_ELEMENT_RESPONSE_CODE     = 7,
		WISPR_ELEMENT_NEXT_URL          = 8,
		WISPR_ELEMENT_DELAY             = 9,
		WISPR_ELEMENT_REPLY_MESSAGE     = 10,
		WISPR_ELEMENT_LOGIN_RESULTS_URL = 11,
		WISPR_ELEMENT_LOGOFF_URL        = 12,
	} element;
} wispr_element_map[] = {
	{ "AccessProcedure",	WISPR_ELEMENT_ACCESS_PROCEDURE	},
	{ "AccessLocation",	WISPR_ELEMENT_ACCESS_LOCATION	},
	{ "LocationName",	WISPR_ELEMENT_LOCATION_NAME	},
	{ "LoginURL",		WISPR_ELEMENT_LOGIN_URL		},
	{ "AbortLoginURL",	WISPR_ELEMENT_ABORT_LOGIN_URL	},
	{ "MessageType",	WISPR_ELEMENT_MESSAGE_TYPE	},
	{ "ResponseCode",	WISPR_ELEMENT_RESPONSE_CODE	},
	{ "NextURL",		WISPR_ELEMENT_NEXT_URL		},
	{ "Delay",		WISPR_ELEMENT_DELAY		},
	{ "ReplyMessage",	WISPR_ELEMENT_REPLY_MESSAGE	},
	{ "LoginResultsURL",	WISPR_ELEMENT_LOGIN_RESULTS_URL	},
	{ "LogoffURL",		WISPR_ELEMENT_LOGOFF_URL	},
	{ NULL,			WISPR_ELEMENT_NONE		},
};

static void xml_wispr_start_element_handler(GMarkupParseContext *context,
					const gchar *element_name,
					const gchar **attribute_names,
					const gchar **attribute_values,
					gpointer user_data, GError **error)
{
	struct connman_wispr_message *msg = user_data;

	msg->current_element = element_name;
}

static void xml_wispr_end_element_handler(GMarkupParseContext *context,
					const gchar *element_name,
					gpointer user_data, GError **error)
{
	struct connman_wispr_message *msg = user_data;

	msg->current_element = NULL;
}

static void xml_wispr_text_handler(GMarkupParseContext *context,
					const gchar *text, gsize text_len,
					gpointer user_data, GError **error)
{
	struct connman_wispr_message *msg = user_data;
	int i;

	if (!msg->current_element)
		return;

	for (i = 0; wispr_element_map[i].str; i++) {
		if (!g_str_equal(wispr_element_map[i].str, msg->current_element))
			continue;

		switch (wispr_element_map[i].element) {
		case WISPR_ELEMENT_NONE:
		case WISPR_ELEMENT_ACCESS_PROCEDURE:
			g_free(msg->access_procedure);
			msg->access_procedure = g_strdup(text);
			break;
		case WISPR_ELEMENT_ACCESS_LOCATION:
			g_free(msg->access_location);
			msg->access_location = g_strdup(text);
			break;
		case WISPR_ELEMENT_LOCATION_NAME:
			g_free(msg->location_name);
			msg->location_name = g_strdup(text);
			break;
		case WISPR_ELEMENT_LOGIN_URL:
			g_free(msg->login_url);
			msg->login_url = g_strdup(text);
			break;
		case WISPR_ELEMENT_ABORT_LOGIN_URL:
			g_free(msg->abort_login_url);
			msg->abort_login_url = g_strdup(text);
			break;
		case WISPR_ELEMENT_MESSAGE_TYPE:
			msg->message_type = atoi(text);
			break;
		case WISPR_ELEMENT_RESPONSE_CODE:
			msg->response_code = atoi(text);
			break;
		case WISPR_ELEMENT_NEXT_URL:
		case WISPR_ELEMENT_DELAY:
		case WISPR_ELEMENT_REPLY_MESSAGE:
		case WISPR_ELEMENT_LOGIN_RESULTS_URL:
			break;
		case WISPR_ELEMENT_LOGOFF_URL:
			g_free(msg->logoff_url);
			msg->logoff_url = g_strdup(text);
			break;
		}
	}
}

static void xml_wispr_error_handler(GMarkupParseContext *context,
					GError *error, gpointer user_data)
{
	struct connman_wispr_message *msg = user_data;

	msg->has_error = true;
}

static const GMarkupParser xml_wispr_parser_handlers = {
	xml_wispr_start_element_handler,
	xml_wispr_end_element_handler,
	xml_wispr_text_handler,
	NULL,
	xml_wispr_error_handler,
};

static void xml_wispr_parser_callback(const char *str, gpointer user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	GMarkupParseContext *parser_context = NULL;
	bool result;

	DBG("");

	parser_context = g_markup_parse_context_new(&xml_wispr_parser_handlers,
					G_MARKUP_TREAT_CDATA_AS_TEXT,
					&(wp_context->wispr_msg), NULL);

	result = g_markup_parse_context_parse(parser_context,
					str, strlen(str), NULL);
	if (result)
		g_markup_parse_context_end_parse(parser_context, NULL);

	g_markup_parse_context_free(parser_context);
}

static void web_debug(const char *str, void *data)
{
	DBG("%s: %s\n", (const char *) data, str);
}

static void wispr_portal_error(struct connman_wispr_portal_context *wp_context)
{
	DBG("Failed to proceed wispr/portal web request");

	wp_context->wispr_result = CONNMAN_WISPR_RESULT_FAILED;
}

static void portal_manage_status(GWebResult *result,
			struct connman_wispr_portal_context *wp_context)
{
	enum connman_ipconfig_type type = wp_context->type;
	struct connman_service *service;
	const char *str = NULL;

	DBG("");

	/* We currently don't do anything with this info */
	if (g_web_result_get_header(result, "X-ConnMan-Client-IP",
				&str))
		DBG("Client-IP: %s", str);

	if (g_web_result_get_header(result, "X-ConnMan-Client-Country",
				&str))
		DBG("Client-Country: %s", str);

	if (g_web_result_get_header(result, "X-ConnMan-Client-Region",
				&str))
		DBG("Client-Region: %s", str);

	if (g_web_result_get_header(result, "X-ConnMan-Client-Timezone",
				&str))
		DBG("Client-Timezone: %s", str);

	/* __connman_service_ipconfig_indicate_state may end up calling
	 * __connman_wispr_start which would reinitialize the wispr context
	 * so we better free it beforehand to avoid deallocating it twice. */
	service = connman_service_ref(wp_context->service);
	wispr_portal_context_unref(wp_context);

	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ONLINE, type);
	connman_service_unref(service);
}

static bool wispr_dns_route_request(int if_index, bool add, gpointer user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	struct connman_service *service;
	const char *gateway;

	DBG("index %d type %s", if_index, add ? "add" : "remove");

	service = __connman_service_lookup_from_index(if_index);
	if (!service)
		return false;

	gateway = __connman_ipconfig_get_gateway_from_index(if_index,
			wp_context->type);
	if (!gateway)
		return false;

	DBG("service %p gw %s", service, gateway);

	if (add)
		__connman_service_nameserver_add_routes(service, gateway);
	else
		__connman_service_nameserver_del_routes(service,
				wp_context->type);

	return true;
}

static bool wispr_route_request(const char *address, int ai_family,
		int if_index, gpointer user_data)
{
	int result = -1;
	struct connman_wispr_portal_context *wp_context = user_data;
	const char *gateway;
	struct wispr_route *route;

	gateway = __connman_ipconfig_get_gateway_from_index(if_index,
		wp_context->type);

	DBG("address %s if %d gw %s", address, if_index, gateway);

	if (!gateway)
		return false;

	route = g_try_new0(struct wispr_route, 1);
	if (route == 0) {
		DBG("could not create struct");
		return false;
	}

	switch (wp_context->type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		result = connman_inet_add_host_route(if_index, address,
				gateway);
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		result = connman_inet_add_ipv6_host_route(if_index, address,
				gateway);
		break;
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
	case CONNMAN_IPCONFIG_TYPE_ALL:
		break;
	}

	if (result < 0) {
		g_free(route);
		DBG("could not add host route %d address %s gateway %s",
				if_index, address, gateway);
		return false;
	}

	route->address = g_strdup(address);
	route->if_index = if_index;
	wp_context->route_list = g_slist_prepend(wp_context->route_list, route);

	return true;
}

static void wispr_portal_request_portal(
		struct connman_wispr_portal_context *wp_context)
{
	DBG("wp_context %p %s", wp_context,
		__connman_ipconfig_type2string(wp_context->type));

	wispr_portal_context_ref(wp_context);
	wp_context->request_id = g_web_request_get(wp_context->web,
					wp_context->status_url,
					wispr_portal_web_result,
					wispr_dns_route_request,
					wispr_route_request,
					wp_context);

	if (wp_context->request_id == 0) {
		wispr_portal_error(wp_context);
		wispr_portal_context_unref(wp_context);
	}
}

#ifdef DEAD_CODE
static bool wispr_input(const guint8 **data, gsize *length,
						gpointer user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	GString *buf;
	gsize count;

	DBG("");

	buf = g_string_sized_new(100);

	g_string_append(buf, "button=Login&UserName=");
	g_string_append_uri_escaped(buf, wp_context->wispr_username,
								NULL, FALSE);
	g_string_append(buf, "&Password=");
	g_string_append_uri_escaped(buf, wp_context->wispr_password,
								NULL, FALSE);
	g_string_append(buf, "&FNAME=0&OriginatingServer=");
	g_string_append_uri_escaped(buf, wp_context->status_url, NULL, FALSE);

	count = buf->len;

	g_free(wp_context->wispr_formdata);
	wp_context->wispr_formdata = g_string_free(buf, FALSE);

	*data = (guint8 *) wp_context->wispr_formdata;
	*length = count;

	return false;
}
#endif

static void wispr_portal_browser_reply_cb(struct connman_service *service,
					bool authentication_done,
					const char *error, void *user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	struct connman_wispr_portal *wispr_portal4;
	struct connman_wispr_portal *wispr_portal6;
	struct connman_ipconfig *ipconfig;
	int index4;
	int index6;

	DBG("");

	if (!service || !wp_context)
		return;

	/*
	 * No way to cancel this if wp_context has been freed, so we lookup
	 * from the service and check that this is still the right context.
	 */
	ipconfig = __connman_service_get_ip4config(service);
	index4 = __connman_ipconfig_get_index(ipconfig);

	ipconfig = __connman_service_get_ip6config(service);
	index6 = __connman_ipconfig_get_index(ipconfig);

	if (index4 < 0 && index6 < 0)
		return;

	wispr_portal4 = g_hash_table_lookup(wispr_portal_hash,
					GINT_TO_POINTER(index4));
	wispr_portal6 = g_hash_table_lookup(wispr_portal_hash,
					GINT_TO_POINTER(index6));
	if (!wispr_portal4 && !wispr_portal6)
		return;

	if (wp_context != wispr_portal4->ipv4_context &&
				wp_context != wispr_portal6->ipv6_context)
		return;

	if (!authentication_done) {
		free_wispr_routes(wp_context);
		wispr_portal_error(wp_context);
		wispr_portal_context_unref(wp_context);
		return;
	}

	/* Restarting the test */
	__connman_service_wispr_start(service, wp_context->type);
	wispr_portal_context_unref(wp_context);
}

#ifdef DEAD_CODE
static void wispr_portal_request_wispr_login(struct connman_service *service,
				bool success,
				const char *ssid, int ssid_len,
				const char *username, const char *password,
				bool wps, const char *wpspin,
				const char *error, void *user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;

	DBG("");

	if (error) {
		if (g_strcmp0(error,
			"net.connman.Agent.Error.LaunchBrowser") == 0) {
			if (__connman_agent_request_browser(service,
					wispr_portal_browser_reply_cb,
					wp_context->redirect_url,
					wp_context) == -EINPROGRESS)
				return;
		}

		wispr_portal_context_unref(wp_context);
		return;
	}

	g_free(wp_context->wispr_username);
	wp_context->wispr_username = g_strdup(username);

	g_free(wp_context->wispr_password);
	wp_context->wispr_password = g_strdup(password);

	wp_context->request_id = g_web_request_post(wp_context->web,
					wp_context->wispr_msg.login_url,
					"application/x-www-form-urlencoded",
					wispr_input, wispr_portal_web_result,
					wp_context);

	connman_wispr_message_init(&wp_context->wispr_msg);
}
#endif

/* Disable, this is not used because of commit
 * 7fad371bdc8ac397812e73d0f5baef25029b1419
static bool wispr_manage_message(GWebResult *result,
			struct connman_wispr_portal_context *wp_context)
{
	DBG("Message type: %s (%d)",
		message_type_to_string(wp_context->wispr_msg.message_type),
					wp_context->wispr_msg.message_type);
	DBG("Response code: %s (%d)",
		response_code_to_string(wp_context->wispr_msg.response_code),
					wp_context->wispr_msg.response_code);

	if (wp_context->wispr_msg.access_procedure)
		DBG("Access procedure: %s",
			wp_context->wispr_msg.access_procedure);
	if (wp_context->wispr_msg.access_location)
		DBG("Access location: %s",
			wp_context->wispr_msg.access_location);
	if (wp_context->wispr_msg.location_name)
		DBG("Location name: %s",
			wp_context->wispr_msg.location_name);
	if (wp_context->wispr_msg.login_url)
		DBG("Login URL: %s", wp_context->wispr_msg.login_url);
	if (wp_context->wispr_msg.abort_login_url)
		DBG("Abort login URL: %s",
			wp_context->wispr_msg.abort_login_url);
	if (wp_context->wispr_msg.logoff_url)
		DBG("Logoff URL: %s", wp_context->wispr_msg.logoff_url);

	switch (wp_context->wispr_msg.message_type) {
	case 100:
		DBG("Login required");

		wp_context->wispr_result = CONNMAN_WISPR_RESULT_LOGIN;

		wispr_portal_context_ref(wp_context);
		if (__connman_agent_request_login_input(wp_context->service,
					wispr_portal_request_wispr_login,
					wp_context) != -EINPROGRESS) {
			wispr_portal_error(wp_context);
			wispr_portal_context_unref(wp_context);
		} else
			return true;

		break;
	case 120: *//* Falling down *//*
	case 140:
		if (wp_context->wispr_msg.response_code == 50) {
			wp_context->wispr_result = CONNMAN_WISPR_RESULT_ONLINE;

			g_free(wp_context->wispr_username);
			wp_context->wispr_username = NULL;

			g_free(wp_context->wispr_password);
			wp_context->wispr_password = NULL;

			g_free(wp_context->wispr_formdata);
			wp_context->wispr_formdata = NULL;

			wispr_portal_request_portal(wp_context);

			return true;
		} else
			wispr_portal_error(wp_context);

		break;
	default:
		break;
	}

	return false;
}
*/

static bool wispr_portal_web_result(GWebResult *result, gpointer user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	const char *redirect = NULL;
	const guint8 *chunk = NULL;
	const char *str = NULL;
	guint16 status;
	gsize length;
	bool skip_failed = false;

	DBG("");

	if (wp_context->wispr_result != CONNMAN_WISPR_RESULT_ONLINE) {
		g_web_result_get_chunk(result, &chunk, &length);

		if (length > 0) {
			g_web_parser_feed_data(wp_context->wispr_parser,
								chunk, length);
			/* read more data */
			return true;
		}

		g_web_parser_end_data(wp_context->wispr_parser);

		/* No idea why this is commented out but let it be
		if (wp_context->wispr_msg.message_type >= 0) {
			if (wispr_manage_message(result, wp_context))
				goto done;
		}
		*/
	}

	status = g_web_result_get_status(result);

	DBG("status: %03u", status);

	switch (status) {
	case 000:
		DBG("Redirect URL: %s", redirect);
		DBG("Status url URL: %s", wp_context->status_url);

		wispr_portal_context_ref(wp_context);
		__connman_agent_request_browser(wp_context->service,
				wispr_portal_browser_reply_cb,
				wp_context->status_url, wp_context);
		break;
	case 200:
		/* No idea why this is commented out but let it be.
		if (wp_context->wispr_msg.message_type >= 0)
			break;
		*/

		if (g_web_result_get_header(result, "X-ConnMan-Status",
						&str)) {
			/*
			 * Cancel browser requests if useragent has not
			 * returned anything
			 */
			connman_agent_cancel(wp_context->service);
			portal_manage_status(result, wp_context);
		} else {
			wispr_portal_context_ref(wp_context);
			__connman_agent_request_browser(wp_context->service,
					wispr_portal_browser_reply_cb,
					wp_context->redirect_url, wp_context);
		}

		break;
	case 204:
		/*
		 * Cancel browser requests if user agent has not returned
		 * anything
		 */
		connman_agent_cancel(wp_context->service);
		portal_manage_status(result, wp_context);
		return false;
	case 302:
		DBG("tls %d, Location header %d", (!g_web_supports_tls()),
				(!g_web_result_get_header(result, "Location",
						&redirect)));

		if (!g_web_supports_tls() ||
			!g_web_result_get_header(result, "Location",
							&redirect)) {

			wispr_portal_context_ref(wp_context);
			__connman_agent_request_browser(wp_context->service,
					wispr_portal_browser_reply_cb,
					wp_context->status_url, wp_context);
			break;
		}

		DBG("Redirect URL: %s", redirect);
		DBG("Status url URL: %s", wp_context->status_url);

		wp_context->redirect_url = g_strdup(redirect);

		wispr_portal_context_ref(wp_context);
		wp_context->request_id = g_web_request_get(wp_context->web,
				redirect, wispr_portal_web_result,
				wispr_dns_route_request, wispr_route_request,
				wp_context);
		skip_failed = true;

		break;
	case 400:
	case 404:

		break;
	case 505:
		DBG("HTTP version not supported, handling over to the browser");
		DBG("Redirect URL: %s", redirect);
		DBG("Status url URL: %s", wp_context->status_url);

		wispr_portal_context_ref(wp_context);
		__connman_agent_request_browser(wp_context->service,
					wispr_portal_browser_reply_cb,
					wp_context->status_url, wp_context);
		break;
	default:
		break;
	}

	if (!skip_failed && __connman_service_online_check_failed(
			wp_context->service, wp_context->type) == 0) {
		wispr_portal_error(wp_context);
		wispr_portal_context_unref(wp_context);
		return false;
	}

	free_wispr_routes(wp_context);
	wp_context->request_id = 0;
	wp_context->wispr_msg.message_type = -1;
	wispr_portal_context_unref(wp_context);
	return false;
}

static char *parse_proxy(const char *proxy)
{
	char *proxy_server;
	char *c;

	if (!g_strcmp0(proxy, "DIRECT"))
		return NULL;

	if (!g_str_has_prefix(proxy, "PROXY "))
		return NULL;

	proxy_server = g_strdup(proxy + 6);

	/* Use first proxy server */
	c = strchr(proxy_server, ';');
	if (c)
		*c = '\0';

	g_strstrip(proxy_server);

	return proxy_server;
}

static void proxy_callback(const char *proxy, void *user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	char *proxy_server;

	DBG("proxy %s", proxy);

	if (!wp_context || !proxy)
		return;

	wp_context->token = 0;

	proxy_server = parse_proxy(proxy);
	if (proxy_server) {
		g_web_set_proxy(wp_context->web, proxy_server);
		g_free(proxy_server);
	}

	g_web_set_accept(wp_context->web, NULL);
	g_web_set_user_agent(wp_context->web, "ConnMan/%s wispr", VERSION);
	g_web_set_close_connection(wp_context->web, TRUE);

	connman_wispr_message_init(&wp_context->wispr_msg);

	wp_context->wispr_parser = g_web_parser_new(
					"<WISPAccessGatewayParam",
					"WISPAccessGatewayParam>",
					xml_wispr_parser_callback, wp_context);

	wispr_portal_request_portal(wp_context);
	wispr_portal_context_unref(wp_context);
}

static gboolean no_proxy_callback(gpointer user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;

	wp_context->timeout = 0;

	proxy_callback("DIRECT", wp_context);

	return FALSE;
}

static int wispr_portal_detect(struct connman_wispr_portal_context *wp_context)
{
	enum connman_service_proxy_method proxy_method;
	char *interface = NULL;
	char **nameservers = NULL;
	int if_index;
	int err = 0;
	int i;

	DBG("wispr/portal context %p service %p", wp_context,
		wp_context->service);

	interface = connman_service_get_interface(wp_context->service);
	if (!interface)
		return -EINVAL;

	DBG("interface %s", interface);

	if_index = connman_inet_ifindex(interface);
	if (if_index < 0) {
		DBG("Could not get ifindex");
		err = -EINVAL;
		goto done;
	}

	nameservers = connman_service_get_nameservers(wp_context->service);
	if (!nameservers) {
		DBG("Could not get nameservers");
		err = -EINVAL;
		goto done;
	}

	wp_context->web = g_web_new(if_index);
	if (!wp_context->web) {
		DBG("Could not set up GWeb");
		err = -ENOMEM;
		goto done;
	}

	if (getenv("CONNMAN_WEB_DEBUG"))
		g_web_set_debug(wp_context->web, web_debug, "WEB");

	if (wp_context->type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		g_web_set_address_family(wp_context->web, AF_INET);
		wp_context->status_url =
			connman_setting_get_string(CONF_STATUS_URL_IPV4);
	} else {
		g_web_set_address_family(wp_context->web, AF_INET6);
		wp_context->status_url =
			connman_setting_get_string(CONF_STATUS_URL_IPV6);
	}

	for (i = 0; nameservers[i]; i++)
		g_web_add_nameserver(wp_context->web, nameservers[i]);

	proxy_method = connman_service_get_proxy_method(wp_context->service);

	DBG("Proxy method %d",proxy_method);
	if (proxy_method != CONNMAN_SERVICE_PROXY_METHOD_DIRECT) {
		wp_context->token = connman_proxy_lookup(interface,
						wp_context->status_url,
						wp_context->service,
						proxy_callback, wp_context);

		if (wp_context->token == 0) {
			err = -EINVAL;
			wispr_portal_context_unref(wp_context);
		}
	} else if (wp_context->timeout == 0) {
		wp_context->timeout = g_idle_add(no_proxy_callback, wp_context);
	}

done:
	g_strfreev(nameservers);

	g_free(interface);
	return err;
}

int __connman_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	struct connman_wispr_portal_context *wp_context = NULL;
	struct connman_wispr_portal *wispr_portal = NULL;
	int index, err;

	DBG("service %p %s", service,
		__connman_ipconfig_type2string(type));

	if (!wispr_portal_hash)
		return -EINVAL;

	switch (connman_service_get_type(service)) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GADGET:
		break;
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_P2P:
		return -EOPNOTSUPP;
	}

	index = __connman_service_get_index(service);
	if (index < 0)
		return -EINVAL;

	wispr_portal = g_hash_table_lookup(wispr_portal_hash,
					GINT_TO_POINTER(index));
	if (!wispr_portal) {
		wispr_portal = g_try_new0(struct connman_wispr_portal, 1);
		if (!wispr_portal)
			return -ENOMEM;

		g_hash_table_replace(wispr_portal_hash,
					GINT_TO_POINTER(index), wispr_portal);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		wp_context = wispr_portal->ipv4_context;
	else
		wp_context = wispr_portal->ipv6_context;

	/* If there is already an existing context, we wipe it */
	if (wp_context)
		wispr_portal_context_unref(wp_context);

	wp_context = create_wispr_portal_context();
	if (!wp_context) {
		err = -ENOMEM;
		goto free_wp;
	}

	wp_context->service = connman_service_ref(service);
	wp_context->type = type;
	wp_context->wispr_portal = wispr_portal;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		wispr_portal->ipv4_context = wp_context;
	else
		wispr_portal->ipv6_context = wp_context;

	err = wispr_portal_detect(wp_context);
	if (err)
		goto free_wp;
	return 0;

free_wp:
	g_hash_table_remove(wispr_portal_hash, GINT_TO_POINTER(index));
	return err;
}

void __connman_wispr_stop(struct connman_service *service)
{
	struct connman_wispr_portal *wispr_portal;
	int index;

	DBG("service %p", service);

	if (!wispr_portal_hash)
		return;

	index = __connman_service_get_index(service);
	if (index < 0)
		return;

	connman_agent_cancel(service);

	wispr_portal = g_hash_table_lookup(wispr_portal_hash,
					GINT_TO_POINTER(index));
	if (!wispr_portal)
		return;

	if ((wispr_portal->ipv4_context &&
	     service == wispr_portal->ipv4_context->service) ||
	    (wispr_portal->ipv6_context &&
	     service == wispr_portal->ipv6_context->service))
		g_hash_table_remove(wispr_portal_hash, GINT_TO_POINTER(index));
}

int __connman_wispr_init(void)
{
	DBG("");

	wispr_portal_hash = g_hash_table_new_full(g_direct_hash,
						g_direct_equal, NULL,
						free_connman_wispr_portal);

	return 0;
}

void __connman_wispr_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(wispr_portal_hash);
	wispr_portal_hash = NULL;
}
