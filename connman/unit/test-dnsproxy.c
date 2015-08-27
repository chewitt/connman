/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014 Jolla Ltd. All rights reserved.
 *  Contact: Hannu Mallat <hannu.mallat@jollamobile.com>
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

/* Include source file to access static variables easily */
#include "src/dnsproxy.c"

static GMainLoop *main_loop = NULL;

/* Stub getaddrinfo() to return test data */
int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	struct addrinfo *ai = g_new0(struct addrinfo, 1);
	ai->ai_socktype = hints->ai_socktype;
	ai->ai_protocol = hints->ai_protocol;
	if (hints->ai_family == AF_INET6) {
		struct sockaddr_in6 *in6 = g_new0(struct sockaddr_in6, 1);
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(53);
		memcpy(&in6->sin6_addr.s6_addr, "0123456789abcdef", 16);

		ai->ai_family = AF_INET6;
		ai->ai_addrlen = sizeof(struct sockaddr_in6);
		ai->ai_addr = (struct sockaddr *)in6;
	} else {
		struct sockaddr_in *in = g_new0(struct sockaddr_in, 1);
		in->sin_family = AF_INET;
		in->sin_port = htons(53);
		in->sin_addr.s_addr = htonl(0x12345678);

		ai->ai_family = AF_INET6;
		ai->ai_addrlen = sizeof(struct sockaddr_in);
		ai->ai_addr = (struct sockaddr *)in;
	}
	ai->ai_canonname = g_strdup(node);
	ai->ai_next = NULL;
	*res = ai;

	return 0;
}

void freeaddrinfo(struct addrinfo *res)
{
	if (res) {
		if (res->ai_addr) {
			g_free(res->ai_addr);
		}
		if (res->ai_canonname) {
			g_free(res->ai_canonname);
		}
		g_free(res);
	}
}

/* Stub socket() that always fails */
int socket(int domain, int type, int protocol)
{
	return -1;
}

GResolv *g_resolv_new(int index)
{
	return NULL;
}

bool g_resolv_set_address_family(GResolv *resolv, int family)
{
	return FALSE;
}

bool g_resolv_add_nameserver(GResolv *resolv, const char *address,
					uint16_t port, unsigned long flags)
{
	return FALSE;
}

guint g_resolv_lookup_hostname(GResolv *resolv, const char *hostname,
				GResolvResultFunc func, gpointer user_data)
{
	return 0;
}

int __connman_agent_request_connection(void *user_data)
{
	return -1;
}

char *connman_inet_ifname(int index)
{
	return NULL;
}

int connman_inet_ifindex(const char *name)
{
	return -1;
}

int __connman_inet_get_interface_address(int index, int family, void *address)
{
	return -1;
}

int __connman_service_get_index(struct connman_service *service)
{
	return -1;
}

bool __connman_service_index_is_default(int index)
{
	return FALSE;
}

bool __connman_service_index_is_split_routing(int index)
{
	return FALSE;
}

int __connman_resolvfile_append(int index, const char *domain, const char *server)
{
	return -1;
}

int __connman_resolvfile_remove(int index, const char *domain, const char *server)
{
	return -1;
}

int connman_notifier_register(struct connman_notifier *notifier)
{
	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
}

int __connman_util_get_random(uint64_t *val)
{
        if (!val)
                return -EINVAL;

	*val = rand() % 2000;
	return 0;
}

static gboolean server_creation_failure_check_state(gpointer user_data)
{
	DBG("cache_refcount is %d, expecting 0.", cache_refcount);
	g_assert(cache_refcount >= 0);
	g_main_loop_quit(main_loop);
	return FALSE;
}

static void server_creation_failure(void)
{
	int i;
	time_t t;

	srand((unsigned) time(&t));

	main_loop = g_main_loop_new(NULL, FALSE);
	__connman_log_init("test-dnsproxy",
				g_test_verbose() ? "*" : NULL,
				FALSE, FALSE,
				"test-dnsproxy", "1");

	/* socket() set to fail, __connman_dnsproxy_append must therefore fail */
	for (i = 0; i < 10; i++) {
		g_assert(__connman_dnsproxy_append(0,
						"example.com",
						"ns.example.com") == -EIO);
	}

	g_timeout_add_seconds(4, server_creation_failure_check_state,
				NULL);
	g_main_loop_run(main_loop);

	g_main_loop_unref(main_loop);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/dnsproxy/server-creation-failure",
			server_creation_failure);

	return g_test_run();
}

