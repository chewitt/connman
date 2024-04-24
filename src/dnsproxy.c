/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2022 Matthias Gerstner of SUSE. All rights reserved.
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
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <gweb/gresolv.h>

#include <glib.h>

#include "connman.h"

#ifdef DNSPROXY_DEBUG
#	define debug(fmt...) do { fprintf(stderr, fmt); fprintf(stderr, "\n"); } while (0)
#else
#	define debug(fmt...) do { } while (0)
#endif

#define NUM_ARRAY_ELEMENTS(a) sizeof(a) / sizeof(a[0])

#if __BYTE_ORDER == __LITTLE_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#elif __BYTE_ORDER == __BIG_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t qr:1;
	uint8_t opcode:4;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;
	uint8_t ra:1;
	uint8_t z:3;
	uint8_t rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#else
#error "Unknown byte order"
#endif

struct qtype_qclass {
	uint16_t qtype;
	uint16_t qclass;
} __attribute__ ((packed));

struct partial_reply {
	uint16_t len;
	uint16_t received;
	unsigned char buf[];
};

struct server_data {
	int index;
	GList *domains;
	char *server;
	struct sockaddr *server_addr;
	socklen_t server_addr_len;
	int protocol;
	GIOChannel *channel;
	guint watch;
	guint timeout;
	bool enabled;
	bool connected;
	struct partial_reply *incoming_reply;
};

struct request_data {
	union {
		struct sockaddr_in6 __sin6; /* Only for the length */
		struct sockaddr sa;
	};
	socklen_t sa_len;
	int client_sk;
	int protocol;
	int family;
	guint16 srcid;
	guint16 dstid;
	guint16 altid;
	guint timeout;
	guint watch;
	guint numserv;
	guint numresp;
	gpointer request;
	gsize request_len;
	gpointer name;
	gpointer resp;
	gsize resplen;
	struct listener_data *ifdata;
	bool append_domain;
};

struct listener_data {
	int index;

	GIOChannel *udp4_listener_channel;
	GIOChannel *tcp4_listener_channel;
	guint udp4_listener_watch;
	guint tcp4_listener_watch;

	GIOChannel *udp6_listener_channel;
	GIOChannel *tcp6_listener_channel;
	guint udp6_listener_watch;
	guint tcp6_listener_watch;
};

/*
 * The TCP client requires some extra handling as we need to
 * be prepared to receive also partial DNS requests.
 */
struct tcp_partial_client_data {
	int family;
	struct listener_data *ifdata;
	GIOChannel *channel;
	guint watch;
	unsigned char *buf;
	unsigned int buf_end;
	guint timeout;
};

struct cache_data {
	time_t inserted;
	time_t valid_until;
	time_t cache_until;
	int timeout;
	uint16_t type;
	uint16_t answers;
	unsigned int data_len;
	unsigned char *data; /* contains DNS header + body */
};

struct cache_entry {
	char *key;
	bool want_refresh;
	size_t hits;
	struct cache_data *ipv4;
	struct cache_data *ipv6;
};

struct cache_timeout {
	time_t current_time;
	time_t max_timeout;
	bool try_harder;
};

struct domain_question {
	uint16_t type;
	uint16_t class;
} __attribute__ ((packed));

struct domain_rr {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
} __attribute__ ((packed));

/*
 * Max length of the DNS TCP packet.
 */
#define TCP_MAX_BUF_LEN 4096

/*
 * We limit how long the cached DNS entry stays in the cache.
 * By default the TTL (time-to-live) of the DNS response is used
 * when setting the cache entry life time. The value is in seconds.
 */
#define MAX_CACHE_TTL (60 * 30)
/*
 * Also limit the other end, cache at least for 30 seconds.
 */
#define MIN_CACHE_TTL (30)

/*
 * We limit the cache size to some sane value so that cached data does
 * not occupy too much memory. Each cached entry occupies on average
 * about 100 bytes memory (depending on DNS name length).
 * Example: caching www.connman.net uses 97 bytes memory.
 * The value is the max amount of cached DNS responses (count).
 */
#define MAX_CACHE_SIZE 256

#define DNS_HEADER_SIZE sizeof(struct domain_hdr)
#define DNS_HEADER_TCP_EXTRA_BYTES 2
#define DNS_TCP_HEADER_SIZE DNS_HEADER_SIZE + DNS_HEADER_TCP_EXTRA_BYTES
#define DNS_QUESTION_SIZE sizeof(struct domain_question)
#define DNS_RR_SIZE sizeof(struct domain_rr)
#define DNS_QTYPE_QCLASS_SIZE sizeof(struct qtype_qclass)

enum dns_type {
	/* IPv4 address 32-bit */
	DNS_TYPE_A = ns_t_a,
	/* IPv6 address 128-bit */
	DNS_TYPE_AAAA = ns_t_aaaa,
	/* alias to another name */
	DNS_TYPE_CNAME = ns_t_cname,
	/* start of a zone of authority */
	DNS_TYPE_SOA = ns_t_soa
};

enum dns_class {
	DNS_CLASS_IN = ns_c_in,
	DNS_CLASS_ANY = ns_c_any /* only valid for QCLASS fields */
};

static int cache_size;
static GHashTable *cache;
static int cache_refcount;
static GSList *server_list;
static GSList *request_list;
static GHashTable *listener_table;
static time_t next_refresh;
static GHashTable *partial_tcp_req_table;
static guint cache_timer;
static in_port_t dns_listen_port = 53;
/* we can keep using the same resolve's */
static GResolv *ipv4_resolve;
static GResolv *ipv6_resolve;

static guint16 get_id(void)
{
	uint64_t rand;

	/* TODO: return code is ignored, should we rather abort() on error? */
	__connman_util_get_random(&rand);

	return rand;
}

static size_t protocol_offset(int protocol)
{
	switch (protocol) {
	case IPPROTO_UDP:
		return 0;

	case IPPROTO_TCP:
		return DNS_HEADER_TCP_EXTRA_BYTES;

	default:
		/* this should never happen */
		abort();
	}
}

static const char* protocol_label(int protocol)
{
	switch(protocol) {
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_TCP:
		return "TCP";
	default:
		return "BAD_PROTOCOL";
	}
}

static int socket_type(int protocol, int extra_flags)
{
	switch (protocol) {
	case IPPROTO_UDP:
		return SOCK_DGRAM | extra_flags;
	case IPPROTO_TCP:
		return SOCK_STREAM | extra_flags;
	default:
		/* this should never happen */
		abort();
	}
}

/*
 * There is a power and efficiency benefit to have entries
 * in our cache expire at the same time. To this extend,
 * we round down the cache valid time to common boundaries.
 */
static time_t round_down_ttl(time_t end_time, int ttl)
{
	if (ttl < 15)
		return end_time;

	/* Less than 5 minutes, round to 10 second boundary */
	if (ttl < 300) {
		end_time = end_time / 10;
		end_time = end_time * 10;
	} else { /* 5 or more minutes, round to 30 seconds */
		end_time = end_time / 30;
		end_time = end_time * 30;
	}
	return end_time;
}

static struct request_data *find_request(guint16 id)
{
	for (GSList *list = request_list; list; list = list->next) {
		struct request_data *req = list->data;

		if (req->dstid == id || req->altid == id)
			return req;
	}

	return NULL;
}

static struct server_data *find_server(int index,
					const char *server,
						int protocol)
{
	debug("index %d server %s proto %d", index, server, protocol);

	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (index < 0 && data->index < 0 &&
				g_str_equal(data->server, server) &&
				data->protocol == protocol)
			return data;

		if (index < 0 ||
				data->index < 0 || !data->server)
			continue;

		if (data->index == index &&
				g_str_equal(data->server, server) &&
				data->protocol == protocol)
			return data;
	}

	return NULL;
}

static void dummy_resolve_func(GResolvResultStatus status,
					char **results, gpointer user_data)
{
}

/*
 * Refresh a DNS entry, but also age the hit count a bit */
static void refresh_dns_entry(struct cache_entry *entry, char *name)
{
	unsigned int age = 1;

	if (!ipv4_resolve) {
		ipv4_resolve = g_resolv_new(0);
		g_resolv_set_address_family(ipv4_resolve, AF_INET);
		g_resolv_add_nameserver(ipv4_resolve, "127.0.0.1", 53, 0);
	}

	if (!ipv6_resolve) {
		ipv6_resolve = g_resolv_new(0);
		g_resolv_set_address_family(ipv6_resolve, AF_INET6);
		g_resolv_add_nameserver(ipv6_resolve, "::1", 53, 0);
	}

	if (!entry->ipv4) {
		debug("Refreshing A record for %s", name);
		g_resolv_lookup_hostname(ipv4_resolve, name,
					dummy_resolve_func, NULL);
		age = 4;
	}

	if (!entry->ipv6) {
		debug("Refreshing AAAA record for %s", name);
		g_resolv_lookup_hostname(ipv6_resolve, name,
					dummy_resolve_func, NULL);
		age = 4;
	}

	if (entry->hits > age)
		entry->hits -= age;
	else
		entry->hits = 0;
}

static size_t dns_name_length(const unsigned char *buf)
{
	if ((buf[0] & NS_CMPRSFLGS) == NS_CMPRSFLGS) /* compressed name */
		return 2;
	return strlen((const char *)buf) + 1;
}

static void update_cached_ttl(unsigned char *ptr, size_t len, int new_ttl)
{
	size_t name_len;
	const uint32_t raw_ttl = ntohl((uint32_t)new_ttl);

	if (new_ttl < 0 || len < DNS_HEADER_SIZE + DNS_QUESTION_SIZE + 1)
		return;

	/* skip the header */
	ptr += DNS_HEADER_SIZE;
	len -= DNS_HEADER_SIZE;

	/* skip the query, which is a name and a struct domain_question */
	name_len = dns_name_length(ptr);

	if (len < name_len + DNS_QUESTION_SIZE)
		return;

	ptr += name_len + DNS_QUESTION_SIZE;
	len -= name_len + DNS_QUESTION_SIZE;

	/* now we get the answer records */

	while (len > 0) {
		struct domain_rr *rr = NULL;
		size_t rr_len;

		/* first a name */
		name_len = dns_name_length(ptr);
		if (len < name_len)
			break;

		ptr += name_len;
		len -= name_len;

		rr = (void*)ptr;
		if (len < sizeof(*rr))
			/* incomplete record */
			break;

		/* update the TTL field */
		memcpy(&rr->ttl, &raw_ttl, sizeof(raw_ttl));

		/* skip to the next record */
		rr_len = sizeof(*rr) + ntohs(rr->rdlen);
		if (len < rr_len)
			break;

		ptr += rr_len;
		len -= rr_len;
	}
}

static void send_cached_response(int sk, const unsigned char *ptr, size_t len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol, int id, uint16_t answers, int ttl)
{
	struct domain_hdr *hdr = NULL;
	int err;
	size_t bytes_sent;
	const size_t offset = protocol_offset(protocol);
	/*
	 * The cached packet contains always the TCP offset (two bytes)
	 * so skip them for UDP.
	 */
	const size_t skip_bytes = offset ? 0 : DNS_HEADER_TCP_EXTRA_BYTES;
	size_t dns_len;

	ptr += skip_bytes;
	len -= skip_bytes;
	dns_len = protocol == IPPROTO_UDP ? len : ntohs(*((uint16_t*)ptr));


	if (len < DNS_HEADER_SIZE)
		return;

	hdr = (void *) (ptr + offset);

	hdr->id = id;
	hdr->qr = 1;
	hdr->rcode = ns_r_noerror;
	hdr->ancount = htons(answers);
	hdr->nscount = 0;
	hdr->arcount = 0;

	/* if this is a negative reply, we are authoritative */
	if (answers == 0)
		hdr->aa = 1;
	else
		update_cached_ttl((unsigned char *)hdr, dns_len, ttl);

	debug("sk %d id 0x%04x answers %d ptr %p length %zd dns %zd",
		sk, hdr->id, answers, ptr, len, dns_len);

	err = sendto(sk, ptr, len, MSG_NOSIGNAL, to, tolen);
	if (err < 0) {
		connman_error("Cannot send cached DNS response: %s",
				strerror(errno));
	}

	bytes_sent = err;
	if (bytes_sent != len || dns_len != (len - offset))
		debug("Packet length mismatch, sent %d wanted %zd dns %zd",
			err, len, dns_len);
}

static void send_response(int sk, unsigned char *buf, size_t len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol)
{
	struct domain_hdr *hdr;
	int err;
	const size_t offset = protocol_offset(protocol);
	const size_t send_size = DNS_HEADER_SIZE + offset;

	debug("sk %d", sk);

	if (len < send_size)
		return;

	hdr = (void *) (buf + offset);
	if (offset) {
		buf[0] = 0;
		buf[1] = DNS_HEADER_SIZE;
	}

	debug("id 0x%04x qr %d opcode %d", hdr->id, hdr->qr, hdr->opcode);

	hdr->qr = 1;
	hdr->rcode = ns_r_servfail;

	hdr->qdcount = 0;
	hdr->ancount = 0;
	hdr->nscount = 0;
	hdr->arcount = 0;

	err = sendto(sk, buf, send_size, MSG_NOSIGNAL, to, tolen);
	if (err < 0) {
		connman_error("Failed to send DNS response to %d: %s",
				sk, strerror(errno));
	}
}

static int get_req_udp_socket(struct request_data *req)
{
	GIOChannel *channel;

	if (req->family == AF_INET)
		channel = req->ifdata->udp4_listener_channel;
	else
		channel = req->ifdata->udp6_listener_channel;

	if (!channel)
		return -1;

	return g_io_channel_unix_get_fd(channel);
}

static void destroy_request_data(struct request_data *req)
{
	if (req->timeout > 0)
		g_source_remove(req->timeout);

	g_free(req->resp);
	g_free(req->request);
	g_free(req->name);
	g_free(req);
}

static gboolean request_timeout(gpointer user_data)
{
	struct request_data *req = user_data;
	struct sockaddr *sa;
	int sk = -1;

	if (!req)
		return FALSE;

	debug("id 0x%04x", req->srcid);

	request_list = g_slist_remove(request_list, req);

	if (req->protocol == IPPROTO_UDP) {
		sk = get_req_udp_socket(req);
		sa = &req->sa;
	} else if (req->protocol == IPPROTO_TCP) {
		sk = req->client_sk;
		sa = NULL;
	}

	if (sk < 0)
		goto out;

	if (req->resplen > 0 && req->resp) {
		/*
		 * Here we have received at least one reply (probably telling
		 * "not found" result), so send that back to client instead
		 * of more fatal server failed error.
		 */
		if (sendto(sk, req->resp, req->resplen, MSG_NOSIGNAL,
				sa, req->sa_len) < 0)
			connman_error("Failed to send response %d: %s",
					sk, strerror(errno));
	} else if (req->request) {
		/*
		 * There was not reply from server at all.
		 */
		struct domain_hdr *hdr = (void *)(req->request + protocol_offset(req->protocol));
		hdr->id = req->srcid;

		send_response(sk, req->request, req->request_len,
			sa, req->sa_len, req->protocol);
	}

	/*
	 * We cannot leave TCP client hanging so just kick it out
	 * if we get a request timeout from server.
	 */
	if (req->protocol == IPPROTO_TCP) {
		debug("client %d removed", req->client_sk);
		g_hash_table_remove(partial_tcp_req_table,
				GINT_TO_POINTER(req->client_sk));
	}

out:
	req->timeout = 0;
	destroy_request_data(req);

	return FALSE;
}

static int append_data(unsigned char *buf, size_t size, const char *data)
{
	unsigned char *ptr = buf;
	size_t len;

	while (true) {
		const char *dot = strchrnul(data, '.');
		len = dot - data;

		if (len == 0)
			break;
		else if (size < len + 1)
			return -1;

		*ptr = len;
		memcpy(ptr + 1, data, len);
		ptr += len + 1;
		size -= len + 1;

		if (!dot)
			break;

		data = dot + 1;
	}

	return ptr - buf;
}

static int append_query(unsigned char *buf, size_t size,
				const char *query, const char *domain)
{
	size_t added;
	size_t left_size = size;
	int res;

	debug("query %s domain %s", query, domain);

	res = append_data(buf, left_size, query);
	if (res < 0)
		return -1;
	left_size -= res;

	res = append_data(buf + res, left_size, domain);
	if (res < 0)
		return -1;
	left_size -= res;

	if (left_size == 0)
		return -1;

	added = size - left_size;
	*(buf + added) = 0x00;

	return added;
}

static bool cache_check_is_valid(struct cache_data *data, time_t current_time)
{
	if (!data)
		return false;
	else if (data->cache_until < current_time)
		return false;

	return true;
}

static void cache_free_ipv4(struct cache_entry *entry)
{
	if (!entry->ipv4)
		return;

	g_free(entry->ipv4->data);
	g_free(entry->ipv4);
	entry->ipv4 = NULL;
}

static void cache_free_ipv6(struct cache_entry *entry)
{
	if (!entry->ipv6)
		return;

	g_free(entry->ipv6->data);
	g_free(entry->ipv6);
	entry->ipv6 = NULL;
}

/*
 * remove stale cached entries so that they can be refreshed
 */
static void cache_enforce_validity(struct cache_entry *entry)
{
	time_t current_time = time(NULL);

	if (entry->ipv4 && !cache_check_is_valid(entry->ipv4, current_time)) {
		debug("cache timeout \"%s\" type A", entry->key);
		cache_free_ipv4(entry);
	}

	if (entry->ipv6 && !cache_check_is_valid(entry->ipv6, current_time)) {
		debug("cache timeout \"%s\" type AAAA", entry->key);
		cache_free_ipv6(entry);
	}
}

static bool cache_check_validity(const char *question, uint16_t type,
				struct cache_entry *entry)
{
	struct cache_data *cached_ip = NULL, *other_ip = NULL;
	const time_t current_time = time(NULL);
	bool want_refresh;

	cache_enforce_validity(entry);

	switch (type) {
	case DNS_TYPE_A: /* IPv4 */
		cached_ip = entry->ipv4;
		other_ip = entry->ipv6;
		break;

	case DNS_TYPE_AAAA: /* IPv6 */
		cached_ip = entry->ipv6;
		other_ip = entry->ipv4;
		break;
	default:
		return false;
	}

	/*
	 * if we have a popular entry, we want a refresh instead of
	 * total destruction of the entry.
	 */
	want_refresh = entry->hits > 2 ? true : false;

	if (!cache_check_is_valid(cached_ip, current_time)) {
		debug("cache %s \"%s\" type %s",
				cached_ip ?  "timeout" : "entry missing",
				question,
				cached_ip == entry->ipv4 ? "A" : "AAAA");

		if (want_refresh)
			entry->want_refresh = true;
		/*
		 * We do not remove cache entry if there is still a
		 * valid entry for another IP version found in the cache.
		 */
		else if (!cache_check_is_valid(other_ip, current_time)) {
			g_hash_table_remove(cache, question);
			return false;
		}
	}

	return true;
}

static void cache_element_destroy(gpointer value)
{
	struct cache_entry *entry = value;

	if (!entry)
		return;

	cache_free_ipv4(entry);
	cache_free_ipv6(entry);

	g_free(entry->key);
	g_free(entry);

	/* TODO: this would be a worrying condition. Does this ever happen? */
	if (--cache_size < 0)
		cache_size = 0;
}

static gboolean try_remove_cache(gpointer user_data)
{
	cache_timer = 0;

	if (__sync_fetch_and_sub(&cache_refcount, 1) == 1) {
		debug("No cache users, removing it.");

		g_hash_table_destroy(cache);
		cache = NULL;
		cache_size = 0;
	}

	return FALSE;
}

static void create_cache(void)
{
	if (__sync_fetch_and_add(&cache_refcount, 1) == 0) {
		cache = g_hash_table_new_full(g_str_hash,
					g_str_equal,
					NULL,
					cache_element_destroy);
		cache_size = 0;
	}
}

static struct cache_entry *cache_check(gpointer request, uint16_t *qtype, int proto)
{
	const char *question;
	size_t offset;
	const struct domain_question *q;
	uint16_t type;
	struct cache_entry *entry;

	if (!request)
		return NULL;

	question = request + protocol_offset(proto) + DNS_HEADER_SIZE;
	offset = strlen(question) + 1;
	q = (void *) (question + offset);
	type = ntohs(q->type);

	/* We only cache either A (1) or AAAA (28) requests */
	if (type != DNS_TYPE_A && type != DNS_TYPE_AAAA)
		return NULL;

	if (!cache) {
		create_cache();
		return NULL;
	}

	entry = g_hash_table_lookup(cache, question);
	if (!entry)
		return NULL;

	if (!cache_check_validity(question, type, entry))
		return NULL;

	*qtype = type;
	return entry;
}

/*
 * Get a label/name from DNS resource record. The function decompresses the
 * label if necessary. The function does not convert the name to presentation
 * form. This means that the result string will contain label lengths instead
 * of dots between labels. We intentionally do not want to convert to dotted
 * format so that we can cache the wire format string directly.
 */
static int get_name(int counter,
		const unsigned char *pkt, const unsigned char *start, const unsigned char *max,
		unsigned char *output, int output_max, int *output_len,
		const unsigned char **end, char *name, size_t max_name, int *name_len)
{
	const unsigned char *p = start;

	/* Limit recursion to 10 (this means up to 10 labels in domain name) */
	if (counter > 10)
		return -EINVAL;

	while (*p) {
		if ((*p & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			const uint16_t offset = (*p & 0x3F) * 256 + *(p + 1);

			if (offset >= max - pkt)
				return -ENOBUFS;

			if (!*end)
				*end = p + 2;

			return get_name(counter + 1, pkt, pkt + offset, max,
					output, output_max, output_len, end,
					name, max_name, name_len);
		} else {
			unsigned label_len = *p;

			if (pkt + label_len > max)
				return -ENOBUFS;
			else if (*output_len > output_max)
				return -ENOBUFS;
			else if ((*name_len + 1 + label_len + 1) > max_name)
				return -ENOBUFS;

			/*
			 * We need the original name in order to check
			 * if this answer is the correct one.
			 */
			name[(*name_len)++] = label_len;
			memcpy(name + *name_len, p + 1,	label_len + 1);
			*name_len += label_len;

			/* We compress the result */
			output[0] = NS_CMPRSFLGS;
			output[1] = 0x0C;
			*output_len = 2;

			p += label_len + 1;

			if (!*end)
				*end = p;

			if (p >= max)
				return -ENOBUFS;
		}
	}

	return 0;
}

static int parse_rr(const unsigned char *buf, const unsigned char *start,
			const unsigned char *max,
			unsigned char *response, size_t *response_size,
			uint16_t *type, uint16_t *class, int *ttl, uint16_t *rdlen,
			const unsigned char **end,
			char *name, size_t max_name)
{
	struct domain_rr *rr;
	size_t offset;
	int name_len = 0, output_len = 0, max_rsp = *response_size;
	int err = get_name(0, buf, start, max, response, max_rsp,
		&output_len, end, name, max_name, &name_len);

	if (err < 0)
		return err;

	offset = output_len;

	if (offset > *response_size)
		return -ENOBUFS;

	rr = (void *) (*end);

	if (!rr)
		return -EINVAL;

	*type = ntohs(rr->type);
	*class = ntohs(rr->class);
	*ttl = ntohl(rr->ttl);
	*rdlen = ntohs(rr->rdlen);

	if (*ttl < 0)
		return -EINVAL;

	memcpy(response + offset, *end, DNS_RR_SIZE);

	offset += DNS_RR_SIZE;
	*end += DNS_RR_SIZE;

	if ((offset + *rdlen) > *response_size)
		return -ENOBUFS;

	memcpy(response + offset, *end, *rdlen);

	*end += *rdlen;
	*response_size = offset + *rdlen;

	return 0;
}

static bool check_alias(GSList *aliases, const char *name)
{
	if (aliases) {
		for (GSList *list = aliases; list; list = list->next) {
			const char *cmpname = (const char*)list->data;
			if (strncmp(cmpname, name, NS_MAXDNAME) == 0)
				return true;
		}
	}

	return false;
}

/*
 * Parses the DNS response packet found in 'buf' consisting of 'buflen' bytes.
 *
 * The parsed question label, response type and class, ttl and number of
 * answer sections are output parameters. The response output buffer will
 * receive all matching resource records to be cached.
 *
 * Return value is < 0 on error (negative errno) or zero on success.
 */
static int parse_response(const unsigned char *buf, size_t buflen,
			char *question, size_t qlen,
			uint16_t *type, uint16_t *class, int *ttl,
			unsigned char *response, size_t *response_len,
			uint16_t *answers)
{
	struct domain_hdr *hdr = (void *) buf;
	struct domain_question *q;
	uint16_t qtype;
	int err = -ENOMSG;
	uint16_t ancount, qclass;
	GSList *aliases = NULL;
	const size_t maxlen = *response_len;
	uint16_t qdcount;
	const unsigned char *ptr;
	const unsigned char *eptr;

	*response_len = 0;
	*answers = 0;

	if (buflen < DNS_HEADER_SIZE)
		return -EINVAL;

	qdcount = ntohs(hdr->qdcount);
	ptr = buf + DNS_HEADER_SIZE;
	eptr = buf + buflen;

	debug("qr %d qdcount %d", hdr->qr, qdcount);

	/* We currently only cache responses where question count is 1 */
	if (hdr->qr != 1 || qdcount != 1)
		return -EINVAL;

	/*
	 * NOTE: currently the *caller* ensures that the `question' buffer is
	 * always zero terminated.
	 */
	strncpy(question, (const char *) ptr, MIN(qlen, buflen - DNS_HEADER_SIZE));
	qlen = strlen(question);
	ptr += qlen + 1; /* skip \0 */

	if (ptr + DNS_QUESTION_SIZE >= eptr)
		return -EINVAL;

	q = (void *) ptr;
	qtype = ntohs(q->type);

	/* We cache only A and AAAA records */
	if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA)
		return -ENOMSG;

	ptr += DNS_QUESTION_SIZE; /* advance to answers section */

	ancount = ntohs(hdr->ancount);
	qclass = ntohs(q->class);

	/*
	 * We have a bunch of answers (like A, AAAA, CNAME etc) to
	 * A or AAAA question. We traverse the answers and parse the
	 * resource records. Only A and AAAA records are cached, all
	 * the other records in answers are skipped.
	 */
	for (uint16_t i = 0; i < ancount; i++) {
		char name[NS_MAXDNAME + 1] = {0};
		/*
		 * Get one address at a time to this buffer.
		 * The max size of the answer is
		 *   2 (pointer) + 2 (type) + 2 (class) +
		 *   4 (ttl) + 2 (rdlen) + addr (16 or 4) = 28
		 * for A or AAAA record.
		 * For CNAME the size can be bigger.
		 * TODO: why are we using the MAXCDNAME constant as buffer
		 * size then?
		 */
		unsigned char rsp[NS_MAXCDNAME] = {0};
		size_t rsp_len = sizeof(rsp) - 1;
		const unsigned char *next = NULL;
		uint16_t rdlen;

		int ret = parse_rr(buf, ptr, buf + buflen, rsp, &rsp_len,
			type, class, ttl, &rdlen, &next, name,
			sizeof(name) - 1);
		if (ret != 0) {
			err = ret;
			break;
		}

		/* set pointer to the next RR for the next iteration */
		ptr = next;

		/*
		 * Now rsp contains a compressed or an uncompressed resource
		 * record. Next we check if this record answers the question.
		 * The name var contains the uncompressed label.
		 * One tricky bit is the CNAME records as they alias
		 * the name we might be interested in.
		 */

		/*
		 * Go to next answer if the class is not the one we are
		 * looking for.
		 */
		if (*class != qclass) {
			continue;
		}

		/*
		 * Try to resolve aliases also, type is CNAME(5).
		 * This is important as otherwise the aliased names would not
		 * be cached at all as the cache would not contain the aliased
		 * question.
		 *
		 * If any CNAME is found in DNS packet, then we cache the alias
		 * IP address instead of the question (as the server
		 * said that question has only an alias).
		 * This means in practice that if e.g., ipv6.google.com is
		 * queried, DNS server returns CNAME of that name which is
		 * ipv6.l.google.com. We then cache the address of the CNAME
		 * but return the question name to client. So the alias
		 * status of the name is not saved in cache and thus not
		 * returned to the client. We do not return DNS packets from
		 * cache to client saying that ipv6.google.com is an alias to
		 * ipv6.l.google.com but we return instead a DNS packet that
		 * says ipv6.google.com has address xxx which is in fact the
		 * address of ipv6.l.google.com. For caching purposes this
		 * should not cause any issues.
		 */
		if (*type == DNS_TYPE_CNAME && strncmp(question, name, qlen) == 0) {
			/*
			 * So now the alias answered the question. This is
			 * not very useful from caching point of view as
			 * the following A or AAAA records will not match the
			 * question. We need to find the real A/AAAA record
			 * of the alias and cache that.
			 */
			const unsigned char *end = NULL;
			int name_len = 0, output_len = 0;

			memset(rsp, 0, sizeof(rsp));
			rsp_len = sizeof(rsp) - 1;

			/*
			 * Alias is in rdata part of the message,
			 * and next-rdlen points to it. So we need to get
			 * the real name of the alias.
			 */
			ret = get_name(0, buf, next - rdlen, buf + buflen,
					rsp, rsp_len, &output_len, &end,
					name, sizeof(name) - 1, &name_len);
			if (ret != 0) {
				/* just ignore the error at this point */
				continue;
			}

			/*
			 * We should now have the alias of the entry we might
			 * want to cache. Just remember it for a while.
			 * We check the alias list when we have parsed the
			 * A or AAAA record.
			 */
			aliases = g_slist_prepend(aliases, g_strdup(name));

			continue;
		} else if (*type == qtype) {
			/*
			 * We found correct type (A or AAAA)
			 */
			if (check_alias(aliases, name) ||
				(!aliases && strncmp(question, name,
							qlen) == 0)) {
				/*
				 * We found an alias or the name of the rr
				 * matches the question. If so, we append
				 * the compressed label to the cache.
				 * The end result is a response buffer that
				 * will contain one or more cached and
				 * compressed resource records.
				 */
				if (*response_len + rsp_len > maxlen) {
					err = -ENOBUFS;
					break;
				}
				memcpy(response + *response_len, rsp, rsp_len);
				*response_len += rsp_len;
				(*answers)++;
				err = 0;
			}
		}
	}

	for (GSList *list = aliases; list; list = list->next)
		g_free(list->data);
	g_slist_free(aliases);

	return err;
}

static gboolean cache_check_entry(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_timeout *data = user_data;
	struct cache_entry *entry = value;
	time_t max_timeout;

	/* Scale the number of hits by half as part of cache aging */

	entry->hits /= 2;

	/*
	 * If either IPv4 or IPv6 cached entry has expired, we
	 * remove both from the cache.
	 */

	if (entry->ipv4 && entry->ipv4->timeout > 0) {
		max_timeout = entry->ipv4->cache_until;
		if (max_timeout > data->max_timeout)
			data->max_timeout = max_timeout;

		if (entry->ipv4->cache_until < data->current_time)
			return TRUE;
	}

	if (entry->ipv6 && entry->ipv6->timeout > 0) {
		max_timeout = entry->ipv6->cache_until;
		if (max_timeout > data->max_timeout)
			data->max_timeout = max_timeout;

		if (entry->ipv6->cache_until < data->current_time)
			return TRUE;
	}

	/*
	 * if we're asked to try harder, also remove entries that have
	 * few hits
	 */
	if (data->try_harder && entry->hits < 4)
		return TRUE;

	return FALSE;
}

static void cache_cleanup(void)
{
	static time_t max_timeout;
	struct cache_timeout data = {
		.current_time = time(NULL),
		.max_timeout = 0,
		.try_harder = false
	};
	int count = 0;

	/*
	 * In the first pass, we only remove entries that have timed out.
	 * We use a cache of the first time to expire to do this only
	 * when it makes sense.
	 */
	if (max_timeout <= data.current_time) {
		count = g_hash_table_foreach_remove(cache, cache_check_entry,
						&data);
	}
	debug("removed %d in the first pass", count);

	/*
	 * In the second pass, if the first pass turned up blank,
	 * we also expire entries with a low hit count,
	 * while aging the hit count at the same time.
	 */
	data.try_harder = true;
	if (count == 0)
		count = g_hash_table_foreach_remove(cache, cache_check_entry,
						&data);

	if (count == 0)
		/*
		 * If we could not remove anything, then remember
		 * what is the max timeout and do nothing if we
		 * have not yet reached it. This will prevent
		 * constant traversal of the cache if it is full.
		 */
		max_timeout = data.max_timeout;
	else
		max_timeout = 0;
}

static gboolean cache_invalidate_entry(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_entry *entry = value;

	/* first, delete any expired elements */
	cache_enforce_validity(entry);

	/* if anything is not expired, mark the entry for refresh */
	if (entry->hits > 0 && (entry->ipv4 || entry->ipv6))
		entry->want_refresh = true;

	/* delete the cached data */
	cache_free_ipv4(entry);
	cache_free_ipv6(entry);

	/* keep the entry if we want it refreshed, delete it otherwise */
	return entry->want_refresh ? FALSE : TRUE;
}

/*
 * cache_invalidate is called from places where the DNS landscape
 * has changed, say because connections are added or we entered a VPN.
 * The logic is to wipe all cache data, but mark all non-expired
 * parts of the cache for refresh rather than deleting the whole cache.
 */
static void cache_invalidate(void)
{
	debug("Invalidating the DNS cache %p", cache);

	if (!cache)
		return;

	g_hash_table_foreach_remove(cache, cache_invalidate_entry, NULL);
}

static void cache_refresh_entry(struct cache_entry *entry)
{
	cache_enforce_validity(entry);

	if (entry->hits > 2 && (!entry->ipv4 || !entry->ipv6))
		entry->want_refresh = true;

	if (entry->want_refresh) {
		char dns_name[NS_MAXDNAME + 1];
		char *c;

		entry->want_refresh = false;

		/* turn a DNS name into a hostname with dots */
		strncpy(dns_name, entry->key, NS_MAXDNAME);
		c = dns_name;
		while (*c) {
			/* fetch the size of the current component and replace
			   it by a dot */
			int jump = *c;
			*c = '.';
			c += jump + 1;
		}
		debug("Refreshing %s\n", dns_name);
		/* then refresh the hostname */
		refresh_dns_entry(entry, &dns_name[1]);
	}
}

static void cache_refresh_iterator(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_entry *entry = value;

	cache_refresh_entry(entry);
}

static void cache_refresh(void)
{
	if (!cache)
		return;

	g_hash_table_foreach(cache, cache_refresh_iterator, NULL);
}

static int reply_query_type(const unsigned char *msg, int len)
{
	/* skip the header */
	const unsigned char *c = msg + DNS_HEADER_SIZE;
	int type;
	len -= DNS_HEADER_SIZE;

	if (len < 0)
		return 0;

	/* now the query, which is a name and 2 16 bit words for type and class */
	c += dns_name_length(c);

	type = c[0] << 8 | c[1];

	return type;
}

/*
 * update the cache with the DNS reply found in msg
 */
static int cache_update(struct server_data *srv, const unsigned char *msg, size_t msg_len)
{
	const size_t offset = protocol_offset(srv->protocol);
	int err, ttl = 0;
	uint16_t *lenhdr;
	size_t qlen;
	bool is_new_entry = false;
	uint16_t answers = 0, type = 0, class = 0;
	struct domain_hdr *hdr = (void *)(msg + offset);
	struct domain_question *q = NULL;
	struct cache_entry *entry;
	struct cache_data *data;
	char question[NS_MAXDNAME + 1];
	unsigned char response[NS_MAXDNAME + 1];
	unsigned char *ptr = NULL;
	size_t rsplen = sizeof(response) - 1;
	const time_t current_time = time(NULL);

	if (cache_size >= MAX_CACHE_SIZE) {
		cache_cleanup();
		if (cache_size >= MAX_CACHE_SIZE)
			return 0;
	}

	/* don't do a cache refresh more than twice a minute */
	if (next_refresh < current_time) {
		cache_refresh();
		next_refresh = current_time + 30;
	}

	debug("offset %zd hdr %p msg %p rcode %d", offset, hdr, msg, hdr->rcode);

	/* Continue only if response code is 0 (=ok) */
	if (hdr->rcode != ns_r_noerror)
		return 0;

	if (!cache)
		create_cache();

	question[sizeof(question) - 1] = '\0';
	err = parse_response(msg + offset, msg_len - offset,
				question, sizeof(question) - 1,
				&type, &class, &ttl,
				response, &rsplen, &answers);

	/*
	 * special case: if we do a ipv6 lookup and get no result
	 * for a record that's already in our ipv4 cache.. we want
	 * to cache the negative response.
	 */
	if ((err == -ENOMSG || err == -ENOBUFS) &&
			reply_query_type(msg + offset,
					msg_len - offset) == DNS_TYPE_AAAA) {
		entry = g_hash_table_lookup(cache, question);
		if (entry && entry->ipv4 && !entry->ipv6) {
			struct cache_data *data = g_try_new(struct cache_data, 1);

			if (!data)
				return -ENOMEM;
			data->inserted = entry->ipv4->inserted;
			data->type = type;
			data->answers = ntohs(hdr->ancount);
			data->timeout = entry->ipv4->timeout;
			data->data_len = msg_len +
				(offset ? 0 : DNS_HEADER_TCP_EXTRA_BYTES);
			data->data = g_malloc(data->data_len);
			ptr = data->data;
			if (srv->protocol == IPPROTO_UDP) {
				/* add the two bytes length header also for
				 * UDP responses */
				lenhdr = (void*)ptr;
				*lenhdr = htons(data->data_len -
						DNS_HEADER_TCP_EXTRA_BYTES);
				ptr += DNS_HEADER_TCP_EXTRA_BYTES;
			}
			data->valid_until = entry->ipv4->valid_until;
			data->cache_until = entry->ipv4->cache_until;
			memcpy(ptr, msg, msg_len);
			entry->ipv6 = data;
			/*
			 * we will get a "hit" when we serve the response
			 * out of the cache
			 */
			entry->hits = entry->hits ? entry->hits - 1 : 0;
			return 0;
		}
	}

	if (err < 0 || ttl == 0)
		return 0;

	/*
	 * If the cache contains already data, check if the
	 * type of the cached data is the same and do not add
	 * to cache if data is already there.
	 * This is needed so that we can cache both A and AAAA
	 * records for the same name.
	 */

	entry = g_hash_table_lookup(cache, question);
	data = NULL;
	is_new_entry = !entry;

	if (!entry) {
		entry = g_try_new(struct cache_entry, 1);
		if (!entry)
			return -ENOMEM;

		data = g_try_new(struct cache_data, 1);
		if (!data) {
			g_free(entry);
			return -ENOMEM;
		}

		entry->key = g_strdup(question);
		entry->ipv4 = entry->ipv6 = NULL;
		entry->want_refresh = false;
		entry->hits = 0;

	} else {
		if (type == DNS_TYPE_A && entry->ipv4)
			return 0;
		else if (type == DNS_TYPE_AAAA && entry->ipv6)
			return 0;

		data = g_try_new(struct cache_data, 1);
		if (!data)
			return -ENOMEM;

		/*
		 * compensate for the hit we'll get for serving
		 * the response out of the cache
		 */
		entry->hits = entry->hits ? entry->hits - 1 : 0;
	}

	if (type == DNS_TYPE_A)
		entry->ipv4 = data;
	else
		entry->ipv6 = data;

	if (ttl < MIN_CACHE_TTL)
		ttl = MIN_CACHE_TTL;

	data->inserted = current_time;
	data->type = type;
	data->answers = answers;
	data->timeout = ttl;
	data->valid_until = current_time + ttl;

	qlen = strlen(question);
	/*
	 * We allocate the extra TCP header bytes here even for UDP packet
	 * because it simplifies the sending of cached packet.
	 */
	data->data_len =  DNS_TCP_HEADER_SIZE + qlen + 1 + 2 + 2 + rsplen;
	data->data = g_malloc(data->data_len);
	if (!data->data) {
		g_free(entry->key);
		g_free(data);
		g_free(entry);
		return -ENOMEM;
	}

	/*
	 * Restrict the cached DNS record TTL to some sane value
	 * in order to prevent data staying in the cache too long.
	 */
	if (ttl > MAX_CACHE_TTL)
		ttl = MAX_CACHE_TTL;

	data->cache_until = round_down_ttl(current_time + ttl, ttl);

	ptr = data->data;

	/*
	 * We cache the two extra bytes at the start of the message
	 * in a TCP packet. When sending UDP packet, we pad the first
	 * two bytes. This way we do not need to know the format
	 * (UDP/TCP) of the cached message.
	 */
	lenhdr = (void*)ptr;
	*lenhdr = htons(data->data_len - DNS_HEADER_TCP_EXTRA_BYTES);
	ptr += DNS_HEADER_TCP_EXTRA_BYTES;

	memcpy(ptr, hdr, DNS_HEADER_SIZE);
	ptr += DNS_HEADER_SIZE;

	memcpy(ptr, question, qlen + 1); /* copy also the \0 */
	ptr += qlen + 1;

	q = (void *)ptr;
	q->type = htons(type);
	q->class = htons(class);
	ptr += DNS_QUESTION_SIZE;

	memcpy(ptr, response, rsplen);

	if (is_new_entry) {
		g_hash_table_replace(cache, entry->key, entry);
		cache_size++;
	}

	debug("cache %d %squestion \"%s\" type %d ttl %d size %zd packet %u "
								"dns len %u",
		cache_size, is_new_entry ? "new " : "old ",
		question, type, ttl,
		sizeof(*entry) + sizeof(*data) + data->data_len + qlen,
		data->data_len,
		srv->protocol == IPPROTO_TCP ?
			(unsigned int)(data->data[0] * 256 + data->data[1]) :
			data->data_len);

	return 0;
}

/*
 * attempts to answer the given request from cached replies.
 *
 * returns:
 * > 0 on cache hit (answer is already sent out to client)
 * == 0 on cache miss
 * < 0 on error condition (errno)
 */
static int ns_try_resolv_from_cache(
		struct request_data *req, gpointer request, const char *lookup)
{
	uint16_t type = 0;
	int ttl_left;
	struct cache_data *data;
	struct cache_entry *entry = cache_check(request, &type, req->protocol);
	if (!entry)
		return 0;

	debug("cache hit %s type %s", lookup, type == 1 ? "A" : "AAAA");

	data = type == DNS_TYPE_A ? entry->ipv4 : entry->ipv6;

	if (!data)
		return 0;

	ttl_left = data->valid_until - time(NULL);
	entry->hits++;

	switch(req->protocol) {
		case IPPROTO_TCP:
			send_cached_response(req->client_sk, data->data,
					data->data_len, NULL, 0, IPPROTO_TCP,
					req->srcid, data->answers, ttl_left);
			return 1;
		case IPPROTO_UDP: {
			int udp_sk = get_req_udp_socket(req);

			if (udp_sk < 0)
				return -EIO;

			send_cached_response(udp_sk, data->data,
				data->data_len, &req->sa, req->sa_len,
				IPPROTO_UDP, req->srcid, data->answers,
				ttl_left);
			return 1;
		}
	}

	return -EINVAL;
}

static int ns_resolv(struct server_data *server, struct request_data *req,
				gpointer request, gpointer name)
{
	int sk = -1;
	const char *lookup = (const char *)name;
	int err = ns_try_resolv_from_cache(req, request, lookup);

	if (err > 0)
		/* cache hit */
		return 1;
	else if (err != 0)
		/* error other than cache miss, don't continue */
		return err;

	/* forward request to real DNS server */
	sk = g_io_channel_unix_get_fd(server->channel);

	err = sendto(sk, request, req->request_len, MSG_NOSIGNAL,
			server->server_addr, server->server_addr_len);
	if (err < 0) {
		debug("Cannot send message to server %s sock %d "
			"protocol %d (%s/%d)",
			server->server, sk, server->protocol,
			strerror(errno), errno);
		return -EIO;
	}

	req->numserv++;

	/* If we have more than one dot, we don't add domains */
	{
		const char *dot = strchr(lookup, '.');
		if (dot && dot != lookup + strlen(lookup) - 1)
			return 0;
	}

	if (server->domains && server->domains->data)
		req->append_domain = true;

	for (GList *list = server->domains; list; list = list->next) {
		int domlen, altlen;
		unsigned char alt[1024];
		const char *domain = list->data;
		const size_t offset = protocol_offset(server->protocol);
		struct domain_hdr *hdr = (void *) (&alt[0] + offset);

		if (!domain)
			continue;

		domlen = strlen(domain) + 1;

		if (domlen < 5)
			return -EINVAL;

		memcpy(alt + offset, &req->altid, sizeof(req->altid));

		memcpy(alt + offset + 2, request + offset + 2, DNS_HEADER_SIZE - 2);
		hdr->qdcount = htons(1);

		altlen = append_query(alt + offset + DNS_HEADER_SIZE, sizeof(alt) - DNS_HEADER_SIZE - offset,
					name, domain);
		if (altlen < 0)
			return -EINVAL;

		altlen += DNS_HEADER_SIZE;
		altlen += offset;

		memcpy(alt + altlen,
			request + altlen - domlen,
			req->request_len - altlen + domlen);

		if (server->protocol == IPPROTO_TCP) {
			uint16_t req_len = req->request_len + domlen - DNS_HEADER_TCP_EXTRA_BYTES;
			uint16_t *len_hdr = (void*)alt;
			*len_hdr = htons(req_len);
		}

		debug("req %p dstid 0x%04x altid 0x%04x", req, req->dstid,
				req->altid);

		err = send(sk, alt, req->request_len + domlen, MSG_NOSIGNAL);
		if (err < 0)
			return -EIO;

		req->numserv++;
	}

	return 0;
}

static bool convert_label(const char *start, const char *end, const char *ptr, char *uptr,
			int remaining_len, int *used_comp, int *used_uncomp)
{
	int comp_pos;
	char name[NS_MAXLABEL];

	const int pos = dn_expand((const u_char *)start, (const u_char *)end, (const u_char *)ptr,
			name, NS_MAXLABEL);
	if (pos < 0) {
		debug("uncompress error [%d/%s]", errno, strerror(errno));
		return false;
	}

	/*
	 * We need to compress back the name so that we get back to internal
	 * label presentation.
	 */
	comp_pos = dn_comp(name, (u_char *)uptr, remaining_len, NULL, NULL);
	if (comp_pos < 0) {
		debug("compress error [%d/%s]", errno, strerror(errno));
		return false;
	}

	*used_comp = pos;
	*used_uncomp = comp_pos;

	return true;
}

static const char* uncompress(int16_t field_count, const char *start, const char *end,
			const char *ptr, char *uncompressed, int uncomp_len,
			char **uncompressed_ptr)
{
	char *uptr = *uncompressed_ptr; /* position in result buffer */
	char * const uncomp_end = uncompressed + uncomp_len - 1;

	debug("count %d ptr %p end %p uptr %p", field_count, ptr, end, uptr);

	while (field_count-- > 0 && ptr < end) {
		int dlen;		/* data field length */
		int ulen;		/* uncompress length */
		int pos;		/* position in compressed string */
		char name[NS_MAXLABEL]; /* tmp label */
		uint16_t dns_type, dns_class;
		int comp_pos;

		if (!convert_label(start, end, ptr, name, NS_MAXLABEL,
					&pos, &comp_pos))
			return NULL;

		/*
		 * Copy the uncompressed resource record, type, class and \0 to
		 * tmp buffer.
		 */

		ulen = strlen(name) + 1;
		if ((uptr + ulen) > uncomp_end)
			return NULL;
		memcpy(uptr, name, ulen);

		debug("pos %d ulen %d left %d name %s", pos, ulen,
			(int)(uncomp_end - (uptr + ulen)), uptr);

		uptr += ulen;

		ptr += pos;

		/*
		 * We copy also the fixed portion of the result (type, class,
		 * ttl, address length and the address)
		 */
		if ((uptr + NS_RRFIXEDSZ) > uncomp_end) {
			debug("uncompressed data too large for buffer");
			return NULL;
		}
		memcpy(uptr, ptr, NS_RRFIXEDSZ);

		dns_type = uptr[0] << 8 | uptr[1];
		dns_class = uptr[2] << 8 | uptr[3];

		if (dns_class != DNS_CLASS_IN)
			return NULL;

		ptr += NS_RRFIXEDSZ;
		uptr += NS_RRFIXEDSZ;

		/*
		 * Then the variable portion of the result (data length).
		 * Typically this portion is also compressed
		 * so we need to uncompress it also when necessary.
		 */
		if (dns_type == DNS_TYPE_CNAME) {
			if (!convert_label(start, end, ptr, uptr,
					uncomp_len - (uptr - uncompressed),
						&pos, &comp_pos))
				return NULL;

			uptr[-2] = comp_pos << 8;
			uptr[-1] = comp_pos & 0xff;

			uptr += comp_pos;
			ptr += pos;

		} else if (dns_type == DNS_TYPE_A || dns_type == DNS_TYPE_AAAA) {
			dlen = uptr[-2] << 8 | uptr[-1];

			if (dlen > (end - ptr) || dlen > (uncomp_end - uptr)) {
				debug("data len %d too long", dlen);
				return NULL;
			}

			memcpy(uptr, ptr, dlen);
			uptr += dlen;
			ptr += dlen;

		} else if (dns_type == DNS_TYPE_SOA) {
			int total_len = 0;
			char *len_ptr;

			/* Primary name server expansion */
			if (!convert_label(start, end, ptr, uptr,
					uncomp_len - (uptr - uncompressed),
						&pos, &comp_pos))
				return NULL;

			total_len += comp_pos;
			len_ptr = &uptr[-2];
			ptr += pos;
			uptr += comp_pos;

			/* Responsible authority's mailbox */
			if (!convert_label(start, end, ptr, uptr,
					uncomp_len - (uptr - uncompressed),
						&pos, &comp_pos))
				return NULL;

			total_len += comp_pos;
			ptr += pos;
			uptr += comp_pos;

			/*
			 * Copy rest of the soa fields (serial number,
			 * refresh interval, retry interval, expiration
			 * limit and minimum ttl). They are 20 bytes long.
			 */
			if ((uptr + 20) > uncomp_end || (ptr + 20) > end) {
				debug("soa record too long");
				return NULL;
			}
			memcpy(uptr, ptr, 20);
			uptr += 20;
			ptr += 20;
			total_len += 20;

			/*
			 * Finally fix the length of the data part
			 */
			len_ptr[0] = total_len << 8;
			len_ptr[1] = total_len & 0xff;
		}

		*uncompressed_ptr = uptr;
	}

	return ptr;
}

/*
 * removes the qualified domain name part from the given answer sections
 * starting at 'answers', consisting of 'length' bytes.
 *
 * 'name' points the start of the unqualified host label including the leading
 * length octet.
 *
 * returns the new (possibly shorter) length of remaining payload in the
 * answers buffer, or a negative (errno) value to indicate error conditions.
 */
static int strip_domains(const char *name, char *answers, size_t length)
{
	uint16_t data_len;
	struct domain_rr *rr;
	/* length of the name label including the length header octet */
	const size_t name_len = strlen(name);
	const char *end = answers + length;

	while (answers < end) {
		char *ptr = strstr(answers, name);
		if (ptr) {
			char *domain = ptr + name_len;

			/* this now points to the domain part length octet. */
			if (*domain) {
				/*
				 * length of the rest of the labels up to the
				 * null label (zero byte).
				 */
				const size_t domain_len = strlen(domain);
				char *remaining = domain + domain_len;

				/*
				 * now shift the rest of the answer sections
				 * to the left to get rid of the domain label
				 * part
				 */
				memmove(ptr + name_len,
					remaining,
					end - remaining);

				end -= domain_len;
				length -= domain_len;
			}
		}

		/* skip to the next answer section */

		/* the labels up to the root null label */
		answers += strlen(answers) + 1;
		/* the fixed part of the RR */
		rr = (void*)answers;
		if (answers + sizeof(*rr) > end)
			return -EINVAL;
		data_len = htons(rr->rdlen);
		/* skip the rest of the RR */
		answers += sizeof(*rr);
		answers += data_len;
	}

	if (answers > end)
		return -EINVAL;

	return length;
}

/*
 * Removes domain names from replies, if one has been appended during
 * forwarding to the real DNS server.
 *
 * Returns:
 * < 0 on error (abort processing reply)
 * == 0 if the reply should be forwarded unmodified
 * > 0 returns a new reply buffer in *new_reply on success. The return value
 * indicates the new length of the data in *new_reply.
 */
static int dns_reply_fixup_domains(
				const char *reply, size_t reply_len,
				const size_t offset,
				struct request_data *req,
				char **new_reply)
{
	char uncompressed[NS_MAXDNAME];
	char *uptr, *answers;
	size_t fixed_len;
	int new_an_len;
	const struct domain_hdr *hdr = (void *)(reply + offset);
	const char *eom = reply + reply_len;
	uint16_t header_len = offset + DNS_HEADER_SIZE;
	uint16_t domain_len;
	struct qtype_qclass *qtc;
	uint16_t dns_type;
	uint16_t dns_class;
	uint16_t section_counts[3];
	const char *ptr;
	uint8_t host_len;
	const char *domain;

	/* full header plus at least one byte for the hostname length */
	if (reply_len < header_len + 1U)
		return -EINVAL;

	section_counts[0] = hdr->ancount;
	section_counts[1] = hdr->nscount;
	section_counts[2] = hdr->arcount;

	/*
	 * length octet of the hostname.
	 * ->hostname.domain.net
	 */
	ptr = reply + header_len;
	host_len = *ptr;
	domain = ptr + host_len + 1;
	if (domain >= eom)
		return -EINVAL;

	domain_len = host_len ? strnlen(domain, eom - domain) : 0;

	/*
	 * If the query type is anything other than A or AAAA, then bail out
	 * and pass the message as is.  We only want to deal with IPv4 or IPv6
	 * addresses.
	 */
	qtc = (void*)(domain + domain_len + 1);
	if (((const char*)(qtc + 1)) > eom)
		return -EINVAL;

	dns_type = ntohs(qtc->qtype);
	dns_class = ntohs(qtc->qclass);

	if (domain_len == 0) {
		/* nothing to do */
		return 0;
	}

	/* TODO: This condition looks wrong. It should probably be
	 *
	 *  (dns_type != A && dns_type != AAAA) || dns_class != IN
	 *
	 * doing so, however, changes the behaviour of dnsproxy, e.g. MX
	 * records will be passed back to the client, but without the
	 * adjustment of the appended domain name.
	 */
	if (dns_type != DNS_TYPE_A && dns_type != DNS_TYPE_AAAA &&
			dns_class != DNS_CLASS_IN) {
		debug("Pass msg dns type %d class %d", dns_type, dns_class);
		return 0;
	}

	/*
	 * Remove the domain name and replace it by the end of reply. Check if
	 * the domain is really there before trying to copy the data. We also
	 * need to uncompress the answers if necessary.  The domain_len can be
	 * 0 because if the original query did not contain a domain name, then
	 * we are sending two packets, first without the domain name and the
	 * second packet with domain name.  The append_domain is set to true
	 * even if we sent the first packet without domain name. In this case
	 * we end up in this branch.
	 */

	/* NOTE: length checks up and including to qtype_qclass have already
	   been done above */

	/*
	 * First copy host (without domain name) into tmp buffer.
	 */
	uptr = &uncompressed[0];
	memcpy(uptr, ptr, host_len + 1);

	uptr[host_len + 1] = '\0'; /* host termination */
	uptr += host_len + 2;

	/*
	 * Copy type and class fields of the question.
	 */
	memcpy(uptr, qtc, sizeof(*qtc));

	/*
	 * ptr points to answers after this
	 */
	ptr = (void*)(qtc + 1);
	uptr += sizeof(*qtc);
	answers = uptr;
	fixed_len = answers - uncompressed;

	/*
	 * We then uncompress the result to buffer so that we can rip off the
	 * domain name part from the question. First answers, then name server
	 * (authority) information, and finally additional record info.
	 */

	for (size_t i = 0; i < NUM_ARRAY_ELEMENTS(section_counts); i++) {
		ptr = uncompress(ntohs(section_counts[i]), reply + offset, eom,
				ptr, uncompressed, NS_MAXDNAME, &uptr);
		if (!ptr) {
			/* failed to uncompress, pass on as is
			 * (TODO: good idea?) */
			return 0;
		}
	}

	/*
	 * The uncompressed buffer now contains an almost valid response.
	 * Final step is to get rid of the domain name because at least glibc
	 * gethostbyname() implementation does extra checks and expects to
	 * find an answer without domain name if we asked a query without
	 * domain part. Note that glibc getaddrinfo() works differently and
	 * accepts FQDN in answer
	 */
	new_an_len = strip_domains(uncompressed, answers, uptr - answers);
	if (new_an_len < 0) {
		debug("Corrupted packet");
		return -EINVAL;
	}

	/*
	 * Because we have now uncompressed the answers we might have to
	 * create a bigger buffer to hold all that data.
	 *
	 * TODO: only create a bigger buffer if actually necessary, pass
	 * allocation size of input buffer via additional parameter.
	 */

	reply_len = header_len + new_an_len + fixed_len;

	*new_reply = g_try_malloc(reply_len);
	if (!*new_reply)
		return -ENOMEM;

	memcpy(*new_reply, reply, header_len);
	memcpy(*new_reply + header_len, uncompressed, new_an_len + fixed_len);

	return reply_len;
}

static struct request_data* lookup_request(
		const unsigned char *reply, size_t len, int protocol)
{
	const size_t offset = protocol_offset(protocol);
	struct request_data *req;
	struct domain_hdr *hdr = (void *)(reply + offset);

	debug("Received %zd bytes (id 0x%04x)", len, hdr->id);

	if (len < DNS_HEADER_SIZE + offset)
		return NULL;

	req = find_request(hdr->id);

	if (!req)
		return NULL;

	debug("req %p dstid 0x%04x altid 0x%04x rcode %d",
			req, req->dstid, req->altid, hdr->rcode);

	req->numresp++;

	return req;
}

static int forward_dns_reply(char *reply, size_t reply_len, int protocol,
			struct server_data *data, struct request_data *req)
{
	const size_t offset = protocol_offset(protocol);
	struct domain_hdr *hdr = (void *)(reply + offset);
	int err, sk;

	/* replace with original request ID from our client */
	hdr->id = req->srcid;

	if (hdr->rcode == ns_r_noerror || !req->resp) {
		/*
		 * If the domain name was appended remove it before forwarding
		 * the reply. If there were more than one question, then this
		 * domain name ripping can be hairy so avoid that and bail out
		 * in that that case.
		 *
		 * The reason we are doing this magic is that if the user's
		 * DNS client tries to resolv hostname without domain part, it
		 * also expects to get the result without a domain name part.
		 */
		char *new_reply = NULL;

		if (req->append_domain && ntohs(hdr->qdcount) == 1) {
			const int fixup_res = dns_reply_fixup_domains(
					reply, reply_len,
					offset, req, &new_reply);
			if (fixup_res < 0) {
				/* error occured */
				return fixup_res;
			} else if (fixup_res > 0 && new_reply) {
				/* new reply length */
				reply_len = fixup_res;
				reply = new_reply;
			} else {
				/* keep message as is */
			}
		}

		g_free(req->resp);
		req->resplen = 0;

		req->resp = g_try_malloc(reply_len);
		if (!req->resp)
			return -ENOMEM;

		memcpy(req->resp, reply, reply_len);
		req->resplen = reply_len;

		cache_update(data, (unsigned char*)reply, reply_len);

		g_free(new_reply);
	}

	if (req->numresp < req->numserv) {
		if (hdr->rcode > ns_r_noerror) {
			return -EINVAL;
		} else if (hdr->ancount == 0 && req->append_domain) {
			return -EINVAL;
		}
	}

	request_list = g_slist_remove(request_list, req);

	if (protocol == IPPROTO_UDP) {
		sk = get_req_udp_socket(req);
		if (sk < 0) {
			errno = -EIO;
			err = -EIO;
		} else
			err = sendto(sk, req->resp, req->resplen, 0,
				&req->sa, req->sa_len);
	} else {
		const uint16_t tcp_len = htons(req->resplen - DNS_HEADER_TCP_EXTRA_BYTES);
		/* correct TCP message length */
		memcpy(req->resp, &tcp_len, sizeof(tcp_len));
		sk = req->client_sk;
		err = send(sk, req->resp, req->resplen, MSG_NOSIGNAL);
	}

	if (err < 0)
		debug("Cannot send msg, sk %d proto %d errno %d/%s", sk,
			protocol, errno, strerror(errno));
	else
		debug("proto %d sent %d bytes to %d", protocol, err, sk);

	return err;
}

static void server_destroy_socket(struct server_data *data)
{
	debug("index %d server %s proto %d", data->index,
					data->server, data->protocol);

	if (data->watch > 0) {
		g_source_remove(data->watch);
		data->watch = 0;
	}

	if (data->timeout > 0) {
		g_source_remove(data->timeout);
		data->timeout = 0;
	}

	if (data->channel) {
		g_io_channel_shutdown(data->channel, TRUE, NULL);
		g_io_channel_unref(data->channel);
		data->channel = NULL;
	}

	g_free(data->incoming_reply);
	data->incoming_reply = NULL;
}

static void destroy_server(struct server_data *server)
{
	debug("index %d server %s sock %d", server->index, server->server,
			server->channel ?
			g_io_channel_unix_get_fd(server->channel): -1);

	server_list = g_slist_remove(server_list, server);
	server_destroy_socket(server);

	if (server->protocol == IPPROTO_UDP && server->enabled)
		debug("Removing DNS server %s", server->server);

	g_free(server->server);
	g_list_free_full(server->domains, g_free);
	g_free(server->server_addr);

	/*
	 * We do not remove cache right away but delay it few seconds.
	 * The idea is that when IPv6 DNS server is added via RDNSS, it has a
	 * lifetime. When the lifetime expires we decrease the refcount so it
	 * is possible that the cache is then removed. Because a new DNS server
	 * is usually created almost immediately we would then loose the cache
	 * without any good reason. The small delay allows the new RDNSS to
	 * create a new DNS server instance and the refcount does not go to 0.
	 */
	if (cache && !cache_timer)
		cache_timer = g_timeout_add_seconds(3, try_remove_cache, NULL);

	g_free(server);
}

static gboolean udp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[4096];
	int sk, res;
	ssize_t len;
	struct server_data *data = user_data;
	struct request_data *req;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP server %s", data->server);
		server_destroy_socket(data);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);
	len = recv(sk, buf, sizeof(buf), 0);

	if (len <= 0)
		return TRUE;

	req = lookup_request(buf, len, IPPROTO_UDP);

	if (!req)
		/* invalid / corrupt request */
		return TRUE;

	res = forward_dns_reply((char*)buf, len, IPPROTO_UDP, data, req);

	/* on success or no further responses are expected, destroy the req */
	if (res == 0 || req->numresp >= req->numserv)
		destroy_request_data(req);

	return TRUE;
}

static gboolean tcp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct request_data *req;
	struct server_data *server = user_data;
	int sk = g_io_channel_unix_get_fd(channel);
	if (sk == 0)
		return FALSE;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		GSList *list;
hangup:
		debug("TCP server channel closed, sk %d", sk);

		/*
		 * Discard any partial response which is buffered; better
		 * to get a proper response from a working server.
		 */
		g_free(server->incoming_reply);
		server->incoming_reply = NULL;

		list = request_list;
		while (list) {
			struct domain_hdr *hdr;
			req = list->data;
			list = list->next;

			if (req->protocol == IPPROTO_UDP)
				continue;
			else if (!req->request)
				continue;

			/*
			 * If we're not waiting for any further response
			 * from another name server, then we send an error
			 * response to the client.
			 */
			if (req->numserv && --(req->numserv))
				continue;

			hdr = (void *)(req->request + DNS_HEADER_TCP_EXTRA_BYTES);
			hdr->id = req->srcid;
			send_response(req->client_sk, req->request,
				req->request_len, NULL, 0, IPPROTO_TCP);

			request_list = g_slist_remove(request_list, req);
		}

		destroy_server(server);

		return FALSE;
	}

	if ((condition & G_IO_OUT) && !server->connected) {
		bool no_request_sent = true;
		struct server_data *udp_server = find_server(
				server->index, server->server,
				IPPROTO_UDP);
		if (udp_server) {
			for (GList *domains = udp_server->domains; domains;
						domains = domains->next) {
				const char *dom = domains->data;

				debug("Adding domain %s to %s",
						dom, server->server);

				server->domains = g_list_append(server->domains,
								g_strdup(dom));
			}
		}

		/*
		 * Remove the G_IO_OUT flag from the watch, otherwise we end
		 * up in a busy loop, because the socket is constantly writable.
		 *
		 * There seems to be no better way in g_io to do that than
		 * re-adding the watch.
		 */
		g_source_remove(server->watch);
		server->watch = g_io_add_watch(server->channel,
			G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
			tcp_server_event, server);

		server->connected = true;
		server_list = g_slist_append(server_list, server);

		/* don't advance the list in the for loop, because we might
		 * need to delete elements while iterating through it */
		for (GSList *list = request_list; list; ) {
			int status;
			req = list->data;

			if (req->protocol == IPPROTO_UDP) {
				list = list->next;
				continue;
			}

			debug("Sending req %s over TCP", (char *)req->name);

			status = ns_resolv(server, req,
						req->request, req->name);
			if (status > 0) {
				/*
				 * A cached result was sent,
				 * so the request can be released
				 */
				list = list->next;
				request_list = g_slist_remove(request_list, req);
				destroy_request_data(req);
				continue;
			} else if (status < 0) {
				list = list->next;
				continue;
			}

			no_request_sent = false;

			if (req->timeout > 0)
				g_source_remove(req->timeout);

			req->timeout = g_timeout_add_seconds(30,
						request_timeout, req);
			list = list->next;
		}

		if (no_request_sent) {
			destroy_server(server);
			return FALSE;
		}

	} else if (condition & G_IO_IN) {
		struct partial_reply *reply = server->incoming_reply;
		int bytes_recv;
		int res;

		if (!reply) {
			uint16_t reply_len;
			size_t bytes_len;

			bytes_recv = recv(sk, &reply_len, sizeof(reply_len), MSG_PEEK);
			if (!bytes_recv) {
				goto hangup;
			} else if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return TRUE;

				connman_error("DNS proxy error %s",
						strerror(errno));
				goto hangup;
			}

			bytes_len = bytes_recv;
			if (bytes_len < sizeof(reply_len))
				return TRUE;

			/* the header contains the length of the message
			 * excluding the two length bytes */
			reply_len = ntohs(reply_len) + DNS_HEADER_TCP_EXTRA_BYTES;

			debug("TCP reply %d bytes from %d", reply_len, sk);

			reply = g_try_malloc(sizeof(*reply) + reply_len + 2);
			if (!reply)
				return TRUE;

			reply->len = reply_len;
			/* we only peeked the two length bytes, so we have to
			   receive the complete message below proper. */
			reply->received = 0;

			server->incoming_reply = reply;
		}

		while (reply->received < reply->len) {
			bytes_recv = recv(sk, reply->buf + reply->received,
					reply->len - reply->received, 0);
			if (!bytes_recv) {
				connman_error("DNS proxy TCP disconnect");
				break;
			} else if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return TRUE;

				connman_error("DNS proxy error %s",
						strerror(errno));
				break;
			}
			reply->received += bytes_recv;
		}

		req = lookup_request(reply->buf, reply->received, IPPROTO_TCP);

		if (!req)
			/* invalid / corrupt request */
			return TRUE;

		res = forward_dns_reply((char*)reply->buf, reply->received, IPPROTO_TCP, server, req);

		g_free(reply);
		server->incoming_reply = NULL;

		/* on success or if no further responses are expected close
		 * connection */
		if (res == 0 || req->numresp >= req->numserv) {
			destroy_request_data(req);
			destroy_server(server);
			return FALSE;
		}

		/*
		 * keep the TCP connection open, there are more
		 * requests to be answered
		 */
		return TRUE;
	}

	return TRUE;
}

static gboolean tcp_idle_timeout(gpointer user_data)
{
	struct server_data *server = user_data;

	debug("\n");

	if (!server)
		return FALSE;

	destroy_server(server);

	return FALSE;
}

static int server_create_socket(struct server_data *data)
{
	int err;
	char *interface;
	int sk = socket(data->server_addr->sa_family,
		data->protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM,
		data->protocol);

	debug("index %d server %s proto %d", data->index,
					data->server, data->protocol);

	if (sk < 0) {
		err = errno;
		connman_error("Failed to create server %s socket",
							data->server);
		server_destroy_socket(data);
		return -err;
	}

	debug("sk %d", sk);

	interface = connman_inet_ifname(data->index);
	if (interface) {
		if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
					interface,
					strlen(interface) + 1) < 0) {
			err = errno;
			connman_error("Failed to bind server %s "
						"to interface %s",
						data->server, interface);
			close(sk);
			server_destroy_socket(data);
			g_free(interface);
			return -err;
		}
		g_free(interface);
	}

	data->channel = g_io_channel_unix_new(sk);
	if (!data->channel) {
		connman_error("Failed to create server %s channel",
							data->server);
		close(sk);
		server_destroy_socket(data);
		return -ENOMEM;
	}

	g_io_channel_set_close_on_unref(data->channel, TRUE);

	if (data->protocol == IPPROTO_TCP) {
		g_io_channel_set_flags(data->channel, G_IO_FLAG_NONBLOCK, NULL);
		data->watch = g_io_add_watch(data->channel,
			G_IO_OUT | G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
						tcp_server_event, data);
		data->timeout = g_timeout_add_seconds(30, tcp_idle_timeout,
								data);
	} else
		data->watch = g_io_add_watch(data->channel,
			G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						udp_server_event, data);

	if (connect(sk, data->server_addr, data->server_addr_len) < 0) {
		err = errno;

		if ((data->protocol == IPPROTO_TCP && errno != EINPROGRESS) ||
				data->protocol == IPPROTO_UDP) {

			connman_error("Failed to connect to server %s",
								data->server);
			server_destroy_socket(data);
			return -err;
		}
	}

	create_cache();

	return 0;
}

static void enable_fallback(bool enable)
{
	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->index != -1)
			continue;

		if (enable)
			DBG("Enabling fallback DNS server %s", data->server);
		else
			DBG("Disabling fallback DNS server %s", data->server);

		data->enabled = enable;
	}
}

static unsigned int get_enabled_server_number(void)
{
	GSList *list;
	unsigned int result = 0;

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->index != -1 && data->enabled == true)
			result++;
	}
	return result;
}

static struct server_data *create_server(int index,
					const char *domain, const char *server,
					int protocol)
{
	struct server_data *data = g_try_new0(struct server_data, 1);
	struct addrinfo hints, *rp;
	int ret;

	DBG("index %d server %s", index, server);

	if (!data) {
		connman_error("Failed to allocate server %s data", server);
		return NULL;
	}

	data->index = index;
	if (domain)
		data->domains = g_list_append(data->domains, g_strdup(domain));
	data->server = g_strdup(server);
	data->protocol = protocol;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socket_type(protocol, 0);
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV | AI_NUMERICHOST;

	ret = getaddrinfo(data->server, "53", &hints, &rp);
	if (ret) {
		connman_error("Failed to parse server %s address: %s\n",
			      data->server, gai_strerror(ret));
		destroy_server(data);
		return NULL;
	}

	/* Do not blindly copy this code elsewhere; it doesn't loop over the
	   results using ->ai_next as it should. That's OK in *this* case
	   because it was a numeric lookup; we *know* there's only one. */

	data->server_addr_len = rp->ai_addrlen;

	switch (rp->ai_family) {
	case AF_INET:
		data->server_addr = (struct sockaddr *)
					g_try_new0(struct sockaddr_in, 1);
		break;
	case AF_INET6:
		data->server_addr = (struct sockaddr *)
					g_try_new0(struct sockaddr_in6, 1);
		break;
	default:
		connman_error("Wrong address family %d", rp->ai_family);
		break;
	}
	if (!data->server_addr) {
		freeaddrinfo(rp);
		destroy_server(data);
		return NULL;
	}
	memcpy(data->server_addr, rp->ai_addr, rp->ai_addrlen);
	freeaddrinfo(rp);

	if (server_create_socket(data) != 0) {
		destroy_server(data);
		return NULL;
	}

	if (protocol == IPPROTO_UDP) {
		if (__connman_service_index_is_default(data->index) ||
				__connman_service_index_is_split_routing(
								data->index)) {
			data->enabled = true;
			DBG("Adding DNS server %s", data->server);

			enable_fallback(false);
		} else if (data->index == -1 && get_enabled_server_number() == 0) {
			data->enabled = true;
			DBG("Adding fallback DNS server %s", data->server);
		}

		server_list = g_slist_append(server_list, data);
	}

	return data;
}

static bool resolv(struct request_data *req,
				gpointer request, gpointer name)
{
	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->protocol == IPPROTO_TCP) {
			DBG("server %s ignored proto TCP", data->server);
			continue;
		}

		debug("server %s enabled %d", data->server, data->enabled);

		if (!data->enabled)
			continue;

		if (!data->channel && data->protocol == IPPROTO_UDP) {
			if (server_create_socket(data) < 0) {
				DBG("socket creation failed while resolving");
				continue;
			}
		}

		if (ns_resolv(data, req, request, name) > 0)
			return true;
	}

	return false;
}

static void update_domain(int index, const char *domain, bool append)
{
	DBG("index %d domain %s", index, domain);

	if (!domain)
		return;

	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;
		char *dom = NULL;
		bool dom_found = false;

		if (data->index < 0)
			continue;
		else if (data->index != index)
			continue;

		for (GList *dom_list = data->domains; dom_list;
				dom_list = dom_list->next) {
			dom = dom_list->data;

			if (g_str_equal(dom, domain)) {
				dom_found = true;
				break;
			}
		}

		if (!dom_found && append) {
			data->domains =
				g_list_append(data->domains, g_strdup(domain));
		} else if (dom_found && !append) {
			data->domains =
				g_list_remove(data->domains, dom);
			g_free(dom);
		}
	}
}

static void append_domain(int index, const char *domain)
{
	update_domain(index, domain, true);
}

static void remove_domain(int index, const char *domain)
{
	update_domain(index, domain, false);
}

static void flush_requests(struct server_data *server)
{
	GSList *list = request_list;
	while (list) {
		struct request_data *req = list->data;

		list = list->next;

		if (ns_resolv(server, req, req->request, req->name)) {
			/*
			 * A cached result was sent,
			 * so the request can be released
			 */
			request_list =
				g_slist_remove(request_list, req);
			destroy_request_data(req);
			continue;
		}

		if (req->timeout > 0)
			g_source_remove(req->timeout);

		req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	}
}

int __connman_dnsproxy_append(int index, const char *domain,
							const char *server)
{
	struct server_data *data;
	DBG("index %d server %s", index, server);

	if (!server) {
		if (!domain) {
			return -EINVAL;
		} else {
			append_domain(index, domain);
			return 0;
		}
	}

	if (g_str_equal(server, "127.0.0.1"))
		return -ENODEV;
	else if (g_str_equal(server, "::1"))
		return -ENODEV;

	data = find_server(index, server, IPPROTO_UDP);
	if (data) {
		append_domain(index, domain);
		return 0;
	}

	data = create_server(index, domain, server, IPPROTO_UDP);
	if (!data)
		return -EIO;

	flush_requests(data);

	return 0;
}

static void remove_server(int index, const char *server, int protocol)
{
	struct server_data *data;

	data = find_server(index, server, protocol);
	if (!data)
		return;

	destroy_server(data);

	if (get_enabled_server_number() == 0)
		enable_fallback(true);
}

int __connman_dnsproxy_remove(int index, const char *domain,
							const char *server)
{
	DBG("index %d server %s", index, server);

	if (!server) {
		if (!domain) {
			return -EINVAL;
		} else {
			remove_domain(index, domain);
			return 0;
		}
	}

	if (g_str_equal(server, "127.0.0.1"))
		return -ENODEV;
	else if (g_str_equal(server, "::1"))
		return -ENODEV;

	remove_server(index, server, IPPROTO_UDP);
	remove_server(index, server, IPPROTO_TCP);

	return 0;
}

static void dnsproxy_offline_mode(bool enabled)
{
	DBG("enabled %d", enabled);

	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (!enabled) {
			DBG("Enabling DNS server %s", data->server);
			data->enabled = true;
			cache_invalidate();
			cache_refresh();
		} else {
			DBG("Disabling DNS server %s", data->server);
			data->enabled = false;
			cache_invalidate();
		}
	}
}

static void dnsproxy_default_changed(struct connman_service *service)
{
	bool any_server_enabled = false;
	int index, vpn_index;

	DBG("service %p", service);

	/* DNS has changed, invalidate the cache */
	cache_invalidate();

	if (!service) {
		/* When no services are active, then disable DNS proxying */
		dnsproxy_offline_mode(true);
		return;
	}

	index = __connman_service_get_index(service);
	if (index < 0)
		return;

	/*
	 * In case non-split-routed VPN is set as split routed the DNS servers
	 * the VPN must be enabled as well, when the transport becomes the
	 * default service.
	 */
	vpn_index = __connman_gateway_get_vpn_index(index);

	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->index == index) {
			DBG("Enabling DNS server %s", data->server);
			data->enabled = true;
			any_server_enabled = true;
		} else if (data->index == vpn_index) {
			DBG("Enabling DNS server of VPN %s", data->server);
			data->enabled = true;
		} else {
			DBG("Disabling DNS server %s", data->server);
			data->enabled = false;
		}
	}

	if (!any_server_enabled)
		enable_fallback(true);

	cache_refresh();
}

static void dnsproxy_service_state_changed(struct connman_service *service,
			enum connman_service_state state)
{
	GSList *list;
	int index;

	switch (state) {
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_IDLE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_ONLINE:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		return;
	}

	index = __connman_service_get_index(service);
	list = server_list;

	while (list) {
		struct server_data *data = list->data;

		/* Get next before the list is changed by destroy_server() */
		list = list->next;

		if (data->index == index) {
			DBG("removing server data of index %d", index);
			destroy_server(data);
		}
	}
}

static const struct connman_notifier dnsproxy_notifier = {
	.name			= "dnsproxy",
	.default_changed	= dnsproxy_default_changed,
	.offline_mode		= dnsproxy_offline_mode,
	.service_state_changed	= dnsproxy_service_state_changed,
};

/*
 * Parses the given request buffer. `buf´ is expected to be the start of the
 * domain_hdr structure i.e. the TCP length header is not handled by this
 * function.
 * Returns the ascii string dot representation of the query in `name´, which
 * must be able to hold `size´ bytes.
 *
 * Returns < 0 on error (errno) or zero on success.
 */
static int parse_request(unsigned char *buf, size_t len,
					char *name, size_t size)
{
	static const unsigned char OPT_EDNS0_TYPE[2] = { 0x00, 0x29 };
	struct domain_hdr *hdr = (void *) buf;
	uint16_t qdcount, ancount, nscount, arcount;
	unsigned char *ptr = buf + DNS_HEADER_SIZE;
	size_t remain = len - DNS_HEADER_SIZE;
	size_t used = 0;

	if (len < DNS_HEADER_SIZE + DNS_QTYPE_QCLASS_SIZE) {
		DBG("Dropped DNS request with short length %zd", len);
		return -EINVAL;
	}

	if (!name || !size)
		return -EINVAL;

	qdcount = ntohs(hdr->qdcount);
	ancount = ntohs(hdr->ancount);
	nscount = ntohs(hdr->nscount);
	arcount = ntohs(hdr->arcount);

	if (hdr->qr || qdcount != 1 || ancount || nscount) {
		DBG("Dropped DNS request with bad flags/counts qr %d "
			"with len %zd qdcount %d ancount %d nscount %d",
			hdr->qr, len, qdcount, ancount, nscount);

		return -EINVAL;
	}

	debug("id 0x%04x qr %d opcode %d qdcount %d arcount %d",
					hdr->id, hdr->qr, hdr->opcode,
							qdcount, arcount);

	name[0] = '\0';

	/* parse DNS query string into `name' out parameter */
	while (remain > 0) {
		uint8_t label_len = *ptr;

		if (label_len == 0x00) {
			struct qtype_qclass *q = (struct qtype_qclass *)(ptr + 1);
			uint16_t class;

			if (remain < sizeof(*q)) {
				DBG("Dropped malformed DNS query");
				return -EINVAL;
			}

			class = ntohs(q->qclass);
			if (class != DNS_CLASS_IN && class != DNS_CLASS_ANY) {
				DBG("Dropped non-IN DNS class %d", class);
				return -EINVAL;
			}

			ptr += sizeof(*q) + 1;
			remain -= (sizeof(*q) + 1);
			break;
		}

		if (used + label_len + 1 > size)
			return -ENOBUFS;

		strncat(name, (char *) (ptr + 1), label_len);
		strcat(name, ".");

		used += label_len + 1;
		ptr += label_len + 1;
		remain -= label_len + 1;
	}

	if (arcount && remain >= DNS_RR_SIZE + 1 && !ptr[0] &&
		ptr[1] == OPT_EDNS0_TYPE[0] && ptr[2] == OPT_EDNS0_TYPE[1]) {
		struct domain_rr *edns0 = (struct domain_rr *)(ptr + 1);

		DBG("EDNS0 buffer size %u", ntohs(edns0->class));
	} else if (!arcount && remain) {
		DBG("DNS request with %zd garbage bytes", remain);
	}

	debug("query %s", name);

	return 0;
}

static void client_reset(struct tcp_partial_client_data *client)
{
	if (!client)
		return;

	if (client->channel) {
		debug("client %d closing",
			g_io_channel_unix_get_fd(client->channel));

		g_io_channel_unref(client->channel);
		client->channel = NULL;
	}

	if (client->watch > 0) {
		g_source_remove(client->watch);
		client->watch = 0;
	}

	if (client->timeout > 0) {
		g_source_remove(client->timeout);
		client->timeout = 0;
	}

	g_free(client->buf);
	client->buf = NULL;

	client->buf_end = 0;
}

static size_t get_msg_len(const unsigned char *buf)
{
	return buf[0]<<8 | buf[1];
}

static bool read_tcp_data(struct tcp_partial_client_data *client,
				void *client_addr, socklen_t client_addr_len,
				int read_len)
{
	char query[TCP_MAX_BUF_LEN];
	struct request_data *req;
	struct domain_hdr *hdr;
	int client_sk = g_io_channel_unix_get_fd(client->channel);
	int err;
	size_t msg_len;
	bool waiting_for_connect = false;
	uint16_t qtype = 0;
	struct cache_entry *entry;

	if (read_len == 0) {
		debug("client %d closed, pending %d bytes",
			client_sk, client->buf_end);
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return false;
	}

	debug("client %d received %d bytes", client_sk, read_len);

	client->buf_end += read_len;

	/* we need at least the message length header */
	if (client->buf_end < DNS_HEADER_TCP_EXTRA_BYTES)
		return true;

	msg_len = get_msg_len(client->buf);
	if (msg_len > TCP_MAX_BUF_LEN) {
		debug("client %d sent too much data %zd", client_sk, msg_len);
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return false;
	}

read_another:
	debug("client %d msg len %zd end %d past end %zd", client_sk, msg_len,
		client->buf_end, client->buf_end - (msg_len + 2));

	if (client->buf_end < (msg_len + 2)) {
		debug("client %d still missing %zd bytes",
			client_sk,
			msg_len + 2 - client->buf_end);
		return true;
	}

	debug("client %d all data %zd received", client_sk, msg_len);

	err = parse_request(client->buf + DNS_HEADER_TCP_EXTRA_BYTES,
			msg_len, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0)) {
		send_response(client_sk, client->buf,
			msg_len + DNS_HEADER_TCP_EXTRA_BYTES,
			NULL, 0, IPPROTO_TCP);
		return true;
	}

	req = g_try_new0(struct request_data, 1);
	if (!req)
		return true;

	memcpy(&req->sa, client_addr, client_addr_len);
	req->sa_len = client_addr_len;
	req->client_sk = client_sk;
	req->protocol = IPPROTO_TCP;
	req->family = client->family;

	hdr = (void*)(client->buf + DNS_HEADER_TCP_EXTRA_BYTES);

	memcpy(&req->srcid, &hdr->id, sizeof(req->srcid));
	req->dstid = get_id();
	req->altid = get_id();
	req->request_len = msg_len + DNS_HEADER_TCP_EXTRA_BYTES;

	/* replace ID the request for forwarding */
	memcpy(&hdr->id, &req->dstid, sizeof(hdr->id));

	req->numserv = 0;
	req->ifdata = client->ifdata;
	req->append_domain = false;

	/*
	 * Check if the answer is found in the cache before
	 * creating sockets to the server.
	 */
	entry = cache_check(client->buf, &qtype, IPPROTO_TCP);
	if (entry) {
		struct cache_data *data;

		debug("cache hit %s type %s", query,
					qtype == DNS_TYPE_A ? "A" : "AAAA");

		data = qtype == DNS_TYPE_A ? entry->ipv4 : entry->ipv6;

		if (data) {
			int ttl_left = data->valid_until - time(NULL);
			entry->hits++;

			send_cached_response(client_sk, data->data,
					data->data_len, NULL, 0, IPPROTO_TCP,
					req->srcid, data->answers, ttl_left);

			g_free(req);
			goto out;
		} else
			debug("data missing, ignoring cache for this query");
	}

	for (GSList *list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->protocol != IPPROTO_UDP || !data->enabled)
			continue;

		if (!create_server(data->index, NULL, data->server,
					IPPROTO_TCP))
			continue;

		waiting_for_connect = true;
	}

	if (!waiting_for_connect) {
		/* No server is waiting for connect */
		send_response(client_sk, client->buf,
			req->request_len, NULL, 0, IPPROTO_TCP);
		g_free(req);
		return true;
	}

	/*
	 * The server is not connected yet.
	 * Copy the relevant buffers.
	 * The request will actually be sent once we're
	 * properly connected over TCP to the nameserver.
	 */
	req->request = g_try_malloc0(req->request_len);
	if (!req->request) {
		send_response(client_sk, client->buf,
			req->request_len, NULL, 0, IPPROTO_TCP);
		g_free(req);
		goto out;
	}
	memcpy(req->request, client->buf, req->request_len);

	req->name = g_try_malloc0(sizeof(query));
	if (!req->name) {
		send_response(client_sk, client->buf,
			req->request_len, NULL, 0, IPPROTO_TCP);
		g_free(req->request);
		g_free(req);
		goto out;
	}
	memcpy(req->name, query, sizeof(query));

	req->timeout = g_timeout_add_seconds(30, request_timeout, req);

	request_list = g_slist_append(request_list, req);

out:
	if (client->buf_end > (msg_len + DNS_HEADER_TCP_EXTRA_BYTES)) {
		debug("client %d buf %p -> %p end %d len %d new %zd",
			client_sk,
			client->buf + msg_len + 2,
			client->buf, client->buf_end,
			TCP_MAX_BUF_LEN - client->buf_end,
			client->buf_end - (msg_len + 2));
		memmove(client->buf, client->buf + msg_len + 2,
			TCP_MAX_BUF_LEN - client->buf_end);
		client->buf_end = client->buf_end - (msg_len + 2);

		/*
		 * If we have a full message waiting, just read it
		 * immediately.
		 */
		msg_len = get_msg_len(client->buf);
		if ((msg_len + 2) == client->buf_end) {
			debug("client %d reading another %zd bytes", client_sk,
								msg_len + 2);
			goto read_another;
		}
	} else {
		debug("client %d clearing reading buffer", client_sk);

		client->buf_end = 0;
		memset(client->buf, 0, TCP_MAX_BUF_LEN);

		/*
		 * We received all the packets from client so we must also
		 * remove the timeout handler here otherwise we might get
		 * timeout while waiting the results from server.
		 */
		g_source_remove(client->timeout);
		client->timeout = 0;
	}

	return true;
}

static gboolean tcp_client_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct tcp_partial_client_data *client = user_data;
	int client_sk = g_io_channel_unix_get_fd(channel);
	int len;
	struct sockaddr_in6 client_addr6;
	socklen_t client_addr6_len = sizeof(client_addr6);
	struct sockaddr_in client_addr4;
	socklen_t client_addr4_len = sizeof(client_addr4);
	void *client_addr;
	socklen_t *client_addr_len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));

		connman_error("Error with TCP client %d channel", client_sk);
		return FALSE;
	}

	switch (client->family) {
	case AF_INET:
		client_addr = &client_addr4;
		client_addr_len = &client_addr4_len;
		break;
	case AF_INET6:
		client_addr = &client_addr6;
		client_addr_len = &client_addr6_len;
		break;
	default:
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		connman_error("client %p corrupted", client);
		return FALSE;
	}

	len = recvfrom(client_sk, client->buf + client->buf_end,
			TCP_MAX_BUF_LEN - client->buf_end - 1, 0,
			client_addr, client_addr_len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return TRUE;

		debug("client %d cannot read errno %d/%s", client_sk, -errno,
			strerror(errno));
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return FALSE;
	}

	client->buf[client->buf_end + len] = '\0';

	return read_tcp_data(client, client_addr, *client_addr_len, len);
}

static gboolean client_timeout(gpointer user_data)
{
	struct tcp_partial_client_data *client = user_data;
	int sock = g_io_channel_unix_get_fd(client->channel);

	debug("client %d timeout pending %d bytes", sock, client->buf_end);

	g_hash_table_remove(partial_tcp_req_table, GINT_TO_POINTER(sock));

	return FALSE;
}

static bool tcp_listener_event(GIOChannel *channel, GIOCondition condition,
				struct listener_data *ifdata, int family,
				guint *listener_watch)
{
	int sk = -1, client_sk = -1;
	int recv_len;
	size_t msg_len;
	fd_set readfds;
	struct timeval tv = {.tv_sec = 0, .tv_usec = 0};

	struct tcp_partial_client_data *client;
	struct sockaddr_in6 client_addr6;
	socklen_t client_addr6_len = sizeof(client_addr6);
	struct sockaddr_in client_addr4;
	socklen_t client_addr4_len = sizeof(client_addr4);
	void *client_addr;
	socklen_t *client_addr_len;

	debug("condition 0x%02x channel %p ifdata %p family %d",
		condition, channel, ifdata, family);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (*listener_watch > 0)
			g_source_remove(*listener_watch);
		*listener_watch = 0;

		connman_error("Error with TCP listener channel");

		return false;
	}

	sk = g_io_channel_unix_get_fd(channel);

	if (family == AF_INET) {
		client_addr = &client_addr4;
		client_addr_len = &client_addr4_len;
	} else {
		client_addr = &client_addr6;
		client_addr_len = &client_addr6_len;
	}

	FD_ZERO(&readfds);
	FD_SET(sk, &readfds);

	/* TODO: check select return code */
	select(sk + 1, &readfds, NULL, NULL, &tv);
	if (!FD_ISSET(sk, &readfds)) {
		debug("No data to read from master %d, waiting.", sk);
		return true;
	}

	client_sk = accept(sk, client_addr, client_addr_len);
	if (client_sk < 0) {
		connman_error("Accept failure on TCP listener");
		*listener_watch = 0;
		return false;
	}
	debug("client %d accepted", client_sk);

	fcntl(client_sk, F_SETFL, O_NONBLOCK);

	client = g_hash_table_lookup(partial_tcp_req_table, GINT_TO_POINTER(client_sk));
	if (!client) {
		client = g_try_new0(struct tcp_partial_client_data, 1);
		if (!client) {
			close(client_sk);
			return false;
		}

		g_hash_table_insert(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk),
					client);

		client->channel = g_io_channel_unix_new(client_sk);
		g_io_channel_set_close_on_unref(client->channel, TRUE);

		client->watch = g_io_add_watch(client->channel,
						G_IO_IN, tcp_client_event,
						(gpointer)client);

		client->ifdata = ifdata;

		debug("client %d created %p", client_sk, client);
	} else {
		debug("client %d already exists %p", client_sk, client);
	}

	if (!client->buf) {
		client->buf = g_try_malloc(TCP_MAX_BUF_LEN);
		if (!client->buf)
			return false;
	}
	memset(client->buf, 0, TCP_MAX_BUF_LEN);
	client->buf_end = 0;
	client->family = family;

	if (client->timeout == 0)
		client->timeout = g_timeout_add_seconds(2, client_timeout,
							client);

	/*
	 * Check how much data there is. If all is there, then we can
	 * proceed normally, otherwise read the bits until everything
	 * is received or timeout occurs.
	 */
	recv_len = recv(client_sk, client->buf, TCP_MAX_BUF_LEN, 0);
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			debug("client %d no data to read, waiting", client_sk);
			return true;
		}

		debug("client %d cannot read errno %d/%s", client_sk, -errno,
			strerror(errno));
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return true;
	}

	if (recv_len < DNS_HEADER_TCP_EXTRA_BYTES) {
		debug("client %d not enough data to read, waiting", client_sk);
		client->buf_end += recv_len;
		return true;
	}

	msg_len = get_msg_len(client->buf);
	if (msg_len > TCP_MAX_BUF_LEN) {
		debug("client %d invalid message length %zd ignoring packet",
			client_sk, msg_len);
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return true;
	}

	/*
	 * The packet length bytes do not contain the total message length,
	 * that is the reason to -2 below.
	 */
	if (msg_len != (size_t)(recv_len - DNS_HEADER_TCP_EXTRA_BYTES)) {
		debug("client %d sent %d bytes but expecting %zd pending %zd",
			client_sk, recv_len, msg_len + 2, msg_len + 2 - recv_len);

		client->buf_end += recv_len;
		return true;
	}

	return read_tcp_data(client, client_addr, *client_addr_len, recv_len);
}

static gboolean tcp4_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct listener_data *ifdata = user_data;

	return tcp_listener_event(channel, condition, ifdata, AF_INET,
				&ifdata->tcp4_listener_watch);
}

static gboolean tcp6_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct listener_data *ifdata = user_data;

	return tcp_listener_event(channel, condition, user_data, AF_INET6,
				&ifdata->tcp6_listener_watch);
}

static bool udp_listener_event(GIOChannel *channel, GIOCondition condition,
				struct listener_data *ifdata, int family,
				guint *listener_watch)
{
	unsigned char buf[769];
	char query[512];
	struct request_data *req = NULL;
	struct domain_hdr *hdr = NULL;
	int sk = -1, err, len;

	struct sockaddr_in6 client_addr6;
	socklen_t client_addr6_len = sizeof(client_addr6);
	struct sockaddr_in client_addr4;
	socklen_t client_addr4_len = sizeof(client_addr4);
	void *client_addr;
	socklen_t *client_addr_len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP listener channel");
		*listener_watch = 0;
		return false;
	}

	if (family == AF_INET) {
		client_addr = &client_addr4;
		client_addr_len = &client_addr4_len;
	} else {
		client_addr = &client_addr6;
		client_addr_len = &client_addr6_len;
	}

	memset(client_addr, 0, *client_addr_len);
	sk = g_io_channel_unix_get_fd(channel);
	len = recvfrom(sk, buf, sizeof(buf) - 1, 0, client_addr, client_addr_len);
	if (len < 2)
		return true;

	buf[len] = '\0';

	debug("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	err = parse_request(buf, len, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0)) {
		send_response(sk, buf, len, client_addr,
				*client_addr_len, IPPROTO_UDP);
		return true;
	}

	req = g_try_new0(struct request_data, 1);
	if (!req)
		return true;

	memcpy(&req->sa, client_addr, *client_addr_len);
	req->sa_len = *client_addr_len;
	req->client_sk = 0;
	req->protocol = IPPROTO_UDP;
	req->family = family;

	hdr = (void*)buf;

	req->srcid = hdr->id;
	req->dstid = get_id();
	req->altid = get_id();
	req->request_len = len;

	hdr->id = req->dstid;

	req->numserv = 0;
	req->ifdata = ifdata;
	req->append_domain = false;

	if (resolv(req, buf, query)) {
		/* a cached result was sent, so the request can be released */
	        g_free(req);
		return true;
	}

	req->name = g_strdup(query);
	req->request = g_malloc(len);
	memcpy(req->request, buf, len);
	req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	request_list = g_slist_append(request_list, req);

	return true;
}

static gboolean udp4_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct listener_data *ifdata = user_data;

	return udp_listener_event(channel, condition, ifdata, AF_INET,
				&ifdata->udp4_listener_watch);
}

static gboolean udp6_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct listener_data *ifdata = user_data;

	return udp_listener_event(channel, condition, user_data, AF_INET6,
				&ifdata->udp6_listener_watch);
}

static GIOChannel *get_listener(int family, int protocol, int index)
{
	GIOChannel *channel = NULL;
	union {
		struct sockaddr sa;
		struct sockaddr_in6 sin6;
		struct sockaddr_in sin;
	} s;
	socklen_t slen;
	const char *proto = protocol_label(protocol);
	const int type = socket_type(protocol, SOCK_CLOEXEC);
	char *interface;
	int sk = socket(family, type, protocol);

	debug("family %d protocol %d index %d", family, protocol, index);

	if (sk < 0) {
		if (family == AF_INET6 && errno == EAFNOSUPPORT) {
			connman_error("No IPv6 support");
		} else {
			connman_error("Failed to create %s listener socket", proto);
		}
		return NULL;
	}

	interface = connman_inet_ifname(index);
	if (!interface || setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
					interface,
					strlen(interface) + 1) < 0) {
		connman_error("Failed to bind %s listener interface "
			"for %s (%d/%s)",
			proto, family == AF_INET ? "IPv4" : "IPv6",
			-errno, strerror(errno));
		close(sk);
		g_free(interface);
		return NULL;
	}
	g_free(interface);

	if (family == AF_INET6) {
		memset(&s.sin6, 0, sizeof(s.sin6));
		s.sin6.sin6_family = AF_INET6;
		s.sin6.sin6_port = htons(dns_listen_port);
		slen = sizeof(s.sin6);

		if (__connman_inet_get_interface_address(index,
						AF_INET6,
						&s.sin6.sin6_addr) < 0) {
			/* So we could not find suitable IPv6 address for
			 * the interface. This could happen if we have
			 * disabled IPv6 for the interface.
			 */
			close(sk);
			return NULL;
		}

	} else if (family == AF_INET) {
		memset(&s.sin, 0, sizeof(s.sin));
		s.sin.sin_family = AF_INET;
		s.sin.sin_port = htons(dns_listen_port);
		slen = sizeof(s.sin);

		if (__connman_inet_get_interface_address(index,
						AF_INET,
						&s.sin.sin_addr) < 0) {
			close(sk);
			return NULL;
		}
	} else {
		close(sk);
		return NULL;
	}

	if (bind(sk, &s.sa, slen) < 0) {
		connman_error("Failed to bind %s listener socket", proto);
		close(sk);
		return NULL;
	}

	if (protocol == IPPROTO_TCP) {
		if (listen(sk, 10) < 0) {
			connman_error("Failed to listen on TCP socket %d/%s",
				-errno, strerror(errno));
			close(sk);
			return NULL;
		}

		if (fcntl(sk, F_SETFL, O_NONBLOCK) < 0) {
			connman_error("Failed to set TCP listener socket to non-blocking %d/%s",
				-errno, strerror(errno));
			close(sk);
			return NULL;
		}
	}

	channel = g_io_channel_unix_new(sk);
	if (!channel) {
		connman_error("Failed to create %s listener channel", proto);
		close(sk);
		return NULL;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);

	return channel;
}

#define UDP_IPv4_FAILED 0x01
#define TCP_IPv4_FAILED 0x02
#define UDP_IPv6_FAILED 0x04
#define TCP_IPv6_FAILED 0x08
#define UDP_FAILED (UDP_IPv4_FAILED | UDP_IPv6_FAILED)
#define TCP_FAILED (TCP_IPv4_FAILED | TCP_IPv6_FAILED)
#define IPv6_FAILED (UDP_IPv6_FAILED | TCP_IPv6_FAILED)
#define IPv4_FAILED (UDP_IPv4_FAILED | TCP_IPv4_FAILED)

static int create_dns_listener(int protocol, struct listener_data *ifdata)
{
	int ret = 0;

	if (protocol == IPPROTO_TCP) {
		ifdata->tcp4_listener_channel = get_listener(AF_INET, protocol,
							ifdata->index);
		if (ifdata->tcp4_listener_channel)
			ifdata->tcp4_listener_watch =
				g_io_add_watch(ifdata->tcp4_listener_channel,
					G_IO_IN, tcp4_listener_event,
					(gpointer)ifdata);
		else
			ret |= TCP_IPv4_FAILED;

		ifdata->tcp6_listener_channel = get_listener(AF_INET6, protocol,
							ifdata->index);
		if (ifdata->tcp6_listener_channel)
			ifdata->tcp6_listener_watch =
				g_io_add_watch(ifdata->tcp6_listener_channel,
					G_IO_IN, tcp6_listener_event,
					(gpointer)ifdata);
		else
			ret |= TCP_IPv6_FAILED;
	} else {
		ifdata->udp4_listener_channel = get_listener(AF_INET, protocol,
							ifdata->index);
		if (ifdata->udp4_listener_channel)
			ifdata->udp4_listener_watch =
				g_io_add_watch(ifdata->udp4_listener_channel,
					G_IO_IN, udp4_listener_event,
					(gpointer)ifdata);
		else
			ret |= UDP_IPv4_FAILED;

		ifdata->udp6_listener_channel = get_listener(AF_INET6, protocol,
							ifdata->index);
		if (ifdata->udp6_listener_channel)
			ifdata->udp6_listener_watch =
				g_io_add_watch(ifdata->udp6_listener_channel,
					G_IO_IN, udp6_listener_event,
					(gpointer)ifdata);
		else
			ret |= UDP_IPv6_FAILED;
	}

	return ret;
}

static void destroy_udp_listener(struct listener_data *ifdata)
{
	DBG("index %d", ifdata->index);

	if (ifdata->udp4_listener_watch > 0)
		g_source_remove(ifdata->udp4_listener_watch);

	if (ifdata->udp6_listener_watch > 0)
		g_source_remove(ifdata->udp6_listener_watch);

	if (ifdata->udp4_listener_channel)
		g_io_channel_unref(ifdata->udp4_listener_channel);
	if (ifdata->udp6_listener_channel)
		g_io_channel_unref(ifdata->udp6_listener_channel);
}

static void destroy_tcp_listener(struct listener_data *ifdata)
{
	DBG("index %d", ifdata->index);

	if (ifdata->tcp4_listener_watch > 0)
		g_source_remove(ifdata->tcp4_listener_watch);
	if (ifdata->tcp6_listener_watch > 0)
		g_source_remove(ifdata->tcp6_listener_watch);

	if (ifdata->tcp4_listener_channel)
		g_io_channel_unref(ifdata->tcp4_listener_channel);
	if (ifdata->tcp6_listener_channel)
		g_io_channel_unref(ifdata->tcp6_listener_channel);
}

static int create_listener(struct listener_data *ifdata)
{
	int index, err;

	err = create_dns_listener(IPPROTO_UDP, ifdata);
	if ((err & UDP_FAILED) == UDP_FAILED)
		return -EIO;

	err |= create_dns_listener(IPPROTO_TCP, ifdata);
	if ((err & TCP_FAILED) == TCP_FAILED) {
		destroy_udp_listener(ifdata);
		return -EIO;
	}

	index = connman_inet_ifindex("lo");
	if (ifdata->index == index) {
		if ((err & IPv6_FAILED) != IPv6_FAILED)
			__connman_resolvfile_append(index, NULL, "::1");

		if ((err & IPv4_FAILED) != IPv4_FAILED)
			__connman_resolvfile_append(index, NULL, "127.0.0.1");
	}

	return 0;
}

static void destroy_listener(struct listener_data *ifdata)
{
	int index = connman_inet_ifindex("lo");

	if (ifdata->index == index) {
		__connman_resolvfile_remove(index, NULL, "127.0.0.1");
		__connman_resolvfile_remove(index, NULL, "::1");
	}

	for (GSList *list = request_list; list; list = list->next) {
		struct request_data *req = list->data;

		debug("Dropping request (id 0x%04x -> 0x%04x)",
						req->srcid, req->dstid);
		destroy_request_data(req);
		list->data = NULL;
	}

	g_slist_free(request_list);
	request_list = NULL;

	destroy_tcp_listener(ifdata);
	destroy_udp_listener(ifdata);
}

int __connman_dnsproxy_add_listener(int index)
{
	struct listener_data *ifdata;
	int err;

	DBG("index %d", index);

	if (index < 0)
		return -EINVAL;

	if (!listener_table)
		return -ENOENT;

	if (g_hash_table_lookup(listener_table, GINT_TO_POINTER(index)))
		return 0;

	ifdata = g_try_new0(struct listener_data, 1);
	if (!ifdata)
		return -ENOMEM;

	ifdata->index = index;
	ifdata->udp4_listener_channel = NULL;
	ifdata->udp4_listener_watch = 0;
	ifdata->tcp4_listener_channel = NULL;
	ifdata->tcp4_listener_watch = 0;
	ifdata->udp6_listener_channel = NULL;
	ifdata->udp6_listener_watch = 0;
	ifdata->tcp6_listener_channel = NULL;
	ifdata->tcp6_listener_watch = 0;

	err = create_listener(ifdata);
	if (err < 0) {
		connman_error("Couldn't create listener for index %d err %d",
				index, err);
		g_free(ifdata);
		return err;
	}
	g_hash_table_insert(listener_table, GINT_TO_POINTER(ifdata->index),
			ifdata);
	return 0;
}

void __connman_dnsproxy_remove_listener(int index)
{
	struct listener_data *ifdata;
	DBG("index %d", index);

	if (!listener_table)
		return;

	ifdata = g_hash_table_lookup(listener_table, GINT_TO_POINTER(index));
	if (!ifdata)
		return;

	destroy_listener(ifdata);

	g_hash_table_remove(listener_table, GINT_TO_POINTER(index));
}

static void remove_listener(gpointer key, gpointer value, gpointer user_data)
{
	int index = GPOINTER_TO_INT(key);
	struct listener_data *ifdata = value;

	DBG("index %d", index);

	destroy_listener(ifdata);
}

static void free_partial_reqs(gpointer value)
{
	struct tcp_partial_client_data *data = value;

	client_reset(data);
	g_free(data);
}

int __connman_dnsproxy_init(void)
{
	int err, index;

	DBG("");

	listener_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, g_free);

	partial_tcp_req_table = g_hash_table_new_full(g_direct_hash,
							g_direct_equal,
							NULL,
							free_partial_reqs);

	index = connman_inet_ifindex("lo");
	err = __connman_dnsproxy_add_listener(index);
	if (err < 0)
		return err;

	err = connman_notifier_register(&dnsproxy_notifier);
	if (err < 0) {
		__connman_dnsproxy_remove_listener(index);
		g_hash_table_destroy(listener_table);
		g_hash_table_destroy(partial_tcp_req_table);

		return err;
	}

	return 0;
}

int __connman_dnsproxy_set_mdns(int index, bool enabled)
{
	return -ENOTSUP;
}

void __connman_dnsproxy_cleanup(void)
{
	DBG("");

	if (cache_timer) {
		g_source_remove(cache_timer);
		cache_timer = 0;
	}

	if (cache) {
		g_hash_table_destroy(cache);
		cache = NULL;
	}

	connman_notifier_unregister(&dnsproxy_notifier);

	g_hash_table_foreach(listener_table, remove_listener, NULL);

	g_hash_table_destroy(listener_table);

	g_hash_table_destroy(partial_tcp_req_table);

	if (ipv4_resolve)
		g_resolv_unref(ipv4_resolve);
	if (ipv6_resolve)
		g_resolv_unref(ipv6_resolve);
}

void __connman_dnsproxy_set_listen_port(unsigned int port)
{
	dns_listen_port = port;
}
