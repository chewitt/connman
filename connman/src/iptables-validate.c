/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013,2015  BMW Car IT GmbH.
 *  Copyright (C) 2018,2019  Jolla Ltd.
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
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#include "connman.h"

enum iptables_switch_type {
	IPTABLES_UNSET     = 0,
	IPTABLES_SWITCH    = 1,
	IPTABLES_MATCH     = 2,
	IPTABLES_TARGET    = 3,
	IPTABLES_PROTO     = 4,
	IPTABLES_PORT      = 5,
	IPTABLES_OPTION    = 6,
	IPTABLES_INTERFACE = 7,
	IPTABLES_IPADDR    = 8,
};

#define MAX_IPTABLES_SWITCH 9

static bool is_string_digits(const char *str)
{
	int i;

	if (!str || !*str)
		return false;

	for (i = 0; str[i]; i++) {
		if (!g_ascii_isdigit(str[i]))
			return false;
	}

	return true;
}

static bool is_string_hexadecimal(const char *str)
{
	int i;

	if (!str || !*str)
		return false;

	if (!g_str_has_prefix(str, "0x"))
		return false;

	for (i = 2; str[i]; i++) {
		if (!g_ascii_isxdigit(str[i]))
			return false;
	}

	return true;
}

/* Increase this if any of the rule options require more than 2 parameters */
#define IPTABLES_OPTION_COUNT_MAX 2

/*
 * List of supported match option types.
 * - UDP not included as it has no other than port switches
 * - hashlimit match is not supported
 * - dcsp match is not supported
 */
enum iptables_match_options_type {
	IPTABLES_OPTION_PORT = 0,
	IPTABLES_OPTION_MULTIPORT,
	IPTABLES_OPTION_TCP,
	IPTABLES_OPTION_MARK,
	IPTABLES_OPTION_CONNTRACK,
	IPTABLES_OPTION_TTL, // Only with IPv4
	IPTABLES_OPTION_PKTTYPE,
	IPTABLES_OPTION_LIMIT,
	IPTABLES_OPTION_HELPER,
	IPTABLES_OPTION_ECN, // Only with TCP
	IPTABLES_OPTION_AH,
	IPTABLES_OPTION_ESP,
	IPTABLES_OPTION_MH,
	IPTABLES_OPTION_SCTP,
	IPTABLES_OPTION_ICMP,
	IPTABLES_OPTION_ICMPv6,
	IPTABLES_OPTION_DCCP,
	IPTABLES_OPTION_OWNER,
	IPTABLES_OPTION_IPRANGE,
	IPTABLES_OPTION_GRE,
	IPTABLES_OPTION_NOT_SUPPORTED
};

/*
 * TODO: change the two arrays of options and option counts into structs
 * having option and option_count as values. Requires big changes for searching
 * of a valid option, g_strv_contains() has to be changed into traversing the
  * array of these new option value structs.
 */

static const char *port_options[] = {"--destination-port", "--dport",
					"--source-port", "--sport", NULL};
static const int port_options_count[] = {1, 1, 1, 1, -1};

static const char *multiport_options[] = {"--destination-ports", "--dports",
					"--source-ports", "--sports",
					"--port", "--ports", NULL};
static const int multiport_options_count[] = {1, 1, 1, 1, 1, 1, -1};
/*
 * tcp match options:
 * [!] --tcp-flags mask comp	match when TCP flags & mask == comp
 * 				(Flags: SYN ACK FIN RST URG PSH ALL NONE)
 * [!] --syn	match when only SYN flag set
 * 				(equivalent to --tcp-flags SYN,RST,ACK,FIN SYN)
 * 				match destination port(s)
 * [!] --tcp-option number	match if TCP option set
*/
static const char *tcp_options[] = {"--tcp-flags",
			"--syn",
			"--tcp-option",
			NULL
};
static const int tcp_options_count[] = {2, 0, 1, -1};

/*
 * mark match options:
 * [!] --mark value[/mask]	Match nfmark value with optional mask
*/
static const char *mark_options[] = {"--mark", NULL};
static const int mark_options_count[] = {1, -1};

/*
 * conntrack match options:
 * [!] --ctstate {INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT}[,...]
 * 				State(s) to match
 * [!] --ctproto proto		Protocol to match; by number or name, e.g. "tcp"
 * [!] --ctorigsrc address[/mask]
 * [!] --ctorigdst address[/mask]
 * [!] --ctreplsrc address[/mask]
 * [!] --ctrepldst address[/mask]
 * 				Original/Reply source/destination address
 * [!] --ctorigsrcport port
 * [!] --ctorigdstport port
 * [!] --ctreplsrcport port
 * [!] --ctrepldstport port
 * 				TCP/UDP/SCTP orig./reply source/destination port
 * [!] --ctstatus {NONE|EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED}[,...]
 * 				Status(es) to match
 * [!] --ctexpire time[:time]	Match remaining lifetime in seconds against
 *				value or range of values (inclusive)
 * --ctdir {ORIGINAL|REPLY}	Flow direction of packet
 */
static const char *conntrack_options[] = {"--ctstate",
			"--ctproto",
			"--ctorigsrc",
			"--ctorigdst",
			"--ctreplsrc",
			"--ctrepldst",
			"--ctorigsrcport",
			"--ctorigdstport",
			"--ctreplsrcport",
			"--ctrepldstport",
			"--ctstatus",
			"--ctexpire",
			"--ctdir",
			NULL
};
static const int conntrack_options_count[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			1, 1,-1};
enum iptables_conntrack_type {
	IPTABLES_CONNTRACK_CTSTATE = 0,
	IPTABLES_CONNTRACK_CTPROTO,
	IPTABLES_CONNTRACK_CTORIGSRC,
	IPTABLES_CONNTRACK_CTORIGDST,
	IPTABLES_CONNTRACK_CTREPLSRC,
	IPTABLES_CONNTRACK_CTREPLDST,
	IPTABLES_CONNTRACK_CTORIGSRCPORT,
	IPTABLES_CONNTRACK_CTORIGDSTPORT,
	IPTABLES_CONNTRACK_CTREPLSRCPORT,
	IPTABLES_CONNTRACK_CTREPLDSTPORT,
	IPTABLES_CONNTRACK_CTSTATUS,
	IPTABLES_CONNTRACK_CTEXPIRE,
	IPTABLES_CONNTRACK_CTDIR,
};

/*
 * ttl match options:
 * [!] --ttl-eq value		Match time to live value
 * --ttl-lt value		Match TTL < value
 * --ttl-gt value		Match TTL > value

 */
static const char *ttl_options[] = {"--ttl-eq", "--ttl-lt", "--ttl-gt", NULL};
static const int ttl_options_count[] = {1, 1, 1, -1};

/*
 * pkttype match options:
 * [!] --pkt-type packettype	match packet type
 * 				Valid packet types:
 * 					unicast		to us
 * 					broadcast	to all
 * 					multicast	to group
*/
static const char *pkttype_options[] = {"--pkt-type", NULL};
static const int pkttype_options_count[] = {1, -1};

/*
 * limit match options:
 * --limit avg			max average match rate: default 3/hour
 * 				[Packets per second unless followed by
 * 				/sec /minute /hour /day postfixes]
 * --limit-burst number		number to match in a burst, default 5
 */
static const char *limit_options[] = {"--limit", "--limit-burst", NULL};
static const int limit_options_count[] = {1, 1, -1};

/*
 * helper match options:
 * [!] --helper string		Match helper identified by string
 */
static const char *helper_options[] = {"--helper", NULL};
static const int helper_options_count[] = {1, -1};

/*
 * ECN match options
 * [!] --ecn-tcp-cwr 		Match CWR bit of TCP header
 * [!] --ecn-tcp-ece		Match ECE bit of TCP header
 * [!] --ecn-ip-ect [0..3]	Match ECN codepoint in IPv4/IPv6 header
 */
static const char *ecn_options[] = {"--ecn-tcp-cwr",
			"--ecn-tcp-ece",
			"--ecn-ip-ect",
			NULL
};
static const int ecn_options_count[] = {0, 0, 1, -1};

/*
 * ah match options:
 * [!] --ahspi spi[:spi]	match spi (range)
 *
 * TODO AH IPv6 option support:
 * [!] --ahspi spi[:spi]	match spi (range)
 * [!] --ahlen length		total length of this header
 * --ahres			check the reserved field too
 */
static const char *ah_options[] = {"--ahspi", NULL};
static const int ah_options_count[] = {1, -1};

/*
 * esp match options:
 * [!] --espspi spi[:spi]	match spi (range)
 */
static const char *esp_options[] = {"--espspi", NULL};
static const int esp_options_count[] = {1, -1};

/*
 * mh match options:
 * [!] --mh-type type[:type]	match mh type
 * 				Valid MH types:
 * 					binding-refresh-request (brr)
 * 					home-test-init (hoti)
 * 					careof-test-init (coti)
 * 					home-test (hot)
 * 					careof-test (cot)
 * 					binding-update (bu)
 * 					binding-acknowledgement (ba)
 * 					binding-error (be)
 */
static const char *mh_options[] = {"--mh-type", NULL};
static const int mh_options_count[] = {1, -1};

/*
 * sctp match options
 * [!] --chunk-types (all|any|none) (chunktype[:flags])+
 * 				match if all, any or none of chunktypes are
 * 				present
 */

static const char *sctp_options[] = {"--chunk-types", NULL};
static const int sctp_options_count[] = {2, -1};

/*
 * icmp match options:
 * [!] --icmp-type typename	match icmp type
 * [!] --icmp-type type[/code]	(or numeric type or type/code)
 */
static const char *icmp_options[] = {"--icmp-type", NULL};
static const int icmp_options_count[] = {1, -1};

/*
 * icmpv6 match options:
 * [!] --icmpv6-type typename	match icmpv6 type
 * 				(or numeric type or type/code)
 */

static const char *icmpv6_options[] = {"--icmpv6-type", NULL};
static const int icmpv6_options_count[] = {1, -1};

/*
 * dccp match options
 * [!] --dccp-types type[,...]	match when packet is one of the given types
 * [!] --dccp-option option	match if option (by number!) is set
 */

static const char *dccp_options[] = {"--dccp-types", "--dccp-option", NULL};
static const int dccp_options_count[] = {1, 1, -1};

/*
 * owner match options
 * [!] --uid-owner userid[-userid]      Match local UID
 * [!] --gid-owner groupid[-groupid]    Match local GID
 * [!] --socket-exists                  Match if socket exists
 */

static const char *owner_options[] = {"--uid-owner", "--gid-owner",
                                      "--socket-exists", NULL};
static const int owner_options_count[] = {1, 1, 0, -1};

/*
 * iprange match options
 * [!] --src-range ip[-ip]    Match source IP in the specified range
 * [!] --dst-range ip[-ip]    Match destination IP in the specified range
 */

static const char *iprange_options[] = {"--src-range", "--dst-range", NULL};
static const int iprange_options_count[] = {1, 1, -1};

/* Protocol gre has no options, just a dummy placeholder. */
static const char *gre_options[] = {NULL};
static const int gre_options_count[] = {-1};

struct iptables_type_options {
	enum iptables_match_options_type type;
	const char **options;
	const int *option_count;
};

static const struct iptables_type_options iptables_opts[] = {
	{IPTABLES_OPTION_PORT, port_options, port_options_count},
	{IPTABLES_OPTION_MULTIPORT, multiport_options, multiport_options_count},
	{IPTABLES_OPTION_TCP, tcp_options, tcp_options_count},
	{IPTABLES_OPTION_MARK, mark_options, mark_options_count},
	{IPTABLES_OPTION_CONNTRACK, conntrack_options, conntrack_options_count},
	{IPTABLES_OPTION_TTL, ttl_options, ttl_options_count},
	{IPTABLES_OPTION_PKTTYPE, pkttype_options, pkttype_options_count},
	{IPTABLES_OPTION_LIMIT, limit_options, limit_options_count},
	{IPTABLES_OPTION_HELPER, helper_options, helper_options_count},
	{IPTABLES_OPTION_ECN, ecn_options, ecn_options_count},
	{IPTABLES_OPTION_AH, ah_options, ah_options_count},
	{IPTABLES_OPTION_ESP, esp_options, esp_options_count},
	{IPTABLES_OPTION_MH, mh_options, mh_options_count},
	{IPTABLES_OPTION_SCTP, sctp_options, sctp_options_count},
	{IPTABLES_OPTION_ICMP, icmp_options, icmp_options_count},
	{IPTABLES_OPTION_ICMPv6, icmpv6_options, icmpv6_options_count},
	{IPTABLES_OPTION_DCCP, dccp_options, dccp_options_count},
	{IPTABLES_OPTION_OWNER, owner_options, owner_options_count},
	{IPTABLES_OPTION_IPRANGE, iprange_options, iprange_options_count},
	{IPTABLES_OPTION_GRE, gre_options, gre_options_count},
};

static const char *opt_names[] = {"port", "multiport", "tcp", "mark",
				"conntrack", "ttl", "pkttype", "limit",
				"helper", "ecn", "ah", "esp", "mh", "sctp",
				"icmp", "ipv6-icmp", "dccp", "owner",
				"iprange", "gre", NULL};

static GHashTable *iptables_options = NULL;

static void initialize_iptables_options(void)
{
	enum iptables_match_options_type type;

	if (!iptables_options)
		iptables_options = g_hash_table_new(g_str_hash,
						g_str_equal);

	for (type = IPTABLES_OPTION_PORT; type < IPTABLES_OPTION_NOT_SUPPORTED;
				type++)
		g_hash_table_insert(iptables_options, (char*)opt_names[type],
			(struct iptables_type_options*)&iptables_opts[type]);
}

static struct protoent *get_protocol_protoent(const char *protocol)
{
	struct protoent *p;
	int protonum;

	/* If protocol is integer */
	if (is_string_digits(protocol)) {
		protonum = (int) g_ascii_strtoll(protocol, NULL, 10);
		p = getprotobynumber(protonum);
	} else {
		p = getprotobyname(protocol);
	}

	return p;
}

static bool is_valid_protocol(const char *protocol)
{
	return get_protocol_protoent(protocol);
}

static enum iptables_match_options_type validate_option_type(
			const char *protocol, const char *match,
			const char *option, int *count, int *position,
			bool multiport)
{
	struct iptables_type_options *type_options;
	struct protoent *p;
	enum iptables_match_options_type return_type =
				IPTABLES_OPTION_NOT_SUPPORTED;
	GSList *keys = NULL, *iter;
	const char *key = NULL;
	int i;

	DBG("");
	
	if (!iptables_options)
		initialize_iptables_options();

	if (match) {
		/* Only port options for udp/udplite */
		if (!g_strcmp0(match, "udp") || !g_strcmp0(match, "udplite"))
			keys = g_slist_prepend(keys, "port");
		/* Use official name of for icmpv6 */
		else if (!g_strcmp0(match, "icmpv6"))
			keys = g_slist_prepend(keys, "ipv6-icmp");
		/*
		 * Otherwise add the match as search key, cast to char* to avoid
		 * compiler warning.
		 */
		else
			keys = g_slist_prepend(keys, (char*)match);

		/* Search for match and port for multiport and TCP.*/
		if (multiport || !g_strcmp0(match, "tcp"))
			keys = g_slist_prepend(keys, "port");
	} else if (protocol) { /* If only protocol is given (sctp|dccp) */
		p = get_protocol_protoent(protocol);

		if (!p)
			return IPTABLES_OPTION_NOT_SUPPORTED;

		/* SCTP options do not work, search with port option */
		if (!g_ascii_strcasecmp(p->p_name, "sctp")) {
			keys = g_slist_prepend(keys, "port");
		/* DCCP can have both port and protocol options */
		} else if (!g_ascii_strcasecmp(p->p_name, "dccp")) {
			keys = g_slist_prepend(keys, p->p_name);
			keys = g_slist_prepend(keys, "port");
		}
	} else {
		return IPTABLES_OPTION_NOT_SUPPORTED;
	}

	DBG("search protocol %s match %s ", protocol, match);

	for (iter = keys; iter; iter = iter->next) {
		key = iter->data;

		DBG("search key %s", key);
		type_options = g_hash_table_lookup(iptables_options, key);

		if (!type_options)
			continue;

		for (i = 0; type_options->options[i]; i++) {
			if (!g_strcmp0(type_options->options[i], option)) {
				DBG("found match for option %s type %d "
					"position %d parameter count %d",
					option, type_options->type, i,
					type_options->option_count[i]);

				*count = type_options->option_count[i];
				*position = i;

				/*
				 * In case a port option was used with multiport
				 * return multiport type since port options work
				 * with multiport as well.
				 */
				if (type_options->type ==
					IPTABLES_OPTION_PORT && multiport)
					return_type = IPTABLES_OPTION_MULTIPORT;
				else
					return_type = type_options->type;

				break;
			}
		}

		/* Match was found */
		if (return_type != IPTABLES_OPTION_NOT_SUPPORTED)
			break;
	}

	g_slist_free(keys);

	return return_type;
}

/*
 * This check has to be done because two same direction port options causes
 * iptables to report invalid parameters which in turn results in exit().
 */
static bool is_port_option_same_group(const char *str1, const char *str2)
{
	const char *dst_port[] = {"--destination-port", "--dport", NULL};
	const char *src_port[] = {"--source-port", "--sport", NULL};
	int i;
	int direction1 = -1, direction2 = -1;

	if (!g_strcmp0(str1, str2))
		return true;

	for (i = 0; dst_port[i]; i++) {
		if (!g_strcmp0(dst_port[i], str1))
			direction1 = 0;
		if (!g_strcmp0(dst_port[i], str2))
			direction2 = 0;
	}

	for (i = 0; src_port[i]; i++) {
		if (!g_strcmp0(src_port[i], str1))
			direction1 = 1;
		if (!g_strcmp0(src_port[i], str2))
			direction2 = 1;
	}

	return direction1 == direction2;
}

static const char *supported_dynamic_switches_in[] = { "--in-interface", "-i",
			NULL};
static const char *supported_dynamic_switches_out[] = { "--out-interface", "-o",
			NULL};

static bool is_in_supported_dynamic_switches(const char *str)
{
	if (g_strv_contains(supported_dynamic_switches_in, str) ||
				g_strv_contains(supported_dynamic_switches_out,
				str))
		return true;

	return false;
}

static bool is_interface_option_same_group(const char *str1, const char *str2)
{
	int i;
	int direction1 = -1, direction2 = -1;

	if (!g_strcmp0(str1, str2))
		return true;

	for (i = 0; supported_dynamic_switches_in[i]; i++) {
		if (!g_strcmp0(supported_dynamic_switches_in[i], str1))
			direction1 = 0;
		if (!g_strcmp0(supported_dynamic_switches_in[i], str2))
			direction2 = 0;
	}

	for (i = 0; supported_dynamic_switches_out[i]; i++) {
		if (!g_strcmp0(supported_dynamic_switches_out[i], str1))
			direction1 = 1;
		if (!g_strcmp0(supported_dynamic_switches_out[i], str2))
			direction2 = 1;
	}

	return direction1 == direction2;
}

static bool is_port_option(const char *str, bool multiport)
{
	if (!str || !*str)
		return true;

	if (multiport) {
		if (g_strv_contains(multiport_options, str))
			return true;
	}

	/* Normal port switches can be used also with -m multiport */
	if (g_strv_contains(port_options, str))
		return true;

	return false;
}

static const char *address_option_src[] = {"--source", "--src", "-s", NULL};
static const char *address_option_dst[] = {"--destination", "--dst", "-d",
			NULL};

static bool is_address_option(const char *str)
{
	if (!str)
		return false;

	if (g_strv_contains(address_option_src, str) ||
			g_strv_contains(address_option_dst, str))
		return true;

	return false;
}

static bool is_address_option_same_direction(const char *str1,
			const char *str2)
{
	int i;
	int direction1 = -1, direction2 = -1;

	if (!g_strcmp0(str1, str2))
		return true;

	for (i = 0; address_option_src[i]; i++) {
		if (!g_strcmp0(address_option_src[i], str1))
			direction1 = 0;
		if (!g_strcmp0(address_option_src[i], str2))
			direction2 = 0;
	}

	for (i = 0; address_option_dst[i]; i++) {
		if (!g_strcmp0(address_option_dst[i], str1))
			direction1 = 1;
		if (!g_strcmp0(address_option_dst[i], str2))
			direction2 = 1;
	}

	return direction1 == direction2;
}

static bool is_valid_port_or_service(const char *protocol,
			const char *port_or_service,
			uint16_t *port)
{
	struct servent *s;
	int portnum;

	/* Plain digits, check if port is valid */
	if (is_string_digits(port_or_service)) {
		portnum = (int) g_ascii_strtoll(port_or_service, NULL, 10);

		/* Valid port number */
		if (portnum && portnum <= G_MAXUINT16) {
			if (port)
				*port = (uint16_t) portnum;

			return true;
		}
	} else {
		/* Check if service name is valid with any protocol */
		s = getservbyname(port_or_service, protocol);

		if (s) {
			/*
			 * Port numbers are 16bit integers but struct servent
			 * contains them as regular (32bit) integers. The value
			 * is set with htons() to s_port in network byte order.
			 */
			if (port)
				*port = ntohs(s->s_port);

			return true;
		}
	}

	return false;
}

static bool is_valid_port_or_service_range(const char *protocol,
			const char *range)
{
	gchar **tokens = NULL;
	const char delimiter[] = ":";
	uint16_t ports[2] = { 0 };
	int i;

	tokens = g_strsplit(range, delimiter, 3);

	if (!tokens)
		return false;

	/* Range can have only two set */
	if (g_strv_length(tokens) == 2) {
		for (i = 0; i < 2 && tokens[i]; i++) {
			if (!is_valid_port_or_service(protocol, tokens[i],
						&ports[i])) {
				DBG("invalid port/service %s in %s", tokens[i],
							range);
				break;
			}
		}
	} else {
		DBG("invalid amount of port range delimiters %s", range);
	}

	g_strfreev(tokens);

	return ports[0] < ports[1];
}

static bool validate_ports_or_services(const char *protocol, const char *str,
			bool multiport)
{
	gchar **tokens = NULL;
	 /* In iptables ports are separated with commas, ranges with colon. */
	const char delimeter[] = ",";
	bool ret = true;
	int i;

	if (!str || !*str)
		return false;

	/* If -m multiport is not used port option can have one value set */
	if (!multiport && !is_valid_port_or_service(protocol, str, NULL)) {
		DBG("invalid port/service in %s", str);
		return false;
	}

	tokens = g_strsplit(str, delimeter, 0);

	if (!tokens)
		return false;

	for (i = 0; tokens[i]; i++) {
		/*
		 * If ':' exists it is a range. Check that only one ':' exists
		 * and the port range is specified correctly
		 */
		if (strstr(tokens[i], ":")) {
			if (is_valid_port_or_service_range(protocol, tokens[i]))
				continue;
		} else {
			if (is_valid_port_or_service(protocol, tokens[i], NULL))
				continue;
		}

		/* If one of the ports/services is invalid, rule is invalid */
		ret = false;
		DBG("invalid port/service %s in %s", tokens[i], str);
		break;
	}

	g_strfreev(tokens);

	return ret;
}

static bool is_valid_netmask(int family, const char *netmask)
{
	int cidr_len = 0;
	int cidr_max = 0;

	/* Netmask with CIDR notation */
	if (is_string_digits(netmask)) {
		switch (family) {
		case AF_INET:
			cidr_len = 2;
			cidr_max = 32;
			break;
		case AF_INET6:
			cidr_len = 3;
			cidr_max = 128;
		}

		return strlen(netmask) <= cidr_len && (int)g_ascii_strtoll(
					netmask, NULL, 10) <= cidr_max;
	} else {
		/* If family differs or error occurs, netmask is invalid */
		return family == connman_inet_check_ipaddress(netmask);
	}
}

static bool validate_address_option_value(int family, const char *address)
{
	gchar **tokens;
	bool ret = false;
	int res;

	tokens = g_strsplit(address, "/", 2);

	if (!tokens)
		return false;

	/* Has netmask defined */
	switch (g_strv_length(tokens)) {
	case 2:
		if (!is_valid_netmask(family, tokens[1])) {
			DBG("invalid netmask in %s", address);
			goto out;
		}
	/* Fallthrough */
	case 1:
		/* IP family or error is returned */
		res = connman_inet_check_ipaddress(tokens[0]);

		if (res == family) {
			ret = true;
			goto out;
		/* If family is different, there is no error set */
		} else if (res > 0) {
			DBG("invalid IP family address %s", address);
			goto out;
		}
		break;
	default:
		goto out;
	}

	ret = connman_inet_check_hostname(address, strlen(address));
out:
	g_strfreev(tokens);
	return ret;
}

static bool validate_addresses(int family, const char *addresses)
{
	gchar **tokens;
	bool ret = false;
	int length;
	int i;

	tokens = g_strsplit(addresses, ",", 0);

	if (!tokens)
		goto out;

	length = g_strv_length(tokens);

	for (i = 0; i < length; i++) {
		ret = validate_address_option_value(family, tokens[i]);

		if (!ret) {
			DBG("invalid address %s", tokens[i]);
			goto out;
		}
	}
out:
	g_strfreev(tokens);
	return ret;
}

static bool is_icmp_int_type_valid(const char *icmp_type)
{
	int icmp_num;

	icmp_num = (int) g_ascii_strtoll(icmp_type, NULL, 10);

	/* Anything from 0...255 is "valid" even though not correct.*/
	if (icmp_num >= 0 && icmp_num <= UINT8_MAX)
		return true;

	return false;
}

static bool is_correct_id(const char *id)
{
	guint64 value = g_ascii_strtoull(id, NULL, 10);
	if (errno != 0)
		return false;

	if (value > UINT32_MAX - 1)
		return false;

	return true;
}

static bool is_valid_iprange(int family, const char *iprange)
{
	char **tokens;
	unsigned int token_count;
	bool value = false;
	union {
		struct in_addr ia;
		struct in6_addr ia6;
	} addr1, addr2;

	if (!iprange)
		return false;

	tokens = g_strsplit(iprange, "-", 2);

	if (!tokens)
		return false;

	token_count = g_strv_length(tokens);

	if (token_count < 1) {
		DBG("Incorrect number of IP addresses in iprange");
		goto out;
	}

	if (!inet_pton(family, tokens[0], &addr1)) {
		DBG("Error parsing %s address or address in wrong family"
					" (ipv4/ipv6)",	tokens[0]);
		goto out;
	}

	if (token_count == 1) {
		value = true;
		goto out;
	}

	if (!inet_pton(family, tokens[1], &addr2)) {
		DBG("Error parsing %s address or address in wrong family"
					" (ipv4/ipv6)", tokens[1]);
		goto out;
	}

	if (memcmp(&addr1, &addr2, family == AF_INET ? sizeof(struct in_addr) :
						sizeof(struct in6_addr)) > 0)
		DBG("%s address is reverted with %s, would not match anything",
					tokens[0], tokens[1]);
	else
		value = true;

out:
	g_strfreev(tokens);
	return value;
}

typedef bool (*range_validation_cb_t)(const char *param);
enum range_callback_operation {
	RANGE_CALLBACK_OR = 0,
	RANGE_CALLBACK_AND,
};

static bool is_valid_pair(const char *range, const char *separator,
			range_validation_cb_t cb,
			enum range_callback_operation operation)
{
	char **tokens;
	int token_count;
	bool value = false;
	int i;

	if (!range || !separator)
		return false;

	tokens = g_strsplit(range, separator, 2);

	if (!tokens)
		return false;

	token_count = g_strv_length(tokens);

	for (i = 0; i < token_count; i++) {
		value = is_string_digits(tokens[i]);

		if (cb) {
			/*
			 * If string has to be digits and callback check must
			 * pass.
			 */
			if (operation == RANGE_CALLBACK_AND)
				value = value && cb(tokens[i]);
			/*
			 * If string can be either digits or the callback check
			 * must pass. Do not execute cb() if the digits check
			 * passes.
			 */
			else
				value = value ? value :
						(value || cb(tokens[i]));
		}

		if (!value)
			break;
	}

	g_strfreev(tokens);

	return value;
}

static bool is_valid_elem(const char *elem, range_validation_cb_t cb,
			enum range_callback_operation operation)
{
	bool numeric = false;
	bool result = false;

	if (!elem)
		return false;

	if (is_string_digits(elem)) {
		numeric = true;
	}

	/* We could skip the callback if numeric is enough */
	if (numeric && operation == RANGE_CALLBACK_OR)
		result = true;
	else if (numeric || operation == RANGE_CALLBACK_OR)
		if (cb && cb(elem))
			result = true;
	/* The other scenario - numeric false, operation AND - result in false */

	return result;
}

static bool is_valid_range(const char *range, const char *separator,
			range_validation_cb_t cb,
			enum range_callback_operation operation)
{
	if (is_valid_elem(range, cb, operation))
		return true;

	gchar **tokens = NULL;
	bool numeric = false;
	bool result = false;
	guint64 value1, value2;

	if (!range || !separator)
		return false;

	tokens = g_strsplit(range, separator, 3);

	if (!tokens)
		return false;

	if (g_strv_length(tokens) != 2) {
		DBG("invalid amount of separators in the string %s", range);
		goto range_free_tokens;
	}

	/* Check if the numerical conditions are met */
	if (is_string_digits(tokens[0]) && is_string_digits(tokens[1])) {
		value1 = g_ascii_strtoull(tokens[0], NULL, 10);
		if (errno != 0)
			goto range_check_string;

		value2 = g_ascii_strtoull(tokens[1], NULL, 10);
		if (errno != 0)
			goto range_check_string;

		/* Essential condition - values come in ascending order */
		if (value1 <= value2)
			numeric = true;
	} /* else numeric = false, set on startup */

range_check_string:

	/* We could skip the callback if numeric is enough */
	if (numeric && operation == RANGE_CALLBACK_OR)
		result = true;
	else if (numeric || operation == RANGE_CALLBACK_OR)
		if (cb && cb(tokens[0]) && cb(tokens[1]))
			result = true;
	/* The other scenario - numeric false, operation AND - result in false */

range_free_tokens:

	g_strfreev(tokens);

	return result;
}

static bool is_valid_param_sequence(const char **haystack, const char *needles,
			const char *needle_separator, int max_tokens)
{
	char **tokens;
	bool value;
	int token_count;
	int i;

	if (!haystack || !needles || !needle_separator)
		return false;

	tokens = g_strsplit(needles, needle_separator, max_tokens);

	if (!tokens)
		return false;

	token_count = g_strv_length(tokens);

	for (i = 0; i < token_count; i++) {
		if (!(value = g_strv_contains(haystack, tokens[i])))
			break;
	}

	g_strfreev(tokens);

	return value;
}

/*
 * To clarify this function a bit, since it is so large, each different match
 * option that is supported and its values are validated here.
 *
 * type: match type of the option 
 * params: parameters given for the option, 2 params max.
 * option_position: this defines the actual option used, it tells the position
 * 		of the supported option within the options array of the match
 * 		defined by the type.
 * multiport: is this a multiport match (special port option case)
 */
static bool is_valid_option_type_params(int family,
			enum iptables_match_options_type option_type,
			const char *protocol, const char **params,
			const int option_position, bool multiport)
{
	const char *valid_tcp_flags[] = {"SYN", "ACK", "FIN", "RST", "URG",
				"PSH", "ALL", "NONE", NULL};
	const char *valid_limit_postfixes[] = { "sec", "minute", "hour", "day",
				NULL};
	const char *valid_pkttypes[] = {"unicast", "broadcast", "multicast",
				NULL};
	const char *valid_conntrack_states[] = {"INVALID", "ESTABLISHED", "NEW",
				"RELATED", "UNTRACKED", "SNAT", "DNAT", NULL};
	const char *valid_conntrack_status[] = {"NONE", "EXPECTED",
				"SEEN_REPLY", "ASSURED", "CONFIRMED", NULL};
	const char *valid_conntrack_flows[] = {"ORIGINAL", "REPLY", NULL};
	const char *valid_dccp_types[] = {"REQUEST", "RESPONSE", "DATA", "ACK",
				"DATAACK", "CLOSEREQ","CLOSE", "RESET", "SYNC",
				"SYNCACK", "INVALID", NULL};
	/* List provided by iptables -p icmp --help */
	const char *icmp_types_ipv4[] = {"any",
				"echo-reply",
				"destination-unreachable",
				"network-unreachable",
				"host-unreachable",
				"protocol-unreachable",
				"port-unreachable",
				"fragmentation-needed",
				"source-route-failed",
				"network-unknown",
				"host-unknown",
				"network-prohibited",
				"host-prohibited",
				"TOS-network-unreachable",
				"TOS-host-unreachable",
				"communication-prohibited",
				"host-precedence-violation",
				"precedence-cutoff",
				"source-quench",
				"redirect",
				"network-redirect",
				"host-redirect",
				"TOS-network-redirect",
				"TOS-host-redirect",
				"echo-request",
				"router-advertisement",
				"router-solicitation",
				"time-exceeded",
				"ttl-zero-during-transit",
				"ttl-zero-during-reassembly",
				"parameter-problem",
				"ip-header-bad",
				"required-option-missing",
				"timestamp-request",
				"timestamp-reply",
				"address-mask-request",
				"address-mask-reply",
				NULL
	};

	/* List provided by ip6tables -p icmpv6 --help */
	const char *icmp_types_ipv6[] = {"destination-unreachable",
				"no-route",
				"communication-prohibited",
				"beyond-scope",
				"address-unreachable",
				"port-unreachable",
				"failed-policy",
				"reject-route",
				"packet-too-big",
				"time-exceeded",
				"ttl-exceeded",
				"ttl-zero-during-transit",
				"ttl-zero-during-reassembly",
				"parameter-problem",
				"bad-header",
				"unknown-header-type",
				"unknown-option",
				"echo-request",
				"echo-reply",
				"router-solicitation",
				"router-advertisement",
				"neighbour-solicitation",
				"neighbor-solicitation",
				"neighbour-advertisement",
				"neighbor-advertisement",
				"redirect",
				NULL
	};
	const char **icmp_types = NULL;
	char **tokens = NULL;
	bool value1 = false;
	bool value2 = false;
	int token_count = 0;

	switch (option_type) {
	/* Both AH and ESP have the same index value with optional range ':' */
	case IPTABLES_OPTION_AH:
	case IPTABLES_OPTION_ESP:
		return is_valid_range(params[0], ":", NULL, 0);
	case IPTABLES_OPTION_CONNTRACK:
		/* --ctstate has a list of states separated with ',' */
		if (option_position == IPTABLES_CONNTRACK_CTSTATE)
			return is_valid_param_sequence(valid_conntrack_states,
						params[0], ",", -1);

		/* --ctproto, protocol must be valid */
		if (option_position == IPTABLES_CONNTRACK_CTPROTO) {
			if (!g_strcmp0(params[0], "all"))
				return true;

			return is_valid_protocol(params[0]);
		}

		/*
		 * --ctorigsrc, --ctorigdst, --ctreplsrc and --ctrepldst have
		 * one address[/mask].
		 */
		if (option_position >= IPTABLES_CONNTRACK_CTORIGSRC &&
			option_position <= IPTABLES_CONNTRACK_CTREPLDST) {
			/*
			 * TODO check if option is checked twice. For now, let
			 * iptables error handling handle them.
			 */
			return validate_address_option_value(family, params[0]);
		}

		/*
		 * --ctorigsrcport, --ctorigdstport, --ctreplsrcport and
		 * --ctrepldstport support one port parameter value.
		 */
		if (option_position >= IPTABLES_CONNTRACK_CTORIGSRCPORT &&
			option_position <= IPTABLES_CONNTRACK_CTREPLDSTPORT)
			return validate_ports_or_services(protocol, params[0],
						multiport);

		/* --ctstatus, values must be separated with ',' */
		if (option_position == IPTABLES_CONNTRACK_CTSTATUS)
			return is_valid_param_sequence(valid_conntrack_status,
						params[0], ",", -1);

		/* --ctexpire has an integer or integer range ':' as sep  */
		if (option_position == IPTABLES_CONNTRACK_CTEXPIRE)
			return is_valid_range(params[0], ":", NULL, 0);

		/* --ctdir has one value only */
		if (option_position == IPTABLES_CONNTRACK_CTDIR) {
			if (!params[0])
				return false;

			return g_strv_contains(valid_conntrack_flows,
						params[0]);
		}

		break;
	case IPTABLES_OPTION_ECN:
		/* --ecn-tcp-cwr or --ecn-tcp-ece have no parameters */
		if (option_position == 0 || option_position == 1)
			return true;

		/* --ecn-ip-ect */
		if (option_position == 2) {
			/* ECN codepoint in IPv4/IPv6 header must be 0...3.*/
			if (is_string_digits(params[0])) {
				int str_digit = (int)g_ascii_strtoll(params[0],
							NULL, 10);

				if (str_digit >= 0 && str_digit <= 3)
					return true;
			}
			return false;
		}

		break;
	case IPTABLES_OPTION_DCCP:
		if (!params[0])
			return false;

		/* --dccp-types */
		if (option_position == 0)
			return is_valid_param_sequence(valid_dccp_types,
						params[0], ",", -1);

		/* --dccp-option */
		if (option_position == 1)
			return is_string_digits(params[0]);

		break;
	case IPTABLES_OPTION_OWNER:

		/* --uid-owner */
		if (option_position == 0) {
			if (getpwnam(params[0]))
				/* a user named as the string exists */
				return true;

			return is_valid_range(params[0], "-", is_correct_id, RANGE_CALLBACK_AND);
		}

		/* --gid-owner */
		if (option_position == 1) {
			if (getgrnam(params[0]))
				/* a group named as the string exists */
				return true;

			return is_valid_range(params[0], "-", NULL, 0);
		}
		/* --socket-exists has no parameters */
		if (option_position == 2)
			return true;

		break;
	case IPTABLES_OPTION_IPRANGE:
		/* --src-range or --dst-range, same verification.
		 * Currently the iprange module offers no other options,
		 * so we can check both options the same way.
		 */
		return is_valid_iprange(family, params[0]);
	case IPTABLES_OPTION_ICMPv6:
		icmp_types = icmp_types_ipv6;
	/* Fallthrough */
	case IPTABLES_OPTION_ICMP:
		if (!icmp_types)
			icmp_types = icmp_types_ipv4;

		/* ICMP types are separated with '/' and type must be checked */
		if (is_valid_pair(params[0], "/", is_icmp_int_type_valid,
					RANGE_CALLBACK_AND))
			return true;

		/* ICMP type was set as charstring */
		return g_strv_contains(icmp_types, params[0]);
	case IPTABLES_OPTION_HELPER:
		/* Iptables does not care what helper text is, can be empty. */
		return true;
	case IPTABLES_OPTION_LIMIT:
		/* --limit can have single digit or digit/postfix */
		if (option_position == 0) {
			if (!params[0])
				return false;

			tokens = g_strsplit(params[0], "/", 2);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			if (token_count == 2) {
				value1 = is_string_digits(tokens[0]);
				value2 = g_strv_contains(valid_limit_postfixes,
							tokens[1]);
			} else if (token_count == 1) {
				value1 = is_string_digits(tokens[0]);
				value2 = true;
			}

			g_strfreev(tokens);

			return value1 && value2;
		}

		/* --limit-burst can have a single digit parameter */
		if (option_position == 1)
			return is_string_digits(params[0]);

		break;
	case IPTABLES_OPTION_MARK:
		/*
		 * --mark has value/mask syntax and supports decimal,
		 * hexadecimal and TODO: octal.
		 */
		return is_valid_pair(params[0], "/", is_string_hexadecimal,
					RANGE_CALLBACK_OR);
	/*
	 * TODO: MH protocol support is not working, protocol specific options
	 * are not added properly to iptables. For this reason, the MH options
	 * are disabled as the option is omitted from the added rule, which is
	 * impossible to remove using the added rule containing these options.
	 */
	case IPTABLES_OPTION_MH:
		return false;
	case IPTABLES_OPTION_MULTIPORT:
	case IPTABLES_OPTION_PORT:
		return validate_ports_or_services(protocol, params[0],
					multiport);
	case IPTABLES_OPTION_PKTTYPE:
		if (!params[0])
			return false;

		return g_strv_contains(valid_pkttypes, params[0]);
	/*
	 * TODO: SCTP protocol support is not working, protocol specific options
	 * are not added properly to iptables. For this reason, the SCTP options
	 * are disabled as the option is omitted from the added rule, which is
	 * impossible to remove using the added rule containing these options.
	 */
	case IPTABLES_OPTION_SCTP:
		return false;
	case IPTABLES_OPTION_TCP:
		/* --tcp-flags */
		if (option_position == 0) {
			/* Two must be set */
			if (!is_valid_param_sequence(valid_tcp_flags, params[0],
						",", 8))
				return false;

			return is_valid_param_sequence(valid_tcp_flags,
						params[1], ",", 8);
		}

		/* --syn has no parameters */
		if (option_position == 1)
			return true;

		/* --tcp-option */
		if (option_position == 2) {
			/* Must be int */
			return is_string_digits(params[0]);
		}

		break;
	case IPTABLES_OPTION_TTL:
		/* Each option requires a single value */
		return is_string_digits(params[0]);
	case IPTABLES_OPTION_GRE: /* Protocol GRE has no parameters */
		/* fall through */
	case IPTABLES_OPTION_NOT_SUPPORTED:
		break;
	}

	return false;
}

static bool is_protocol_str_match(const char *protocol_str_int,
			const char *protocol_str)
{
	struct protoent *p;
	int proto_int;

	if (!protocol_str || !protocol_str_int)
		return false;

	if (!is_string_digits(protocol_str_int))
		return false;

	proto_int = (int)g_ascii_strtoll(protocol_str_int, NULL, 10);
	p = getprotobyname(protocol_str);

	return p && p->p_proto == proto_int;
}

static bool is_valid_option_for_protocol_match(const char* protocol,
			const char* match,
			enum iptables_match_options_type type)
{
	struct protoent *p;
	const char *port_protocols[] = {"tcp", "udp", "udplite", "sctp", "dccp",
				NULL};
	const char *icmp_ipv6[] = { "icmpv6", "ipv6-icmp", NULL };
	bool protocol_found = false;
	bool match_found = false;
	int proto_int = 0;
	int i;

	switch (type) {
	case IPTABLES_OPTION_AH:
		if (is_string_digits(protocol))
			protocol_found = is_protocol_str_match(protocol, "ah");
		else
			protocol_found = protocol &&
						!g_ascii_strcasecmp(protocol,
						"ah");

		return protocol_found && !g_strcmp0(match, "ah");
	case IPTABLES_OPTION_ESP:
		if (is_string_digits(protocol))
			protocol_found = is_protocol_str_match(protocol, "esp");
		else
			protocol_found = protocol &&
						!g_ascii_strcasecmp(protocol,
						"esp");

		return protocol_found && !g_strcmp0(match, "esp");
	case IPTABLES_OPTION_CONNTRACK:
		return !g_strcmp0(match, "conntrack");
	case IPTABLES_OPTION_DCCP:
		if (!g_strcmp0(match, "dccp")) /* Match cannot be dccp */
			return false;

		if (is_string_digits(protocol))
			return is_protocol_str_match(protocol, "dccp");

		return protocol && !g_ascii_strcasecmp(protocol, "dccp");
	case IPTABLES_OPTION_ECN:
		if (g_strcmp0(match, "ecn"))
			return false;

		match_found = true;
	/* Fallthrough, ECN match needs TCP protocol */
	case IPTABLES_OPTION_TCP:
		if (is_string_digits(protocol)) {
			if (is_protocol_str_match(protocol, "tcp"))
				protocol_found = true;
			else
				return false;
		} else {
			if (protocol && !g_ascii_strcasecmp(protocol, "tcp"))
				protocol_found = true;
			else
				return false;
		}

		if (!match_found && !g_strcmp0(match, "tcp"))
			match_found = true;

		return protocol_found && match_found;
	case IPTABLES_OPTION_HELPER:
		return !g_strcmp0(match, "helper");
	case IPTABLES_OPTION_ICMP:
		return !g_strcmp0(match, "icmp");
	case IPTABLES_OPTION_ICMPv6:
		return g_strv_contains(icmp_ipv6, match);
	case IPTABLES_OPTION_LIMIT:
		return !g_strcmp0(match, "limit");
	case IPTABLES_OPTION_MARK:
		return !g_strcmp0(match, "mark");
	case IPTABLES_OPTION_MH:
		return false; /* MH options not supported */
	case IPTABLES_OPTION_OWNER:
		return !g_strcmp0(match, "owner");
	case IPTABLES_OPTION_IPRANGE:
		return !g_strcmp0(match, "iprange");
	case IPTABLES_OPTION_MULTIPORT:
		/* Match must be -m multiport for multiport options */
		if (g_strcmp0(match, "multiport"))
			return false;

		match_found = true;
	/* Fallthrough */
	case IPTABLES_OPTION_PORT:
		/*
		 * -p sctp -m sctp is not supported and -m sctp is ignored in
		 * earlier checks so it is safe to set match as found if the
		 * protocol is SCTP. Same with protocol DCCP.
		 */
		if (protocol && (!g_ascii_strcasecmp(protocol, "sctp") ||
					!g_ascii_strcasecmp(protocol, "dccp")))
			match_found = true;

		if (is_string_digits(protocol))
			proto_int = (int)g_ascii_strtoll(protocol, NULL, 10);

		/*
		 * Port options do not work with iptables.c if they do not have
		 * both match and protocol set */
		for (i = 0; port_protocols[i]; i++) {
			if (!protocol_found) {
				if (proto_int) {
					p = getprotobyname(port_protocols[i]);

					if (!p)
						continue;

					if (p->p_proto == proto_int)
						protocol_found = true;

					/*
					 * Set match to found if SCTP is the
					 * protocol defined with integer.
					 */
					if (!g_strcmp0(port_protocols[i],
							"sctp") ||
						!g_strcmp0(port_protocols[i],
							"dccp"))
						match_found = true;
				} else if (protocol && !g_ascii_strcasecmp(
							port_protocols[i],
							protocol)) {
					protocol_found = true;
				}
			}

			if (!match_found &&
					!g_strcmp0(port_protocols[i], match))
					match_found = true;
		}

		return protocol_found && match_found;
	case IPTABLES_OPTION_PKTTYPE:
		return !g_strcmp0(match, "pkttype");
	case IPTABLES_OPTION_SCTP:
		return false; /* SCTP options not supported */
	case IPTABLES_OPTION_TTL:
		return !g_strcmp0(match, "ttl");
	case IPTABLES_OPTION_GRE: /* GRE protocol has no options */
		/* fall through */
	case IPTABLES_OPTION_NOT_SUPPORTED:
		return false;
	}

	return false;
}

static bool is_supported(int family, enum iptables_switch_type switch_type,
					const char *str)
{
	/*
	 * The switches and matches that are not supported.
	 *
	 * Chain manipulation is not supported, the rules are going to specific
	 * managed chains within connman.
	 *
	 * Setting specific addresses is not supported because the purpose of
	 * these rules is to set the base line of prevention to be used on both
	 * IPv4 and IPv6. In the future rules may be separated to have own for
	 * both of the IP protocols.
	.*
	 * Setting specific interfaces is not supported for dynamic rules, these
	 * are added dynamically into the rules when interface comes up. For
	 * General rules setting interfaces is allowed.
	 */
	const char *not_supported_switches[] = {"--append", "-A",
						"--delete", "-D",
						"--delete-chain", "-X",
						"--flush", "-F",
						"--insert", "-I",
						"--new-chain", "-N",
						"--policy", "-P",
						"--rename-chain", "-E",
						"--replace", "-R",
						"--zero", "-Z",
						"--to-destination",
						"--from-destination",
						"--ipv4", "-4",
						"--ipv6", "-6",
						"-f", "--fragment",
						NULL
	};

	const char *not_supported_matches_ipv4[] = { "comment",
						"state",
						"recent",
						"sctp",
						"mh",
						"hashlimit",
						"frag",
						"icmpv6",
						"ipv6-icmp",
						NULL
	};
	const char *not_supported_matches_ipv6[] = { "comment",
						"state",
						"recent",
						"ttl",
						"sctp",
						"mh",
						"hashlimit",
						"frag",
						"icmp",
						NULL
	};

	const char **not_supported_matches = NULL;

	/* Protocols that iptables supports with -p or --protocol switch */
	const char *supported_protocols_ipv4[] = { "tcp",
						"udp",
						"udplite",
						"icmp",
						"esp",
						"ah",
						"sctp",
						"dccp",
						"gre",
						"all",
						NULL
	};

	/* Protocols that iptables supports with -p or --protocol switch */
	const char *supported_protocols_ipv6[] = { "tcp",
						"udp",
						"udplite",
						"icmpv6",
						"ipv6-icmp",
						"esp",
						"ah",
						"sctp",
						"mh",
						"dccp",
						"gre",
						"all",
						NULL
	};

	const char **supported_protocols = NULL;

	/*
	 * Targets that are supported. No targets to custom chains are
	 * allowed
	 */
	const char *supported_targets[] = { "ACCEPT",
						"DROP",
						"REJECT",
						"LOG",
						"QUEUE",
						NULL
	};

	int i = 0;

	/* Do not care about empty or nonexistent content */
	if (!str || !*str)
		return true;

	switch (family) {
	case AF_INET:
		not_supported_matches = not_supported_matches_ipv4;
		supported_protocols = supported_protocols_ipv4;
		break;
	case AF_INET6:
		not_supported_matches = not_supported_matches_ipv6;
		supported_protocols = supported_protocols_ipv6;
		break;
	default:
		return false;
	}

	switch (switch_type) {
	case IPTABLES_SWITCH:
		return !g_strv_contains(not_supported_switches, str);
	case IPTABLES_MATCH:
		return !g_strv_contains(not_supported_matches, str);
	case IPTABLES_TARGET:
		return g_strv_contains(supported_targets, str);
	case IPTABLES_PROTO:
		for (i = 0; supported_protocols[i]; i++) {
			/* Protocols can be also capitalized */
			if (!g_ascii_strcasecmp(str, supported_protocols[i]))
				return true;

			/* Protocols can be defined by their number. */
			if (is_protocol_str_match(str, supported_protocols[i]))
				return true;
		}

		return false;
	case IPTABLES_PORT: /* Fallthrough, checked with port options */
	case IPTABLES_OPTION: /* Fallthrough, options are checked elsewhere */
		return true;
	case IPTABLES_INTERFACE:
		return true;
	case IPTABLES_IPADDR:
		/* Multiple addresses can be defined */
		return validate_addresses(family, str);
	case IPTABLES_UNSET:
		break;
	}

	return false;
}

enum icmp_check_result {
			NOT_ICMP = 0,
			VALID_ICMP,
			INVALID_ICMP,
};

static enum icmp_check_result is_icmp_proto_or_match(int family,
			const char *proto_or_match)
{
	const char *icmp_ipv4[] = { "icmp", NULL };
	const char *icmp_ipv6[] = { "icmpv6", "ipv6-icmp", NULL };

	if (!proto_or_match || !*proto_or_match)
		return NOT_ICMP;

	switch (family) {
	case AF_INET:
		if (g_strv_contains(icmp_ipv4, proto_or_match))
			return VALID_ICMP;

		/* IPv4 cannot use IPv6 ICMP types */
		if (g_strv_contains(icmp_ipv6, proto_or_match))
			return INVALID_ICMP;
		break;
	case AF_INET6:
		if (g_strv_contains(icmp_ipv6, proto_or_match))
			return VALID_ICMP;

		/* IPv4 cannot use IPv6 ICMP types */
		if (g_strv_contains(icmp_ipv4, proto_or_match))
			return INVALID_ICMP;
	}

	return NOT_ICMP;
}

static bool protocol_match_equals(int family, const char *protocol,
			const char *match)
{
	struct protoent *p;
	int i;

	if (!protocol || !match)
		return false;

	/* Matches cannot be integers, matches are case sensitive */
	if (is_string_digits(match))
		return false;

	/* Protocols are not case sensitive */
	if (!g_ascii_strcasecmp(protocol, match))
		return true;

	/*
	 * ICMP matches are a special case, if protocol is ICMP match must be
	 * also valid ICMP for the type. Protocol "icmpv6" is not found with
	 * getprotobyname() but is understood by iptables.
	*/
	switch (is_icmp_proto_or_match(family, protocol)) {
	case NOT_ICMP:
		break; // Is not ICMP protocol
	case VALID_ICMP:
		return is_icmp_proto_or_match(family, match);
	case INVALID_ICMP:
		return false;
	}

	/* Check if it is valid protocol */
	p = get_protocol_protoent(protocol);

	if (!p)
		return false;

	/* Protocol official name equals */
	if (!g_ascii_strcasecmp(p->p_name, match))
		return true;

	/* If ICMP protocol was defined as integer */
	switch (is_icmp_proto_or_match(family, p->p_name)) {
	case NOT_ICMP:
		break; // Is not ICMP protocol
	case VALID_ICMP:
		return is_icmp_proto_or_match(family, match);
	case INVALID_ICMP:
		return false;
	}

	/* Check if it is one of the aliases */
	for (i = 0; p->p_aliases && p->p_aliases[i]; i++) {
		/* Protocols can be also capitalized */
		if (!g_ascii_strcasecmp(p->p_aliases[i], match))
			return true;
	}

	return false;
}

static bool is_valid_prefix(const char prefix)
{
	/* Only '-' and negation prefixed rules are allowed in iptables. */
	char valid_prefixes[] = "-!";

	return !!strchr(valid_prefixes, prefix);
}

bool __connman_iptables_validate_rule(int family, bool allow_dynamic,
			const char *rule_spec)
{
	gchar **argv = NULL;
	GError *error = NULL;
	bool ret = false;
	int i = 0;
	int argc = 0;
	int port_option_index = 0;
	bool multiport_used = false;
	unsigned int switch_types_found[MAX_IPTABLES_SWITCH] = { 0 };
	enum iptables_switch_type switch_type = IPTABLES_UNSET;
	const char *arg = NULL;
	const char *opt = NULL;
	const char *protocol = NULL;
	const char *match = NULL;
	const char *interface = NULL;
	const char *address_option = NULL;

	if (!g_shell_parse_argv(rule_spec, &argc, &argv, &error)) {
		DBG("failed in parsing %s", error ? error->message : "");
		goto out;
	}

	/* -j TARGET is the bare minimum of a rule */
	if (argc < 2 || !argv[0][0]) {
		DBG("parsed content is invalid");
		goto out;
	}

	if (!is_valid_prefix(argv[0][0])) {
		DBG("invalid rule prefix");
		goto out;
	}

	for (i = 0; i < argc; ) {
		arg = argv[i++];

		if (!is_valid_prefix(arg[0])) {
			DBG("prefix for %s is not valid, invalid rule %s", arg,
						rule_spec);
			goto out;
		}

		if (!is_supported(family, IPTABLES_SWITCH, arg)) {
			DBG("switch %s is not supported", arg);
			goto out;
		}

		if (!g_strcmp0(arg, "-m") || !g_strcmp0(arg, "--match")) {
			switch_type = IPTABLES_MATCH;
			opt = argv[i++];

			if (!opt)
				goto trailing;

			/* Negation cannot be used after -m/--match */
			if (!g_strcmp0(opt, "!"))
				goto negation_failure;

			DBG("match %s", opt);

			/* multiport match has to have valid port switches */
			if (!g_strcmp0(opt, "multiport")) {
				multiport_used = true;
				
				/* Cannot use -m multiport with -m protocol */
				if (match) {
					DBG("-m multiport with -m %s", match);
					goto out;
				}
			/* If this is one of the supported protocols */
			} else if (is_supported(family, IPTABLES_PROTO, opt)) {
				/*
				 * If no protocol is set before, protocol match
				 * cannot be used
				 */
				if (!switch_types_found[IPTABLES_PROTO]) {
					DBG("-m %s without -p protocol", opt);
					goto out;
				}

				/*
				 * SCTP protocol -m sctp, MH protocol -m mh and
				 * DCCP protocol -m dccp cannot be used because
				 * because iptables gives error (commit/quit)
				 * with these.
				 */
				if (!g_strcmp0(opt, "sctp") ||
					!g_strcmp0(opt, "mh") ||
					!g_strcmp0(opt, "dccp")) {
					DBG("-m %s is not supported", opt);
					goto out;
				}

				/* Check if match protocol equals */
				if (!protocol_match_equals(family, protocol,
							opt)) {
					DBG("-p %s -m %s different protocol",
								protocol, opt);
					goto out;
				}

				if (multiport_used) {
					DBG("-m multiport -m %s not supported",
							opt);
					goto out;
				}
			}

			/* Save match for multiport and option checks.*/
			match = argv[i-1];
		} else if (!g_strcmp0(arg, "-j") || !g_strcmp0(arg, "--jump") ||
					!g_strcmp0(arg, "-g") ||
					!g_strcmp0(arg, "--goto")) {
			switch_type = IPTABLES_TARGET;
			opt = argv[i++];

			if (!opt)
				goto trailing;

			DBG("target %s", opt);
		} else if (!g_strcmp0(arg, "-p") ||
					!g_strcmp0(arg, "--protocol")) {
			switch_type = IPTABLES_PROTO;
			opt = argv[i++];

			if (!opt)
				goto trailing;

			/* Save the protocol for -m switch check */
			protocol = argv[i-1];
			DBG("protocol %s", opt);
		} else if (allow_dynamic &&
					is_in_supported_dynamic_switches(arg)) {
			/* Check if one switch has been defined already */
			if (interface && is_interface_option_same_group(
						interface, arg)) {
				DBG("duplicate dynamic switch in %s",
							rule_spec);
				goto out;
			} else {
				interface = arg;
			}

			switch_type = IPTABLES_INTERFACE;
			opt = argv[i++];

			if (!opt)
				goto trailing;

			if (!g_strcmp0(opt, "!"))
				goto negation_failure;
		} else if (is_address_option(arg)) {
			if (address_option && is_address_option_same_direction(
						arg, address_option)) {
				DBG("duplicate address option in %s",
							rule_spec);
				goto out;
			}

			address_option = arg;

			switch_type = IPTABLES_IPADDR;
			opt = argv[i++];

			if (!opt)
				goto trailing;

			if (!g_strcmp0(opt, "!"))
				goto negation_failure;

			DBG("address %s %s", arg, opt);
		} else if (g_str_has_prefix(arg, "--")) {
			enum iptables_match_options_type option_type;
			int option_type_params = 0;
			int option_type_position = 0;
			int opt_index;
			const char *params[IPTABLES_OPTION_COUNT_MAX] =
						{NULL, NULL};

			switch_type = IPTABLES_OPTION;

			/*
			 * Port switches must be recorded. 2 is max and they
			 * must be different direction switches. With multiport
			 * the --port and --ports can be used only once.
			 */
			if (is_port_option(arg, multiport_used)) {
				/* One port option switch is set */
				if (port_option_index) {
					if (multiport_used) {
						DBG("multiport cannot have more"
							"than one port option");
						goto out;
					}

					if (is_port_option_same_group(
						argv[port_option_index], arg)) {
						DBG("port option %s defined "
							"twice", arg);
						goto out;
					}
				} else {
					port_option_index = i-1;
					DBG("port option %s", arg);
				}
				switch_type = IPTABLES_PORT;
			} else {
				DBG("option %s", arg);
			}

			option_type = validate_option_type(protocol, match, arg,
				&option_type_params,&option_type_position,
				multiport_used);

			if (option_type == IPTABLES_OPTION_NOT_SUPPORTED) {
				DBG("%s is not supported", arg);
				goto out;
			}

			if (!is_valid_option_for_protocol_match(protocol, match,
						option_type)) {
				DBG("option %s does not work with protocol %s "
						"match %s", arg, protocol,
						match);
				goto out;
			}

			for (opt_index = 0; opt_index < option_type_params &&
					opt_index < IPTABLES_OPTION_COUNT_MAX;
					opt_index++) {
				/* Negations cannot be as option parameters */
				if (!g_strcmp0(argv[i], "!"))
					goto negation_failure;

				params[opt_index] = argv[i++];
			}

			if (!is_valid_option_type_params(family, option_type,
						protocol,
						params,
						option_type_position,
						multiport_used))
			{
				DBG("option %s has invalid params %s %s",
							arg, params[0],
							params[1]);
				goto out;
			}
		} else if (!g_strcmp0(arg, "!")) {
			continue;
		} else {
			DBG("non supported switch %s in rule %s", arg,
						rule_spec);
			goto out;
		}

		if (opt && !is_supported(family, switch_type, opt)) {
			DBG("%s %s is not supported", arg, opt);
			goto out;
		}

		/* Record the current switch type */
		switch_types_found[switch_type]++;
		switch_type = IPTABLES_UNSET;
		opt = NULL;
	}

	if (switch_types_found[IPTABLES_IPADDR] > 2)
		goto out;

	/* With Genral rules dynamic options are allowed, max two (in + out) */
	if (allow_dynamic && switch_types_found[IPTABLES_INTERFACE] > 2)
		goto out;

	if (multiport_used) {
		/* Multiport has to has one port option. */
		if (switch_types_found[IPTABLES_PORT] != 1)
			goto out;
	} else {
		/* There can be 0...2 port switches in rule */
		if (switch_types_found[IPTABLES_PORT] > 2)
			goto out;
	}

	/* There should be 0...2 matches in one rule */
	if (switch_types_found[IPTABLES_MATCH] > 2)
		goto out;
	
	/*
	 * If there are matches used, there must be options for it. There can
	 * be two matches and options are set only for one of them. Port options
	 * are accounted for as well.
	 */
	if (switch_types_found[IPTABLES_MATCH] &&
				!switch_types_found[IPTABLES_PORT] &&
				!switch_types_found[IPTABLES_OPTION]) {
		DBG("rule has match(es) but not options");
		goto out;
	}

	/* There should be 0...1 protocols defined in rule */
	if (switch_types_found[IPTABLES_PROTO] > 1)
		goto out;

	/* There has to be exactly one target in rule */
	if (switch_types_found[IPTABLES_TARGET] != 1)
		goto out;

	ret = true;

out:
	g_clear_error(&error);
	g_strfreev(argv);

	return ret;

negation_failure:
	DBG("improper use of negation in %s", rule_spec);
	goto out;

trailing:
	DBG("trailing '%s' in rule \"%s\"", arg, rule_spec);
	goto out;
}


void __connman_iptables_validate_init(void)
{
	DBG("");

	initialize_iptables_options();
}

void __connman_iptables_validate_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(iptables_options);
	iptables_options = NULL;
}
