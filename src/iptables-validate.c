/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013,2015  BMW Car IT GmbH.
 *  Copyright (C) 2018,2019  Jolla Ltd.
 *  Copyright (C) 2019  Open Mobile Platform LLC.
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
#include <net/if.h>

#include "connman.h"

struct validator_data {
	int family;
	GHashTable *ipt_options;
	GSList *invoked;
	GSList *invoked_match;
	uint16_t invoked_proto;
};

typedef bool (*opt_handler_t)(struct validator_data *data, gchar **args);

struct ipt_option_entry {
	const gchar	*opt_name;
	gint		arg_count;
	gboolean	allow_neg;
	const gchar	*unique_id;

	opt_handler_t	opt_handler;
};

struct match_option_entry {
	const gchar			*match_name;
	int				family_dep;
	uint16_t			proto_dep;
	const struct ipt_option_entry	*opts_enabled;

	opt_handler_t			opt_handler;
};

typedef bool (*range_validation_cb_t)(const char *param);

struct match_invoked_dep {
	const gchar	*match_name;
	const gchar	*option_name;
};

enum range_callback_operation {
	RANGE_CALLBACK_OR = 0,
	RANGE_CALLBACK_AND,
};

/*
 * The validator_data is a single struct used for parsing a full single line
 * of iptables options. Parsing happens in a left-to-right order, and there are
 * many options that are only valid after a particular match (-m match) was
 * specified. When that happens, the validator_data.ipt_option hash table
 * is extended with option => ipt_option_entry* key-value. The known_matches
 * array specifies which array(s) of ipt_option_entries are added
 * on a particular match invocation, and for which family/protocol it happens.
 * There's also a basic_options array that are added on startup.
 *
 * The ipt_option_entry for a long (--protocol) and short (-p) options
 * are separate, but mostly share a unique_id string, which serves as a flag
 * added to validator_data.invoked. This allows to verify that an option is not
 * used more than once. Some options are mutually-exclusive. It is common
 * to give them the same unique_id.
 *
 * If the same "-m match" is invoked on the command line again, this is a valid
 * scenario, but means that all of the match-specific options that happened
 * prior to the second "-m match" invocation are the first one's parameters,
 * and match-specific options coming after the second "-m match" applies
 * to the second match. Eg.
 * iptables -A INPUT -p tcp -m multiport --dports 80 --destination 10.0.0.1 \
 *          -m multiport --sports 1024:2048 --source 1.1.1.1 -j ACCEPT
 *
 * Here, --dports applies to the first -m multiport invocation, while
 * --sports apply to the second one. --destination and --source are options
 * that are unrelated to -m multiport, therefore can happen anywhere.
 *
 * To allow such scenarios, the validator_data.invoked_match flag is used
 * to store previously issued -m options. When another instance of the same
 * match appears, the validator.invoked list is cleaned of the options
 * that applied to the first instance. Since some of the -m matches require
 * some of its options to appear on the command line, a verification
 * is performed with the use of match_deps array. It specifies which flag
 * needs to appear in validator_data.invoked for the match dependency to be
 * satisfied. The same verification happens after all arguments are parsed.
 *
 * The ipt_option_entry also specifies how many arguments the option takes,
 * and thus treats the next options as arguments for that one. Eg.
 * iptables -A INPUT -p tcp -m tcp --tcp-flags --source 10.0.0.8 -j ACCEPT
 * will make "--source" the 1st argument to --tcp-flags, and "10.0.0.8"
 * the 2nd one, thus producing errors for incorrect arguments.
 *
 * There's also a allow_neg bool, which specifies if there can be a ! negation
 * in front of the argument. iptables only uses these negations before
 * the option, never as part of the argument.
 *
 * The opt_handler of an ipt_option_entry is called when the option appears
 * on the command line. It is mostly used to verify the syntax
 * of the arguments, though it may also set flags in validator_data.invoked,
 * used to collectively check the match dependency is met (see eg.
 * the conntrack match handlers).
 */
static void add_iptables_options(struct validator_data *data,
				 const struct ipt_option_entry *new_options)
{
	char *option_name;
	struct ipt_option_entry *option_p;

	// discard the const qualifier
	option_p = (struct ipt_option_entry *) new_options;

	// last array element has a NULL value in all fields
	for (; option_p->opt_name; option_p++) {
		// discard the const qualifier
		option_name = (char *) option_p->opt_name;
		g_hash_table_replace(data->ipt_options, option_name, option_p);
	}
}

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

/*
 * The specalias_* structs come from xtables.c, were named xtables_*
 * Here used only for special alias names, supported by iptables,
 * but not resolvable with getprotobyname()
 */
struct specalias_pprot {
	const char *name;
	uint8_t num;
};

static const struct specalias_pprot specalias_chain_protos[] = {
// ipv6-icmp as referenced in /etc/protocols
	{"icmpv6",	IPPROTO_ICMPV6},
// mobility-header as referenced in /etc/protocols
	{"ipv6-mh",	IPPROTO_MH},
	{"mh",		IPPROTO_MH},
	{"all",		0},
	{NULL,		0},
};

// heavily inspired on xtables_parse_protocol from xtables.c
static uint16_t resolve_protocol(const char *protoname)
{
	const struct protoent *pent;
	unsigned int i;
	gchar *s;
	uint16_t retval = UINT16_MAX;

	if (is_string_digits(protoname))
		return g_ascii_strtoull(protoname, &s, 10);

	/*
	 * Some protocol names won't resolve in all-lowercase
	 * eg. IP-ENCAP, a proto alias for ipencap will not resolve as ip-encap
	 */
	pent = getprotobyname(protoname);
	if (pent)
		return pent->p_proto;

	s = g_ascii_strdown(protoname, -1);
	if (!s)
		return UINT16_MAX;

	for (i = 0; specalias_chain_protos[i].name; i++)
		if (!g_strcmp0(s, specalias_chain_protos[i].name)) {
			retval = specalias_chain_protos[i].num;
			goto out;
		}

	pent = getprotobyname(s);
	if (pent)
		retval = pent->p_proto;

out:
	g_free(s);

	return retval;

}

static bool is_valid_port_or_service(const char *protocol,
			const char *port_or_service,
			uint16_t *port)
{
	struct servent *s;
	gint64 portnum;

	/* Plain digits, check if port is valid */
	if (is_string_digits(port_or_service)) {
		/* Valid port number */
		portnum = g_ascii_strtoll(port_or_service, NULL, 10);
		if (portnum > G_MAXUINT16)
			return false;

		if (port)
			*port = (uint16_t) portnum;

		return true;
	}

	/* Check if service name is valid with any protocol */
	s = getservbyname(port_or_service, protocol);
	if (!s)
		return false;
	/*
	 * Port numbers are 16bit integers but struct servent
	 * contains them as regular (32bit) integers. The value
	 * is set with htons() to s_port in network byte order.
	 */
	if (port)
		*port = ntohs(s->s_port);

	return true;
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
		for (i = 0; i < 2; i++) {
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

static bool is_valid_netmask(int family, const char *netmask)
{
	int cidr_len = 0;
	gint64 cidr_max = 0;

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

		return strlen(netmask) <= cidr_len && g_ascii_strtoll(
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

static bool is_icmp_int_type_valid(const char *icmp_type)
{
	gint64 icmp_num;

	icmp_num = g_ascii_strtoll(icmp_type, NULL, 10);

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

	if (!elem)
		return false;

	if (is_string_digits(elem)) {
		numeric = true;
	}

	/* We could skip the callback if numeric is enough */
	if (numeric && operation == RANGE_CALLBACK_OR)
		return true;

	/* Either numeric was false or operation was AND. Run callback. */
	if (numeric || operation == RANGE_CALLBACK_OR) {

		if (cb && cb(elem))
			return true;
	}

	/* The last scenario - numeric false, operation AND - result in false */
	return false;
}

static bool is_valid_range(const char *range, const char *separator,
			range_validation_cb_t cb,
			enum range_callback_operation operation)
{
	gchar **tokens = NULL;
	bool numeric = false;
	bool result = false;
	guint64 value1, value2;

	if (is_valid_elem(range, cb, operation))
		return true;

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
		errno = 0;
		value1 = g_ascii_strtoull(tokens[0], NULL, 10);
		if (errno)
			goto range_check_string;

		value2 = g_ascii_strtoull(tokens[1], NULL, 10);
		if (errno)
			goto range_check_string;

		/* Essential condition - values come in ascending order */
		if (value1 <= value2)
			numeric = true;
	} /* else numeric = false, set on startup */

range_check_string:

	/* We could skip the callback if numeric is enough */
	if (numeric && operation == RANGE_CALLBACK_OR) {
		result = true;
	} else if (numeric || operation == RANGE_CALLBACK_OR) {
		if (cb && cb(tokens[0]) && cb(tokens[1]))
			result = true;
	}

	/* The last scenario - numeric false, operation AND - result in false */

range_free_tokens:

	g_strfreev(tokens);

	return result;
}

static bool is_valid_param_sequence(const char **haystack, const char *needles,
			const char *needle_separator, int max_tokens)
{
	char **tokens;
	bool value = false;
	int token_count;
	int i;

	if (!haystack || !needles || !needle_separator)
		return value;

	tokens = g_strsplit(needles, needle_separator, max_tokens);

	if (!tokens)
		return value;

	token_count = g_strv_length(tokens);

	for (i = 0; i < token_count; i++) {
		if (!(value = g_strv_contains(haystack, tokens[i])))
			break;
	}

	g_strfreev(tokens);

	return value;
}

/*
 * [!] --source-port port[:port]
 *  --sport ...
 *                                 match source port(s)
 * [!] --destination-port port[:port]
 *  --dport ...
 *                                 match destination port(s)
*/
static bool handle_port(struct validator_data *data, gchar **args)
{
	uint16_t port;
	struct protoent *p;
	char *protoname = NULL;

	if (data->invoked_proto) {
		p = getprotobynumber(data->invoked_proto);
		if (p)
			protoname = p->p_name;
	}

	return is_valid_port_or_service(protoname, args[0], &port) ||
		is_valid_port_or_service_range(protoname, args[0]);
}

static const struct ipt_option_entry port_options[] = {
	{ "--destination-port", 1, true, "dport", handle_port },
	{ "--dport", 1, true, "dport", handle_port },
	{ "--source-port", 1, true, "sport", handle_port },
	{ "--sport", 1, true, "sport", handle_port },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * multiport match options:
 * [!] --source-ports port[,port:port,port...]
 *  --sports ...
 *                                 match source port(s)
 * [!] --destination-ports port[,port:port,port...]
 *  --dports ...
 *                                 match destination port(s)
 * [!] --ports port[,port:port,port]
 *                                 match both source and destination port(s)
*/
static bool handle_ports(struct validator_data *data, gchar **args)
{
	struct protoent *p;
	char *protoname = NULL;
	gchar **tokens = NULL;
	int token_count;

	 /* In iptables ports are separated with commas, ranges with colon. */
	const char delimeter[] = ",";
	bool ret = true;
	int i;

	p = getprotobynumber(data->invoked_proto);
	if (p)
		protoname = p->p_name;

	tokens = g_strsplit(args[0], delimeter, 0);

	if (!tokens)
		return false;

	token_count = g_strv_length(tokens);
	if (token_count < 1)
		ret = false;

	for (i = 0; i < token_count; i++) {
		/*
		 * If ':' exists it is a range. Check that only one ':' exists
		 * and the port range is specified correctly
		 */
		if (strstr(tokens[i], ":")) {
			if (is_valid_port_or_service_range(protoname, tokens[i]))
				continue;
		} else {
			if (is_valid_port_or_service(protoname, tokens[i], NULL))
				continue;
		}

		/* If one of the ports/services is invalid, rule is invalid */
		ret = false;
		DBG("invalid port/service %s in %s", tokens[i], args[0]);
		break;
	}

	g_strfreev(tokens);

	return ret;
}

static const struct ipt_option_entry multiport_match_options[] = {
	{ "--destination-ports", 1, true, "ports", handle_ports },
	{ "--dports", 1, true, "ports", handle_ports },
	{ "--source-ports", 1, true, "ports", handle_ports },
	{ "--sports", 1, true, "ports", handle_ports },
	{ "--ports", 1, true, "ports", handle_ports },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * tcp match options:
 * [!] --tcp-flags mask comp	match when TCP flags & mask == comp
 * 				(Flags: SYN ACK FIN RST URG PSH ALL NONE)
 * [!] --syn	match when only SYN flag set
 * 				(equivalent to --tcp-flags SYN,RST,ACK,FIN SYN)
 * 				match destination port(s)
 * [!] --tcp-option number	match if TCP option set
*/
static bool handle_tcp_flags(struct validator_data *data, gchar **args)
{
	const char *valid_tcp_flags[] = {"SYN", "ACK", "FIN", "RST", "URG",
				"PSH", "ALL", "NONE", NULL};

	/* Two must be set */
	if (!is_valid_param_sequence(valid_tcp_flags, args[0], ",", 8))
		return false;

	return is_valid_param_sequence(valid_tcp_flags,	args[1], ",", 8);
}

static bool handle_tcp_option(struct validator_data *data, gchar **args)
{
	return is_string_digits(args[0]);
}

static const struct ipt_option_entry tcp_proto_options[] = {
	{ "--tcp-flags", 2, true, "tcp-flags", handle_tcp_flags },
	{ "--syn", 0, true, "syn", NULL },
	{ "--tcp-option", 1, true, "tcp-option", handle_tcp_option },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * mark match options:
 * [!] --mark value[/mask]	Match nfmark value with optional mask
*/
static bool handle_mark(struct validator_data *data, gchar **args)
{
	/*
	 * --mark has value/mask syntax and supports decimal,
	 * hexadecimal and TODO: octal.
	 */
	return is_valid_pair(args[0], "/", is_string_hexadecimal,
				RANGE_CALLBACK_OR);
}

static const struct ipt_option_entry mark_match_options[] = {
	{ "--mark", 1, true, "mark", handle_mark },
	{ NULL, 0, false, NULL, NULL }
};

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

static bool add_ct_invoked_marker(struct validator_data *data, gchar **args)
{
	if (!g_slist_find_custom(data->invoked, "conntrack-option",
						(GCompareFunc) g_strcmp0))
		data->invoked = g_slist_prepend(data->invoked,
							 "conntrack-option");

	return true;
}

static bool handle_ctstate(struct validator_data *data, gchar **args)
{
	/* --ctstate has a list of states separated with ',' */
	const char *valid_conntrack_states[] = {"INVALID", "ESTABLISHED", "NEW",
				"RELATED", "UNTRACKED", "SNAT", "DNAT", NULL};

	add_ct_invoked_marker(data, args);

	return is_valid_param_sequence(valid_conntrack_states,
						args[0], ",", -1);
}

static bool handle_ctproto(struct validator_data *data, gchar **args)
{
	add_ct_invoked_marker(data, args);

	return resolve_protocol(args[0]) < UINT8_MAX;
}

static bool handle_ct_address(struct validator_data *data, gchar **args)
{
	/*
	 * TODO check if option is checked twice. For now, let
	 * iptables error handling handle them.
	 */
	add_ct_invoked_marker(data, args);

	return validate_address_option_value(data->family, args[0]);
}

static bool handle_ct_port(struct validator_data *data, gchar **args)
{
	add_ct_invoked_marker(data, args);

	// Same verification as that of --dport/--sport
	return handle_port(data, args);
}

static bool handle_ctstatus(struct validator_data *data, gchar **args)
{
	/* --ctstatus, values must be separated with ',' */
	const char *valid_conntrack_status[] = {"NONE", "EXPECTED",
				"SEEN_REPLY", "ASSURED", "CONFIRMED", NULL};

	add_ct_invoked_marker(data, args);

	return is_valid_param_sequence(valid_conntrack_status,
				args[0], ",", -1);
}

static bool handle_ctexpire(struct validator_data *data, gchar **args)
{
	add_ct_invoked_marker(data, args);

	/* --ctexpire has an integer or integer range ':' as sep  */
	return is_valid_range(args[0], ":", NULL, 0);
}

static bool handle_ctdir(struct validator_data *data, gchar **args)
{
	const char *valid_conntrack_flows[] = {"ORIGINAL", "REPLY", NULL};

	add_ct_invoked_marker(data, args);

	return g_strv_contains(valid_conntrack_flows, args[0]);
}

static const struct ipt_option_entry conntrack_match_options[] = {
	{ "--ctstate", 1, true, "ctstate", handle_ctstate },
	{ "--ctproto", 1, true, "ctproto", handle_ctproto },
	{ "--ctorigsrc", 1, true, "ctorigsrc", handle_ct_address },
	{ "--ctorigdst", 1, true, "ctorigdst", handle_ct_address },
	{ "--ctreplsrc", 1, true, "ctreplsrc", handle_ct_address },
	{ "--ctrepldst", 1, true, "ctrepldst", handle_ct_address },
	{ "--ctorigsrcport", 1, true, "ctorigsrcport", handle_ct_port },
	{ "--ctorigdstport", 1, true, "ctorigdstport", handle_ct_port },
	{ "--ctreplsrcport", 1, true, "ctreplsrcport", handle_ct_port },
	{ "--ctrepldstport", 1, true, "ctrepldstport", handle_ct_port },
	{ "--ctstatus", 1, true, "ctstatus", handle_ctstatus },
	{ "--ctexpire", 1, true, "ctexpire", handle_ctexpire },
	{ "--ctdir", 1, false, "ctdir", handle_ctdir },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * ttl match options:
 * [!] --ttl-eq value		Match time to live value
 * --ttl-lt value		Match TTL < value
 * --ttl-gt value		Match TTL > value

 */
static bool handle_ttl_value(struct validator_data *data, gchar **args)
{
	return is_string_digits(args[0]);
}

static const struct ipt_option_entry ttl_match_options[] = {
	{ "--ttl-eq", 1, true, "ttl", handle_ttl_value },
	{ "--ttl-lt", 1, false, "ttl", handle_ttl_value },
	{ "--ttl-gt", 1, false, "ttl", handle_ttl_value },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * pkttype match options:
 * [!] --pkt-type packettype	match packet type
 * 				Valid packet types:
 * 					unicast		to us
 * 					broadcast	to all
 * 					multicast	to group
*/
static bool handle_pkt_type(struct validator_data *data, gchar **args)
{
	const char *valid_pkttypes[] = {"unicast", "broadcast", "multicast",
				NULL};

	return g_strv_contains(valid_pkttypes, args[0]);
}

static const struct ipt_option_entry pkttype_match_options[] = {
	{ "--pkt-type", 1, true, "pkt-type", handle_pkt_type },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * limit match options:
 * --limit avg			max average match rate: default 3/hour
 * 				[Packets per second unless followed by
 * 				/sec /minute /hour /day postfixes]
 * --limit-burst number		number to match in a burst, default 5
 */
static bool handle_limit(struct validator_data *data, gchar **args)
{
	bool value1 = false;
	bool value2 = false;
	char** tokens;
	int token_count;
	const char *valid_limit_postfixes[] = { "sec", "minute", "hour", "day",
				NULL};

	tokens = g_strsplit(args[0], "/", 2);
	if (!tokens)
		return false;

	token_count = g_strv_length(tokens);
	if (token_count == 2) {
		value1 = is_string_digits(tokens[0]);
		value2 = g_strv_contains(valid_limit_postfixes, tokens[1]);
	} else if (token_count == 1) {
		value1 = is_string_digits(tokens[0]);
		value2 = true;
	}

	g_strfreev(tokens);

	return value1 && value2;
}

static bool handle_limit_burst(struct validator_data *data, gchar **args)
{
	return is_string_digits(args[0]);
}

static const struct ipt_option_entry limit_match_options[] = {
	{ "--limit", 1, false, "limit", handle_limit },
	{ "--limit-burst", 1, false, "limit-burst", handle_limit_burst },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * helper match options:
 * [!] --helper string		Match helper identified by string
 */
static const struct ipt_option_entry helper_match_options[] = {
	{ "--helper", 1, true, "helper", NULL },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * ECN match options
 * [!] --ecn-tcp-cwr 		Match CWR bit of TCP header
 * [!] --ecn-tcp-ece		Match ECE bit of TCP header
 * [!] --ecn-ip-ect [0..3]	Match ECN codepoint in IPv4/IPv6 header
 */
static bool add_ecn_invoked_marker(struct validator_data *data, gchar **args)
{
	if (!g_slist_find_custom(data->invoked, "ecn-option",
						(GCompareFunc) g_strcmp0))
		data->invoked = g_slist_prepend(data->invoked, "ecn-option");

	return true;
}

static bool handle_ecn_ip_ect(struct validator_data *data, gchar **args)
{
	gint64 str_digit;

	add_ecn_invoked_marker(data, args);

	/* ECN codepoint in IPv4/IPv6 header must be 0...3.*/
	if (is_string_digits(args[0])) {

		str_digit = g_ascii_strtoll(args[0], NULL, 10);
		if (str_digit >= 0 && str_digit <= 3)
			return true;
	}

	return false;
}

static const struct ipt_option_entry ecn_tcp_match_options[] = {
	{ "--ecn-tcp-cwr", 0, true, "ecn-tcp-cwr", add_ecn_invoked_marker },
	{ "--ecn-tcp-ece", 0, true, "ecn-tcp-ece", add_ecn_invoked_marker },
	{ NULL, 0, false, NULL, NULL }
};

static const struct ipt_option_entry ecn_ip_match_options[] = {
	{ "--ecn-ip-ect", 1, true, "ecn-ip-ect", handle_ecn_ip_ect },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * ah match options:
 * [!] --ahspi spi[:spi]	match spi (range)
 *
 * AH IPv6 option support:
 * [!] --ahspi spi[:spi]	match spi (range)
 * [!] --ahlen length		total length of this header
 * --ahres			check the reserved field too
 */

static bool handle_ahspi(struct validator_data *data, gchar **args)
{
	return is_valid_range(args[0], ":", NULL, 0);
}

static bool handle_ahlen(struct validator_data *data, gchar **args)
{
	return is_string_digits(args[0]);
}

static const struct ipt_option_entry ah_proto_options4[] = {
	{ "--ahspi", 1, true, "ahspi", handle_ahspi },
	{ NULL, 0, false, NULL, NULL }
};

static const struct ipt_option_entry ah_proto_options6[] = {
	{ "--ahspi", 1, true, "ahspi", handle_ahspi },
	{ "--ahlen", 1, true, "ahlen", handle_ahlen },
	{ "--ahres", 0, false, "ahres", NULL },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * esp match options:
 * [!] --espspi spi[:spi]	match spi (range)
 */
static bool handle_espspi(struct validator_data *data, gchar **args)
{
	return is_valid_range(args[0], ":", NULL, 0);
}

static const struct ipt_option_entry esp_proto_options[] = {
	{ "--espspi", 1, true, "espspi", handle_espspi },
	{ NULL, 0, false, NULL, NULL }
};

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
static bool handle_mh_type(struct validator_data *data, gchar **args)
{
	/*
	 * TODO: MH protocol support is not working, protocol specific options
	 * are not added properly to iptables. For this reason, the MH options
	 * are disabled as the option is omitted from the added rule, which is
	 * impossible to remove using the added rule containing these options.
	 */
	return false;
}

static const struct ipt_option_entry mh_proto_options[] = {
	{ "--mh-type", 1, true, "mh-type", handle_mh_type },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * sctp match options
 * [!] --chunk-types (all|any|none) (chunktype[:flags])+
 * 				match if all, any or none of chunktypes are
 * 				present
 */
static bool handle_chunk_types(struct validator_data *data, gchar **args)
{
	/*
	 * TODO: SCTP protocol support is not working, protocol specific options
	 * are not added properly to iptables. For this reason, the SCTP options
	 * are disabled as the option is omitted from the added rule, which is
	 * impossible to remove using the added rule containing these options.
	 */
	return false;
}

static const struct ipt_option_entry sctp_proto_options[] = {
	{ "--chunk-types", 2, true, "chunk-types", handle_chunk_types },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * icmp match options:
 * [!] --icmp-type typename	match icmp type
 * [!] --icmp-type type[/code]	(or numeric type or type/code)
 */
static bool handle_icmp_type(struct validator_data *data, gchar **args)
{
	/* List provided by iptables -p icmp --help */
	const char *icmp_types[] = {"any",
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

	/* ICMP types are separated with '/' and type must be checked */
	if (is_valid_pair(args[0], "/", is_icmp_int_type_valid,
				RANGE_CALLBACK_AND))
		return true;

	/* ICMP type was set as charstring */
	return g_strv_contains(icmp_types, args[0]);
}

static const struct ipt_option_entry icmp_proto_options[] = {
	{ "--icmp-type", 1, true, "icmp-type", handle_icmp_type },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * icmpv6 match options:
 * [!] --icmpv6-type typename	match icmpv6 type
 * 				(or numeric type or type/code)
 */

static bool handle_icmpv6_type(struct validator_data *data, gchar **args)
{
	/* List provided by ip6tables -p icmpv6 --help */
	const char *icmpv6_types[] = {"destination-unreachable",
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

	/* ICMP types are separated with '/' and type must be checked */
	if (is_valid_pair(args[0], "/", is_icmp_int_type_valid,
				RANGE_CALLBACK_AND))
		return true;

	/* ICMP type was set as charstring */
	return g_strv_contains(icmpv6_types, args[0]);
}

static const struct ipt_option_entry icmpv6_proto_options[] = {
	{ "--icmpv6-type", 1, true, "icmpv6-type", handle_icmpv6_type },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * dccp match options
 * [!] --dccp-types type[,...]	match when packet is one of the given types
 * [!] --dccp-option option	match if option (by number!) is set
 */

static bool handle_dccp_types(struct validator_data *data, gchar **args)
{
	const char *valid_dccp_types[] = {"REQUEST", "RESPONSE", "DATA", "ACK",
				"DATAACK", "CLOSEREQ","CLOSE", "RESET", "SYNC",
				"SYNCACK", "INVALID", NULL};

	return is_valid_param_sequence(valid_dccp_types, args[0], ",", -1);
}

static bool handle_dccp_option(struct validator_data *data, gchar **args)
{
	return is_string_digits(args[0]);
}

static const struct ipt_option_entry dccp_proto_options[] = {
	{ "--dccp-types", 1, true, "dccp-types", handle_dccp_types },
	{ "--dccp-option", 1, true, "dccp-option", handle_dccp_option },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * owner match options
 * [!] --uid-owner userid[-userid]      Match local UID
 * [!] --gid-owner groupid[-groupid]    Match local GID
 * [!] --socket-exists                  Match if socket exists
 */
static bool add_owner_invoked_marker(struct validator_data *data, gchar **args)
{
	if (!g_slist_find_custom(data->invoked, "owner-option",
						(GCompareFunc) g_strcmp0))
		data->invoked = g_slist_prepend(data->invoked, "owner-option");

	return true;
}

static bool handle_uid_owner(struct validator_data *data, gchar **args)
{
	add_owner_invoked_marker(data, args);

	/* a user named as the string exists */
	if (getpwnam(args[0]))
		return true;

	return is_valid_range(args[0], "-", is_correct_id, RANGE_CALLBACK_AND);
}

static bool handle_gid_owner(struct validator_data *data, gchar **args)
{
	add_owner_invoked_marker(data, args);

	/* a group named as the string exists */
	if (getgrnam(args[0]))
		return true;

	return is_valid_range(args[0], "-", NULL, 0);
}

static const struct ipt_option_entry owner_match_options[] = {
	{ "--uid-owner", 1, true, "uid-owner", handle_uid_owner },
	{ "--gid-owner", 1, true, "gid-owner", handle_gid_owner },
	{ "--socket-exists", 0, true, "socket-exists",
						 add_owner_invoked_marker },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * iprange match options
 * [!] --src-range ip[-ip]    Match source IP in the specified range
 * [!] --dst-range ip[-ip]    Match destination IP in the specified range
 */

static bool handle_ip_range(struct validator_data *data, gchar **args)
{
	if (!g_slist_find_custom(data->invoked, "iprange-option",
						(GCompareFunc) g_strcmp0))
		data->invoked = g_slist_prepend(data->invoked,
							"iprange-option");

	return is_valid_iprange(data->family, args[0]);
}

static const struct ipt_option_entry iprange_match_options[] = {
	{ "--src-range", 1, true, "src-range", handle_ip_range },
	{ "--dst-range", 1, true, "dst-range", handle_ip_range },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * rpfilter match options
 * --loose          permit reverse path via any interface
 * --validmark      use skb nfmark when performing route lookup
 * --accept-local   do not reject packets with a local source address
 * --invert         match packets that failed the reverse path test
 */
static const struct ipt_option_entry rpfilter_match_options[] = {
	{ "--loose", 0, false, "loose", NULL },
	{ "--validmark", 0, false, "validmark", NULL },
	{ "--accept-local", 0, false, "accept-local", NULL },
	{ "--invert", 0, false, "invert", NULL },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * Options:
 * [!] --in-interface -i input name[+]
 *                                 network interface name ([+] for wildcard)
 * [!] --out-interface -o output name[+]
 *                                 network interface name ([+] for wildcard)
 */

static bool handle_interface(struct validator_data *data, gchar **args)
{
	/*
	 * Allowed set of characters for interface - alnum, : - interface alias,
	 * . - vlan interface, and _ - supposedly used as well
	 */
	const char ifchars[] = ".0123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
				"abcdefghijklmnopqrstuvwxyz";
	int len;

	char *str = args[0];
	if (!str || !*str)
		return false;

	len = strlen(str);
	if (len >= IFNAMSIZ)
		return false;

	if (strspn(str, ifchars) != len)
		return false;

	return true;
}

static const struct ipt_option_entry dynamic_options[] = {
	{ "--in-interface", 1, true, "in-interface", handle_interface },
	{ "-i", 1, true, "in-interface", handle_interface },
	{ "--out-interface", 1, true, "out-interface", handle_interface },
	{ "-o", 1, true, "out-interface", handle_interface },
	{ NULL, 0, false, NULL, NULL }
};

/*
 * Options:
 * [!] --protocol  -p proto        protocol: by number or name, eg. `tcp'
 * [!] --source    -s address[/mask][...]
 *                                 source specification
 * [!] --destination -d address[/mask][...]
 *                                 destination specification
 *  --jump -j target
 *                                 target for rule (may load target extension)
 *   --goto      -g chain
 *                               jump to chain with no return
 *   --match       -m match
 *                                 extended match (may load extension)
 */

static bool handle_proto(struct validator_data *data, gchar **args)
{
	data->invoked_proto = resolve_protocol(args[0]);

	return data->invoked_proto < UINT8_MAX;
}

static bool handle_addresses(struct validator_data *data, gchar **args)
{
	gchar **tokens;
	bool ret = false;
	int length;
	int i;

	tokens = g_strsplit(args[0], ",", 0);

	if (!tokens)
		goto out;

	length = g_strv_length(tokens);

	for (i = 0; i < length; i++) {
		ret = validate_address_option_value(data->family, tokens[i]);

		if (!ret) {
			DBG("invalid address %s", tokens[i]);
			goto out;
		}
	}

out:
	g_strfreev(tokens);
	return ret;
}

static bool handle_jump(struct validator_data *data, gchar **args)
{
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

	return g_strv_contains(supported_targets, args[0]);
}

static bool is_port_protocol(struct validator_data *data, gchar **args)
{
	switch (data->invoked_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		return true;
	default:
		return false;
	}
}

// AF_UNSPEC and IPPROTO_IP == NULL
static const struct match_option_entry known_matches[] = {
	{ "ah", AF_INET, IPPROTO_AH, ah_proto_options4, NULL },
	{ "ah", AF_INET6, IPPROTO_AH, ah_proto_options6, NULL },
	{ "icmp", AF_INET, IPPROTO_ICMP, icmp_proto_options, NULL },
	{ "ttl", AF_INET, IPPROTO_IP, ttl_match_options, NULL },
	{ "icmp6", AF_INET6, IPPROTO_ICMPV6, icmpv6_proto_options, NULL },
	{ "icmpv6", AF_INET6, IPPROTO_ICMPV6, icmpv6_proto_options, NULL },
	{ "ipv6-icmp", AF_INET6, IPPROTO_ICMPV6, icmpv6_proto_options, NULL },
	{ "mh", AF_INET6, IPPROTO_MH, mh_proto_options, NULL },
	{ "esp", AF_UNSPEC, IPPROTO_ESP, esp_proto_options, NULL },
	{ "dccp", AF_UNSPEC, IPPROTO_DCCP, dccp_proto_options, NULL },
	{ "dccp", AF_UNSPEC, IPPROTO_DCCP, port_options, NULL },
	{ "sctp", AF_UNSPEC, IPPROTO_SCTP, sctp_proto_options, NULL },
	{ "sctp", AF_UNSPEC, IPPROTO_SCTP, port_options, NULL },
	{ "tcp", AF_UNSPEC, IPPROTO_TCP, tcp_proto_options, NULL },
	{ "tcp", AF_UNSPEC, IPPROTO_TCP, port_options, NULL },
	{ "udp", AF_UNSPEC, IPPROTO_UDP, port_options, NULL },
	{ "multiport", AF_UNSPEC, IPPROTO_IP, multiport_match_options,
							 is_port_protocol },
	{ "ecn", AF_UNSPEC, IPPROTO_IP, ecn_ip_match_options, NULL },
	{ "ecn", AF_UNSPEC, IPPROTO_TCP, ecn_tcp_match_options, NULL },
	{ "conntrack", AF_UNSPEC, IPPROTO_IP, conntrack_match_options, NULL },
	{ "owner", AF_UNSPEC, IPPROTO_IP, owner_match_options, NULL },
	{ "iprange", AF_UNSPEC, IPPROTO_IP, iprange_match_options, NULL },
	{ "helper", AF_UNSPEC, IPPROTO_IP, helper_match_options, NULL },
	{ "limit", AF_UNSPEC, IPPROTO_IP, limit_match_options, NULL },
	{ "mark", AF_UNSPEC, IPPROTO_IP, mark_match_options, NULL },
	{ "pkttype", AF_UNSPEC, IPPROTO_IP, pkttype_match_options, NULL },
	{ "rpfilter", AF_UNSPEC, IPPROTO_IP, rpfilter_match_options, NULL },
	{ NULL, AF_UNSPEC, IPPROTO_IP, NULL, NULL },
};

/*
 * The dependency is on the string name in the invoked slist,
 * so it should equal to the unique_id value from thc ipt_option_entry element,
 * or to the value reserved there by the opt_handler function.
 */
static const struct match_invoked_dep match_deps[] = {
	{ "icmp", "icmp-type" },
	{ "ttl", "ttl" },
	{ "icmp6", "icmpv6-type" },
	{ "icmpv6", "icmpv6-type" },
	{ "multiport", "ports" },
	{ "ecn", "ecn-option" },
	{ "conntrack", "conntrack-option" },
	{ "owner", "owner-option" },
	{ "iprange", "iprange-option" },
	{ "helper", "helper" },
	{ "mark", "mark" },
	{ "pkttype", "pkt-type" },
	{ NULL, NULL }
};

/*
 * Verifies the -m match has its required arguments, and removes it,
 * so that further invocations of the same match also supply that.
 */
static bool check_and_clean_match(struct validator_data *data, gchar *match)
{
	int i;
	GSList *opt_elem = NULL;
	char *opt_name = NULL;

	for (i = 0; match_deps[i].match_name; i++) {
		if (!g_strcmp0(match_deps[i].match_name, match)) {
			opt_name = (char *) match_deps[i].option_name;
			break;
		}
	}

	// This match has no dependency, so give ok
	if (!opt_name)
		return true;

	opt_elem = g_slist_find_custom(data->invoked, opt_name,
					(GCompareFunc) g_strcmp0);

	if (!opt_elem) {
		DBG("-m %s requires the use of %s", match, opt_name);

		return false;
	}

	data->invoked = g_slist_remove(data->invoked, opt_elem->data);

	return true;
}

static void remove_unique_ids_from_invoked(struct validator_data *data,
				const struct ipt_option_entry *opt_array)
{
	int i;
	GSList *opt_elem;

	for (i = 0; opt_array[i].opt_name; i++) {
		if (!opt_array[i].unique_id)
			continue;

		opt_elem = g_slist_find_custom(data->invoked,
						opt_array[i].unique_id,
						(GCompareFunc) g_strcmp0);
		if (opt_elem)
			data->invoked = g_slist_remove(data->invoked,
							opt_elem->data);
	}
}

/*
 * More fine-grained cleaning of invoked slist.
 * Used when there's another invocation of the same -m match, so that
 * we can check both the uniqueness of the options and the presence
 * of required options.
 */
static void clean_match_options(struct validator_data *data, gchar *match)
{
	int i;

	for (i = 0; known_matches[i].match_name; i++) {
		if (!g_strcmp0(known_matches[i].match_name, match)) {
			remove_unique_ids_from_invoked(data,
					 known_matches[i].opts_enabled);
		}
	}
}

static bool handle_match(struct validator_data *data, gchar **args)
{
	int i;
	bool match_found = false;

	if (g_slist_find_custom(data->invoked_match, args[0],
						(GCompareFunc) g_strcmp0)) {

		if (!check_and_clean_match(data, args[0]))
			return false;

		clean_match_options(data, args[0]);
	} else {
		data->invoked_match = g_slist_prepend(data->invoked_match,
						args[0]);
	}

	for (i = 0; known_matches[i].match_name; i++) {
		if (g_strcmp0(known_matches[i].match_name, args[0]))
			continue;

		if (known_matches[i].family_dep != AF_UNSPEC &&
				known_matches[i].family_dep != data->family)
			continue;

		if (known_matches[i].proto_dep != IPPROTO_IP &&
				known_matches[i].proto_dep !=
				data->invoked_proto)
			continue;

		if (known_matches[i].opts_enabled)
			add_iptables_options(data,
						known_matches[i].opts_enabled);

		if (known_matches[i].opt_handler) {
			if (!known_matches[i].opt_handler(data, args))
				return false;
		}

		match_found = true;
	}

	return match_found;
}

static const struct ipt_option_entry basic_options[] = {
	{ "--protocol", 1, true, "protocol", handle_proto },
	{ "-p", 1, true, "protocol", handle_proto },
	{ "--source", 1, true, "source", handle_addresses },
	{ "-s", 1, true, "source", handle_addresses },
	{ "--destination", 1, true, "destination", handle_addresses },
	{ "-d", 1, true, "destination", handle_addresses },
	{ "--jump", 1, false, "jump", handle_jump },
	{ "-j", 1, false, "jump", handle_jump },
	{ "--goto", 1, false, "jump", handle_jump },
	{ "-g", 1, false, "jump", handle_jump },
	{ "--match", 1, false, NULL, handle_match },
	{ "-m", 1, false, NULL, handle_match },
	{ NULL, 0, false, NULL, NULL }
};

static void initialize_iptables_options(struct validator_data *data)
{
	data->invoked = NULL;
	data->invoked_match = NULL;
	data->invoked_proto = 0;
	data->ipt_options = g_hash_table_new(g_str_hash, g_str_equal);
	add_iptables_options(data, basic_options);
}

bool __connman_iptables_validate_rule(int family, bool allow_dynamic,
			const char *rule_spec)
{
	gchar **argv = NULL;
	GError *error = NULL;
	bool ret = false;
	int i = 0;
	int argc = 0;
	const char *arg = NULL;
	struct validator_data vdata;
	struct ipt_option_entry* option;
	GSList *match_p;
	gchar **arg_opts;
	bool negated = false;

	initialize_iptables_options(&vdata);
	vdata.family = family;

	if (allow_dynamic)
		add_iptables_options(&vdata, dynamic_options);

	DBG("Parsing commandline: %s", rule_spec);

	if (!g_shell_parse_argv(rule_spec, &argc, &argv, &error)) {
		DBG("Failed parsing %s", error ? error->message : "");
		goto out;
	}

	for (i = 0; i < argc;) {
		arg = argv[i++];

		if (!g_strcmp0(arg, "!")) {
			negated = true;
			continue;
		}

		option = g_hash_table_lookup(vdata.ipt_options, arg);
		if (!option) {
			DBG("Failed parsing %s. Unexpected option.", arg);
			goto out;
		}

		if (negated && !option->allow_neg) {
			DBG("Failed parsing option %s. It does not allow "
							"negation.", arg);
			goto out;
		}

		if (option->unique_id) {
			if (g_slist_find_custom(vdata.invoked,
				 option->unique_id, (GCompareFunc) g_strcmp0)) {
				DBG("Failed parsing option %s. It is invoked "
						"too many times.", arg);
				goto out;
			}

			vdata.invoked = g_slist_prepend(vdata.invoked,
						 (char *) option->unique_id);
		}

		arg_opts = &argv[i];
		i += option->arg_count;

		if (i > argc) {
			DBG("Failed parsing option %s. It expects more "
				"arguments than available on the commandline.",
								 arg);
			goto out;
		}

		if (option->opt_handler)
			if (!option->opt_handler(&vdata, arg_opts)) {
				DBG("Failed parsing arguments of option %s. "
					"Argument verification failed.", arg);
				goto out;
			}

		negated = false;
	}

	if (!g_slist_find_custom(vdata.invoked, "jump",
						 (GCompareFunc) g_strcmp0)) {
		DBG("Failed parsing rule. It does not invoke any -j options.");
		goto out;
	}

	/*
	 * Match dependency verification - some of the match rules
	 * require an option to be provided, otherwise the rule fails.
	 * This verifies (one of) the options were provided on the cmdline.
	 */
	for (match_p = vdata.invoked_match; match_p; match_p = match_p->next)
		if (!check_and_clean_match(&vdata, match_p->data))
			goto out;

	ret = true;

out:
	g_clear_error(&error);
	g_strfreev(argv);
	g_hash_table_destroy(vdata.ipt_options);
	g_slist_free(vdata.invoked);
	g_slist_free(vdata.invoked_match);

	return ret;
}

void __connman_iptables_validate_init(void)
{
	DBG("");

}

void __connman_iptables_validate_cleanup(void)
{
	DBG("");

}
