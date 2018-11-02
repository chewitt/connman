/*
 *
 *  Connection Manager wrapper implementation of the exposed iptables
 *  functions for SailfishOS MDM. Contains save, restore and clear
 *  functionality.
 *
 *  Copyright (C) 2017-2018 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "src/connman.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>

#include <netdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <libgen.h>
#include <endian.h>

#include <netinet/ip.h>
#include <xtables.h>
#include <libiptc/libiptc.h>

#include <linux/netfilter/xt_connmark.h>

#include <iptables_ext.h>

#define INFO(fmt,arg...)			connman_info(fmt, ## arg)
#define ERR(fmt,arg...)				connman_error(fmt, ## arg)

#define IPTABLES_NAMES_FILE			"/proc/net/ip_tables_names"

gint check_save_directory(const char* fpath)
{
	gchar* path = NULL;
	gint mode = S_IRWXU;
	gint access_mode = R_OK|W_OK|X_OK;
	gint rval = 0;
	
	if (!fpath || !(*fpath))
		return 1;
		
	path = g_path_get_dirname(fpath);
	
	// If given path has no proper prefix or is is ending with / or
	// is the same as the STORAGEDIR path
	if (!g_str_has_prefix(path, STORAGEDIR) || g_str_has_suffix(path,"/") ||
		g_strcmp0(path,STORAGEDIR) == 0) {
		rval = 1;
		goto out;
	}

	if (g_file_test(path,G_FILE_TEST_EXISTS)) {
		// Try to remove regular file or symlink 
		if (g_file_test(path,G_FILE_TEST_IS_REGULAR) ||
			g_file_test(path, G_FILE_TEST_IS_SYMLINK)) {
			DBG("Removing %s",path);
			if (g_remove(path)) {
				ERR("check_save_directory() Remove of %s failed (%s)",
					path, strerror(errno));
				rval = -1;
				goto out;
			}
		}
		
		// exists and is a dir
		if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
			// Check that this dir can be accessed
			if (access(path, access_mode) == -1) {
				ERR("check_save_directory() Dir %s cannot be accessed (%s).",
					path, strerror(errno));
				rval = -1;
				goto out;
			}
			
			DBG("Dir %s exists, nothing done.", path);
			goto out;
		}
	}
	
	DBG("Creating new dir for saving %s", path);
	rval = g_mkdir_with_parents(path,mode);

out:
	g_free(path);
	return rval;
}

/*
	Set content to given file, calls check_save_directory() to check the
	save location.
	
	@returns: 0 on success, 1 on access/content and -1 on parameter error.
*/
gint iptables_set_file_contents(const gchar *fpath, GString *str,
	gboolean free_str)
{
	gint rval = 1;
	
	if (!fpath || !(*fpath) || !str || !str->len)
		return -1;
		
	if (!check_save_directory(fpath)) {
		GError *err = NULL;
		
		rval = g_file_set_contents(fpath, str->str, str->len, &err) ? 0 : 1;
			
		if (rval || err) {
			ERR("iptables_set_file_contents() %s",
				err ? err->message : "noerror");
			g_error_free(err);
		}
	}
	
	if (free_str && str)
		g_string_free(str, true);
	
	return rval;
}

/*
	Get content from a file specified in path.
*/
GString* iptables_get_file_contents(const gchar* fpath)
{
	GString *contents = NULL;
	
	if (fpath && *fpath && g_str_has_prefix(fpath, STORAGEDIR)) {
		gchar *content = NULL;
		gsize len = -1;
		GError *err = NULL;
		
		if (g_file_get_contents(fpath, &content, &len, &err))
			contents = g_string_new_len(content, len);
		else {
			ERR("iptables_get_file_contents() %s", err->message);
			g_error_free(err);
		}
		
		g_free(content);
	}
	return contents;
}

static gboolean str_has_connman_prefix(const gchar* str)
{
	if(!str)
		return false;

	return g_str_has_prefix(str,"connman-");
}

static gboolean str_contains_connman(const gchar* str)
{
	if(!str)
		return false;
	
	return g_strrstr(str, "connman-") ? true : false;
}

typedef struct output_capture_data {
	gint stdout_pipes[2];
	gint stdout_saved;
	gint stdout_read_limit;
	gint stdout_bytes_read;
	gchar *stdout_data;
} output_capture_data;

gint stdout_capture_end(output_capture_data *data)
{
	gint rval = 0;

	if(!data)
		return 1;

	if (fflush(stdout))
		DBG("fflushing stdout failed: %s", strerror(errno));

	if (data->stdout_saved != -1) {
		if (dup2(data->stdout_saved,fileno(stdout)) == -1) {
			DBG("Cannot restore stdout: %s", strerror(errno));
			rval = -1;
		}

		if (close(data->stdout_saved) == -1) {
			DBG("Cannot close saved stdout: %s", strerror(errno));
			rval = -1;
		} else {
			data->stdout_saved = -1;
		}
	}

	if (data->stdout_pipes[0] != -1) {
		if (close(data->stdout_pipes[0]) == -1) {
			DBG("Cannot close stdout_pipes[0]: %s",
				strerror(errno));
			rval = -1;
		}

		data->stdout_pipes[0] = -1;
	}

	if (data->stdout_pipes[1] != -1 ) {
		if (close(data->stdout_pipes[1])) {
			DBG("Cannot close stdout_pipes[1]: %s",
				strerror(errno));
			rval = -1;
		}
	}

	return rval != -1 ? 0 : 1;
}

gint stdout_capture_start(output_capture_data *data)
{
	if(!data)
		return -1;

	if (fflush(stdout)) {
		DBG("fflushing stdout failed: %s", strerror(errno));
		goto error;
	}

	data->stdout_saved = dup(fileno(stdout));

	if (data->stdout_saved == -1) {
		DBG("Cannot copy stdout: %s", strerror(errno));
		goto error;
	}

	if (pipe(data->stdout_pipes) == -1) {
		DBG("cannot create pipe: %s", strerror(errno));
		goto error;
	}

	if (dup2(data->stdout_pipes[1], fileno(stdout)) == -1) {
		DBG("cannot duplicate fp with dup2: %s", strerror(errno));
		goto error;
	}
	
	if (close(data->stdout_pipes[1])) {
		DBG("cannot close existing fp: %s", strerror(errno));
		goto error;
	}
	
	data->stdout_pipes[1] = -1;
	
	return 0;

error:
	stdout_capture_end(data);
	return -1;
}

void stdout_capture_data(output_capture_data *data)
{
	data->stdout_data = g_try_malloc0(data->stdout_read_limit);
	ssize_t bytes_read = 0;

	if (fflush(stdout)) {
		DBG("fflushing stdout failed: %s", strerror(errno));
		return;
	}

	do {
		bytes_read = read(data->stdout_pipes[0],
			&(data->stdout_data[data->stdout_bytes_read]),
			data->stdout_read_limit);

		data->stdout_bytes_read += bytes_read;
		
		// Read full amount
		if (bytes_read == data->stdout_read_limit) {
			// Increase size of the data by the amount of read limit
			data->stdout_data = g_try_realloc(data->stdout_data, 
				data->stdout_bytes_read + data->stdout_read_limit);
			
			// g_try_realloc() does not zero bytes, do it with memset
			memset(&(data->stdout_data[data->stdout_bytes_read]), '\0',
				data->stdout_read_limit);
		}
		// Read less than limit, stop
		else
			break;
			
	} while (bytes_read > 0);
	
	if (bytes_read == -1)
		ERR("stdout_capture_data() error while reading stdout: %s",
			strerror(errno));
	
	if (fflush(stdout))
		DBG("flushing stdout failed");
}

/*
	Calls the save() function of iptables entry. Captures the stdout
	of the save() method and appends it to given GString.
*/
static void print_target_or_match(GString *line, const void *ip,
	const struct xtables_target *target, const struct xt_entry_target *t_entry,
	const struct xtables_match *match, const struct xt_entry_match *m_entry)
{
	output_capture_data data = {
		.stdout_pipes = {-1},
		.stdout_saved = -1,
		.stdout_read_limit = 1024,
		.stdout_bytes_read = 0,
		.stdout_data = NULL
	};
	
	if (!(line && ip && ((target && t_entry) || (match && m_entry))))
		return;


	if (stdout_capture_start(&data)) {
		ERR("Starting stdout capture failed.");
		goto out;
	}
	
	// t_entry/m_entry->u.user.revision from iptables 1.6.1 iptables.c:1139
	if (target && t_entry && target->save &&
		t_entry->u.user.revision == target->revision)
		target->save(ip,t_entry);
	else if (match && m_entry && match->save && 
		m_entry->u.user.revision == match->revision)
		match->save(ip,m_entry);

	stdout_capture_data(&data);
	
	if (data.stdout_bytes_read > 0) {
		g_string_append(line,data.stdout_data);
		g_free(data.stdout_data);
	}

out:
	if (stdout_capture_end(&data))
		ERR("Ending stdout capture failed.");
}

static void print_target(GString *line, const void *ip,
	const struct xtables_target *target, const struct xt_entry_target *entry)
{
	if (line && ip && target && entry)
		print_target_or_match(line,ip,target,entry,NULL,NULL);
}

static void print_match(GString *line, const void *ip,
	const struct xtables_match *match, const struct xt_entry_match *entry)
{
	if (line && ip && match && entry)
		print_target_or_match(line,ip,NULL,NULL,match,entry);
}

/* 	Adapted from GPLv2 iptables source file (v.1.4.15) iptables.c:987
	function print_proto().
*/
static void print_proto(GString* line, uint16_t proto, int invert)
{
	if (proto) {
		unsigned int i;
		const char *invertstr = invert ? " !" : "";

		const struct protoent *pent = getprotobynumber(proto);
		if (pent) {
			g_string_append_printf(line,"%s -p %s", invertstr, pent->p_name);
			return;
		}

		for (i = 0; xtables_chain_protos[i].name != NULL; ++i) {
			if (xtables_chain_protos[i].num == proto) {
				g_string_append_printf(line,"%s -p %s",
						invertstr, xtables_chain_protos[i].name);
				return;
			}
		}
		g_string_append_printf(line,"%s -p %u", invertstr, proto);
	}
}

/* 	From GPLv2 iptables source file (v.1.4.15) iptables.c:1010 */
#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

/* 	Adapted from GPLv2 iptables source file (v.1.4.15) iptables.c:1068
	function print_ip().
*/
static void print_ip(GString* line, const char *prefix, uint32_t ip,
			uint32_t mask, int invert)
{
	uint32_t bits, hmask = ntohl(mask);
	int i;
	
	if (!mask && !ip && !invert)
		return;
	
	g_string_append_printf(line, "%s %s %u.%u.%u.%u",
		invert ? " !" : "",
		prefix,
		IP_PARTS(ip));

	if (mask == 0xFFFFFFFFU)
		g_string_append(line,"/32");
	else {
		i    = 32;
		bits = 0xFFFFFFFEU;
		while (--i >= 0 && hmask != bits)
			bits <<= 1;
		if (i >= 0)
			g_string_append_printf(line,"/%u", i);
		else
			g_string_append_printf(line,"/%u.%u.%u.%u", IP_PARTS(mask));
	}
}

/* 	Adapted from GPLv2 iptables source file (v.1.4.15) iptables.c:1020
	function print_iface().
*/
static void print_iface(GString* line, char letter, const char *iface,
	const unsigned char *mask, int invert)
{
	unsigned int i;

	if (mask[0] == 0)
		return;

	g_string_append_printf(line,"%s -%c ", invert ? " !" : "", letter);

	for (i = 0; i < IFNAMSIZ; i++) {
		if (mask[i] != 0) {
			if (iface[i] != '\0')
				g_string_append_printf(line,"%c", iface[i]);
		} else {
			/* we can access iface[i-1] here, because
			 * a few lines above we make sure that mask[0] != 0 */
			if (iface[i-1] != '\0')
				g_string_append(line,"+");
			break;
		}
	}
}

/* Re-implemented XT_MATCH_ITERATE preprocessor macro in C from GPLv2 iptables
	source header include/linux/netfilter/x_tables.h
*/
static int match_iterate(
	GString *line, const struct ipt_entry *entry, const struct ipt_ip *ip,
	int (*fn) (
		GString *fn_line,
		const struct xt_entry_match *fn_entry, 
		const struct ipt_ip *fn_ip)
	 )
{
	guint i = 0;
	gint rval = 0;
	struct xt_entry_match *match = NULL;
	
	if(!line || !entry || !ip || !fn)
		return 1;
	
	for (i = sizeof(struct ipt_entry);
		i < (entry)->target_offset;
		i += match ? match->u.match_size : 0) {
		match = (void *)entry + i;
		rval = fn(line, match, ip);
		if (rval != 0)
			break;
	}
	return rval;
}

/* 	Adapted from GPLv2 iptables source file (v.1.6.1) iptables.c:1025
	function print_match_save().
*/
static int print_match_save(GString *line, const struct xt_entry_match *e,
			const struct ipt_ip *ip)
{
	struct xtables_match *match =
		xtables_find_match(e->u.user.name, XTF_TRY_LOAD, NULL);

	if (match) {
		g_string_append_printf(line, " -m %s",
			match->alias ? match->alias(e) : e->u.user.name);
		print_match(line, ip, match, e);

		/*
		 * xtables_find_match allocates a clone in case the found
		 * match has struct xt_entry_match* set (match->m). Otherwise
		 * an entry from the internal list is returned that must not
		 * be free'd. (iptables v.1.6.1 libxtables/xtables.c:653)
		 */
		if (match->m)
			free(match);
	} else {
		if (e->u.match_size) {
			ERR("print_match_save() Can't find library for match `%s'\n",
				e->u.user.name);
			return 1;
		}
	}
	return 0;
}

/* 	Adapted from GPLv2 iptables source file (v.1.4.15) iptables.c:1099
	function print_rule4().
*/
void print_iptables_rule(GString* line, const struct ipt_entry *e,
		struct xtc_handle *h, const char *chain, int counters)
{
	const struct xt_entry_target *t = NULL;
	const char *target_name = NULL;

	/* print counters for iptables-save */
	if (counters > 0)
		g_string_append_printf(line,"[%llu:%llu] ", 
				(unsigned long long)e->counters.pcnt,
				(unsigned long long)e->counters.bcnt);
	
	/* print chain name */
	g_string_append_printf(line,"-A %s", chain);

	/* Print IP part. */
	print_ip(line,"-s", e->ip.src.s_addr,e->ip.smsk.s_addr,
			e->ip.invflags & IPT_INV_SRCIP);	

	print_ip(line,"-d", e->ip.dst.s_addr, e->ip.dmsk.s_addr,
			e->ip.invflags & IPT_INV_DSTIP);

	print_iface(line,'i', e->ip.iniface, e->ip.iniface_mask,
			e->ip.invflags & IPT_INV_VIA_IN);

	print_iface(line,'o', e->ip.outiface, e->ip.outiface_mask,
			e->ip.invflags & IPT_INV_VIA_OUT);

	print_proto(line,e->ip.proto, e->ip.invflags & XT_INV_PROTO);

	if (e->ip.flags & IPT_F_FRAG)
		g_string_append_printf(line,"%s -f",
			e->ip.invflags & IPT_INV_FRAG ? " !" : "");
	
	/* Print matchinfo part */
	if (e->target_offset)
		match_iterate(line, e, &e->ip, print_match_save);

	/* print counters for iptables -R */
	if (counters < 0)
		g_string_append_printf(line," -c %llu %llu",
			(unsigned long long)e->counters.pcnt,
			(unsigned long long)e->counters.bcnt);
	
	/* Print target name and targinfo part */
	// iptc_get_target() returns an empty string if target does not exist
	target_name = iptc_get_target(e, h);
	t = ipt_get_target((struct ipt_entry *)e);
	
	if (t->u.user.name[0]) {
		const struct xtables_target *target =
			xtables_find_target(t->u.user.name, XTF_TRY_LOAD);
		
		if (!target) {
			ERR("print_iptables_rule() can't find library for target `%s'\n",
				t->u.user.name);
			return;
		}

		// Make sure that alias exists or target_name has content
		if (target->alias || *target_name) {
			// Iptables v1.6.1 iptables.c:1138 print target info before checks
			g_string_append_printf(line, " -j %s",
				target->alias ? target->alias(t) : target_name);
		}
			
		print_target(line, &e->ip, target, t);
	} else if (target_name && (*target_name != '\0'))
		g_string_append_printf(line," -%c %s",
			e->ip.flags & IPT_F_GOTO ? 'g' : 'j', target_name);

	g_string_append(line, "\n");
}

static struct xtc_handle* get_iptc_handle(const char *table_name)
{
	struct xtc_handle *h = NULL;

	if (table_name && *table_name) {
		h = iptc_init(table_name);

		if (!h) {
			xtables_load_ko(xtables_modprobe_program, false);
			h = iptc_init(table_name);
		}
		if (!h)
			ERR("get_iptc_handle() Cannot initialize iptc: %s for table %s\n",
				iptc_strerror(errno), table_name);
	}

	return h;
}


/* 	Adapted from GPLv2 iptables source file (v.1.4.15) iptables-save.c:35
	function for_each_table().
*/
int iptables_check_table(const char *table_name)
{
	int ret = 1;
	FILE *procfile = NULL;
	char read_table_name[XT_TABLE_MAXNAMELEN+1];
	struct xtc_handle *handle = NULL;
	
	if (!table_name || !(*table_name))
		return ret;
	
	/* Try to get iptc handle for the table first,
	 * otherwise read from file */
	if ((handle = get_iptc_handle(table_name))) {
		iptc_free(handle);
		return 0;
	}

	memset(&read_table_name,0,sizeof(read_table_name));

	procfile = fopen(IPTABLES_NAMES_FILE, "re");
	
	if (!procfile) {
		switch (errno) {
		case ENOENT:
			ERR("iptables_check_table() names file %s does not exist",
				IPTABLES_NAMES_FILE);
			return -ENOENT;
		case EACCES:
			ERR("iptables_check_table() names file %s cannot be accessed",
				IPTABLES_NAMES_FILE);
			return -EACCES;
		default:
			ERR("iptables_check_table() cannot open names file %s, %s",
				IPTABLES_NAMES_FILE, strerror(errno));
			return -1;
		}
	}
	
	while (fgets(read_table_name, sizeof(read_table_name), procfile)) {
		if (read_table_name[strlen(read_table_name) - 1] != '\n')
			ERR("iptables_check_table() Badly formed table_name `%s'",
				read_table_name);
		else {
			read_table_name[strlen(read_table_name) - 1] = '\0';
		
			ret = g_ascii_strcasecmp(read_table_name,table_name);
		
			if (!ret) // 0, match
				break;
		}
		
		memset(&read_table_name,0,sizeof(read_table_name));
	}

	fclose(procfile);
	return ret;
}

/* 	Adapted from GPLv2 iptables source file (v.1.4.15) iptables-save.c:59
	function do_output().
*/
static int iptables_save_table(const char *fpath, GString** output,
	const char *table_name, gboolean save_to_file)
{
	struct xtc_handle *h = NULL;
	const char *chain = NULL;
	GString *line = NULL;
	time_t now = {0};
	gint table_result = iptables_check_table(table_name);
	
	switch (table_result) {
	case 0:
		break;
	case 1:
		ERR("iptables_save_table() called with invalid table name");
	default:
		return 1; // Error accessing iptables names file
	}
	
	if (!save_to_file && (!output || !(*output) || (*output)->len)) {
		ERR("iptables_save_table() invalid GString pointer given");
		return 1;
	}
	
	DBG("%s %s", "iptables_save_table() saving table: ", table_name);
	
	if (!(h = get_iptc_handle(table_name)))
		return 1;
	
	// Create new Gstring only if saving to file
	if (fpath) {
		line = g_string_new("");
		now = time(NULL);
	
		g_string_append_printf(line,"# Generated by connman on %s",
			ctime(&now));
		g_string_append_printf(line,"*%s\n", table_name);
	} else
		line = *output; // Use given GString

	/* Dump out chain names first,
	 * thereby preventing dependency conflicts */
	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h)) {
	
		// Skip chains with connman prefix
		if(str_has_connman_prefix(chain))
			continue;
	
		g_string_append_printf(line,":%s ", chain);
		if (iptc_builtin(chain, h)) {
			struct xt_counters count = {0};
			
			g_string_append_printf(line,"%s ",
					iptc_get_policy(chain, &count, h));
					
			g_string_append_printf(line,"[%llu:%llu]\n", 
					(unsigned long long)count.pcnt,
					(unsigned long long)count.bcnt);
		} else
			g_string_append_printf(line,"- [0:0]\n");
	}

	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h)) {
		const struct ipt_entry *e = NULL;
		
		// Skip chains with connman prefix
		if(str_has_connman_prefix(chain))
			continue;

		/* Dump out rules */
		e = iptc_first_rule(chain, h);
		while (e) {
			print_iptables_rule(line, e, h, chain, 0);
			e = iptc_next_rule(e, h);
		}
	}

	now = time(NULL);
	
	if (fpath) {
		g_string_append_printf(line,"COMMIT\n");
		g_string_append_printf(line,"# Completed on %s", ctime(&now));
	}
	
	iptc_free(h);
	
	if (fpath)
		return iptables_set_file_contents(fpath, line, true);
	else
		return 0;
}

static int iptables_clear_table(const char *table_name)
{
	struct xtc_handle *h = NULL;
	const char *chain = NULL;
	gint rval = 0;
	gint table_result = iptables_check_table(table_name);
	
	switch (table_result) {
	case 0:
		break;
	case 1:
		ERR("iptables_clear_table() called with invalid table name");
	default:
		return 1; // Error accessing iptables names file
	}
			
	if (!(h = get_iptc_handle(table_name)))
		return 1;
	
	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h)) {
		if (!iptc_flush_entries(chain,h))
			rval = 1;
	}

	if (!iptc_commit(h))
		rval = 1;
	
	if (h)
		iptc_free(h);

	return rval;
}

static int iptables_iptc_set_policy(const gchar* table_name,
	const gchar* chain, const gchar* policy,
	guint64 packet_counter, guint64 byte_counter)
{
	gint rval = 0;
	struct xtc_handle *h = NULL;
	struct xt_counters counters = {0};
	
	if (!(table_name && *table_name && chain && *chain && policy && *policy))
		return 1;
		
	if (!(h = get_iptc_handle(table_name)))
		return 1;

	if (!iptc_is_chain(chain,h)) {
		DBG("Chain \"%s\" does not exist, adding new.", chain);
		rval = connman_iptables_new_chain(table_name, chain);
		goto out; // No policy change for custom chains
	}
	
	// Do nothing for chains that are not builtin, iptc_set_policy supports
	// builtin only
	if (!iptc_builtin(chain,h))
		goto out;

	counters.pcnt = packet_counter;
	counters.bcnt = byte_counter;

	DBG("Set to table \"%s\" chain \"%s\" policy \"%s\" counters %llu %llu",
		table_name, chain, policy,
		(unsigned long long)packet_counter, (unsigned long long)byte_counter);

	// returns 1 on success
	if (!iptc_set_policy(chain, policy, &counters, h)) {
		ERR("iptables_iptc_set_policy() policy cannot be set %s", 
			iptc_strerror(errno));
		rval = 1;
		goto out;
	}
	
	if (!iptc_commit(h)) {
		ERR("iptables_iptc_set_policy() commit error %s",
			iptc_strerror(errno));
		rval = 1;
	}

out:
	if (h)
		iptc_free(h);

	return rval;
}

static int iptables_parse_policy(const gchar* table_name, const gchar* policy)
{
	gint rval = 1;
	guint policy_tokens = 3;
	
	if (!table_name || !(*table_name) || !policy || !(*policy))
		return rval;
		
	// Format :CHAIN POLICY [int:int]
	gchar** tokens = g_strsplit(&(policy[1]), " ", policy_tokens);
	
	if (tokens && g_strv_length(tokens) == policy_tokens) {
	
		// Check chain for connman prefix
		if(str_has_connman_prefix(tokens[0]))
			goto out;
	
		gchar** counter_tokens = g_strsplit_set(tokens[2], "[:]", -1);

		if (counter_tokens && g_strv_length(counter_tokens) > 2) {
			// counters start with '[' so first token is empty, start from 1
			guint64 packet_cntr = g_ascii_strtoull(counter_tokens[1],NULL, 10);
			guint64 byte_cntr = g_ascii_strtoull(counter_tokens[2], NULL, 10);
			
			rval = iptables_iptc_set_policy(table_name, tokens[0], tokens[1],
					packet_cntr, byte_cntr);
		}
		g_strfreev(counter_tokens);
	
	}
out:
	g_strfreev(tokens);
	
	return rval;
}

static void iptables_append_arg(GString *string, const gchar *arg, bool quote)
{
	/* Note: Any characters with high bit set are assumed to be
	 * part of valid utf8 sequence and are passed through as-is.
	 */
	size_t i = 0;

	if (string->len) {
		/* Separate from previous arg with a space */
		g_string_append_c(string, ' ');
	}

	if (!quote) {
		/* Auto-quote if string contains spaces or control chars */
		for (i = 0; ; ) {
			int chr = (unsigned char)arg[i++];
			if (chr > 32)
				continue;
			if (chr > 0)
				quote = true;
			break;
		}
	}

	if (quote) {
		/* Note: g_shell_quote() uses single quote escaping, which
		 * basically means we can't use if if we wish to retain the
		 * original formatting with the expected inputs where no
		 * special characters are used except for the spaces within
		 * quoted comment strings.
		 */
		g_string_append_c(string, '"');
		for (i = 0; ; ) {
			int chr = (unsigned char)arg[i++];
			if (chr == 0 ) {
				break;
			}
			if (chr >= 32) {
				g_string_append_c(string, chr);
				continue;
			}
			switch (chr) {
			case '\a': chr = 'a'; break;
			case '\b': chr = 'b'; break;
			case '\t': chr = 't'; break;
			case '\n': chr = 'n'; break;
			case '\v': chr = 'v'; break;
			case '\f': chr = 'f'; break;
			case '\r': chr = 'r'; break;
			case '"': break;
			default:
				g_string_append_printf(string, "\\%#o", chr);
				continue;
			}
			g_string_append_c(string, '\\');
			g_string_append_c(string, chr);
		}
		g_string_append_c(string, '"');
	} else {
		/* Add as-is */
		g_string_append(string, arg);
	}
}
static int iptables_parse_rule(const gchar* table_name, gchar* rule)
{
	int rval = 1, i = 0;
	gint argc = 0;
	gchar **argv = NULL;
	GError *error = NULL;
	GString *rule_str = NULL;

	if (!table_name || !*table_name || !rule || !*rule)
		goto out;

	/* Format, e.g., -A CHAIN -p tcp -s 1.2.3.4  ... separated with spaces
	 * However a shell command line parser needs to be used to deal with
	 * arguments like: ... -m comment --comment "foo bar"
	 */
	if (!g_shell_parse_argv(rule, &argc, &argv, &error))
		goto out;

	if (argc < 4 || !argv[0][0])
		goto out;

	/* Discard all rules that have prefix "connman-" in chain name or
	 * target name. Chain = token[1], target = last token.
	 */
	if (str_has_connman_prefix(argv[1]) ||
		str_has_connman_prefix(argv[argc - 1])) {
		DBG("Skipping connman rule \"%s\"", rule);
		rval = 0; // Not an error situation
		goto out;
	}

	rule_str = g_string_new(NULL);

	/* Match "-m comment" should be checked that it is followed
	 * by a --comment content section, otherwise iptables will
	 * call exit as rule is invalid. Any words "comment" in the
	 * actual comment should not trigger this.
	 */
	for (i = 2; i < argc; ) {
		const char *arg = argv[i++];
		if (!g_strcmp0(arg, "-m")) {
			const char *match = argv[i++];
			if (!match) {
				DBG("trailing '-m' in rule \"%s\"", rule);
				goto out;
			}
			iptables_append_arg(rule_str, arg, false);
			iptables_append_arg(rule_str, match, false);
			if (!g_strcmp0(match, "comment")) {
				const char *opt = argv[i++];
				if (g_strcmp0(opt, "--comment")) {
					DBG("malformed '-m comment' "
						"in rule \"%s\"", rule);
					goto out;
				}
				const char *txt = argv[i++];
				if (!txt || g_str_has_prefix(txt, "-")) {
					DBG("malformed '--comment' "
						"in rule \"%s\"", rule);
					goto out;
				}
				iptables_append_arg(rule_str, opt, false);
				iptables_append_arg(rule_str, txt, true);
			}
		} else if (!g_strcmp0(arg, "-j")) {
			const char *match = argv[i++];
			if (!match) {
				DBG("trailing '-j' in rule \"%s\"", rule);
				goto out;
			}
			iptables_append_arg(rule_str, arg, false);
			iptables_append_arg(rule_str, match, false);
			if (!g_strcmp0(match, "REJECT")) {
				const char *opt = argv[i++];
				if (g_strcmp0(opt, "--reject-with")) {
					DBG("malformed '-j REJECT' "
						"in rule \"%s\"", rule);
					goto out;
				}
				const char *txt = argv[i++];
				if (!txt || g_str_has_prefix(txt, "-")) {
					DBG("malformed '--reject-with' "
						"in rule \"%s\"", rule);
					goto out;
				}
				iptables_append_arg(rule_str, opt, false);
				iptables_append_arg(rule_str, txt, true);
			}
		} else {
			iptables_append_arg(rule_str, arg, false);
		}
	}

	// First token contains the mode, prefixed with '-'
	switch (argv[0][1]) {
	// Append
	case 'A':
		DBG("Append to table \"%s\" chain \"%s\" rule: %s",
			table_name, argv[1], rule_str->str);
		rval = __connman_iptables_append(table_name, argv[1],
				rule_str->str);
		break;
	// Insert
	case 'I':
		DBG("Insert to table \"%s\" chain \"%s\" rule: %s",
			table_name, argv[1], rule_str->str);
		rval = __connman_iptables_insert(table_name, argv[1],
				rule_str->str);
		break;
	// Delete
	case 'D':
		DBG("Delete from table \"%s\" chain \"%s\" rule: %s",
			table_name, argv[1], rule_str->str);
		rval = __connman_iptables_delete(table_name, argv[1],
				rule_str->str);
		break;
	default:
		ERR("iptables_parse_rule() invalid rule prefix %c",
			rule[1]);
	}

out:
	if (rule_str)
		g_string_free(rule_str, true);
	if (error)
		g_error_free(error);
	g_strfreev(argv);
	return rval;
}

static int iptables_restore_table(const char *table_name, const char *fpath)
{
	gint rval = 0, i = 0, rules = 0;
	gboolean content_matches = false;
	gboolean process = true;
	gint table_result = iptables_check_table(table_name);
	
	switch (table_result) {
	case 0:
		break;
	case 1:
		ERR("iptables_restore_table() called with invalid table name");
	default:
		return 1;
	}
	
	GString *content = iptables_get_file_contents(fpath);
	
	if (!content)
		return 1;
		
	gchar** tokens = g_strsplit(content->str,"\n",0);
	
	for (i = 0; tokens[i] && process; i++) {
		switch (tokens[i][0]) {
		// Skip comment
		case '#':
			break;
		// Table name
		case '*':
			content_matches = !g_ascii_strcasecmp(&(tokens[i][1]), 
				table_name) ? true : false;
			break;
		// Chain and policy
		case ':':
			if (content_matches) {
				if (iptables_parse_policy(table_name, tokens[i]))
					ERR("iptables_restore_table() Invalid policy %s",
						tokens[i]);
			}
			break;
		// Rule
		case '-':
			if (content_matches) {
				if (iptables_parse_rule(table_name, tokens[i]))
					ERR("iptables_restore_table() Invalid rule %s",
						tokens[i]);
				else
					rules++;
			}
			break;
		// If any other prefix for a line is found and we are processing
		// 'COMMIT' is the last line in iptables saved format, stop processing
		default:
			if (content_matches)
				process = false;
			break;
		}
	}
	g_strfreev(tokens);
	
	g_string_free(content,true);
	
	if (content_matches) {
		/* Commit fails if there has not been any changes */
		if (rules) {
			DBG("Added %d rules to table %s", rules, table_name);
			rval = __connman_iptables_commit(table_name);
		}
	} else {
		ERR("iptables_restore_table() %s",
			"requested table name does not match file table name");
	}

	return rval;
}

/*
*
* return: 0 on success, 1 error and -1 if save is already in progress
*/
int iptables_save(const char* table_name)
{
	// TODO ADD MUTEX
	gint rval = 1;
	gchar *save_file = NULL;
	
	if (!table_name || !(*table_name))
		goto out;
	
	save_file = g_strconcat(STORAGEDIR, "/iptables/", table_name, ".v4", NULL);

	if (g_file_test(save_file, G_FILE_TEST_EXISTS)) {
		// Don't allow to overwrite executables
		if (g_file_test(save_file,G_FILE_TEST_IS_EXECUTABLE)) {
			ERR("connman_iptables_save() cannot save firewall to %s",
				save_file);
			goto out;
		}
	}
		
	DBG("saving iptables table %s to %s", table_name, save_file);

	rval = iptables_save_table(save_file, NULL, table_name, true);
	
out:
	g_free(save_file);

	return rval;
}


int iptables_restore(const char* table_name)
{
	gint rval = 1;
	gchar *load_file = NULL;
	
	if (!table_name || !(*table_name))
		goto out;
		
	load_file = g_strconcat(STORAGEDIR, "/iptables/", table_name, ".v4", NULL);

	// Allow only regular files from connman storage
	if (!g_file_test(load_file,G_FILE_TEST_EXISTS) ||
		!g_file_test(load_file,G_FILE_TEST_IS_REGULAR)) {
			ERR("Cannot restore table %s, file %s not found",
				table_name, load_file);
			goto out;
	}

	DBG("restoring iptables table %s from %s", table_name, load_file);

	if ((rval = iptables_clear_table(table_name))) {
		ERR("clearing of table %s failed, cannot restore.",
			table_name);
		goto out;
	}

	if((rval = iptables_restore_table(table_name, load_file)))
		ERR("connman_iptables_restore() cannot restore table %s",
			table_name);

out:
	g_free(load_file);
	return rval;
}

static gchar** get_default_tables()
{
	gchar **tables = NULL;
	gchar *content = NULL;
	gsize length = 0;
	GError *error = NULL;
	
	if (g_file_get_contents(IPTABLES_NAMES_FILE, &content, &length, &error)) {
		tables = g_strsplit(content, "\n", 0);
		g_free(content);
	} else {
		if (error) {
			DBG("get_file_contents error %s", error->message);
			g_error_free(error);
		}
			
		DBG("Cannot read default iptables table names from %s",
			IPTABLES_NAMES_FILE);
	}

	return tables;
}

int __connman_iptables_save_all()
{
	gchar **tables = get_default_tables();
	
	gint i = 0;
	
	if(!tables || !g_strv_length(tables))
		return 1;
	
	for (i = 0; tables[i] && *tables[i]; i++) {
		if (iptables_save(tables[i]))
			DBG("cannot save table \"%s\"", tables[i]);
	}
	
	g_strfreev(tables);
	
	return 0;
}

int __connman_iptables_restore_all()
{
	gchar **tables = get_default_tables();
	gint i = 0;
	
	if(!tables || !g_strv_length(tables))
		return 1;
	
	for (i = 0; tables[i] && *tables[i]; i++) {
		if(iptables_restore(tables[i]))
			DBG("cannot restore table %s", tables[i]);
	}
	
	g_strfreev(tables);
	
	return 0;
}

int connman_iptables_clear(const char* table_name)
{
	if (!table_name || !(*table_name) ||
		g_ascii_strcasecmp(table_name,"filter"))
		return 1;

	DBG("%s", table_name);

	return iptables_clear_table(table_name);
}

/*
	Returns: 0 Ok, -1 Parameter error, -EINVAL or -ENOMEM on Error
*/
int connman_iptables_new_chain(const char *table_name,
					const char *chain)
{
	if (!table_name || !(*table_name) || !chain || !(*chain))
		return -1;

	DBG("%s %s", table_name, chain);

	if (str_has_connman_prefix(chain))
		return -EINVAL;

	return __connman_iptables_new_chain(table_name, chain);
}

/*
	Returns: 0 Ok, -1 Parameter error, -EINVAL or -ENOMEM on error,
*/
int connman_iptables_delete_chain(const char *table_name,
					const char *chain)
{
	if (!table_name || !(*table_name) || !chain || !(*chain))
		return -1;

	DBG("%s %s", table_name, chain);

	if (str_has_connman_prefix(chain))
		return -EINVAL;

	return __connman_iptables_delete_chain(table_name, chain);
}

int connman_iptables_flush_chain(const char *table_name,
					const char *chain)
{
	if (!table_name || !(*table_name) || !chain || !(*chain))
		return -1;

	DBG("%s %s", table_name, chain);

	if (str_has_connman_prefix(chain))
		return -EINVAL;

	return __connman_iptables_flush_chain(table_name, chain);
}

/*
	Returns: 0 if chain found, -ENOENT if not found, -EINVAL on parameter error
*/
int connman_iptables_find_chain(const char *table_name, const char *chain)
{
	if (!table_name || !(*table_name) || !chain || !(*chain))
		return -EINVAL;

	DBG("%s %s", table_name, chain);

	return __connman_iptables_find_chain(table_name, chain);
}

int connman_iptables_insert(const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	if (!table_name || !chain || !rule_spec || 
		!(*table_name) || !(*chain) || !(*rule_spec))
		return -EINVAL;

	DBG("%s %s %s", table_name, chain, rule_spec);

	if (str_has_connman_prefix(chain) || str_contains_connman(rule_spec))
		return -EINVAL;

	return __connman_iptables_insert(table_name, chain, rule_spec);
}

int connman_iptables_append(const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	if (!table_name || !chain || !rule_spec || 
		!(*table_name) || !(*chain) || !(*rule_spec))
		return -EINVAL;

	DBG("%s %s %s", table_name, chain, rule_spec);

	if (str_has_connman_prefix(chain) || str_contains_connman(rule_spec))
		return -EINVAL;

	return __connman_iptables_append(table_name, chain, rule_spec);
}
	
int connman_iptables_delete(const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	if (!table_name || !chain || !rule_spec || 
		!(*table_name) || !(*chain) || !(*rule_spec))
		return -EINVAL;

	DBG("%s %s %s", table_name, chain, rule_spec);

	if (str_has_connman_prefix(chain) || str_contains_connman(rule_spec))
		return -EINVAL;

	return __connman_iptables_delete(table_name, chain, rule_spec);
}
	
int connman_iptables_commit(const char *table_name)
{
	if (!table_name || !(*table_name))
		return -EINVAL;

		DBG("%s", table_name);

	return __connman_iptables_commit(table_name);
}

int connman_iptables_change_policy(const char *table_name,
					const char *chain,
					const char *policy)
{
	if (!table_name || !chain || !policy || 
		!(*table_name) || !(*chain) || !(*policy))
		return -EINVAL;

	DBG("%s %s %s", table_name, chain, policy);

	if (str_has_connman_prefix(chain))
		return -EINVAL;

	return __connman_iptables_change_policy(table_name, chain, policy);
}

const char* connman_iptables_default_save_path(int ip_version)
{
	if (ip_version == 4)
		return STORAGEDIR;
	
	return NULL;
}

static struct iptables_content* iptables_content_new(const gchar* table_name)
{
	struct iptables_content* content = g_new0(struct iptables_content,1);
	content->chains = NULL;
	content->rules = NULL;
	content->table = g_strdup(table_name);
	
	return content;
}

struct iptables_content* iptables_get_content(GString *output,
	const gchar* table_name)
{
	struct iptables_content *content = NULL;
	gchar **tokens = NULL, **policy_tokens = NULL;
	gboolean process = true;
	gint i = 0;
	
	if (!output || !output->len)
		return NULL;

	content = iptables_content_new(table_name);
		
	tokens = g_strsplit(output->str, "\n", -1);
	
	for (i = 0; tokens[i] && process; i++) {
		switch (tokens[i][0]) {
		// Skip comment and table name
		case '#':
		case '*':
			break;
		// Chain and policy
		case ':':
			// TODO improve this to allocate less memory
			policy_tokens = g_strsplit(&(tokens[i][1]), " ", 3);
			if (g_strv_length(policy_tokens) > 2) {
				content->chains = g_list_prepend(content->chains,
					g_strdup_printf("%s %s", 
						policy_tokens[0], policy_tokens[1]));
			}
			g_strfreev(policy_tokens);

			break;
		// Rule
		case '-':
			content->rules = g_list_prepend(content->rules,
				g_strdup(tokens[i]));	
			break;
		// Anything else, stop processing
		default:
			process = false;
			break;
		}
	}
	
	content->chains = g_list_reverse(content->chains);
	content->rules = g_list_reverse(content->rules);
	
	g_strfreev(tokens);
	
	return content;
}

void connman_iptables_free_content(struct iptables_content *content)
{
	if (!content)
		return;

	DBG("");
	
	g_list_free_full(content->chains, g_free);
	g_list_free_full(content->rules, g_free);
	g_free(content->table);
	g_free(content);
}

struct iptables_content* connman_iptables_get_content(const char *table_name)
{
	struct iptables_content *content = NULL;
	GString *output = NULL;
	
	if(!table_name || !(*table_name))
		return NULL;

	DBG("%s", table_name);
	
	output = g_string_new(NULL);
	
	if (!iptables_save_table(NULL, &output, table_name, false))
		content = iptables_get_content(output, table_name);
	
	g_string_free(output, true);
	
	return content;
}

