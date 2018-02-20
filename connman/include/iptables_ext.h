/*
 *
 *  Connection Manager wrapper to expose iptables functions for SailfishOS MDM.
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

#ifndef _CONNMAN_IPTABLES_EXTENSION_H
#define _CONNMAN_IPTABLES_EXTENSION_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct iptables_content {
	gchar *table;
	GList *chains;
	GList *rules;
};

int connman_iptables_new_chain(const char *table_name,
					const char *chain);
	
int connman_iptables_delete_chain(const char *table_name,
					const char *chain);

int connman_iptables_flush_chain(const char *table_name,
					const char *chain);

int connman_iptables_find_chain(const char *table_name,
					const char *chain);

int connman_iptables_insert(const char *table_name,
				const char *chain,
				const char *rule_spec);

int connman_iptables_append(const char *table_name,
				const char *chain,
				const char *rule_spec);
	
int connman_iptables_delete(const char *table_name,
				const char *chain,
				const char *rule_spec);

int connman_iptables_commit(const char *table_name);

int connman_iptables_change_policy(const char *table_name,
					const char *chain,
					const char *policy);
					
int connman_iptables_clear(const char *table_name);

const char* connman_iptables_default_save_path(int ip_version);

struct iptables_content* connman_iptables_get_content(const char *table_name);
void connman_iptables_free_content(struct iptables_content *content);

#ifdef __cplusplus
}
#endif

#endif /* _CONNMAN_IPTABLES_EXTENSION_H */
