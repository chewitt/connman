/*
 *  ConnMan VPN daemon settings
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018 Jolla Ltd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <connman/log.h>

#include "vpn.h"

#define DEFAULT_INPUT_REQUEST_TIMEOUT 300 * 1000
#define DEFAULT_STORAGE_DIR_PERMISSIONS (0700)
#define DEFAULT_STORAGE_FILE_PERMISSIONS (0600)
#define DEFAULT_UMASK (0077)

#define PLUGIN_CONFIGDIR CONFIGDIR "/vpn-plugin"

static struct {
	unsigned int timeout_inputreq;
	char *fs_identity;
	char *storage_root;
	char *state_dir;
	mode_t storage_dir_permissions;
	mode_t storage_file_permissions;
	mode_t umask;
	char *binary_user;
	char *binary_group;
	char **binary_supplementary_groups;
} connman_vpn_settings  = {
	.timeout_inputreq		= DEFAULT_INPUT_REQUEST_TIMEOUT,
	.fs_identity 			= NULL,
	.storage_root			= NULL,
	.state_dir			= NULL,
	.storage_dir_permissions	= DEFAULT_STORAGE_DIR_PERMISSIONS,
	.storage_file_permissions	= DEFAULT_STORAGE_FILE_PERMISSIONS,
	.umask				= DEFAULT_UMASK,
	.binary_user			= NULL,
	.binary_group			= NULL,
	.binary_supplementary_groups	= NULL,
};

struct vpn_plugin_data {
	char *binary_user;
	char *binary_group;
	char **binary_supplementary_groups;
};

GHashTable *plugin_hash = NULL;

const char *__vpn_settings_state_dir()
{
	return connman_vpn_settings.state_dir ?
		connman_vpn_settings.state_dir :
		DEFAULT_VPN_STATEDIR;
}

const char *__vpn_settings_get_fs_identity(void)
{
	return connman_vpn_settings.fs_identity;
}

const char *__vpn_settings_get_storage_root()
{
	return connman_vpn_settings.storage_root;
}

mode_t __vpn_settings_get_storage_dir_permissions()
{
	return connman_vpn_settings.storage_dir_permissions;
}

mode_t __vpn_settings_get_storage_file_permissions()
{
	return connman_vpn_settings.storage_file_permissions;
}

mode_t __vpn_settings_get_umask()
{
	return connman_vpn_settings.umask;
}

const char *__vpn_settings_get_binary_user(struct vpn_plugin_data *data)
{
	if (data && data->binary_user)
		return data->binary_user; 

	return connman_vpn_settings.binary_user;
}

const char *__vpn_settings_get_binary_group(struct vpn_plugin_data *data)
{
	if (data && data->binary_group)
		return data->binary_group;

	return connman_vpn_settings.binary_group;
}

char **__vpn_settings_get_binary_supplementary_groups
						(struct vpn_plugin_data *data)
{
	if (data && data->binary_supplementary_groups)
		return data->binary_supplementary_groups;

	return connman_vpn_settings.binary_supplementary_groups;
}

unsigned int __vpn_settings_get_timeout_inputreq()
{
	return connman_vpn_settings.timeout_inputreq;
}

char *__vpn_settings_get_string(GKeyFile *config, const char *group,
		const char *key)
{
	char *str = g_key_file_get_string(config, group, key, NULL);
	return str ? g_strstrip(str) : NULL;
}

char **__vpn_settings_get_string_list(GKeyFile *config, const char *group,
		const char *key)
{
	int i = 0;
	gsize len = 0;

	char **str = g_key_file_get_string_list(config, group, key, &len, NULL);

	if (str)
	{
		for (i = 0; i < len ; i++)
			str[i] = g_strstrip(str[i]);
	}

	return str;
}

static gboolean get_perm(GKeyFile *config, const char *group,
		const char *key, mode_t *perm)
{
	gboolean ok = FALSE;
	char *str = g_key_file_get_string(config, group, key, NULL);
	if (str) {
		/*
		 * Some people are thinking that # is a comment
		 * anywhere on the line, not just at the beginning
		 */
		unsigned long val;
		char *comment = strchr(str, '#');
		if (comment) *comment = 0;
		val = strtoul(g_strstrip(str), NULL, 0);
		if (val > 0 && !(val & ~0777UL)) {
			*perm = (mode_t)val;
			ok = TRUE;
		}
		g_free(str);
	}
	return ok;
}

static void parse_config(GKeyFile *config, const char *file)
{
	const char *group = "General";
	const char *vpn_group = "VPNBinary";
	GError *error = NULL;
	int timeout;

	if (!config)
		return;

	DBG("parsing %s", file);

	timeout = g_key_file_get_integer(config, group,
			"InputRequestTimeout", &error);
	if (!error && timeout >= 0)
		connman_vpn_settings.timeout_inputreq = timeout * 1000;

	g_clear_error(&error);

	connman_vpn_settings.fs_identity =
		__vpn_settings_get_string(config, group, "FileSystemIdentity");
	connman_vpn_settings.storage_root =
		__vpn_settings_get_string(config, group, "StorageRoot");
	connman_vpn_settings.state_dir =
		__vpn_settings_get_string(config, group, "StateDirectory");

	get_perm(config, group, "StorageDirPermissions",
			&connman_vpn_settings.storage_dir_permissions);
	get_perm(config, group, "StorageFilePermissions",
			&connman_vpn_settings.storage_file_permissions);
	get_perm(config, group, "Umask", &connman_vpn_settings.umask);

	connman_vpn_settings.binary_user = __vpn_settings_get_string(config,
						vpn_group, "User");
	connman_vpn_settings.binary_group = __vpn_settings_get_string(config,
						vpn_group, "Group");
	connman_vpn_settings.binary_supplementary_groups = 
			__vpn_settings_get_string_list(config, vpn_group,
					"SupplementaryGroups");
}

struct vpn_plugin_data *__vpn_settings_get_vpn_plugin_config(const char *name)
{
	struct vpn_plugin_data *data = NULL;

	if (plugin_hash)
		data = g_hash_table_lookup(plugin_hash, name);

	return data;
}

void vpn_plugin_data_free(gpointer data)
{
	struct vpn_plugin_data *plugin_data = (struct vpn_plugin_data*)data;

	g_free(plugin_data->binary_user);
	g_free(plugin_data->binary_group);
	g_strfreev(plugin_data->binary_supplementary_groups);

	g_free(data);
}

int __vpn_settings_parse_vpn_plugin_config(const char *name)
{
	struct vpn_plugin_data *data = NULL;
	gchar *file = NULL;
	gchar *group = "VPNBinary";
	gchar *ext = ".conf";
	GKeyFile *config = NULL;
	gint err = 0;

	if (!name || !*name)
		return 1;

	file = g_strconcat(PLUGIN_CONFIGDIR, "/", name, ext, NULL);

	config =  __vpn_settings_load_config(file);

	if (!config) {
		err = 1;
		DBG("Cannot load config %s for %s", file, name);
		goto out;
	}

	data = g_try_new0(struct vpn_plugin_data, 1);

	data->binary_user = __vpn_settings_get_string(config, group, "User");
	data->binary_group = __vpn_settings_get_string(config, group, "Group");
	data->binary_supplementary_groups =
		__vpn_settings_get_string_list(config, group,
						"SupplementaryGroups");

	DBG("Loaded settings for %s: %s - %s",
		name, data->binary_user, data->binary_group);

	if (!plugin_hash)
		plugin_hash = g_hash_table_new_full(g_str_hash,	g_str_equal,
			g_free, vpn_plugin_data_free);

	g_hash_table_replace(plugin_hash, g_strdup(name), data);

	g_key_file_unref(config);

out:
	g_free(file);
	return err;
}

void __vpn_settings_delete_vpn_plugin_config(const char *name)
{
	if (plugin_hash && name)
		g_hash_table_remove(plugin_hash, name);
}

GKeyFile *__vpn_settings_load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	return keyfile;
}

int __vpn_settings_init(const char *file)
{
	GKeyFile *config;

	config = __vpn_settings_load_config(file);
	parse_config(config, file);
	if (config)
		g_key_file_unref(config);

	return 0;
}

void __vpn_settings_free()
{
	g_free(connman_vpn_settings.fs_identity);
	g_free(connman_vpn_settings.storage_root);
	g_free(connman_vpn_settings.state_dir);
	g_free(connman_vpn_settings.binary_user);
	g_free(connman_vpn_settings.binary_group);
	g_strfreev(connman_vpn_settings.binary_supplementary_groups);

	if (plugin_hash) {
		g_hash_table_destroy(plugin_hash);
		plugin_hash = NULL;
	}
}
