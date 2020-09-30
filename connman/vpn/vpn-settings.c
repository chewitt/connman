/*
 *  ConnMan VPN daemon settings
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018-2020 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
 *  Contact: jussi.laakkonen@jolla.com
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
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>

#include <connman/log.h>

#include "vpn.h"

#define DEFAULT_INPUT_REQUEST_TIMEOUT 300 * 1000
#define DEFAULT_STORAGE_DIR_PERMISSIONS (0700)
#define DEFAULT_STORAGE_FILE_PERMISSIONS (0600)
#define DEFAULT_UMASK (0077)

#define PLUGIN_CONFIGDIR "vpn-plugin"
#define VPN_GROUP "DACPrivileges"

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
	char *binary_user_override;
	char **system_binary_users;
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
	.binary_user_override		= NULL,
	.system_binary_users		= NULL,
};

struct vpn_plugin_data {
	char *binary_user;
	char *binary_group;
	char **binary_supplementary_groups;
};

GHashTable *plugin_hash = NULL;
static char *configdir = NULL;

const char *vpn_settings_get_state_dir()
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
	return connman_vpn_settings.storage_root ?
				connman_vpn_settings.storage_root :
				DEFAULT_STORAGE_ROOT;
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

void __vpn_settings_set_binary_user_override(uid_t uid, void *user_data)
{
	struct passwd *pwd;

	if (connman_vpn_settings.binary_user_override) {
		g_free(connman_vpn_settings.binary_user_override);
		connman_vpn_settings.binary_user_override = NULL;
	}

	/* Setting override to root (0) resets the override */
	if (!uid)
		return;

	pwd = getpwuid(uid);
	if (!pwd)
		return;

	connman_vpn_settings.binary_user_override = g_strdup(pwd->pw_name);
}

bool vpn_settings_is_system_user(const char *user)
{
	struct passwd *pwd;
	struct passwd *system_pwd;
	int i;

	/*
	 * The username is not set = override should not be used. This is the
	 * case after the override is reset.
	 */
	if (!user)
		return true;

	DBG("check user \"%s\"", user);

	/*
	 * Ignore errors if no entry was found. Treat as system user to
	 * prevent using an invalid override.
	 */
	pwd = vpn_util_get_passwd(user);
	if (!pwd)
		return true;

	if (!connman_vpn_settings.system_binary_users) {
		DBG("no binary users set");

		/*
		 * Check if the user is root, or the uid equals to process
		 * effective uid.
		 */
		return !pwd->pw_uid || pwd->pw_uid == geteuid();
	}

	/* Root set as user or the effective user id */
	if (!pwd->pw_uid || pwd->pw_uid == geteuid())
		return true;

	for (i = 0; connman_vpn_settings.system_binary_users[i]; i++) {
		const char *system_user =
				connman_vpn_settings.system_binary_users[i];

		system_pwd = vpn_util_get_passwd(system_user);
		if (!system_pwd)
			continue;

		if (pwd->pw_uid == system_pwd->pw_uid)
			return true;
	}

	return false;
}

const char *vpn_settings_get_binary_user(struct vpn_plugin_data *data)
{
	const char *binary_user;

	if (data && data->binary_user)
		binary_user = data->binary_user;
	else
		binary_user = connman_vpn_settings.binary_user;

	/*
	 * Use overridden user instead configured one if set, but don't
	 * override configured  system user.
	 */
	if (connman_vpn_settings.binary_user_override &&
				!vpn_settings_is_system_user(binary_user))
		binary_user = connman_vpn_settings.binary_user_override;

	return binary_user;
}

const char *vpn_settings_get_binary_group(struct vpn_plugin_data *data)
{
	if (data && data->binary_group)
		return data->binary_group;

	return connman_vpn_settings.binary_group;
}

char **vpn_settings_get_binary_supplementary_groups(struct vpn_plugin_data *data)
{
	if (data && data->binary_supplementary_groups)
		return data->binary_supplementary_groups;

	return connman_vpn_settings.binary_supplementary_groups;
}

unsigned int __vpn_settings_get_timeout_inputreq()
{
	return connman_vpn_settings.timeout_inputreq;
}

static char *get_string(GKeyFile *config, const char *group, const char *key)
{
	char *str = g_key_file_get_string(config, group, key, NULL);
	return str ? g_strstrip(str) : NULL;
}

static char **get_string_list(GKeyFile *config, const char *group,
				const char *key)
{
	gsize len = 0;
	char **str = g_key_file_get_string_list(config, group, key, &len, NULL);

	if (str) {
		guint i = 0;

		for (i = 0; i < len ; i++) {
			str[i] = g_strstrip(str[i]);
		}
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
		get_string(config, group, "FileSystemIdentity");
	connman_vpn_settings.storage_root =
		get_string(config, group, "StorageRoot");
	connman_vpn_settings.state_dir =
		get_string(config, group, "StateDirectory");

	get_perm(config, group, "StorageDirPermissions",
			&connman_vpn_settings.storage_dir_permissions);
	get_perm(config, group, "StorageFilePermissions",
			&connman_vpn_settings.storage_file_permissions);
	get_perm(config, group, "Umask", &connman_vpn_settings.umask);

	connman_vpn_settings.binary_user = get_string(config, VPN_GROUP,
						"User");
	connman_vpn_settings.binary_group = get_string(config, VPN_GROUP,
						"Group");
	connman_vpn_settings.binary_supplementary_groups = get_string_list(
						config, VPN_GROUP,
						"SupplementaryGroups");
	connman_vpn_settings.system_binary_users = get_string_list(
						config, VPN_GROUP,
						"SystemBinaryUsers");
}

struct vpn_plugin_data *vpn_settings_get_vpn_plugin_config(const char *name)
{
	struct vpn_plugin_data *data = NULL;

	if (plugin_hash)
		data = g_hash_table_lookup(plugin_hash, name);

	return data;
}

static void vpn_plugin_data_free(gpointer data)
{
	struct vpn_plugin_data *plugin_data = (struct vpn_plugin_data*)data;

	g_free(plugin_data->binary_user);
	g_free(plugin_data->binary_group);
	g_strfreev(plugin_data->binary_supplementary_groups);

	g_free(data);
}

int vpn_settings_parse_vpn_plugin_config(const char *name)
{
	struct vpn_plugin_data *data;
	gchar *file;
	gchar *ext = ".conf";
	GKeyFile *config;
	gint err = 0;

	if (!name || !*name)
		return -EINVAL;

	if (vpn_settings_get_vpn_plugin_config(name))
		return -EALREADY;

	file = g_strconcat(configdir, "/", name, ext, NULL);

	config =  __vpn_settings_load_config(file);

	if (!config) {
		err = -ENOENT;
		DBG("Cannot load config %s for %s", file, name);
		goto out;
	}

	data = g_try_new0(struct vpn_plugin_data, 1);

	data->binary_user = get_string(config, VPN_GROUP, "User");
	data->binary_group = get_string(config, VPN_GROUP, "Group");
	data->binary_supplementary_groups = get_string_list(config, VPN_GROUP,
						"SupplementaryGroups");

	DBG("Loaded settings for %s: %s - %s",
		name, data->binary_user, data->binary_group);

	if (!plugin_hash)
		plugin_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, vpn_plugin_data_free);

	g_hash_table_replace(plugin_hash, g_strdup(name), data);

	g_key_file_unref(config);

out:
	g_free(file);
	return err;
}

void vpn_settings_delete_vpn_plugin_config(const char *name)
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

int __vpn_settings_init(const char *file, const char *dir)
{
	GKeyFile *config;

	if (!file || !dir)
		return -EINVAL;

	connman_vpn_settings.timeout_inputreq = DEFAULT_INPUT_REQUEST_TIMEOUT;
	connman_vpn_settings.storage_dir_permissions =
				DEFAULT_STORAGE_DIR_PERMISSIONS;
	connman_vpn_settings.storage_file_permissions =
				DEFAULT_STORAGE_FILE_PERMISSIONS;
	connman_vpn_settings.umask = DEFAULT_UMASK;

	configdir = g_build_filename(dir, PLUGIN_CONFIGDIR, NULL);

	config = __vpn_settings_load_config(file);
	parse_config(config, file);
	if (config)
		g_key_file_unref(config);

	return 0;
}

void __vpn_settings_cleanup()
{
	g_free(connman_vpn_settings.fs_identity);
	connman_vpn_settings.fs_identity = NULL;

	g_free(connman_vpn_settings.storage_root);
	connman_vpn_settings.storage_root = NULL;

	g_free(connman_vpn_settings.state_dir);
	connman_vpn_settings.state_dir = NULL;

	g_free(connman_vpn_settings.binary_user);
	connman_vpn_settings.binary_user = NULL;

	g_free(connman_vpn_settings.binary_group);
	connman_vpn_settings.binary_group = NULL;

	g_strfreev(connman_vpn_settings.binary_supplementary_groups);
	connman_vpn_settings.binary_supplementary_groups = NULL;

	g_strfreev(connman_vpn_settings.system_binary_users);
	connman_vpn_settings.system_binary_users = NULL;

	g_free(connman_vpn_settings.binary_user_override);
	connman_vpn_settings.binary_user_override = NULL;

	g_free(configdir);
	configdir = NULL;

	if (plugin_hash) {
		g_hash_table_destroy(plugin_hash);
		plugin_hash = NULL;
	}
}
