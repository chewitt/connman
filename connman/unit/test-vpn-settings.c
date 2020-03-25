/*
 *  ConnMan VPN daemon settings unit tests
 *
 *  Copyright (C) 2018-2020  Jolla Ltd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <errno.h>

#include "src/connman.h"
#include "../vpn/vpn.h"

#define TEST_PREFIX "/vpn-settings"
#define TEST_PATH_PREFIX "connman_test"
#define TEST_PATH_PREFIX_PLUGIN "vpn-plugin"
#define CONFFILE "connman-vpn.conf"

/* overrides for pwd functionality */
struct passwd {
	char	*pw_name;	/* username */
	char	*pw_passwd;	/* user password */
	uid_t	pw_uid;		/* user ID */
	gid_t	pw_gid;		/* group ID */
	char	*pw_gecos;	/* user information */
	char	*pw_dir;	/* home directory */
	char	*pw_shell;	/* shell program */
};

static struct passwd passwd_list[] = {
	{
		.pw_name = "root",
		.pw_uid = 0,
		.pw_shell = "/sbin/bash",
	},
	{
		.pw_name = "user",
		.pw_uid = 1000,
		.pw_shell = "/bin/sh",
	},
	{
		.pw_name = "username",
		.pw_uid = 1001,
		.pw_shell = "/bin/sh",
	},
	{
		.pw_name = "toor",
		.pw_uid = 999,
		.pw_shell = "/usr/bin/nologin",
	},
	{
		.pw_name = "sys",
		.pw_uid = 1,
		.pw_shell = "/bin/false",
	}
};

struct passwd *getpwnam(const char *name)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(passwd_list); i++) {
		if (!g_strcmp0(passwd_list[i].pw_name, name))
			return &passwd_list[i];
	}

	return NULL;
}

uid_t geteuid(void)
{
	return 0;
}

static gchar* setup_test_directory()
{
	gchar *test_path = NULL;

	test_path = g_strdup_printf("%s/%s.XXXXXX", g_get_tmp_dir(),
				TEST_PATH_PREFIX);
	g_assert(test_path);

	test_path = g_mkdtemp_full(test_path, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
	g_assert(test_path);

	DBG("setup test dir %s", test_path);

	g_assert_true(g_file_test(test_path, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(test_path, G_FILE_TEST_IS_DIR));
	g_assert_cmpint(g_access(test_path, R_OK|W_OK|X_OK), ==, 0);

	return test_path;
}

static gchar* setup_plugin_test_directory(const char *path)
{
	gchar *plugin_path = g_build_filename(path, TEST_PATH_PREFIX_PLUGIN,
				NULL);

	g_assert(plugin_path);

	g_assert_cmpint(g_mkdir_with_parents(plugin_path,
				S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH), ==, 0);

	g_assert_true(g_file_test(plugin_path, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(plugin_path, G_FILE_TEST_IS_DIR));
	g_assert_cmpint(g_access(plugin_path, F_OK), ==, 0);
	g_assert_cmpint(g_access(plugin_path, R_OK|X_OK|W_OK), ==, 0);

	DBG("plugin dir %s", plugin_path);

	return plugin_path;
}

static void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;

	if (g_file_test(test_path, G_FILE_TEST_IS_DIR)) {
		g_assert(!access(test_path, access_mode));
		g_rmdir(test_path);
	}
}

static void set_and_verify_content(const gchar *file, gchar **content_in)
{
	const char separator[] = "\n";
	gchar *content = NULL;
	gchar *content_verify = NULL;
	gsize content_verify_len = 0;

	g_assert(file);

	if(!content_in || g_strv_length(content_in) == 0)
		content = g_strdup("");
	else
		content = g_strjoinv(separator, content_in);

	DBG("set file %s content:%s", file, content);

	g_assert_true(g_file_set_contents(file, content, -1, NULL));
	g_assert(g_file_get_contents(file, &content_verify,
				&content_verify_len, NULL));

	g_assert(g_ascii_strcasecmp(content, content_verify) == 0);

	g_free(content);
	g_free(content_verify);
}

static void test_vpn_settings_no_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_build_filename(test_path, CONFFILE, NULL);
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	guint timeout = 300 * 1000;

	g_assert_cmpint(__vpn_settings_init(NULL, NULL), ==, -EINVAL);
	g_assert_cmpint(__vpn_settings_init(NULL, test_path), ==, -EINVAL);
	g_assert_cmpint(__vpn_settings_init(file_path, NULL), ==, -EINVAL);
	g_assert_cmpint(__vpn_settings_init(file_path, test_path), ==, 0);

	g_assert(vpn_settings_get_state_dir());
	g_assert(g_ascii_strcasecmp(vpn_settings_get_state_dir(),
				DEFAULT_VPN_STATEDIR) == 0);
	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root());
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_storage_root(),
				DEFAULT_STORAGE_ROOT) == 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);

	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);

	g_assert(vpn_settings_get_binary_user(NULL) == NULL);
	g_assert(vpn_settings_get_binary_group(NULL) == NULL);

	g_assert(!vpn_settings_get_binary_supplementary_groups(NULL));

	__vpn_settings_cleanup();

	g_remove(file_path);
	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(file_path);
}

static void test_vpn_settings_empty_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_build_filename(test_path, CONFFILE, NULL);
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	guint timeout = 300 * 1000;

	set_and_verify_content(file_path, NULL);
	g_assert_cmpint(__vpn_settings_init(file_path, test_path), ==, 0);

	g_assert(vpn_settings_get_state_dir());
	g_assert(g_ascii_strcasecmp(vpn_settings_get_state_dir(),
				DEFAULT_VPN_STATEDIR) == 0);
	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root());
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_storage_root(),
				DEFAULT_STORAGE_ROOT) == 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);

	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);

	g_assert(vpn_settings_get_binary_user(NULL) == NULL);
	g_assert(vpn_settings_get_binary_group(NULL) == NULL);

	g_assert(!vpn_settings_get_binary_supplementary_groups(NULL));

	__vpn_settings_cleanup();

	g_remove(file_path);
	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(file_path);
}

static void test_vpn_settings_plugin_empty_config()
{
	gchar *test_path = setup_test_directory();
	gchar *test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *plugin_name = "test_plugin";
	gchar *plugin_path = setup_plugin_test_directory(test_path);
	gchar *plugin_file = g_strconcat(plugin_path, "/", plugin_name,
				".conf", NULL);
	struct vpn_plugin_data *test_data = NULL;

	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	set_and_verify_content(plugin_file, NULL);

	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(NULL), ==,
								-EINVAL);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								0);

	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);
	g_assert(test_data);

	g_assert(vpn_settings_get_binary_user(test_data) == NULL);
	g_assert(vpn_settings_get_binary_group(test_data) == NULL);

	g_assert(!vpn_settings_get_binary_supplementary_groups(test_data));

	vpn_settings_delete_vpn_plugin_config(NULL);
	vpn_settings_delete_vpn_plugin_config("plugin");
	__vpn_settings_cleanup();

	g_remove(plugin_file);
	g_remove(plugin_path);
	g_remove(test_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_path);
	g_free(plugin_file);
}

static void test_vpn_settings_plugin_default_config()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar* plugin_name = "test_plugin";
	gchar *plugin_path = setup_plugin_test_directory(test_path);
	gchar *plugin_file = g_strconcat(plugin_path, "/", plugin_name,
				".conf", NULL);
	gchar *content_min[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};

	gchar **groups = NULL;
	const gchar *group_verify[] = {"inet", "net_admin", "net_raw", NULL};
	gint i = 0;
	struct vpn_plugin_data *test_data = NULL;

	set_and_verify_content(test_file, content_min);
	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								-ENOENT);

	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);

	g_assert(!test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"user") == 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_group(test_data),
								"vpn") == 0);

	groups = vpn_settings_get_binary_supplementary_groups(test_data);
	g_assert(groups);

	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);

	vpn_settings_delete_vpn_plugin_config(NULL);
	vpn_settings_delete_vpn_plugin_config(plugin_name);
	__vpn_settings_cleanup();

	g_remove(test_file);
	g_remove(plugin_path);
	g_remove(plugin_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_path);
	g_free(plugin_file);
}

static void test_vpn_settings_min_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content_min[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};

	gchar **groups = NULL;
	const gchar *group_verify[] = {"inet", "net_admin", "net_raw", NULL};
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	gint i = 0;
	guint timeout = 200 * 1000;

	set_and_verify_content(file_path, content_min);

	g_assert_cmpint(__vpn_settings_init(file_path, test_path), ==, 0);

	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root());
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_storage_root(),
				DEFAULT_STORAGE_ROOT) == 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);

	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(NULL), "user")
									== 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_group(NULL), "vpn")
									== 0);

	groups = vpn_settings_get_binary_supplementary_groups(NULL);
	g_assert(groups);

	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);

	__vpn_settings_cleanup();

	g_remove(file_path);
	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(file_path);
}

static void test_vpn_settings_full_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content_full[] = {
		"# ConnMan vpn-settings test full",
		"[General]",
		"FileSystemIdentity = root",
		"StateDirectory = /tmp/state",
		"StorageRoot = /tmp/storage",
		"StorageDirPermissions = 0754",
		"StorageFilePermissions = 0645",
		"Umask = 0067",
		"InputRequestTimeout = 100",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet,net_admin",
		NULL
	};

	gchar **groups = NULL;
	const gchar *group_verify[] = {"inet", "net_admin", NULL};
	mode_t dir_p = 0754, file_p = 0645, umask = 0067;
	gint i = 0;
	guint timeout = 100 * 1000;

	set_and_verify_content(file_path, content_full);

	g_assert_cmpint(__vpn_settings_init(file_path, test_path), ==, 0);

	g_assert(g_ascii_strcasecmp(__vpn_settings_get_fs_identity(),
		"root")== 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_state_dir(),
		"/tmp/state") == 0);
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_storage_root(),
		"/tmp/storage") == 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);

	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(NULL), "user")
									== 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_group(NULL), "vpn")
									== 0);

	groups = vpn_settings_get_binary_supplementary_groups(NULL);
	g_assert(groups);

	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);

	__vpn_settings_cleanup();

	g_remove(file_path);
	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(file_path);
}

/* Cannot read the set config, values should be default */
static void test_vpn_settings_invalid_config1()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content_min[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 300",
		"StorageDirPermissions = 0754",
		"StorageFilePermissions = 0645",
		"Umask = 0",
		NULL
	};
	mode_t normal_access = 0600, no_access = 0000;
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	guint timeout = 300 * 1000;

	set_and_verify_content(test_file, content_min);
	g_assert_cmpint(g_chmod(test_file, no_access), ==, 0);

	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);

	DBG("timeout %u", __vpn_settings_get_timeout_inputreq());
	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);

	g_assert(vpn_settings_get_binary_user(NULL) == NULL);
	g_assert(vpn_settings_get_binary_group(NULL) == NULL);

	g_assert(!vpn_settings_get_binary_supplementary_groups(NULL));

	__vpn_settings_cleanup();

	g_assert_cmpint(g_chmod(test_file, normal_access), ==, 0);

	g_remove(test_file);
	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
}

/* Invalid values in config */
static void test_vpn_settings_invalid_config2()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content_min[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 0",
		"StorageDirPermissions = 07#54",
		"StorageFilePermissions = 0645#",
		"Umask = 0",
		NULL
	};
	mode_t dir_p = 0754, file_p = 0645, umask = 0077;
	guint timeout = 0;

	set_and_verify_content(test_file, content_min);

	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root());
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_storage_root(),
				DEFAULT_STORAGE_ROOT) == 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() != dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	/* The default umask is used */
	g_assert(__vpn_settings_get_umask() == umask);

	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);

	__vpn_settings_cleanup();

	g_remove(test_file);
	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
}

static void test_vpn_settings_plugin_config1()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		NULL
	};

	gchar* plugin_name = "test_plugin";
	gchar *plugin_file = NULL;
	gchar* plugin_path = NULL;
	gchar *plugin_content[] = {
		"# ConnMan vpn-settings plugin test config",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};

	gchar **groups = NULL;
	const gchar *group_verify[] = {"inet", "net_admin", "net_raw", NULL};
	gint i = 0;
	struct vpn_plugin_data *test_data = NULL;

	set_and_verify_content(test_file, content);
	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	/* Prepare plugin content */
	plugin_path = setup_plugin_test_directory(test_path);
	plugin_file = g_strdup_printf("%s/%s.conf", plugin_path, plugin_name);
	set_and_verify_content(plugin_file, plugin_content);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								0);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								-EALREADY);

	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);
	g_assert(test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"user") == 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_group(test_data),
								"vpn") == 0);

	groups = vpn_settings_get_binary_supplementary_groups(test_data);
	g_assert(groups);
	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);

	vpn_settings_delete_vpn_plugin_config(plugin_name);
	__vpn_settings_cleanup();

	g_remove(plugin_file);
	g_remove(plugin_path);
	g_remove(test_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_file);
	g_free(plugin_path);
}

static void test_vpn_settings_plugin_config2()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[DACPrivileges]",
		"User = user2",
		"Group = vpn2",
		"SupplementaryGroups = inet2, net_admin2",
		NULL
	};

	gchar *plugin_name = "test_plugin";
	gchar *plugin2_name = "test_plugin2";
	gchar *plugin_file = NULL;
	gchar *plugin_path = NULL;
	gchar *plugin_content[] = {
		"# ConnMan vpn-settings plugin test config",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};

	gchar **groups = NULL;
	const gchar *group_verify[] = {"inet", "net_admin", "net_raw", NULL};
	const gchar *group_verify2[] = {"inet2", "net_admin2", NULL};
	gint i = 0;
	struct vpn_plugin_data *test_data = NULL;

	set_and_verify_content(test_file, content);
	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	/* Prepare plugin content */
	plugin_path = setup_plugin_test_directory(test_path);
	plugin_file = g_strdup_printf("%s/%s.conf", plugin_path, plugin_name);
	set_and_verify_content(plugin_file, plugin_content);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								0);

	/* Plugin with config */
	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);
	g_assert(test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"user") == 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_group(test_data),
								"vpn") == 0);

	groups = vpn_settings_get_binary_supplementary_groups(test_data);
	g_assert(groups);
	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);

	/* Plugin without config */
	test_data = vpn_settings_get_vpn_plugin_config(plugin2_name);
	g_assert(!test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"user2") == 0);
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_group(test_data),
								"vpn2") == 0);

	groups = vpn_settings_get_binary_supplementary_groups(test_data);
	g_assert(groups);

	for(i = 0; groups[i]; i++) {
		DBG("compare %s - %s", groups[i], group_verify2[i]);
		g_assert(g_ascii_strcasecmp(groups[i], group_verify2[i]) == 0);
	}

	vpn_settings_delete_vpn_plugin_config(plugin_name);
	vpn_settings_delete_vpn_plugin_config(plugin2_name);
	__vpn_settings_cleanup();

	g_remove(plugin_file);
	g_remove(plugin_path);
	g_remove(test_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_file);
	g_free(plugin_path);
}

/* No SystemBinaryUsers set - override works */
static void test_vpn_settings_plugin_config_override1()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		NULL
	};

	gchar* plugin_name = "test_plugin";
	gchar *plugin_file = NULL;
	gchar* plugin_path = NULL;
	gchar *plugin_content[] = {
		"# ConnMan vpn-settings plugin test config",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};
	gchar* plugin2_name = "test_plugin2";
	gchar *plugin2_file = NULL;
	/* Omits user */
	gchar *plugin2_content[] = {
		"# ConnMan vpn-settings plugin test config",
		"[DACPrivileges]",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};
	struct vpn_plugin_data *test_data = NULL;

	set_and_verify_content(test_file, content);
	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	/* Prepare plugin content */
	plugin_path = setup_plugin_test_directory(test_path);
	plugin_file = g_strdup_printf("%s/%s.conf", plugin_path, plugin_name);
	set_and_verify_content(plugin_file, plugin_content);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								0);

	/* Prepare plugin content without username */
	plugin2_file = g_strdup_printf("%s/%s.conf", plugin_path,
				plugin2_name);
	set_and_verify_content(plugin2_file, plugin2_content);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin2_name), ==,
								0);

	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);
	g_assert(test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"user") == 0);

	/* Override works */
	__vpn_settings_set_binary_user_override("username");
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
							"username") == 0);

	/* No username set in plugin or main config - override is not used */
	test_data = vpn_settings_get_vpn_plugin_config(plugin2_name);
	g_assert(test_data);
	g_assert(vpn_settings_get_binary_user(test_data) == NULL);

	__vpn_settings_set_binary_user_override(NULL);

	vpn_settings_delete_vpn_plugin_config(plugin_name);
	vpn_settings_delete_vpn_plugin_config(plugin2_name);
	__vpn_settings_cleanup();

	g_remove(plugin_file);
	g_remove(plugin2_file);
	g_remove(plugin_path);
	g_remove(test_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_file);
	g_free(plugin2_file);
	g_free(plugin_path);
}

/* SystemBinaryUsers set but User for VPN is different, override works */
static void test_vpn_settings_plugin_config_override2()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[DACPrivileges]",
		"SystemBinaryUsers = toor, sys",
		NULL
	};

	gchar* plugin_name = "test_plugin";
	gchar *plugin_file = NULL;
	gchar* plugin_path = NULL;
	gchar *plugin_content[] = {
		"# ConnMan vpn-settings plugin test config",
		"[DACPrivileges]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};
	struct vpn_plugin_data *test_data = NULL;

	set_and_verify_content(test_file, content);
	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	/* Prepare plugin content */
	plugin_path = setup_plugin_test_directory(test_path);
	plugin_file = g_strdup_printf("%s/%s.conf", plugin_path, plugin_name);
	set_and_verify_content(plugin_file, plugin_content);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								0);

	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);
	g_assert(test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"user") == 0);

	/* Regular username can be overridden */
	__vpn_settings_set_binary_user_override("username");
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
							"username") == 0);
	__vpn_settings_set_binary_user_override(NULL);

	vpn_settings_delete_vpn_plugin_config(plugin_name);
	__vpn_settings_cleanup();

	g_remove(plugin_file);
	g_remove(plugin_path);
	g_remove(test_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_file);
	g_free(plugin_path);
}

/* Binary user is system user - override is not used */
static void test_vpn_settings_plugin_config_override3()
{
	gchar* test_path = setup_test_directory();
	gchar* test_file = g_build_filename(test_path, CONFFILE, NULL);
	gchar *content[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[DACPrivileges]",
		"SystemBinaryUsers = toor, sys",
		NULL
	};

	gchar* plugin_name = "test_plugin";
	gchar *plugin_file = NULL;
	gchar* plugin_path = NULL;
	gchar *plugin_content[] = {
		"# ConnMan vpn-settings plugin test config",
		"[DACPrivileges]",
		"User = toor",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};
	struct vpn_plugin_data *test_data = NULL;

	set_and_verify_content(test_file, content);
	g_assert_cmpint(__vpn_settings_init(test_file, test_path), ==, 0);

	/* Prepare plugin content */
	plugin_path = setup_plugin_test_directory(test_path);
	plugin_file = g_strdup_printf("%s/%s.conf", plugin_path, plugin_name);
	set_and_verify_content(plugin_file, plugin_content);
	g_assert_cmpint(vpn_settings_parse_vpn_plugin_config(plugin_name), ==,
								0);

	test_data = vpn_settings_get_vpn_plugin_config(plugin_name);
	g_assert(test_data);

	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
								"toor") == 0);

	/* Cannot override system user */
	__vpn_settings_set_binary_user_override("username");
	g_assert(g_ascii_strcasecmp(vpn_settings_get_binary_user(test_data),
							"toor") == 0);
	__vpn_settings_set_binary_user_override(NULL);

	vpn_settings_delete_vpn_plugin_config(plugin_name);
	__vpn_settings_cleanup();

	g_remove(plugin_file);
	g_remove(plugin_path);
	g_remove(test_file);

	cleanup_test_directory(test_path);

	g_free(test_path);
	g_free(test_file);
	g_free(plugin_file);
	g_free(plugin_path);
}

static gchar *option_debug = NULL;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

int main(int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else {
			g_printerr("An unknown error occurred\n");
		}
		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func(TEST_PREFIX "/no_config",
		test_vpn_settings_no_config);
	g_test_add_func(TEST_PREFIX "/empty_config",
		test_vpn_settings_empty_config);
	g_test_add_func(TEST_PREFIX "/plugin_empty_config",
		test_vpn_settings_plugin_empty_config);
	g_test_add_func(TEST_PREFIX "/plugin_default_config",
		test_vpn_settings_plugin_default_config);
	g_test_add_func(TEST_PREFIX "/min_config",
		test_vpn_settings_min_config);
	g_test_add_func(TEST_PREFIX "/full_config",
		test_vpn_settings_full_config);
	g_test_add_func(TEST_PREFIX "/invalid_config1",
		test_vpn_settings_invalid_config1);
	g_test_add_func(TEST_PREFIX "/invalid_config2",
		test_vpn_settings_invalid_config2);
	g_test_add_func(TEST_PREFIX "/plugin_test_config1",
		test_vpn_settings_plugin_config1);
	g_test_add_func(TEST_PREFIX "/plugin_test_config2",
		test_vpn_settings_plugin_config2);
	g_test_add_func(TEST_PREFIX "/plugin_test_config_override1",
		test_vpn_settings_plugin_config_override1);
	g_test_add_func(TEST_PREFIX "/plugin_test_config_override2",
		test_vpn_settings_plugin_config_override2);
	g_test_add_func(TEST_PREFIX "/plugin_test_config_override3",
		test_vpn_settings_plugin_config_override3);

	return g_test_run();
}
