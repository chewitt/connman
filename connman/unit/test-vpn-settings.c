/*
 *
 *  ConnMan VPN daemon settings unit tests
 *
 *  Copyright (C) 2018 Jolla Ltd. All rights reserved.
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>

#include "src/connman.h"
#include "../vpn/vpn.h"

#define TEST_PREFIX "/vpn-settings"
#define TEST_PATH_PREFIX "/tmp/connman_test"

gchar* setup_test_directory()
{
	gchar *test_path = NULL;

	test_path = g_strdup_printf("%s.XXXXXX", TEST_PATH_PREFIX);
	
	g_assert(test_path);
	
	if(!g_file_test(test_path, G_FILE_TEST_EXISTS))
		test_path = g_mkdtemp(test_path);
	
	g_assert(g_file_test(test_path, G_FILE_TEST_EXISTS));
	g_assert(g_file_test(test_path, G_FILE_TEST_IS_DIR));
	
	return test_path;
}

void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;
		
	if(g_file_test(test_path, G_FILE_TEST_IS_DIR))
	{
		g_assert(!access(test_path, access_mode));
		
		g_rmdir(test_path);
	}
}

void set_and_verify_content(const gchar *file, gchar **content_in)
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
	
	g_assert(g_file_set_contents(file, content, -1, NULL));
	
	g_assert(g_file_get_contents(file, &content_verify, &content_verify_len,
		NULL));
	
	g_assert(g_ascii_strcasecmp(content, content_verify) == 0);
	
	g_free(content);
	g_free(content_verify);
}

void test_vpn_settings_no_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_strdup_printf("%s%s", test_path, "/connman-vpn.conf");
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	gint timeout = 300 * 1000;
	
	__vpn_settings_init(file_path);
	
	//g_assert(g_ascii_strcasecmp( __vpn_settings_state_dir()) == 0);
	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root() == NULL);
	
	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);
	
	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);
	
	g_assert(__vpn_settings_get_binary_user(NULL) == NULL);
	g_assert(__vpn_settings_get_binary_group(NULL) == NULL);
	
	char **groups = __vpn_settings_get_binary_supplementary_groups(NULL);
	
	g_assert(groups == NULL);
	
	__vpn_settings_free();
	
	cleanup_test_directory(test_path);
	
	g_free(test_path);
	g_free(file_path);
}

void test_vpn_settings_empty_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_strdup_printf("%s%s", test_path, "/connman-vpn.conf");
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	gint timeout = 300 * 1000;
	
	set_and_verify_content(file_path, NULL);
	
	__vpn_settings_init(file_path);
	
	//g_assert(g_ascii_strcasecmp( __vpn_settings_state_dir()) == 0);
	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root() == NULL);
	
	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);
	
	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);
	
	g_assert(__vpn_settings_get_binary_user(NULL) == NULL);
	g_assert(__vpn_settings_get_binary_group(NULL) == NULL);
	
	char **groups = __vpn_settings_get_binary_supplementary_groups(NULL);
	
	g_assert(groups == NULL);
	
	__vpn_settings_free();
	
	cleanup_test_directory(test_path);
	
	g_free(test_path);
	g_free(file_path);
}

void test_vpn_settings_plugin_empty_config()
{
	gchar* test_path = setup_test_directory();
	gchar* test_plugin = "test_plugin";
	gchar* file_path = g_strjoin("", test_path, "/", test_plugin, ".conf",
		NULL);
	struct vpn_plugin_data *test_data = NULL;
	
	set_and_verify_content(file_path, NULL);
	
	g_assert(__vpn_settings_parse_vpn_plugin_config(test_plugin) == 1);
	
	test_data =  __vpn_settings_get_vpn_plugin_config(test_plugin);
	
	g_assert(!test_data);
	
	g_assert(__vpn_settings_get_binary_user(test_data) == NULL);
	g_assert(__vpn_settings_get_binary_group(test_data) == NULL);
	
	char **groups = __vpn_settings_get_binary_supplementary_groups(test_data);
	
	g_assert(groups == NULL);
	
	__vpn_settings_free();
	
	cleanup_test_directory(test_path);
	
	g_free(test_path);
	g_free(file_path);
}


void test_vpn_settings_plugin_default_config()
{
	gchar* test_path = setup_test_directory();
	gchar* test_plugin = "test_plugin";
	gchar* file_path = g_strdup_printf("%s%s", test_path, "/connman-vpn.conf");
	
	gchar * content_min[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[VPNBinary]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};
	
	gchar **groups = NULL;
	const gchar const * group_verify[] = {"inet", "net_admin", "net_raw", NULL};
	gint i = 0;

	struct vpn_plugin_data *test_data = NULL;
	
	set_and_verify_content(file_path, content_min);
	
	__vpn_settings_init(file_path);
	
	g_assert(__vpn_settings_parse_vpn_plugin_config(test_plugin) == 1);
	
	test_data =  __vpn_settings_get_vpn_plugin_config(test_plugin);
	
	g_assert(!test_data);
	
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_binary_user(test_data),
		"user") == 0);
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_binary_group(test_data),
		"vpn") == 0);
	
	groups = __vpn_settings_get_binary_supplementary_groups(test_data);
	
	g_assert(groups);
	
	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);
	
	__vpn_settings_free();
	
	cleanup_test_directory(test_path);
	
	g_free(test_path);
	g_free(file_path);
}

void test_vpn_settings_min_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_strdup_printf("%s%s", test_path, "/connman-vpn.conf");
	
	gchar * content_min[] = {
		"# ConnMan vpn-settings test minimal",
		"[General]",
		"InputRequestTimeout = 200",
		"[VPNBinary]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet, net_admin, net_raw",
		NULL
	};
	
	gchar **groups = NULL;
	const gchar const * group_verify[] = {"inet", "net_admin", "net_raw", NULL};
	mode_t dir_p = 0700, file_p = 0600, umask = 0077;
	gint i = 0;
	gint timeout = 200 * 1000;
	
	set_and_verify_content(file_path, content_min);
	
	__vpn_settings_init(file_path);
	
	g_assert(__vpn_settings_get_fs_identity() == NULL);
	g_assert(__vpn_settings_get_storage_root() == NULL);
	
	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);
	
	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);
	
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_binary_user(NULL), "user")
		== 0);
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_binary_group(NULL), "vpn")
		== 0);
	
	groups = __vpn_settings_get_binary_supplementary_groups(NULL);
	
	g_assert(groups);
	
	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);
	
	__vpn_settings_free();
	
	cleanup_test_directory(test_path);
	
	g_free(test_path);
	g_free(file_path);
}

void test_vpn_settings_full_config()
{
	gchar* test_path = setup_test_directory();
	gchar* file_path = g_strdup_printf("%s%s", test_path, "/connman-vpn.conf");
	
	gchar * content_full[] = {
		"# ConnMan vpn-settings test full",
		"[General]",
		"FileSystemIdentity = root",
		"StateDirectory = /tmp/state",
		"StorageRoot = /tmp/storage",
		"StorageDirPermissions = 0754",
		"StorageFilePermissions = 0645",
		"Umask = 0067",
		"InputRequestTimeout = 100",
		"[VPNBinary]",
		"User = user",
		"Group = vpn",
		"SupplementaryGroups = inet,net_admin",
		NULL
	};
	
	gchar **groups = NULL;
	const gchar const * group_verify[] = {"inet", "net_admin", NULL};
	mode_t dir_p = 0754, file_p = 0645, umask = 0067;
	gint i = 0;
	gint timeout = 100 * 1000;
	
	set_and_verify_content(file_path, content_full);
	
	__vpn_settings_init(file_path);
	
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_fs_identity(),
		"root")== 0);
	g_assert(g_ascii_strcasecmp( __vpn_settings_state_dir(),
		"/tmp/state") == 0);	
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_storage_root(),
		"/tmp/storage") == 0);

	g_assert(__vpn_settings_get_storage_dir_permissions() == dir_p);
	g_assert(__vpn_settings_get_storage_file_permissions() == file_p);
	g_assert(__vpn_settings_get_umask() == umask);
	
	g_assert(__vpn_settings_get_timeout_inputreq() == timeout);
	
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_binary_user(NULL), "user")
		== 0);
	g_assert(g_ascii_strcasecmp(__vpn_settings_get_binary_group(NULL), "vpn")
		== 0);
	
	groups = __vpn_settings_get_binary_supplementary_groups(NULL);
	
	g_assert(groups);
	
	for(i = 0; groups[i]; i++)
		g_assert(g_ascii_strcasecmp(groups[i], group_verify[i]) == 0);
	
	__vpn_settings_free();
	
	cleanup_test_directory(test_path);
	
	g_free(test_path);
	g_free(file_path);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	
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
	
	return g_test_run();
}
