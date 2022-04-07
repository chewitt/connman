/*
 *  ConnMan VPN daemon utils
 *
 *  Copyright (C) 2020  Jolla Ltd. All rights reserved.
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

#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>
#include <fcntl.h>

#include "src/connman.h"
#include "../vpn/vpn.h"

#define TEST_PREFIX "/vpn-unit"
#define TEST_PATH_PREFIX "connman_vpn_unit_test"

static struct passwd passwds[] = {
			{
				.pw_uid = 0,
				.pw_name = "root"
			},
			{
				.pw_uid = 1000,
				.pw_name = "user"
			},
			{
				.pw_uid = 1001,
				.pw_name = "resu"
			},
};

struct passwd *getpwuid(uid_t uid)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(passwds); i++) {
		if (passwds[i].pw_uid == uid)
			return &passwds[i];
	}

	return NULL;
}

struct passwd *getpwnam(const char *username)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(passwds); i++) {
		if (!g_strcmp0(passwds[i].pw_name, username))
			return &passwds[i];
	}

	return NULL;
}

static struct group groups[] = {
			{
				.gr_gid = 0,
				.gr_name = "root"
			},
			{
				.gr_gid = 100,
				.gr_name = "vpn"
			},
			{
				.gr_gid = 1000,
				.gr_name = "user"
			},
			{
				.gr_gid = 1001,
				.gr_name = "user1"
			}
};

struct group *getgrgid(gid_t gid)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(groups); i++) {
		if (groups[i].gr_gid == gid)
			return &groups[i];
	}

	return NULL;
}

struct group *getgrnam(const char *groupname)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(groups); i++) {
		if (!g_strcmp0(groups[i].gr_name, groupname))
			return &groups[i];
	}

	return NULL;
}

const char *dir_prefix = NULL;

gchar *g_path_get_dirname(const char *file)
{
	gchar *path;
	gchar *ret = NULL;
	gchar *test_prefix;

	DBG("in %s", file);

	g_assert(dir_prefix);

	test_prefix = g_build_filename(g_get_tmp_dir(), TEST_PATH_PREFIX,
				NULL);
	g_assert(test_prefix);

	if (!*dir_prefix || !g_str_has_prefix(dir_prefix, test_prefix))
		goto out;

	path = g_strconcat(dir_prefix, file[0] == G_DIR_SEPARATOR ?
				"" : G_DIR_SEPARATOR_S, file, NULL);
	DBG("path %s", path);

	if (path[strlen(path)-1] == G_DIR_SEPARATOR) {
		DBG("dirname %s", path);
		return path;
	}

	ret = g_strdup(dirname(path));
	DBG("dirname %s", ret);

	g_free(path);

out:
	g_free(test_prefix);

	return ret;
}

int unlink_override = 0;

int g_unlink(const gchar *file)
{
	DBG("%s", file);

	if (unlink_override) {
		DBG("override %d", unlink_override);
		errno = unlink_override;
		unlink_override = 0;
		return -1;
	}

	if (!dir_prefix || !*dir_prefix ||
				!g_str_has_prefix(file, dir_prefix)) {
		DBG("illegal path %s", file);
		errno = EFAULT;
		return -1;
	}

	return unlink(file);
}

static gchar* setup_test_directory()
{
	struct stat st;
	gchar *test_path = NULL;
	mode_t mode = S_IRWXU;

	test_path = g_strdup_printf("%s/%s.XXXXXX", g_get_tmp_dir(),
				TEST_PATH_PREFIX);
	g_assert(test_path);

	test_path = g_mkdtemp_full(test_path, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
	g_assert(test_path);

	DBG("setup test dir %s", test_path);

	g_assert_true(g_file_test(test_path, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(test_path, G_FILE_TEST_IS_DIR));

	g_assert_cmpint(stat(test_path, &st), ==, 0);
	g_assert_true(st.st_mode & mode);

	dir_prefix = test_path;

	return test_path;
}

static int rmdir_r(const gchar* path)
{
	DIR *d = opendir(path);

	if (d) {
		const struct dirent *p;
		int r = 0;

		while (!r && (p = readdir(d))) {
			char *buf;
			struct stat st;

			if (!strcmp(p->d_name, ".") ||
						!strcmp(p->d_name, "..")) {
				continue;
			}

			buf = g_strdup_printf("%s/%s", path, p->d_name);
			if (!stat(buf, &st)) {
				r =  S_ISDIR(st.st_mode) ? rmdir_r(buf) :
								unlink(buf);
			}
			g_free(buf);
		}
		closedir(d);
		return r ? r : rmdir(path);
	} else {
		return -1;
	}
}

static void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;

	if (g_file_test(test_path, G_FILE_TEST_IS_DIR)) {
		g_assert(!access(test_path, access_mode));
		rmdir_r(test_path);
	}

	dir_prefix = NULL;
}

static void test_util_username_ok1()
{
	const char *usernames_str[] = { "root", "user", "resu"};
	const char *usernames_uid[] = { "0", "1000", "1001"};
	int i;

	DBG("");

	for (i = 0; i < G_N_ELEMENTS(usernames_str); i++) {
		struct passwd *pwd_s = vpn_util_get_passwd(usernames_str[i]);
		g_assert(pwd_s);

		struct passwd *pwd_u = vpn_util_get_passwd(usernames_uid[i]);
		g_assert(pwd_u);

		g_assert_cmpstr(usernames_str[i], ==, pwd_s->pw_name);
		g_assert_cmpstr(usernames_str[i], ==, pwd_u->pw_name);
		g_assert_cmpint(pwd_s->pw_uid, ==, pwd_u->pw_uid);
	}
}

static void test_util_groupname_ok1()
{
	const char *groupnames_str[] = { "root", "user", "user1"};
	const char *groupnames_uid[] = { "0", "1000", "1001"};
	int i;

	DBG("");

	for (i = 0; i < G_N_ELEMENTS(groupnames_str); i++) {
		struct group *grp_s = vpn_util_get_group(groupnames_str[i]);
		g_assert(grp_s);

		struct group *grp_u = vpn_util_get_group(groupnames_uid[i]);
		g_assert(grp_u);

		g_assert_cmpstr(groupnames_str[i], ==, grp_s->gr_name);
		g_assert_cmpstr(groupnames_str[i], ==, grp_u->gr_name);
		g_assert_cmpint(grp_s->gr_gid, ==, grp_u->gr_gid);
	}
}

/* Create nonexistent paths */
static void test_util_create_path_ok1()
{
	const char *paths[] = { RUNSTATEDIR "/connman-vpn/test/",
				RUNSTATEDIR "/connman-vpn/test/file",
				RUNSTATEDIR "/connman-vpn/test/dir/file",
				RUNSTATEDIR "/user/1000/",
				RUNSTATEDIR "/user/1000/file",
				RUNSTATEDIR "/user/1000/test/file",
				RUNSTATEDIR "/user/1000/test/dir/file",
				"/tmp/test/",
				"/tmp/test/file",
				"/tmp/test/dir/file"};
	char *test_path;
	int i;
	uid_t uid = geteuid(); /* TODO: use arbitrary uid here, add caps */
	gid_t gid = uid;

	test_path = setup_test_directory();

	for (i = 0; i < G_N_ELEMENTS(paths); i++) {
		struct stat st;
		char *full_path;

		DBG("try '%s'", paths[i]);
		g_assert_cmpint(vpn_util_create_path(paths[i], uid, gid,
					S_IRWXU|S_IRWXG), ==, 0);

		full_path = g_build_filename(test_path, paths[i], NULL);
		g_assert_cmpint(stat(dirname(full_path), &st), ==, 0);
		g_assert_cmpint(st.st_mode & S_IFMT, ==, S_IFDIR);
		g_assert_cmpint(st.st_uid, ==, uid);
		g_assert_cmpint(st.st_gid, ==, gid);
		g_assert_true(st.st_mode & S_IRWXU);
		g_assert_true(st.st_mode & S_IRWXG);

		g_free(full_path);
	}

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Overwrite existing paths with same mode */
static void test_util_create_path_ok2()
{
	const char *paths[] = { RUNSTATEDIR "/connman-vpn/test/",
				RUNSTATEDIR "/user/1000/file",
				RUNSTATEDIR "/user/1000/test/file"};
	char *test_path;
	char *full_path;
	uid_t uid = geteuid(); /* TODO: use arbitrary uid here, add caps */
	gid_t gid = uid;
	gint mode = S_IRWXU|S_IRWXG;
	struct stat st;

	test_path = setup_test_directory();

	full_path = g_build_filename(test_path, paths[0], NULL);
	g_assert_cmpint(g_mkdir_with_parents(full_path, mode), ==, 0);

	DBG("try '%s'", paths[0]);
	g_assert_cmpint(vpn_util_create_path(paths[0], uid, gid, mode), ==, 0);

	g_assert_cmpint(stat(dirname(full_path), &st), ==, 0);
	g_assert_cmpint(st.st_mode & S_IFMT, ==, S_IFDIR);
	g_assert_cmpint(st.st_uid, ==, uid);
	g_assert_cmpint(st.st_gid, ==, gid);
	g_assert_true(st.st_mode & S_IRWXU);
	g_assert_true(st.st_mode & S_IRWXG);

	g_free(full_path);

	full_path = g_build_filename(test_path, paths[1], NULL);
	g_assert_cmpint(g_mkdir_with_parents(full_path, mode), ==, 0);
	g_free(full_path);

	full_path = g_build_filename(test_path, paths[2], NULL);

	DBG("try '%s'", paths[2]);
	g_assert_cmpint(vpn_util_create_path(paths[2], uid, gid, mode), ==, 0);

	g_assert_cmpint(stat(dirname(full_path), &st), ==, 0);
	g_assert_cmpint(st.st_mode & S_IFMT, ==, S_IFDIR);
	g_assert_cmpint(st.st_uid, ==, uid);
	g_assert_cmpint(st.st_gid, ==, gid);
	g_assert_true(st.st_mode & S_IRWXU);
	g_assert_true(st.st_mode & S_IRWXG);

	g_free(full_path);

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Overwrite existing paths with different mode */
static void test_util_create_path_ok3()
{
	const char *paths[] = { RUNSTATEDIR "/connman-vpn/test/",
				RUNSTATEDIR "/user/1000/file",
				RUNSTATEDIR "/user/1000/test/file"};
	char *test_path;
	char *full_path;
	uid_t uid = geteuid(); /* TODO: use arbitrary uid here, add caps */
	gid_t gid = uid;
	gint mode_a = S_IRWXU;
	gint mode_b = S_IRWXU|S_IRWXG;
	mode_t old_umask;
	struct stat st;

	test_path = setup_test_directory();

	full_path = g_build_filename(test_path, paths[0], NULL);

	old_umask = umask(~mode_a & 0777);
	g_assert_cmpint(g_mkdir_with_parents(full_path, mode_a), ==, 0);
	umask(old_umask);

	DBG("try '%s'", paths[0]);
	g_assert_cmpint(vpn_util_create_path(paths[0], uid, gid, mode_b), ==, 0);

	g_assert_cmpint(stat(dirname(full_path), &st), ==, 0);
	g_assert_cmpint(st.st_mode & S_IFMT, ==, S_IFDIR);

	/*
	 * No benefit in testing the perms/owner as changing them requires
	 * granting capabilities for the unit test.
	 */
	g_assert_cmpint(st.st_uid, ==, uid);
	g_assert_cmpint(st.st_gid, ==, gid);

	g_assert_true(st.st_mode & S_IRWXU);
	/* Cannot be set without capabilities
	g_assert_true(st.st_mode & S_IRWXG);
	*/

	g_free(full_path);

	/* Create base dir structure */
	full_path = g_build_filename(test_path, paths[1], NULL);
	g_assert_cmpint(g_mkdir_with_parents(full_path, mode_a), ==, 0);
	g_free(full_path);

	full_path = g_build_filename(test_path, paths[2], NULL);

	DBG("try '%s'", paths[2]);
	g_assert_cmpint(vpn_util_create_path(paths[2], uid, gid, mode_b), ==, 0);

	g_assert_cmpint(stat(dirname(full_path), &st), ==, 0);
	g_assert_cmpint(st.st_mode & S_IFMT, ==, S_IFDIR);
	g_assert_cmpint(st.st_uid, ==, uid);
	g_assert_cmpint(st.st_gid, ==, gid);
	g_assert_true(st.st_mode & mode_b);

	g_free(full_path);

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void test_util_username_fail1()
{
	const char *usernames[] = { "", "nobody123", "invalid1", "999", "-1",
							"1000000"};
	int i;

	DBG("");

	for (i = 0; i < G_N_ELEMENTS(usernames); i++)
		g_assert_null(vpn_util_get_passwd(usernames[i]));

	g_assert_null(vpn_util_get_passwd(NULL));
}

static void test_util_groupname_fail1()
{
	const char *groupnames[] = { "", "nogroup", "invalid", "9991", "-1",
							"1000000"};
	int i;

	DBG("");

	for (i = 0; i < G_N_ELEMENTS(groupnames); i++)
		g_assert_null(vpn_util_get_group(groupnames[i]));

	g_assert_null(vpn_util_get_group(NULL));
}

/* Create too short paths */
static void test_util_create_path_fail1()
{
	const char *paths[] = { RUNSTATEDIR "/connman-vpn",
				RUNSTATEDIR "/connman-vpn/",
				RUNSTATEDIR "/connman-vpn//",
				RUNSTATEDIR "/connman-vpn/./",
				RUNSTATEDIR "/connman-vpn/test",
				RUNSTATEDIR "/user",
				RUNSTATEDIR "/user/",
				RUNSTATEDIR "/user/1000",
				"/tmp/dir",
				RUNSTATEDIR "/connman-vpn/test/../../../",
				RUNSTATEDIR "/connman-vpn/test/../../../lib"};
	char *test_path;
	int i;

	test_path = setup_test_directory();

	for (i = 0; i < G_N_ELEMENTS(paths); i++) {
		struct stat st;
		char *full_path;

		DBG("try '%s'", paths[i]);
		g_assert_cmpint(vpn_util_create_path(paths[i], 0, 0, 0), ==,
								-EPERM);

		full_path = g_build_filename(test_path, paths[i], NULL);

		g_assert_cmpint(stat(dirname(full_path), &st), ==, -1);
		g_assert_cmpint(errno, ==, ENOENT);

		g_free(full_path);
	}

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Create invalid paths */
static void test_util_create_path_fail2()
{
	const char *paths[] = { NULL,
				"",
				" ",
				"run",
				"var/run",
				"run/connman-vpn/",
				"var/run/connman-vpn/",
				"run/user/1000/test/file",
				"var/run/user/1000/test/file",
				"tmp/test/file"};
	char *test_path;
	int i;

	test_path = setup_test_directory();

	for (i = 0; i < G_N_ELEMENTS(paths); i++) {
		DBG("try '%s'", paths[i]);
		g_assert_cmpint(vpn_util_create_path(paths[i], 0, 0, 0), ==,
								-EINVAL);
	}

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Try to create existing paths */
static void test_util_create_path_fail3()
{
	const char *paths[] = { "/tmp",
				"/tmp/",
				"/",
				"/root/",
				"/root/tmp",
				"/root/tmp/dir"
				"/var/lib/",
				"/home/user",
				"/home/user/dir",
				"/etc",
				"/etc/connman",
				"/etc/connman-vpn",
				"/boot/dir",
				"/usr/lib/dir",
				"/usr/lib",
				};
	char *test_path;
	int i;

	test_path = setup_test_directory();

	for (i = 0; i < G_N_ELEMENTS(paths); i++) {
		DBG("try '%s'", paths[i]);
		g_assert_cmpint(vpn_util_create_path(paths[i], 0, 0, 0), ==,
								-EPERM);
	}

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Simulate unlink errors */
static void test_util_create_path_fail4()
{
	struct stat st;
	const char *paths[] = { "/tmp/test/file",
				"/tmp/test2",
				"/tmp/test2/file",
				"/tmp/test3/file"};
	char *test_path;
	char *test_file;
	uid_t uid = geteuid();
	gid_t gid = uid;
	int mode = S_IRWXU;
	int fd;

	test_path = setup_test_directory();

	/* Dir does not exist, next succeeds */
	unlink_override = EACCES;
	g_assert_cmpint(vpn_util_create_path(paths[0], uid, gid, mode), ==,
								-EACCES);
	g_assert_cmpint(vpn_util_create_path(paths[0], uid, gid, mode), ==, 0);

	/* Dir exists, creation succeeds with no write access */
	unlink_override = EACCES;
	g_assert_cmpint(vpn_util_create_path(paths[0], uid, gid, mode), ==, 0);

	/* Create plain file and simulate write access */
	test_file = g_build_filename(test_path, paths[1], NULL);
	fd = open(test_file, O_CREAT, mode);
	g_assert_cmpint(fd, >=, 0);
	g_assert_cmpint(close(fd), ==, 0);
	g_assert_cmpint(stat(test_file, &st), ==, 0);

	unlink_override = EACCES;
	g_assert_cmpint(vpn_util_create_path(paths[2], uid, gid, mode), ==,
								-EACCES);
	g_assert_cmpint(vpn_util_create_path(paths[2], uid, gid, mode), ==, 0);
	g_free(test_file);

	/* Other error */
	unlink_override = EIO;
	g_assert_cmpint(vpn_util_create_path(paths[3], uid, gid, mode), ==,
								-EIO);

	cleanup_test_directory(test_path);
	g_free(test_path);
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

	g_test_add_func(TEST_PREFIX "/username_ok1",
						test_util_username_ok1);
	g_test_add_func(TEST_PREFIX "/groupname_ok1",
						test_util_groupname_ok1);
	g_test_add_func(TEST_PREFIX "/create_path_ok1",
						test_util_create_path_ok1);
	g_test_add_func(TEST_PREFIX "/create_path_ok2",
						test_util_create_path_ok2);
	g_test_add_func(TEST_PREFIX "/create_path_ok3",
						test_util_create_path_ok3);
	g_test_add_func(TEST_PREFIX "/username_fail1",
						test_util_username_fail1);
	g_test_add_func(TEST_PREFIX "/groupname_fail1",
						test_util_groupname_fail1);
	g_test_add_func(TEST_PREFIX "/create_path_fail1",
						test_util_create_path_fail1);
	g_test_add_func(TEST_PREFIX "/create_path_fail2",
						test_util_create_path_fail2);
	g_test_add_func(TEST_PREFIX "/create_path_fail3",
						test_util_create_path_fail3);
	g_test_add_func(TEST_PREFIX "/create_path_fail4",
						test_util_create_path_fail4);


	return g_test_run();
}
