/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/inotify.h>

#include <connman/storage.h>

#include "connman.h"

#define SETTINGS	"settings"
#define DEFAULT		"default.profile"

#define MODE		(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | \
			S_IXGRP | S_IROTH | S_IXOTH)

#define NAME_MASK (IN_ACCESS | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | \
			IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | \
			IN_MOVED_TO | IN_OPEN)

struct storage_subdir {
	gchar *name;
	gboolean has_settings;
};

struct storage_dir_context {
	gboolean initialized;
	GList *subdirs;
};

static struct storage_dir_context storage = {
	.initialized = FALSE,
	.subdirs = NULL
};

struct keyfile_record {
	gchar *pathname;
	GKeyFile *keyfile;
};

static GHashTable *keyfile_hash = NULL;

static void storage_dir_cleanup(void);

static void storage_inotify_subdir_cb(struct inotify_event *event,
					const char *ident,
					gpointer user_data);

static void keyfile_inotify_cb(struct inotify_event *event,
				const char *ident,
				gpointer user_data);

gboolean is_service_dir_name(const char *name);

gboolean is_provider_dir_name(const char *name);

static void debug_subdirs(void)
{
	GList *l;

	if (!storage.initialized) {
		DBG("Storage subdirs not initialized.");
		return;
	}

	DBG("Storage subdirs: {");
	for (l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		DBG("\t%s[%s]", subdir->name,
			subdir->has_settings ? (
				is_service_dir_name(subdir->name) ? "S" :
				is_provider_dir_name(subdir->name) ? "P" :
				"X") : "-");
	}
	DBG("}");
}

static void debug_inotify_event(struct inotify_event *event)
{
	static const char *flags[] = {
		"IN_ACCESS", 		// 1
		"IN_MODIFY", 		// 2
		"IN_ATTRIB", 		// 4
		"IN_CLOSE_WRITE",	// 8

		"IN_CLOSE_NOWRITE",	// 10
		"IN_OPEN",		// 20
		"IN_MOVED_FROM",	// 40
		"IN_MOVED_TO",		// 80

		"IN_CREATE",		// 100
		"IN_DELETE",		// 200
		"IN_DELETE_SELF",	// 400
		"IN_MOVE_SELF",		// 800

		"UNDEFINED_1000",
		"IN_UNMOUNT",		// 2000
		"IN_Q_OVERFLOW",	// 4000
		"IN_IGNORED",		// 8000

		"UNDEFINED_10000",
		"UNDEFINED_20000",
		"UNDEFINED_40000",
		"UNDEFINED_80000",

		"UNDEFINED_100000",
		"UNDEFINED_200000",
		"UNDEFINED_400000",
		"UNDEFINED_800000",

		"IN_ONLYDIR",           // 1000000
		"IN_DONT_FOLLOW",	// 2000000
		"IN_EXCL_UNLINK",	// 4000000
		"UNDEFINED_800000",

		"UNDEFINED_1000000",
		"IN_MASK_ADD",		// 20000000
		"IN_ISDIR",		// 40000000
		"IN_ONESHOT",		// 80000000
	};
	int i;

	DBG("Event flags: ");
	for (i = 0; i < 32; i++) {
		if (event->mask & (1 << i))
			DBG("\t%s", flags[i]);
	}

	if (event->mask & NAME_MASK)
		DBG("Event name: %s", event->name);
}

bool service_id_is_valid(const char *id)
{
	char *check = g_strdup_printf("%s/service/%s", CONNMAN_PATH, id);
	bool valid = dbus_validate_path(check, NULL) == TRUE;
	if (!valid)
		DBG("Service ID '%s' is not valid.", id);
	g_free(check);
	return valid;
}

gboolean is_service_dir_name(const char *name)
{
	DBG("name %s", name);

	if (strncmp(name, "provider_", 9) == 0 || !service_id_is_valid(name))
		return FALSE;

	return TRUE;
}

gboolean is_provider_dir_name(const char *name)
{
	DBG("name %s", name);

	if (strncmp(name, "provider_", 9) == 0)
		return TRUE;

	return FALSE;
}

gint storage_subdir_cmp(gconstpointer a, gconstpointer b)
{
	const struct storage_subdir *d1 = a;
	const struct storage_subdir *d2 = b;

	DBG("name1 %s name2 %s", d1->name, d2->name);

	return g_strcmp0(d1->name, d2->name);
}

static void storage_subdir_free(gpointer data)
{
	struct storage_subdir *subdir = data;
	DBG("%s", subdir->name);
	storage.subdirs = g_list_remove(storage.subdirs, subdir);
	g_free(subdir->name);
	g_free(subdir);
}

static void storage_subdir_unregister(gpointer data)
{
	struct storage_subdir *subdir = data;
	gchar *str;

	DBG("%s", subdir->name);
	str = g_strdup_printf("%s/%s", STORAGEDIR, subdir->name);
	connman_inotify_unregister(str, storage_inotify_subdir_cb, subdir);
	g_free(str);
}

static void storage_subdir_append(const char *name)
{
	struct storage_subdir *subdir;
	struct stat buf;
	gchar *str;
	int ret;

	DBG("%s", name);

	subdir = g_new0(struct storage_subdir, 1);
	subdir->name = g_strdup(name);

	str = g_strdup_printf("%s/%s/%s", STORAGEDIR, subdir->name, SETTINGS);
	ret = stat(str, &buf);
	g_free(str);
	if (ret == 0)
		subdir->has_settings = TRUE;

	storage.subdirs = g_list_prepend(storage.subdirs, subdir);

	str = g_strdup_printf("%s/%s", STORAGEDIR, subdir->name);

	if (connman_inotify_register(str, storage_inotify_subdir_cb, subdir,
				storage_subdir_free) != 0)
		storage_subdir_free(subdir);

	g_free(str);
}

static void storage_inotify_subdir_cb(struct inotify_event *event,
					const char *ident,
					gpointer user_data)
{
	struct storage_subdir *subdir = user_data;

	DBG("name %s", subdir->name);
	debug_inotify_event(event);

	/* Only interested in files here */
	if (event->mask & IN_ISDIR)
		return;

	if ((event->mask & IN_DELETE) || (event->mask & IN_MOVED_FROM)) {
		DBG("delete/move-from %s", event->name);
		if (!g_strcmp0(event->name, SETTINGS))
			subdir->has_settings = FALSE;
		return;
	}

	if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
		DBG("create/move-to %s", event->name);
		if (!g_strcmp0(event->name, SETTINGS)) {
			struct stat st;
			gchar *pathname;
			pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR,
						subdir->name, event->name);
			if (stat(pathname, &st) == 0 && S_ISREG(st.st_mode)) {
				subdir->has_settings = TRUE;
			}
			g_free(pathname);
		}
		return;
	}
}

static void storage_inotify_cb(struct inotify_event *event, const char *ident,
				gpointer user_data)
{
	DBG("");
	debug_inotify_event(event);

	if (event->mask & IN_DELETE_SELF) {
		DBG("delete self");
		storage_dir_cleanup();
		return;
	}

	/* Only interested in subdirectories here */
	if (!(event->mask & IN_ISDIR))
		return;

	if ((event->mask & IN_DELETE) || (event->mask & IN_MOVED_FROM)) {
		struct storage_subdir key = { .name = event->name };
		GList *pos;

		DBG("delete/move-from %s", event->name);
		pos = g_list_find_custom(storage.subdirs, &key,
					storage_subdir_cmp);
		if (pos) {
			storage_subdir_unregister(pos->data);
			debug_subdirs();
		}

		return;
	}

	if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
		DBG("create %s", event->name);
		storage_subdir_append(event->name);
		debug_subdirs();
		return;
	}
}

static void storage_dir_init(void)
{
	DIR *dir;
	struct dirent *d;

	if (storage.initialized)
		return;

	DBG("Initializing storage directories.");

	dir = opendir(STORAGEDIR);
	if (!dir)
		return;

	while ((d = readdir(dir))) {

		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;

		switch (d->d_type) {
		case DT_DIR:
		case DT_UNKNOWN:
			storage_subdir_append(d->d_name);
			debug_subdirs();
			break;
		}
	}

	closedir(dir);

	connman_inotify_register(STORAGEDIR, storage_inotify_cb, NULL, NULL);

	storage.initialized = TRUE;

	DBG("Initialization done.");
}

static void storage_dir_cleanup(void)
{
	if (!storage.initialized)
		return;

	DBG("Cleaning up storage directories.");

	connman_inotify_unregister(STORAGEDIR, storage_inotify_cb, NULL);

	while (storage.subdirs)
		storage_subdir_unregister(storage.subdirs->data);
	storage.subdirs = NULL;

	storage.initialized = FALSE;

	DBG("Cleanup done.");
}

static void keyfile_free(gpointer data)
{
	struct keyfile_record *record = data;
	DBG("Freeing record %p for %s", record, record->pathname);
	g_hash_table_remove(keyfile_hash, record->pathname);
	g_key_file_unref(record->keyfile);
	g_free(record->pathname);
	g_free(record);
}

static void keyfile_unregister(gpointer data)
{
	struct keyfile_record *record = data;
	char *str = g_strdup(record->pathname);
	connman_inotify_unregister(str, keyfile_inotify_cb, record);
	g_free(str);
}

static void keyfile_insert(const char *pathname, GKeyFile *keyfile)
{
	struct keyfile_record *record = g_new0(struct keyfile_record, 1);
	record->pathname = g_strdup(pathname);
	record->keyfile = g_key_file_ref(keyfile);
	g_hash_table_insert(keyfile_hash, record->pathname, record);

	if (connman_inotify_register(pathname, keyfile_inotify_cb, record,
				keyfile_free) != 0)
		keyfile_free(record);
}

static void keyfile_inotify_cb(struct inotify_event *event,
				const char *ident,
				gpointer user_data)
{
	struct keyfile_record *record = user_data;

	DBG("name %s", record->pathname);
	debug_inotify_event(event);

	if ((event->mask & IN_DELETE_SELF) || (event->mask & IN_MOVE_SELF) ||
		(event->mask & IN_MODIFY) || (event->mask & IN_IGNORED)) {
		DBG("File for record %p path %s changed, dropping from cache.",
			record, record->pathname);
		keyfile_unregister(record);
		return;
	}
}

static void keyfile_init(void)
{
	if (keyfile_hash)
		return;

	DBG("Creating keyfile hash.");
	keyfile_hash = g_hash_table_new(g_str_hash, g_str_equal);
}

static void keyfile_cleanup(void)
{
	GHashTableIter iter;
	gpointer key, value;

	if (!keyfile_hash)
		return;

	g_hash_table_iter_init(&iter, keyfile_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		g_hash_table_iter_steal(&iter);
		keyfile_unregister(value);
	}
	g_hash_table_unref(keyfile_hash);
	keyfile_hash = NULL;
}

static GKeyFile *storage_load(const char *pathname)
{
	struct keyfile_record *record = NULL;
	GError *error = NULL;
	GKeyFile *keyfile = NULL;

	DBG("Loading %s", pathname);

	record = g_hash_table_lookup(keyfile_hash, pathname);
	if (record) {
		DBG("Found record %p for %s from cache.", record, pathname);
		return g_key_file_ref(record->keyfile);
        }

	DBG("No keyfile in cache for %s", pathname);
	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, pathname, 0, &error)) {
		DBG("Unable to load %s: %s", pathname, error->message);
		g_clear_error(&error);

		g_key_file_unref(keyfile);
		keyfile = NULL;
	} else {
		DBG("Storing record for %s into cache.", pathname);
		keyfile_insert(pathname, keyfile);
	}

	return keyfile;
}

static int storage_save(GKeyFile *keyfile, char *pathname)
{
	gchar *data = NULL;
	gsize length = 0;
	GError *error = NULL;
	int ret = 0;
	const mode_t perm = STORAGE_FILE_MODE;
	const mode_t old_mask = umask(~perm & 0777);

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (!g_file_set_contents(pathname, data, length, &error)) {
		DBG("Failed to store information: %s", error->message);
		g_error_free(error);
		ret = -EIO;
	}

	if (ret == 0) {
		ret = chmod(pathname, perm);
		if (ret < 0) {
			ret = -errno;
			DBG("Failed to set permissions 0%o on %s: %s",
					perm, pathname, strerror(errno));
		}
	}

	g_free(data);
	umask(old_mask);

	return ret;
}

static void storage_delete(const char *pathname)
{
	DBG("file path %s", pathname);

	if (unlink(pathname) < 0)
		connman_error("Failed to remove %s", pathname);
}

GKeyFile *__connman_storage_load_global(void)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

int __connman_storage_save_global(GKeyFile *keyfile)
{
	gchar *pathname;
	int ret;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if (!pathname)
		return -ENOMEM;

	ret = storage_save(keyfile, pathname);

	g_free(pathname);

	return ret;
}

void __connman_storage_delete_global(void)
{
	gchar *pathname;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if (!pathname)
		return;

	storage_delete(pathname);

	g_free(pathname);
}

GKeyFile *__connman_storage_load_config(const char *ident)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s.config", STORAGEDIR, ident);
	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

GKeyFile *__connman_storage_load_provider_config(const char *ident)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s.config", VPN_STORAGEDIR, ident);
	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

GKeyFile *__connman_storage_open_service(const char *service_id)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	if (!service_id_is_valid(service_id))
		return NULL;

	pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR, service_id, SETTINGS);
	if (!pathname)
		return NULL;

	keyfile =  storage_load(pathname);
	if (keyfile) {
		g_free(pathname);
		return keyfile;
	}

	g_free(pathname);

	keyfile = g_key_file_new();

	return keyfile;
}

gchar **connman_storage_get_services(void)
{
	gchar **result = NULL;
	GList *l;
	int sum, pos;

	DBG("");

	if (!storage.initialized) {
		storage_dir_init();
		if (!storage.initialized)
			return NULL;
	}

	for (sum = 0, l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		if (is_service_dir_name(subdir->name) && subdir->has_settings)
			sum++;
	}

	result = g_new0(gchar *, sum + 1);

	for (pos = 0, l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		if (is_service_dir_name(subdir->name) && subdir->has_settings)
			result[pos++] = g_strdup(subdir->name);
	}

	return result;
}

GKeyFile *connman_storage_load_service(const char *service_id)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	if (!service_id_is_valid(service_id))
		return NULL;

	pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR, service_id, SETTINGS);
	if (!pathname)
		return NULL;

	keyfile =  storage_load(pathname);
	g_free(pathname);

	return keyfile;
}

int __connman_storage_save_service(GKeyFile *keyfile, const char *service_id)
{
	int ret = 0;
	gchar *pathname, *dirname;

	if (!service_id_is_valid(service_id))
		return -EINVAL;

	dirname = g_strdup_printf("%s/%s", STORAGEDIR, service_id);
	if (!dirname)
		return -ENOMEM;

	/* If the dir doesn't exist, create it */
	if (!g_file_test(dirname, G_FILE_TEST_IS_DIR)) {
		if (mkdir(dirname, STORAGE_DIR_MODE) < 0) {
			if (errno != EEXIST) {
				g_free(dirname);
				return -errno;
			}
		}
	}

	pathname = g_strdup_printf("%s/%s", dirname, SETTINGS);

	g_free(dirname);

	ret = storage_save(keyfile, pathname);

	g_free(pathname);

	return ret;
}

static bool remove_file(const char *service_id, const char *file)
{
	gchar *pathname;
	bool ret = false;

	pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR, service_id, file);
	if (!pathname)
		return false;

	if (!g_file_test(pathname, G_FILE_TEST_EXISTS)) {
		ret = true;
	} else if (g_file_test(pathname, G_FILE_TEST_IS_REGULAR)) {
		unlink(pathname);
		ret = true;
	}

	g_free(pathname);
	return ret;
}

static bool remove_dir(const char *service_id)
{
	gchar *pathname;
	bool ret = false;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, service_id);
	if (!pathname)
		return false;

	if (!g_file_test(pathname, G_FILE_TEST_EXISTS)) {
		ret = true;
	} else if (g_file_test(pathname, G_FILE_TEST_IS_DIR)) {
		rmdir(pathname);
		ret = true;
	}

	g_free(pathname);
	return ret;
}

bool __connman_storage_remove_service(const char *service_id)
{
	bool removed = false;
	gchar *pathname = g_strdup_printf("%s/%s", STORAGEDIR, service_id);
	DIR *dir = opendir(pathname);

	if (dir) {
		struct dirent *d;

		/* Remove the configuration files */
		while ((d = readdir(dir)) != NULL) {
			if (strcmp(d->d_name, ".") != 0 &&
					strcmp(d->d_name, "..") != 0) {
				remove_file(service_id, d->d_name);
			}
		}

		closedir(dir);
		remove_dir(service_id);
		DBG("Removed service dir %s", pathname);
		removed = true;
	}

	g_free(pathname);
	return removed;
}

GKeyFile *__connman_storage_load_provider(const char *identifier)
{
	gchar *pathname;
	GKeyFile *keyfile;

	pathname = g_strdup_printf("%s/%s_%s/%s", STORAGEDIR, "provider",
			identifier, SETTINGS);
	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);
	g_free(pathname);

	return keyfile;
}

void __connman_storage_save_provider(GKeyFile *keyfile, const char *identifier)
{
	gchar *pathname, *dirname;

	dirname = g_strdup_printf("%s/%s_%s", STORAGEDIR,
			"provider", identifier);
	if (!dirname)
		return;

	if (!g_file_test(dirname, G_FILE_TEST_IS_DIR) &&
			mkdir(dirname, MODE) < 0) {
		g_free(dirname);
		return;
	}

	pathname = g_strdup_printf("%s/%s", dirname, SETTINGS);
	g_free(dirname);

	storage_save(keyfile, pathname);
	g_free(pathname);
}

static bool remove_all(const char *id)
{
	bool removed;

	remove_file(id, SETTINGS);
	remove_file(id, "data");

	removed = remove_dir(id);
	if (!removed)
		return false;

	return true;
}

bool __connman_storage_remove_provider(const char *identifier)
{
	bool removed;
	gchar *id;

	id = g_strdup_printf("%s_%s", "provider", identifier);
	if (!id)
		return false;

	if (remove_all(id))
		DBG("Removed provider dir %s/%s", STORAGEDIR, id);

	g_free(id);

	id = g_strdup_printf("%s_%s", "vpn", identifier);
	if (!id)
		return false;

	if ((removed = remove_all(id)))
		DBG("Removed vpn dir %s/%s", STORAGEDIR, id);

	g_free(id);

	return removed;
}

gchar **__connman_storage_get_providers(void)
{
	gchar **result = NULL;
	GList *l;
	int sum, pos;

	DBG("");

	if (!storage.initialized) {
		storage_dir_init();
		if (!storage.initialized)
			return NULL;
	}

	for (sum = 0, l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		if (is_provider_dir_name(subdir->name) && subdir->has_settings)
			sum++;
	}

	result = g_new0(gchar *, sum + 1);

	for (pos = 0, l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		if (is_provider_dir_name(subdir->name) && subdir->has_settings)
			result[pos++] = g_strdup(subdir->name);
	}

	return result;
}

static char *storage_dir = NULL;
static char *vpn_storage_dir = NULL;
static int storage_dir_mode;
static int storage_file_mode;

const char *connman_storage_dir(void)
{
	return storage_dir;
}

const char *connman_storage_vpn_dir(void)
{
	return vpn_storage_dir;
}

int __connman_storage_dir_mode(void)
{
	return storage_dir_mode;
}

int __connman_storage_file_mode(void)
{
	return storage_file_mode;
}

int __connman_storage_init(const char *dir, int dir_mode, int file_mode)
{
	const char *root = dir ? dir : DEFAULT_STORAGE_ROOT;

	DBG("%s 0%o 0%o", root, dir_mode, file_mode);
	storage_dir = g_strconcat(root, "/connman", NULL);
	vpn_storage_dir = g_strconcat(root, "/connman-vpn", NULL);
	storage_dir_mode = dir_mode;
	storage_file_mode = file_mode;
	keyfile_init();
	return 0;
}

void __connman_storage_cleanup(void)
{
	DBG("");
	storage_dir_cleanup();
	keyfile_cleanup();
	g_free(storage_dir);
	g_free(vpn_storage_dir);
}
