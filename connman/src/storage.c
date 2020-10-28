/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2019-2020  Jolla Ltd. All rights reserved.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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
#include <pwd.h>

#include <gdbus.h>

#include <connman/storage.h>
#include <vpn/vpn.h>

#include "connman.h"
#include "connman/vpn-dbus.h"

#define SETTINGS	"settings"
#define DEFAULT		"default.profile"

#define MODE		(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | \
			S_IXGRP | S_IROTH | S_IXOTH)

#define NAME_MASK (IN_ACCESS | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | \
			IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | \
			IN_MOVED_TO | IN_OPEN)

/* Delay for the delayed vpnd user change. */
#define USER_CHANGE_DELAY 200

struct storage_subdir {
	gchar *name;
	gboolean has_settings;
};

struct storage_dir_context {
	gboolean initialized;
	gboolean user_initialized;
	gboolean vpn_initialized;
	gboolean user_vpn_initialized;
	gboolean only_unload;
	GList *subdirs;
	GList *user_subdirs;
	uid_t current_uid;
};

static struct storage_dir_context storage = {
	.initialized = FALSE,
	.user_initialized = FALSE,
	.vpn_initialized = FALSE,
	.user_vpn_initialized = FALSE,
	.only_unload = FALSE,
	.subdirs = NULL,
	.user_subdirs = NULL,
	.current_uid = 0
};

struct keyfile_record {
	gchar *pathname;
	GKeyFile *keyfile;
};

static GHashTable *keyfile_hash = NULL;
static DBusConnection *connection = NULL;
static DBusPendingCall *vpn_change_call = NULL;
static const char *dbus_path = NULL;
static const char *dbus_interface = NULL;
static struct connman_storage_callbacks *cbs = NULL;
struct connman_access_storage_policy *storage_access_policy = NULL;
static guint vpnd_watch = 0;
static bool send_vpnd_change_user = false;
static guint delayed_user_change_id = 0;

static void storage_dir_cleanup(const char *storagedir, int type);

static void storage_inotify_subdir_cb(struct inotify_event *event,
					const char *ident,
					gpointer user_data);

static void keyfile_inotify_cb(struct inotify_event *event,
				const char *ident,
				gpointer user_data);

static gboolean is_service_wifi_dir_name(const char *name);

static gboolean is_service_dir_name(const char *name);

static gboolean is_provider_dir_name(const char *name);

static gboolean is_vpn_dir_name(const char *name);

static gboolean is_vpn_dir(const char *name);

static const char* storagedir_for(const char *name);

static struct connman_access_storage_policy* get_storage_access_policy()
{
	/*
	 * We can't initialize this variable in __connman_storage_init
	 * because __connman_storage_init runs before sailfish access
	 * plugin (or any other plugin) is loaded
	 */
	if (!storage_access_policy && cbs && cbs->access_policy_create) {
		/* Use the default policy */
		storage_access_policy = cbs->access_policy_create(NULL);
	}

	return storage_access_policy;
}

static void debug_subdirs(void)
{
	GList *l;

	if ((!storage.initialized && !storage.user_initialized) ||
		(storage.vpn_initialized && !storage.user_vpn_initialized)) {
		DBG("Storage subdirs not initialized.");
		return;
	}

	DBG("Storage subdirs: {");
	for (l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		DBG("\t%s[%s]", subdir->name,
			subdir->has_settings ? (
				is_service_dir_name(subdir->name) ?
				(is_service_wifi_dir_name(subdir->name) ?
					"W" : "S") :
				is_provider_dir_name(subdir->name) ? "P" :
				is_vpn_dir_name(subdir->name) ? "V" :
				"X") : "-");
	}
	DBG("}");
	DBG("User storage subdirs: {");
	for (l = storage.user_subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		DBG("\t%s[%s]", subdir->name,
			subdir->has_settings ? (
				is_service_dir_name(subdir->name) ?
				(is_service_wifi_dir_name(subdir->name) ?
					"W" : "S") :
				is_provider_dir_name(subdir->name) ? "P" :
				is_vpn_dir_name(subdir->name) ? "V" :
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
	char *check;
	bool valid;

	if (!id)
		return false;

	check = g_strdup_printf("%s/service/%s", CONNMAN_PATH, id);

	valid = dbus_validate_path(check, NULL) == TRUE;
	if (!valid)
		DBG("Service ID '%s' is not valid.", id);

	g_free(check);

	return valid;
}

static gboolean is_service_wifi_dir_name(const char *name)
{
	if (!strncmp(name, "wifi_", 5) && service_id_is_valid(name))
		return TRUE;

	return FALSE;
}

static gboolean is_service_dir_name(const char *name)
{
	if (strncmp(name, "provider_", 9) == 0 || !service_id_is_valid(name))
		return FALSE;

	return TRUE;
}

static gboolean is_provider_dir_name(const char *name)
{
	if (strncmp(name, "provider_", 9) == 0)
		return TRUE;

	return FALSE;
}

static gboolean is_vpn_dir_name(const char *name)
{
	if (strncmp(name, "vpn_", 4) == 0)
		return TRUE;

	return FALSE;
}

static gboolean is_vpn_dir(const char *name)
{
	if (is_vpn_dir_name(name) || is_provider_dir_name(name))
		return TRUE;

	return FALSE;
}

static bool is_user_wifi(const char *name)
{
	if (!name)
		return false;

	return USER_STORAGEDIR && is_service_wifi_dir_name(name);
}

static bool is_user_vpn(const char *name)
{
	if (!name)
		return false;

	return USER_VPN_STORAGEDIR && is_vpn_dir(name);
}

static bool is_user_dir(const char *name)
{
	return is_user_wifi(name) || is_user_vpn(name);
}

static const char *storagedir_for(const char *name)
{
	DBG("name %s", name);

	if (is_vpn_dir(name)) {
		if (USER_VPN_STORAGEDIR) {
			DBG("user VPN %s", USER_VPN_STORAGEDIR);
			return USER_VPN_STORAGEDIR;
		}

		DBG("system VPN %s", VPN_STORAGEDIR);
		return VPN_STORAGEDIR;
	} else if (service_id_is_valid(name)){
		if (is_user_wifi(name)) {
			DBG("user WiFi %s", USER_STORAGEDIR);
			return USER_STORAGEDIR;
		}

		DBG("system main %s", STORAGEDIR);
		return STORAGEDIR;
	}

	DBG("service %s is not valid", name);
	return NULL;
}

static gint storage_subdir_cmp(gconstpointer a, gconstpointer b)
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

	if (is_user_dir(subdir->name)) {
		DBG("removing %s from user subdirs", subdir->name);
		storage.user_subdirs = g_list_remove(storage.user_subdirs,
					subdir);
	} else {
		DBG("removing %s from system subdirs", subdir->name);
		storage.subdirs = g_list_remove(storage.subdirs, subdir);
	}

	g_free(subdir->name);
	g_free(subdir);
}

static void storage_subdir_unregister(gpointer data)
{
	struct storage_subdir *subdir = data;
	const char *storagedir;
	gchar *str;

	DBG("%s", subdir->name);

	storagedir = storagedir_for(subdir->name);
	if (!storagedir)
		return;

	str = g_build_filename(storagedir, subdir->name, NULL);
	DBG("path %s", str);
	connman_inotify_unregister(str, storage_inotify_subdir_cb, subdir);
	g_free(str);
}

static void storage_subdir_append(const char *name)
{
	struct storage_subdir *subdir;
	struct stat buf;
	gchar *str;
	const char *storagedir;
	int ret;

	DBG("%s", name);

	subdir = g_new0(struct storage_subdir, 1);
	subdir->name = g_strdup(name);

	storagedir = storagedir_for(subdir->name);
	if (!storagedir)
		return;

	str = g_build_filename(storagedir, subdir->name, SETTINGS, NULL);
	DBG("path %s", str);
	ret = stat(str, &buf);
	g_free(str);
	if (ret == 0)
		subdir->has_settings = TRUE;

	if (is_user_dir(subdir->name)) {
		storage.user_subdirs = g_list_prepend(storage.user_subdirs,
					subdir);
		DBG("into user subdirs");
	} else {
		storage.subdirs = g_list_prepend(storage.subdirs, subdir);
		DBG("into system subdirs");
	}

	str = g_build_filename(storagedir, subdir->name, NULL);
	DBG("register with inotify %s", str);

	if (connman_inotify_register(str, storage_inotify_subdir_cb, subdir,
				storage_subdir_free) != 0) {
		DBG("failed to register %s", str);
		storage_subdir_free(subdir);
	}

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
			const char *storagedir;
			gchar *pathname;

			storagedir = storagedir_for(subdir->name);
			if (!storagedir)
				return;

			pathname = g_build_filename(storagedir, subdir->name,
						event->name, NULL);
			DBG("pathname %s", pathname);

			if (stat(pathname, &st) == 0 && S_ISREG(st.st_mode)) {
				subdir->has_settings = TRUE;
			}

			g_free(pathname);
		}
	}
}

static void storage_inotify_cb(struct inotify_event *event, const char *ident,
				gpointer user_data)
{
	DBG("");
	debug_inotify_event(event);

	if (event->mask & IN_DELETE_SELF) {
		DBG("delete self");
		storage_dir_cleanup(STORAGEDIR, STORAGE_DIR_TYPE_MAIN);
		storage_dir_cleanup(VPN_STORAGEDIR, STORAGE_DIR_TYPE_VPN);

		if (USER_STORAGEDIR)
			storage_dir_cleanup(USER_STORAGEDIR,
						STORAGE_DIR_TYPE_MAIN |
						STORAGE_DIR_TYPE_USER);

		if (USER_VPN_STORAGEDIR)
			storage_dir_cleanup(USER_VPN_STORAGEDIR,
						STORAGE_DIR_TYPE_VPN |
						STORAGE_DIR_TYPE_USER);

		return;
	}

	/* Only interested in subdirectories here */
	if (!(event->mask & IN_ISDIR))
		return;

	if ((event->mask & IN_DELETE) || (event->mask & IN_MOVED_FROM)) {
		struct storage_subdir key = { .name = event->name };
		GList *subdirs;
		GList *pos;

		DBG("delete/move-from %s", event->name);

		/*
		 * To support manual removal of services as well call the
		 * unload callback to propagate the notify about the removal
		 * to proper locations and for the service/provider to be
		 * removed from the service/provider lists.
		 */
		if (cbs && cbs->unload) {
			bool unload_state = storage.only_unload;
			char *name = event->name;

			DBG("unloading %s (unload in progress: %s)",
					name, unload_state ? "y" : "n");

			/*
			 * To prevent attempt to remove an already removed one
			 * and to eventually call the unregister set only
			 * unload mode and restore original mode afterwards.
			 *
			 * If the service was not manually removed then the
			 * unload callback does nothing as the service/provider
			 * is not found.
			 */
			storage.only_unload = TRUE;
			cbs->unload(&name, 1);
			storage.only_unload = unload_state;
		}

		if (is_user_dir(event->name))
			subdirs = storage.user_subdirs;
		else
			subdirs = storage.subdirs;

		/*
		 * If the service was manually removed it is removed also from
		 * subdirs when the unload callback reaches back to service/
		 * provider removal in unload only mode. But in case it was
		 * removed using internal functionality it must be removed from
		 * the subdirs here.
		 */
		pos = g_list_find_custom(subdirs, &key, storage_subdir_cmp);
		if (pos) {
			storage_subdir_unregister(pos->data);
			debug_subdirs();
		}

		return;
	}

	if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
		DBG("create %s", event->name);
		storage_subdir_append(event->name);

		/*
		 * This ensures manually added services/providers are also
		 * loaded and notified properly.
		 */
		if (cbs && cbs->load)
			cbs->load();

		debug_subdirs();
		return;
	}
}

static void storage_dir_init(const char *storagedir, int type)
{
	DIR *dir;
	struct dirent *d;

	if (!storagedir)
		return;

	if (type & STORAGE_DIR_TYPE_MAIN) {
		if (type & STORAGE_DIR_TYPE_USER) {
			if (storage.user_initialized) {
				DBG("user main already initialized");
				return;
			}
		} else if (storage.initialized) {
			DBG("system main already initialized");
			return;
		}
	} else if (type & STORAGE_DIR_TYPE_VPN) {
		if (type & STORAGE_DIR_TYPE_USER) {
			if (storage.user_vpn_initialized) {
				DBG("user VPN already initialized");
				return;
			}
		} else if (storage.vpn_initialized) {
			DBG("system VPN already initialized");
			return;
		}
	}

	DBG("Initializing storage directories for %s %s (%s)",
				type & STORAGE_DIR_TYPE_MAIN ? "main" : "vpn",
				type & STORAGE_DIR_TYPE_USER ? "user" : "sys",
				storagedir);

	dir = opendir(storagedir);
	if (!dir)
		return;

	while ((d = readdir(dir))) {

		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;

		/* Ignore same WiFi networks from system if user is set */
		if (!(type & STORAGE_DIR_TYPE_USER) &&
					is_user_wifi(d->d_name)) {
			DBG("ignore system wifi %s with user set",
						d->d_name);
			continue;
		}

		DBG("add %s", d->d_name);

		switch (d->d_type) {
		case DT_DIR:
		case DT_UNKNOWN:
			storage_subdir_append(d->d_name);
			debug_subdirs();
			break;
		}
	}

	closedir(dir);

	connman_inotify_register(storagedir, storage_inotify_cb, NULL, NULL);

	if (type & STORAGE_DIR_TYPE_MAIN) {
		if (type & STORAGE_DIR_TYPE_USER) {
			DBG("initialized user main");
			storage.user_initialized = TRUE;
		} else {
			DBG("initialized system main");
			storage.initialized = TRUE;
		}
	} else if (type & STORAGE_DIR_TYPE_VPN) {
		if (type & STORAGE_DIR_TYPE_USER) {
			DBG("initialized user VPN");
			storage.user_vpn_initialized = TRUE;
		} else {
			DBG("initialized system VPN");
			storage.vpn_initialized = TRUE;
		}
	}

	DBG("Initialization done.");
}

static void storage_dir_cleanup(const char *storagedir, int type)
{
	if (!storagedir)
		return;

	if (type & STORAGE_DIR_TYPE_MAIN) {
		if (type & STORAGE_DIR_TYPE_USER) {
			if (!storage.user_initialized) {
				DBG("user main not initialized");
				return;
			}
		} else if (!storage.initialized) {
			DBG("system main not initialized");
			return;
		}
	} else if (type & STORAGE_DIR_TYPE_VPN) {
		if (type & STORAGE_DIR_TYPE_USER) {
			if (!storage.user_vpn_initialized) {
				DBG("user VPN not initialized");
				return;
			}
		} else if (!storage.vpn_initialized) {
			DBG("system VPN not initialized");
			return;
		}
	}

	DBG("Cleaning up storage directories.");

	connman_inotify_unregister(storagedir, storage_inotify_cb, NULL);

	if (type & STORAGE_DIR_TYPE_USER) {
		while (storage.user_subdirs)
			storage_subdir_unregister(storage.user_subdirs->data);
		storage.user_subdirs = NULL;

		if (type & STORAGE_DIR_TYPE_MAIN) {
			DBG("cleanup user main");
			storage.user_initialized = FALSE;
		} else if (type & STORAGE_DIR_TYPE_VPN) {
			DBG("cleanup user VPN");
			storage.user_vpn_initialized = FALSE;
		}
	} else {
		while (storage.subdirs)
			storage_subdir_unregister(storage.subdirs->data);
		storage.subdirs = NULL;

		if (type & STORAGE_DIR_TYPE_MAIN) {
			DBG("cleanup system main");
			storage.initialized = FALSE;
		} else if (type & STORAGE_DIR_TYPE_VPN) {
			DBG("cleanup system VPN");
			storage.vpn_initialized = FALSE;
		}
	}

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

	pathname = g_build_filename(USER_STORAGEDIR ? USER_STORAGEDIR :
				STORAGEDIR, SETTINGS, NULL);
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

	if (!keyfile)
		return -EINVAL;

	pathname = g_build_filename(USER_STORAGEDIR ? USER_STORAGEDIR :
				STORAGEDIR, SETTINGS, NULL);
	if (!pathname)
		return -ENOMEM;

	ret = storage_save(keyfile, pathname);

	g_free(pathname);

	return ret;
}

void __connman_storage_delete_global(void)
{
	gchar *pathname;

	pathname = g_build_filename(USER_STORAGEDIR ? USER_STORAGEDIR :
				STORAGEDIR, SETTINGS, NULL);
	if (!pathname)
		return;

	storage_delete(pathname);

	g_free(pathname);
}

GKeyFile *__connman_storage_load_config(const char *ident)
{
	gchar *pathname;
	const char *storagedir;
	GKeyFile *keyfile;

	if (!ident)
		return NULL;

	storagedir =  storagedir_for(ident);
	if (!storagedir)
		return NULL;

	pathname = g_strdup_printf("%s/%s.config", storagedir, ident);
	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

GKeyFile *__connman_storage_load_provider_config(const char *ident)
{
	gchar *pathname;
	const char *storagedir;
	GKeyFile *keyfile = NULL;

	if (!ident)
		return NULL;

	storagedir = storagedir_for(ident);
	if (!storagedir)
		return NULL;

	pathname = g_strdup_printf("%s/%s.config", storagedir, ident);
	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

GKeyFile *__connman_storage_open_service(const char *service_id)
{
	gchar *pathname;
	const char *storagedir;
	GKeyFile *keyfile = NULL;

	if (!service_id_is_valid(service_id))
		return NULL;

	storagedir = storagedir_for(service_id);
	if (!storagedir)
		return NULL;

	pathname = g_build_filename(storagedir, service_id, SETTINGS, NULL);
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

static gchar **__connman_storage_get_system_services(int *len)
{
	gchar **result = NULL;
	GList *l;
	unsigned int subdir_count;
	unsigned int pos = 0;

	DBG("");

	if (!storage.initialized) {
		DBG("initialize system storage %s", STORAGEDIR);
		storage_dir_init(STORAGEDIR, STORAGE_DIR_TYPE_MAIN);
		if (!storage.initialized)
			return NULL;
	}

	subdir_count = g_list_length(storage.subdirs);
	if (!subdir_count)
		goto out;

	result = g_new0(gchar *, subdir_count + 1);

	for (pos = 0, l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;

		if (is_user_dir(subdir->name)) {
			DBG("ignore system WiFi/VPN %s with user storage",
						subdir->name);
			continue;
		}

		if (is_service_dir_name(subdir->name) && subdir->has_settings) {
			result[pos++] = g_strdup(subdir->name);
			DBG("keep service %s", subdir->name);
		} else {
			DBG("non-service %s - %s settings", subdir->name,
						subdir->has_settings ?
						"has" : "no");
		}
	}

	DBG("%d system services", pos);

	/* Set the list to correct size */
	if (subdir_count != pos)
		result = g_renew(gchar *, result, pos + 1);

out:
	*len = pos;
	return result;
}

static gchar **__connman_storage_get_user_services(gchar **list, int *len)
{
	GList *l;
	unsigned int subdir_count;
	unsigned int pos;
	unsigned int count;

	DBG("");

	if (!storage.user_initialized) {
		storage_dir_init(USER_STORAGEDIR, STORAGE_DIR_TYPE_MAIN |
					STORAGE_DIR_TYPE_USER);
		if (!storage.user_initialized)
			return list;
	}

	subdir_count = g_list_length(storage.user_subdirs);
	if (!subdir_count)
		return list;

	if (!list)
		list = g_new0(gchar *, subdir_count + 1);
	else
		list = g_renew(gchar *, list, *len + subdir_count + 1);

	for (pos = *len, count = 0, l = storage.user_subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;

		if (!is_user_dir(subdir->name)) {
			DBG("ignore non-WiFi/VPN %s with user storage",
						subdir->name);
			continue;
		}

		if (is_service_dir_name(subdir->name) &&
					subdir->has_settings) {
			DBG("keep WiFi/VPN service %s", subdir->name);
			list[pos++] = g_strdup(subdir->name);
			count++;
		} else {
			DBG("non-service %s - %s settings", subdir->name,
						subdir->has_settings ?
						"has" : "no");
		}
	}

	DBG("%d user services", count);

	/* Set list to correct size if all in the user subdirs are not added */
	if (subdir_count != count)
		list = g_renew(gchar *, list, pos + 1);

	list[pos] = NULL;
	*len = pos;

	return list;
}

gchar **connman_storage_get_services(void)
{
	gchar **result = NULL;
	int len = 0;

	result = __connman_storage_get_system_services(&len);
	DBG("got %d system services", len);

	result = __connman_storage_get_user_services(result, &len);
	DBG("got %d system+user services", len);

	return result;
}

GKeyFile *connman_storage_load_service(const char *service_id)
{
	gchar *pathname;
	const char *storagedir;
	GKeyFile *keyfile = NULL;

	if (!service_id_is_valid(service_id))
		return NULL;

	storagedir = storagedir_for(service_id);
	if (!storagedir)
		return NULL;

	pathname = g_build_filename(storagedir, service_id, SETTINGS, NULL);
	if (!pathname)
		return NULL;

	keyfile =  storage_load(pathname);
	g_free(pathname);

	return keyfile;
}

int __connman_storage_save_service(GKeyFile *keyfile, const char *service_id)
{
	int ret = 0;
	gchar *pathname;
	gchar *dirname;
	const char *storagedir;

	if (!keyfile || !service_id_is_valid(service_id))
		return -EINVAL;

	storagedir = storagedir_for(service_id);
	if (!storagedir)
		return -EINVAL;

	dirname = g_build_filename(storagedir, service_id, NULL);
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

	pathname = g_build_filename(dirname, SETTINGS, NULL);

	g_free(dirname);

	ret = storage_save(keyfile, pathname);

	g_free(pathname);

	return ret;
}

static int remove_file(const char *service_id, const char *file)
{
	gchar *pathname;
	const char *storagedir;
	int err = 0;

	if (!service_id || !file)
		return -EINVAL;

	storagedir = storagedir_for(service_id);
	if (!storagedir)
		return -EINVAL;

	pathname = g_build_filename(storagedir, service_id, file, NULL);
	if (!pathname)
		return -ENOMEM;

	if (!g_file_test(pathname, G_FILE_TEST_EXISTS) ||
			!g_file_test(pathname, G_FILE_TEST_IS_REGULAR)) {
		err = -ENOENT;
		goto out;
	}

	if (unlink(pathname))
		err = -errno;

out:
	g_free(pathname);
	return err;
}

static int remove_dir(const char *service_id)
{
	gchar *pathname;
	const char *storagedir;
	int err = 0;

	if (!service_id || !*service_id)
		return -EINVAL;

	storagedir = storagedir_for(service_id);
	if (!storagedir)
		return -EINVAL;

	pathname = g_build_filename(storagedir, service_id, NULL);
	if (!pathname) {
		err = -ENOMEM;
		goto out;
	}

	if (!g_file_test(pathname, G_FILE_TEST_EXISTS)) {
		err = -ENOENT;
		goto out;
	}

	if (!g_file_test(pathname, G_FILE_TEST_IS_DIR)) {
		err = -ENOTDIR;
		goto out;
	}

	if (rmdir(pathname))
		err = -errno;

out:
	g_free(pathname);
	return err;
}

bool __connman_storage_remove_service(const char *service_id)
{
	bool removed = false;
	gchar *pathname;
	const char *storagedir;
	DIR *dir;
	int err;

	if (!service_id || !service_id_is_valid(service_id))
		return false;

	if (storage.only_unload) {
		struct storage_subdir key = { .name = (gchar*) service_id };
		GList *subdirs;
		GList *pos;

		DBG("Unload service %s", service_id);

		if (is_user_dir(service_id))
			subdirs = storage.user_subdirs;
		else
			subdirs = storage.subdirs;

		pos = g_list_find_custom(subdirs, &key, storage_subdir_cmp);
		if (!pos) {
			DBG("cannot unregister %s", service_id);
			return false;
		}

		storage_subdir_unregister(pos->data);
		return true;
	}

	storagedir = storagedir_for(service_id);
	if (!storagedir)
		return false;

	pathname = g_build_filename(storagedir, service_id, NULL);
	dir = opendir(pathname);

	if (dir) {
		struct dirent *d;

		/* Remove the configuration files */
		while ((d = readdir(dir)) != NULL) {
			if (strcmp(d->d_name, ".") != 0 &&
					strcmp(d->d_name, "..") != 0) {
				err = remove_file(service_id, d->d_name);
				if (err)
					DBG("remove %s/%s failed: %s",
							service_id, d->d_name,
							strerror(-err));
			}
		}

		closedir(dir);

		err = remove_dir(service_id);
		if (err) {
			DBG("Removing %s failed: %s", pathname,
					strerror(-err));
		} else {
			DBG("Removed service dir %s", pathname);
			removed = true;
		}
	}

	g_free(pathname);
	return removed;
}

GKeyFile *__connman_storage_load_provider(const char *identifier)
{
	gchar *pathname;
	gchar *id;
	const char *storagedir;
	GKeyFile *keyfile;

	if (!identifier || !*identifier)
		return NULL;

	DBG("loading %s", identifier);

	id = g_strconcat("provider_", identifier, NULL);

	storagedir = storagedir_for(id);
	if (!storagedir)
		return NULL;

	pathname = g_build_filename(storagedir, id, SETTINGS, NULL);
	DBG("path %s", pathname);
	g_free(id);

	if (!pathname)
		return NULL;

	keyfile = storage_load(pathname);
	g_free(pathname);

	return keyfile;
}

void __connman_storage_save_provider(GKeyFile *keyfile, const char *identifier)
{
	gchar *pathname;
	gchar *dirname;
	gchar *id;
	const char *storagedir;

	if (!keyfile || !identifier || !*identifier)
		return;

	id = g_strconcat("provider_", identifier, NULL);

	storagedir = storagedir_for(id);
	if (!storagedir)
		return;

	dirname = g_build_filename(storagedir, id, NULL);
	g_free(id);

	if (!dirname)
		return;

	if (!g_file_test(dirname, G_FILE_TEST_IS_DIR) &&
			mkdir(dirname, MODE) < 0) {
		g_free(dirname);
		return;
	}

	pathname = g_build_filename(dirname, SETTINGS, NULL);
	g_free(dirname);

	storage_save(keyfile, pathname);
	g_free(pathname);
}

static bool remove_all(const char *id)
{
	bool ret = true;
	int err;

	if (storage.only_unload) {
		struct storage_subdir key = { .name = (gchar*) id };
		GList *subdirs;
		GList *pos;

		DBG("Unload provider %s", id);

		if (is_user_dir(id))
			subdirs = storage.user_subdirs;
		else
			subdirs = storage.subdirs;

		pos = g_list_find_custom(subdirs, &key, storage_subdir_cmp);
		if (!pos) {
			DBG("cannot unregister %s", id);
			return false;
		}

		storage_subdir_unregister(pos->data);
		return true;
	}

	err = remove_file(id, SETTINGS);
	if (err) {
		DBG("remove %s/%s failed: %s", id, SETTINGS, strerror(-err));
		ret = false;
	}

	err = remove_file(id, "data");
	if (err) {
		DBG("remove %s/data failed: %s", id, strerror(-err));
		/* Ignore this, is data used anywhere? */
	}

	err = remove_dir(id);
	if (err) {
		DBG("removing %s failed: %s", id, strerror(-err));
		ret = false;
	}

	return ret;
}

bool __connman_storage_remove_provider(const char *identifier)
{
	bool removed;
	gchar *id;

	if (!identifier)
		return false;

	id = g_strdup_printf("%s_%s", "provider", identifier);
	if (!id)
		return false;

	if (remove_all(id))
		DBG("Removed provider dir %s/%s", storagedir_for(id), id);

	g_free(id);

	id = g_strdup_printf("%s_%s", "vpn", identifier);
	if (!id)
		return false;

	if ((removed = remove_all(id)))
		DBG("Removed vpn dir %s/%s", storagedir_for(id), id);

	g_free(id);

	return removed;
}

static gchar **__connman_storage_get_system_providers(int *len)
{
	gchar **result = NULL;
	GList *l;
	unsigned int subdir_count;
	unsigned int pos = 0;

	DBG("");

	if (USER_VPN_STORAGEDIR) {
		DBG("no system providers USER VPN defined %s",
					USER_VPN_STORAGEDIR);
		return NULL;
	}

	if (!storage.vpn_initialized) {
		storage_dir_init(VPN_STORAGEDIR, STORAGE_DIR_TYPE_VPN);
		if (!storage.vpn_initialized)
			return NULL;
	}

	subdir_count = g_list_length(storage.subdirs);
	if (!subdir_count)
		goto out;

	result = g_new0(gchar *, subdir_count + 1);

	for (pos = 0, l = storage.subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		if (is_provider_dir_name(subdir->name) && subdir->has_settings)
			result[pos++] = g_strdup(subdir->name);
	}

	/* Set the list to correct size */
	if (subdir_count != pos)
		result = g_renew(gchar *, result, pos + 1);

out:
	*len = pos;
	return result;
}

static gchar **__connman_storage_get_user_providers(gchar **list, int *len)
{
	GList *l;
	unsigned int subdir_count;
	unsigned int pos;
	unsigned int count;

	DBG("list %p len %d", list, *len);

	if (!storage.user_vpn_initialized) {
		storage_dir_init(USER_VPN_STORAGEDIR, STORAGE_DIR_TYPE_VPN |
					STORAGE_DIR_TYPE_USER);
		if (!storage.user_vpn_initialized)
			return list;
	}

	subdir_count = g_list_length(storage.user_subdirs);
	if (!subdir_count)
		return list;

	if (!list)
		list = g_new0(gchar *, subdir_count + 1);
	else
		list = g_renew(gchar *, list, *len + subdir_count + 1);

	for (pos = *len, count = 0, l = storage.user_subdirs; l; l = l->next) {
		struct storage_subdir *subdir = l->data;
		if (is_provider_dir_name(subdir->name) &&
					subdir->has_settings) {
			list[pos++] = g_strdup(subdir->name);
			count++;
		}
	}

	DBG("%d user providers ", count);

	/* Set list to correct size if all in user subdirs are not added */
	if (subdir_count != count)
		list = g_renew(gchar *, list, pos + 1);

	list[pos] = NULL;
	*len = pos;

	return list;
}

gchar **__connman_storage_get_providers(void)
{
	gchar **result = NULL;
	int len = 0;

	DBG("");

	result = __connman_storage_get_system_providers(&len);
	DBG("got %d system providers", len);

	result = __connman_storage_get_user_providers(result, &len);
	DBG("got %d system + user providers", len);

	return result;
}

static char *storage_dir = NULL;
static char *vpn_storage_dir = NULL;
static char *user_storage_dir = NULL;
static char *user_vpn_storage_dir = NULL;
static mode_t storage_dir_mode;
static mode_t storage_file_mode;

const char *connman_storage_dir(void)
{
	return storage_dir;
}

const char *connman_storage_vpn_dir(void)
{
	return vpn_storage_dir;
}

const char *connman_storage_user_dir(void)
{
	return user_storage_dir;
}

const char *connman_storage_user_vpn_dir(void)
{
	return user_vpn_storage_dir;
}

const char *connman_storage_dir_for(const char *service_id)
{
	/* TODO perhaps always default to STORAGEDIR even with invalid ones */
	if (!service_id || !*service_id)
		return NULL;

	return storagedir_for(service_id);
}

static char* build_filename(const char *dir,
					enum connman_storage_dir_type type)
{
	char *path = NULL;

	if (!dir)
		return NULL;

	switch (type) {
	case STORAGE_DIR_TYPE_MAIN:
		path = g_build_filename(dir, "connman", NULL);
		break;
	case STORAGE_DIR_TYPE_VPN:
		path = g_build_filename(dir, "connman-vpn", NULL);
		break;
	case STORAGE_DIR_TYPE_STATE:
		path = g_strdup(dir);
		break;
	case STORAGE_DIR_TYPE_USER:
		DBG("invalid type %d/user", type);
		return NULL;
	}

	DBG("created path %s", path);

	return path;
}

static int change_storage_dir(const char *root,
			enum connman_storage_dir_type type, bool prepare_only)
{
	gchar **items;
	char *path;
	char *vpn_path;
	bool user_reset = false;
	int len = 0;
	int err = 0;

	DBG("change %s dir to %s", type == STORAGE_DIR_TYPE_MAIN ?
				"main" : type == STORAGE_DIR_TYPE_VPN ? "vpn" :
				type == STORAGE_DIR_TYPE_STATE ? "state" :
				"user = invalid", root);

	/* User change needs to unload the services from use, not to remove */
	storage.only_unload = TRUE;

	switch (type) {
	case STORAGE_DIR_TYPE_MAIN:
		path = build_filename(root, type);

		if (user_storage_dir && !g_strcmp0(user_storage_dir, path)) {
			DBG("system main is already at %s", path);
			err = -EALREADY;
			g_free(path);
			goto out;
		}

		vpn_path = build_filename(root, STORAGE_DIR_TYPE_VPN);

		/*
		 * Set user VPN regarless if it is already set as the same.
		 * This shouldn't be reached as the user storage would be also
		 * set. */
		if (user_vpn_storage_dir &&
				!g_strcmp0(user_vpn_storage_dir, vpn_path))
			DBG("system vpn is already at %s", path);

		/*
		 * Changing to other user or going back to root both are set.
		 * This cleans the user services and cleanups the dirs.
		 */
		if (user_storage_dir || user_vpn_storage_dir) {
			DBG("clean user dir %s vpn %s",
						user_storage_dir,
						user_vpn_storage_dir);

			if (cbs && cbs->pre && !cbs->pre())
				DBG("main user preparations failed");

			/* Nothing to unload if user dir isn't initialized */
			if (storage.user_initialized) {
				DBG("unload user services");

				items = __connman_storage_get_user_services(
							NULL, &len);
				if (items) {
					if (cbs && cbs->unload)
						cbs->unload(items, len);

					g_strfreev(items);
					len = 0;
				}
			}

			if (user_storage_dir) {
				DBG("clean user storage dir %s",
							user_storage_dir);

				storage_dir_cleanup(user_storage_dir,
							STORAGE_DIR_TYPE_MAIN |
							STORAGE_DIR_TYPE_USER);
			}

			if (user_vpn_storage_dir) {
				DBG("clean user vpn storage dir %s",
							user_vpn_storage_dir);

				storage_dir_cleanup(user_vpn_storage_dir,
							STORAGE_DIR_TYPE_VPN |
							STORAGE_DIR_TYPE_USER);
			}

			g_free(user_storage_dir);
			g_free(user_vpn_storage_dir);
			user_storage_dir = NULL;
			user_vpn_storage_dir = NULL;
			user_reset = true;
		}

		/* Path given, cleanup system technologies and services.*/
		if (root) {
			DBG("change user dir to %s vpn %s", path, vpn_path);

			if (!prepare_only && cbs && cbs->pre && !cbs->pre())
				DBG("main system preparations failed");

			/* Nothing to unload if storage isn't initialized */
			if (!prepare_only && storage.initialized) {
				DBG("unload system services");

				items = __connman_storage_get_system_services(
							&len);
				if (items) {
					if (cbs && cbs->unload)
						cbs->unload(items, len);

					g_strfreev(items);
				}
			}

			DBG("clean system dirs");

			storage_dir_cleanup(storage_dir,
						STORAGE_DIR_TYPE_MAIN);
			storage_dir_cleanup(vpn_storage_dir,
						STORAGE_DIR_TYPE_VPN);

			user_storage_dir = path;
			user_vpn_storage_dir = vpn_path;
		} else {
			/*
			 * User was not reset, already running as root.
			 * Skip loading and post callbacks.
			 */
			if (!user_reset) {
				err = -EALREADY;
				DBG("already running as root, no user reset");
				goto out;
			}

			DBG("going back to root (system %s vpn %s)",
						storage_dir, vpn_storage_dir);
			/* TODO: may be a better way to do reset */
			storage_dir_cleanup(storage_dir,
						STORAGE_DIR_TYPE_MAIN);
			storage_dir_cleanup(vpn_storage_dir,
						STORAGE_DIR_TYPE_VPN);
		}

		/*
		 * If requested only to prepare technology setup and service
		 * loading will be done by the component initialization using
		 * the user set here in storage. Thus, load and post cb's are
		 * skipped.
		 */
		if (prepare_only)
			goto out;

		break;
	case STORAGE_DIR_TYPE_VPN:
		path = build_filename(root, type);

		if (user_vpn_storage_dir) {
			if (!g_strcmp0(user_vpn_storage_dir, path)) {
				err = -EALREADY;
				g_free(path);
				goto out;
			}

			if (cbs && cbs->pre && !cbs->pre())
				DBG("VPN user preparations failed");

			/*
			 * Nothing to unload If the user dir isn't
			 * initialized.
			 */
			if (storage.user_vpn_initialized) {
				items = __connman_storage_get_user_providers(
							NULL, &len);
				if (items) {
					if (cbs && cbs->unload)
						cbs->unload(items, len);

					g_strfreev(items);
					len = 0;
				}
			}

			storage_dir_cleanup(user_vpn_storage_dir,
						STORAGE_DIR_TYPE_VPN |
						STORAGE_DIR_TYPE_USER);

			g_free(user_vpn_storage_dir);
			user_vpn_storage_dir = NULL;
			user_reset = true;
		}

		if (root) {
			if (cbs && cbs->pre && !cbs->pre())
				DBG("VPN system preparations failed");

			if (storage.vpn_initialized) {
				items = __connman_storage_get_system_providers(
							&len);
				if (items) {
					if (cbs && cbs->unload)
						cbs->unload(items, len);

					g_strfreev(items);
				}
			}

			storage_dir_cleanup(vpn_storage_dir,
						STORAGE_DIR_TYPE_VPN);

			user_vpn_storage_dir = path;
		} else {
			/* User was not set, already running as root */
			if (!user_reset) {
				err = -EALREADY;
				DBG("already running as root");
				goto out;
			}

			DBG("going back to root");

			storage_dir_cleanup(vpn_storage_dir,
							STORAGE_DIR_TYPE_VPN);
		}

		break;
	case STORAGE_DIR_TYPE_USER:
	case STORAGE_DIR_TYPE_STATE:
		err = -EINVAL;
		goto out;
	}

	if (cbs && cbs->load) {
		DBG("load services");
		cbs->load();
	}

	if (cbs && cbs->post) {
		DBG("Run post setup");

		if (!cbs->post())
			DBG("post setup failed");
	}

out:
	/*
	 * Restore the default behavior in storage to allow removal of the
	 * service and provider files.
	 */
	storage.only_unload = FALSE;

	return err;
}

int __connman_storage_create_dir(const char *dir, mode_t permissions)
{
	if (g_mkdir_with_parents(dir, permissions) < 0) {
		if (errno != EEXIST) {
			DBG("Failed to create storage directory "
						"\"%s\", error: %s", dir,
						strerror(errno));
			return -errno;
		}
	}

	return 0;
}

mode_t __connman_storage_dir_mode(void)
{
	return storage_dir_mode;
}

mode_t __connman_storage_file_mode(void)
{
	return storage_file_mode;
}

static struct passwd *check_user(uid_t uid, int *err,
							bool *system_user)
{
	const char *shell;
	struct passwd *pwd;
	bool login_shell = false;

	/*
	 * Stated in the manual pages of getpwuid(): "If one wants to check
	 * errno after the call, it should be set to zero before the call".
	 */
	errno = 0;

	pwd = getpwuid(uid);
	if (!pwd) {
		if (!errno)
			DBG("uid \"%d\" does not exist", uid);

		*system_user = false;
		goto out;
	}

	setusershell();

	/* Exclude users that have no system accepted login shell set */
	while ((shell = getusershell())) {
		if (!g_strcmp0(pwd->pw_shell, shell)) {
			login_shell = true;
			break;
		}
	}

	endusershell();

	if (!login_shell) {
		DBG("invalid user %d:%s login shell %s", uid, pwd->pw_name,
					pwd->pw_shell);
		pwd = NULL;
		*system_user = false;
		goto out;
	}

	*system_user = pwd->pw_uid == 0 || pwd->pw_uid == geteuid();

	DBG("\"%d:%s\" is %s user", uid, pwd->pw_name,
				*system_user ? "system" : "regular");

out:
	*err = errno;

	return pwd;
}

static int set_user_dir(const char *root, enum connman_storage_dir_type type,
			bool prepare_only)
{
	const char *dir;
	int err;

	DBG("");

	/* This sets both main and VPN! */
	err = change_storage_dir(root, type, prepare_only);
	if (err) {
		DBG("cannot change dir root to %s error %s", root,
					strerror(-err));
		return err;
	}

	/* Skip user storage dir creations if changing back to root */
	if (!root || !*root)
		return 0;

	switch (type) {
	case STORAGE_DIR_TYPE_MAIN:
		dir = USER_STORAGEDIR;
		break;
	case STORAGE_DIR_TYPE_VPN:
		dir = USER_VPN_STORAGEDIR;
		break;
	default:
		return -EINVAL;
	}

	err = __connman_storage_create_dir(dir, storage_dir_mode);
	if (err) {
		DBG("cannot create connman user storage dir in %s error %s",
					root, strerror(-err));
		goto err;
	}

	/* connmand needs also VPN dir to be set */
	if (type == STORAGE_DIR_TYPE_MAIN) {
		err = __connman_storage_create_dir(USER_VPN_STORAGEDIR,
					storage_dir_mode);
		if (err) {
			DBG("cannot create connman user VPN storage dir in %s "
						" error %s", root,
						strerror(-err));
			goto err;
		}
	}

	return 0;

err:
	change_storage_dir(NULL, type, prepare_only);

	return err;
}

struct change_user_data {
	DBusMessage *pending;
	connman_storage_change_user_result_cb_t result_cb;
	void *user_cb_data;
	uid_t uid;
	char *path;
	bool prepare_only;
};

static struct change_user_data *new_change_user_data(DBusMessage *msg,
			connman_storage_change_user_result_cb_t cb,
			void *user_cb_data, uid_t uid, const char *path,
			bool system_user, bool prepare_only)
{
	struct change_user_data *data;

	data = g_new0(struct change_user_data, 1);

	if (msg)
		data->pending = dbus_message_ref(msg);

	data->result_cb = cb;
	data->user_cb_data = user_cb_data;
	data->uid = uid;

	/* For system user path is NULL */
	if (!system_user)
		data->path = g_build_filename(path, DEFAULT_USER_STORAGE,
					NULL);

	data->prepare_only = prepare_only;

	return data;
}

static void free_change_user_data(struct change_user_data *data)
{
	if (!data)
		return;

	if (data->pending)
		dbus_message_unref(data->pending);

	g_free(data->path);
	g_free(data);
}

static void storage_change_uid(uid_t uid)
{
	storage.current_uid = uid;

	if (cbs && cbs->uid_changed)
		cbs->uid_changed(storage.current_uid);
}

static int send_change_user_msg(struct change_user_data *data);

static gboolean send_delayed_user_change(gpointer user_data)
{
	struct change_user_data *data = user_data;
	DBusMessage *reply;
	int err;

	DBG("");

	/* Stop this if the user change has been already notified */
	if (!send_vpnd_change_user) {
		DBG("user change already notified, stopping");
		goto out;
	}

	err = send_change_user_msg(data);
	switch (err) {
	case -EINPROGRESS:
		DBG("sent user %u change to vpnd", data->uid);
		goto out;
	case -EBUSY:
		DBG("pending call is still active, wait");
		/*
		 * EBUSY is reported if there is a pending call ongoing. In
		 * such case reply to the pending request that change is in
		 * progress to avoid potential sending of timeout. Callback is
		 * eventually called in change_user_reply().
		 */
		if (data->pending) {
			reply = __connman_error_in_progress(data->pending);
			if (reply) {
				g_dbus_send_message(connection, reply);
				dbus_message_unref(data->pending);
				data->pending = NULL;
			}
		}

		return G_SOURCE_CONTINUE;
	default:
		connman_error("failed to send user change message, error %d",
					err);

		if (data->pending) {
			reply = __connman_error_failed(data->pending, -err);
			if (reply)
				g_dbus_send_message(connection, reply);
		}

		if (data->result_cb)
			data->result_cb(data->uid, err, data->user_cb_data);

		break;
	}

	send_vpnd_change_user = false;
	free_change_user_data(data);

out:
	delayed_user_change_id = 0;

	return G_SOURCE_REMOVE;
}

static int init_delayed_user_change(gpointer user_data, guint timeout)
{
	DBG("");

	if (delayed_user_change_id)
		return -EALREADY;

	delayed_user_change_id = g_timeout_add(timeout,
				send_delayed_user_change, user_data);

	return 0;
}

static void change_user_reply(DBusPendingCall *call, void *user_data)
{
	struct change_user_data *data;
	DBusMessage *reply;
	DBusError error;
	int err = 0;
	int delay = USER_CHANGE_DELAY;

	data = user_data;

	if (call != vpn_change_call) {
		DBG("pending call not set or invalid (ongoing %p this %p)",
					vpn_change_call, call);
		return;
	}

	reply = dbus_pending_call_steal_reply(call);
	if (!reply) {
		err = -ETIMEDOUT;
		goto err;
	}

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		if (g_str_has_suffix(error.name, ".InvalidArguments")) {
			DBG("Cannot change user root for VPN");
			err = -EINVAL;
		} else if (g_str_has_suffix(error.name, ".AlreadyEnabled")) {
			DBG("User is already active");
			err = -EALREADY;
		} else if (g_str_has_suffix(error.name, ".PermissionDenied")) {
			DBG("Not allowed to change user, permission denied");
			err = -EPERM;
		} else if (g_str_has_suffix(error.name, ".Timeout") ||
				g_str_has_suffix(error.name, ".TimedOut")) {
			DBG("Timeout with D-Bus occurred");
			err = -ETIMEDOUT;
		} else if (g_str_has_suffix(error.name, ".NotConnected")) {
			DBG("D-Bus peering not complete yet, try later");
			err = -ENOTCONN;
		} else if (g_str_has_suffix(error.name, ".UnknownMethod") ||
				g_str_has_suffix(error.name, ".NoReply")) {
			DBG("vpnd server not available, try later");
			err = -ENONET;
		} else if (g_str_has_suffix(error.name, ".LimitsExceeded")) {
			DBG("D-Bus is congested, try later with double limit");
			err = -EBUSY;
		} else {
			DBG("unknown error %s", error.name);
			err = -ENOENT;
		}

		dbus_error_free(&error);
	}

	dbus_message_unref(reply);

	switch (err) {
	case 0:
	case -EALREADY:
		/*
		 * If connmand has crashed and tries to set vpnd to the same
		 * user as the vpnd already had it is not an error. Just
		 * continue as normal. Both D-Bus API and internal API handles
		 the check for uid prior to this.
		 */
		break;
	case -EBUSY:
		/* D-Bus was congested, double delay */
		delay += USER_CHANGE_DELAY;
	case -ETIMEDOUT:
		/* fall through */
	case -ENOTCONN:
		/* fall through */
	case -ENONET:
		if (!init_delayed_user_change(data, delay)) {
			send_vpnd_change_user = true;
			goto out_no_free;
		}

		/* Otherwise, fall though */
	default:
		goto err;
	}

	/*
	 * Got a reply from vpnd with the same uid that is currently set =
	 * vpnd has crashed and the current user was notified to it. No action.
	 */
	if (storage.current_uid == data->uid)
		goto out;

	/* Preparations are done prior to D-Bus message to vpnd */
	if (!data->prepare_only) {
		err = set_user_dir(data->path, STORAGE_DIR_TYPE_MAIN,
					data->prepare_only);
		if (err)
			goto err;
	}

	storage_change_uid(data->uid);

	if (cbs && cbs->finalize)
		cbs->finalize(data->uid, cbs->finalize_user_data);

	if (data->pending) {
		if (!g_dbus_send_reply(connection, data->pending,
					DBUS_TYPE_INVALID))
			connman_error("cannot reply to pending user change");

		/* g_dbus_send_reply() always unrefs the message */
		data->pending = NULL;
	}

	goto out;

err:
	/* When preparing revert to root user if vpnd fails to change user. */
	if (data->prepare_only) {
		set_user_dir(NULL, STORAGE_DIR_TYPE_MAIN, false);
		data->uid = geteuid();
		storage_change_uid(data->uid);
	}

	if (!data->pending)
		goto out;

	switch (-err) {
	case EALREADY:
		reply = __connman_error_already_enabled(data->pending);
		break;
	case ENOENT:
		reply = __connman_error_not_found(data->pending);
		break;
	default:
		/* EINVAL, EPERM and ETIMEDOUT are handled correctly */
		reply = __connman_error_failed(data->pending, -err);
	}

	if (!g_dbus_send_message(connection, reply))
		connman_error("cannot send D-Bus error %d/%s reply", err,
					strerror(-err));

out:
	if (data->result_cb)
		data->result_cb(data->uid, err, data->user_cb_data);

	free_change_user_data(data);

out_no_free:
	dbus_pending_call_unref(vpn_change_call);
	vpn_change_call = NULL;
}

static int send_change_user_msg(struct change_user_data *data)
{
	DBusMessage *msg;
	dbus_uint32_t uid;
	int err = -EINPROGRESS;

	if (!data)
		return -EINVAL;

	if (vpn_change_call) {
		DBG("user change call already in progress");
		return -EBUSY;
	}

	DBG("user %u", data->uid);

	msg = dbus_message_new_method_call(VPN_SERVICE, VPN_STORAGE_PATH,
				VPN_STORAGE_INTERFACE,
				VPN_STORAGE_CHANGE_USER);
	if (!msg) {
		err = -ENOMEM;
		goto out;
	}

	uid = (dbus_uint32_t)data->uid;

	if (!dbus_message_append_args(msg, DBUS_TYPE_UINT32, &uid,
				DBUS_TYPE_INVALID)) {
		err = -EINVAL;
		goto out;
	}

	if (!g_dbus_send_message_with_reply(connection, msg, &vpn_change_call,
				DBUS_TIMEOUT_USE_DEFAULT)) {
		connman_error("Unable to call %s.%s()", VPN_STORAGE_INTERFACE,
					VPN_STORAGE_CHANGE_USER);
		err = -ECOMM;
		goto out;
	}

	if (!vpn_change_call) {
		err = -ECANCELED;
		goto out;
	}

	if (!dbus_pending_call_set_notify(vpn_change_call, change_user_reply,
				data, NULL)) {
		connman_warn("Failed to set notify for change user request");
		err = -ENOMEM;
		dbus_pending_call_unref(vpn_change_call);
		vpn_change_call = NULL;
	}

out:
	if (msg)
		dbus_message_unref(msg);

	return err;
}

static DBusMessage *change_user(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct change_user_data *user_data;
	struct passwd *pwd;
	DBusError error;
	dbus_uint32_t uid;
	int err;
	bool system_user;

	DBG("conn %p", conn);

	dbus_error_init(&error);

	dbus_message_get_args(msg, &error, DBUS_TYPE_UINT32, &uid,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&error)) {
		dbus_error_free(&error);
		return __connman_error_invalid_arguments(msg);
	}

	if (cbs && cbs->access_change_user) {
		DBusMessage *error_reply = NULL;
		const char *sender = dbus_message_get_sender(msg);
		/* Because of libdbus da_policy_check() use int as string */
		char *userid = g_strdup_printf("%u", uid);

		switch (cbs->access_change_user(get_storage_access_policy(),
					userid, sender,
					CONNMAN_ACCESS_ALLOW)) {
		case CONNMAN_ACCESS_ALLOW:
			break;
		case CONNMAN_ACCESS_DENY:
			/* fall through */
		default:
			connman_warn("%s is not allowed to change user",
						sender);
			error_reply = __connman_error_permission_denied(msg);
		}

		g_free(userid);

		if (error_reply)
			return error_reply;
	}

	if ((uid_t)uid == storage.current_uid) {
		DBG("user %u already set", uid);
		return __connman_error_already_enabled(msg);
	}

	/* No error set = invalid user */
	pwd = check_user((uid_t)uid, &err, &system_user);
	if (!pwd)
		return __connman_error_failed(msg, err ? err : EINVAL);

	user_data = new_change_user_data(msg, NULL, NULL, uid, pwd->pw_dir,
				system_user, false);

	DBG("path \"%s\"", user_data->path);

	err = send_change_user_msg(user_data);
	if (err != -EINPROGRESS) {
		free_change_user_data(user_data);
		return __connman_error_failed(msg, -err);
	}

	return NULL;
}

static DBusMessage *change_user_vpn(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct passwd *pwd;
	DBusMessage *error_reply = NULL;
	DBusError error;
	char *path = NULL;
	dbus_uint32_t uid;
	int err;
	bool system_user;

	DBG("conn %p", conn);

	dbus_error_init(&error);

	dbus_message_get_args(msg, &error, DBUS_TYPE_UINT32, &uid,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&error)) {
		dbus_error_free(&error);
		return __connman_error_invalid_arguments(msg);
	}

	if (cbs && cbs->get_peer_dbus_name) {
		const char *sender = dbus_message_get_sender(msg);
		const char *connman_dbus_name = cbs->get_peer_dbus_name();

		if (!connman_dbus_name) {
			connman_warn("D-Bus peer name not established yet");
			return __connman_error_not_connected(msg);
		}

		if (g_strcmp0(sender, connman_dbus_name)) {
			connman_warn("user change from %s, expected %s",
						sender, connman_dbus_name);
			return __connman_error_permission_denied(msg);
		}
	}

	if (cbs && cbs->vpn_access_change_user) {
		const char *sender = dbus_message_get_sender(msg);
		char *userid = g_strdup_printf("%d", uid);

		if (!cbs->vpn_access_change_user(sender, userid, TRUE)) {
			connman_warn("%s is not allowed to change user",
						sender);
			error_reply = __connman_error_permission_denied(msg);
		}

		g_free(userid);

		if (error_reply)
			return error_reply;
	}

	if ((uid_t)uid == storage.current_uid)
		return __connman_error_already_enabled(msg);

	pwd = check_user((uid_t)uid, &err, &system_user);
	if (!pwd)
		return __connman_error_failed(msg, err ? err : EINVAL);

	DBG("user %d:%s", uid, pwd->pw_name);

	if (!system_user)
		path = g_build_filename(pwd->pw_dir, DEFAULT_USER_STORAGE,
					NULL);

	DBG("path \"%s\"", path);

	err = set_user_dir(path, STORAGE_DIR_TYPE_VPN, false);
	switch (err) {
	case 0:
		break;
	case -EALREADY:
		/* EALREADY in error.c is treated as in progress error. */
		error_reply = __connman_error_already_enabled(msg);
		break;
	default:
		error_reply = __connman_error_failed(msg, -err);
		break;
	}

	g_free(path);

	if (error_reply)
		return error_reply;

	if (cbs && cbs->finalize)
		cbs->finalize((uid_t)uid, cbs->finalize_user_data);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

/*
 * This function is called internally only. When doing the initial preparation
 * at startup (prepare_only = true) the callback (cb) is called twice. First at
 * the end of the function, and second when a reply from vpnd arrives.When
 * calling this with prepare_only = false, the callback will be called when
 * reply is received from vpnd.
 *
 * In case of an error, the callback is called only once, as the call to vpnd
 * is not sent.
 *
 * When success this function returns -EINPROGRESS to indicate that the call
 * to vpnd is sent and reply is pending.
 */
int __connman_storage_change_user(uid_t uid,
			connman_storage_change_user_result_cb_t cb,
			void *user_cb_data, bool prepare_only)
{
	struct change_user_data *user_data;
	struct passwd *pwd;
	int err;
	bool system_user;

	/* No error set = invalid user */
	pwd = check_user(uid, &err, &system_user);
	if (!pwd)
		return err ? -err : -EINVAL;

	/*
	 * UID is normally an unsigned 32bit integer. Report error if the UID
	 * value is bigger than that.
	 */
	if (uid > UINT32_MAX) {
		connman_error("uid exceeds uint32 limit");
		return -EINVAL;
	}

	if (storage.current_uid == uid)
		return -EALREADY;

	user_data = new_change_user_data(NULL, cb, user_cb_data, uid,
				pwd->pw_dir, system_user, prepare_only);

	DBG("path \"%s\"", user_data->path);

	/* Use reverse order in preparation, set connmand paths before
	 * communicating with vpnd. vpnd is initialized by systemd and has
	 * initialized all when the message is processed. But connmand has
	 * not initialized technology, service and device.
	 */
	if (user_data->prepare_only) {
		err = set_user_dir(user_data->path, STORAGE_DIR_TYPE_MAIN,
					user_data->prepare_only);
		if (err)
			goto out;
	}

	err = send_change_user_msg(user_data);

out:
	if (user_data->prepare_only) {
		/* If sending of D-Bus message fails or the setup of user dir
		 * is not successful revert back to root user in connmand.
		 */
		if (err != -EINPROGRESS) {
			set_user_dir(NULL, STORAGE_DIR_TYPE_MAIN, false);
			user_data->uid = geteuid();
		}

		/* Inform the caller twice when preparing */
		if (user_data->result_cb)
			user_data->result_cb(user_data->uid, err,
						user_data->user_cb_data);

		storage_change_uid(user_data->uid);
	}

	if (err != -EINPROGRESS)
		free_change_user_data(user_data);

	return err;
}

static void result_cb(uid_t uid, int err, void *user_data)
{
	if (err && err != -EALREADY) {
		connman_error("changing uid %u to vpnd failed (err: %d), "
				"reset to uid %u", storage.current_uid, err,
				geteuid());
		set_user_dir(NULL, STORAGE_DIR_TYPE_MAIN, false);
		storage_change_uid(geteuid());
		return;
	}

	DBG("user %u changed to vpnd", storage.current_uid);
}

static void vpnd_created(DBusConnection *conn, void *user_data)
{
	struct change_user_data *data;
	struct passwd *pwd;
	bool system_user;
	int err;

	DBG("");

	/* Send the user change only when vpnd was closed/crashed */
	if (!send_vpnd_change_user)
		return;

	/* When user was not changed, only reset the flag */
	if (storage.current_uid == geteuid())
		goto out;

	pwd = check_user(storage.current_uid, &err, &system_user);
	if (!pwd) {
		connman_warn("invalid current user %u", storage.current_uid);
		goto out;
	}

	data = new_change_user_data(NULL, result_cb, NULL, storage.current_uid,
				pwd->pw_dir, system_user, false);

	err = send_change_user_msg(data);
	switch (err) {
	case -EINPROGRESS:
		DBG("sent user %u change to vpnd", data->uid);
		goto out; /* Success */
	case -EBUSY:
		DBG("ongoing pending call, delay user change");

		/*
		 * If vpnd crashes in between user change and comes up during
		 * the timeout wait the user notify needs to be sent later to
		 * vpn if there is a pending call waiting for reply.
		 */
		if (!init_delayed_user_change(data, USER_CHANGE_DELAY))
			return;

		goto free;
	default:
		connman_error("failed to send user change message, error: %d",
					err);
		goto free;
	}

free:
	free_change_user_data(data);

out:
	send_vpnd_change_user = false;
}

static void vpnd_removed(DBusConnection *conn, void *user_data)
{
	DBG("");

	send_vpnd_change_user = true;
}

static const GDBusMethodTable storage_methods[] = {
	{ GDBUS_ASYNC_METHOD("ChangeUser", GDBUS_ARGS({ "uid", "u" }),
				NULL, change_user) },
	{ },
};


static const GDBusMethodTable storage_methods_vpn[] = {
	{ GDBUS_ASYNC_METHOD(VPN_STORAGE_CHANGE_USER,
				GDBUS_ARGS({ "uid", "u" }),
				NULL, change_user_vpn) },
	{ },
};

/*
 * Registration of D-Bus and callbacks is to be called once per process using
 * storage.
 */
int __connman_storage_register_dbus(enum connman_storage_dir_type type,
				struct connman_storage_callbacks *callbacks)
{
	const GDBusMethodTable *methods;

	if (!connection)
		connection = connman_dbus_get_connection();

	if (!connection)
		return -ENOTCONN;

	/*
	 * Not the best practice, but TODO: enable this later when unit test
	 * simulation is done using forking or threads, to avoid this being
	 * called more than once.
	if (dbus_interface && dbus_path)
		return -EALREADY;
	*/

	switch (type) {
	case STORAGE_DIR_TYPE_MAIN:
		methods = storage_methods;
		dbus_interface = CONNMAN_STORAGE_INTERFACE;
		dbus_path = CONNMAN_STORAGE_PATH;
		vpnd_watch = g_dbus_add_service_watch(connection, VPN_SERVICE,
					vpnd_created, vpnd_removed, NULL,
					NULL);
		break;
	case STORAGE_DIR_TYPE_VPN:
		methods = storage_methods_vpn;
		dbus_interface = VPN_STORAGE_INTERFACE;
		dbus_path = VPN_STORAGE_PATH;
		break;
	default:
		return -EINVAL;
	}

	if (!g_dbus_register_interface(connection, dbus_path, dbus_interface,
				methods, NULL, NULL, NULL, NULL)) {
		connman_error("cannot register %s D-Bus methods",
					dbus_interface);
		dbus_path = dbus_interface = NULL;
		return -ENOENT;
	}

	cbs = callbacks;

	return 0;
}

/* Update the finalize callback, when cb is NULL the callback is reset. */
void connman_storage_update_finalize_cb(
				void (*cb) (uid_t uid, void *user_data),
				void *user_data)
{
	if (!cbs)
		return;

	cbs->finalize = cb;
	cbs->finalize_user_data = user_data;
}

int __connman_storage_init(const char *dir, mode_t dir_mode, mode_t file_mode)
{
	const char *root = dir ? dir : DEFAULT_STORAGE_ROOT;

	DBG("%s 0%o 0%o", root, dir_mode, file_mode);
	storage_dir = build_filename(root, STORAGE_DIR_TYPE_MAIN);
	vpn_storage_dir = build_filename(root, STORAGE_DIR_TYPE_VPN);
	storage_dir_mode = dir_mode;
	storage_file_mode = file_mode;
	storage.current_uid = geteuid();
	keyfile_init();

	return 0;
}

void __connman_storage_cleanup(void)
{
	DBG("");
	storage_dir_cleanup(storage_dir, STORAGE_DIR_TYPE_MAIN);
	storage_dir_cleanup(vpn_storage_dir, STORAGE_DIR_TYPE_VPN);

	if (user_storage_dir)
		storage_dir_cleanup(user_storage_dir, STORAGE_DIR_TYPE_MAIN |
						STORAGE_DIR_TYPE_USER);

	if (user_vpn_storage_dir)
		storage_dir_cleanup(user_vpn_storage_dir,
					STORAGE_DIR_TYPE_VPN |
					STORAGE_DIR_TYPE_USER);

	if (vpnd_watch)
		g_dbus_remove_watch(connection, vpnd_watch);

	if (delayed_user_change_id)
		g_source_remove(delayed_user_change_id);

	if (connection) {
		if (dbus_path && dbus_interface) {
			if (!g_dbus_unregister_interface(connection,
						dbus_path, dbus_interface))
				connman_error("cannot unregister interface %s",
							dbus_interface);
		}

		dbus_connection_unref(connection);
	}

	keyfile_cleanup();
	g_free(storage_dir);
	g_free(vpn_storage_dir);
	g_free(user_storage_dir);
	g_free(user_vpn_storage_dir);

	storage_dir = NULL;
	vpn_storage_dir = NULL;
	user_storage_dir = NULL;
	user_vpn_storage_dir = NULL;

	dbus_path = NULL;
	dbus_interface = NULL;

	if (cbs && cbs->access_policy_free && storage_access_policy)
		cbs->access_policy_free(storage_access_policy);

	storage_access_policy = NULL;

}
