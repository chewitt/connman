/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2015-2018  Jolla Ltd.
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

#include <dlfcn.h>

#include <glib.h>

#ifdef CONNMAN_PLUGIN_BUILTIN
#undef CONNMAN_PLUGIN_BUILTIN
#endif

#include "connman.h"

static GSList *plugins = NULL;

struct connman_plugin {
	void *handle;
	bool active;
	struct connman_plugin_desc *desc;
};

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_plugin *plugin1 = a;
	const struct connman_plugin *plugin2 = b;

	return plugin2->desc->priority - plugin1->desc->priority;
}

#define NUM_VER 3

static gboolean parse_version(const char *str, guint *v)
{
	gboolean ok = FALSE;

	memset(v, 0, sizeof(v[0]) * NUM_VER);
	if (str) {
		int i;

		for (i = 0; i < NUM_VER && *str; i++) {
			while (*str && !g_ascii_isdigit(*str)) str++;
			while (*str && g_ascii_isdigit(*str)) {
				ok = TRUE;
				v[i] *= 10;
				v[i] += *str++ - '0';
				if (v[i] >= 0x7fffffff/10) {
					return FALSE;
				}
			}
		}
	}

	return ok;
}

static int compare_versions(const guint* v1, const guint* v2)
{
	int i;

	for (i = 0; i < NUM_VER; i++) {
		if (v1[i] < v2[i])
			return -1;
		else if (v1[i] > v2[i])
			return 1;
	}

	return 0;
}

static bool add_plugin(void *handle, struct connman_plugin_desc *desc)
{
	struct connman_plugin *plugin;
	guint connman_version[NUM_VER], plugin_version[NUM_VER];

	if (!desc->init)
		return false;

	/* Check the validity of the interface version */
	if (desc->interface_version != CONNMAN_PLUGIN_INTERFACE_VERSION) {
		connman_error("Invalid plugin interface version %d for %s",
				desc->interface_version, desc->description);
		return false;
	}

	/* This better work */
	parse_version(CONNMAN_VERSION, connman_version);

	/* Allow older versions (API must be backward compatible) */
	if (!parse_version(desc->version, plugin_version)) {
		connman_error("Failed to parse version %s of %s", desc->version,
							desc->description);
		return false;
	}

	if (compare_versions(plugin_version, connman_version) > 0) {
		connman_error("%s version %s (%u.%u.%u) is newer than "
			"connman version %s (%u.%u.%u)", desc->description,
			desc->version, plugin_version[0],
			plugin_version[1], plugin_version[2],
			CONNMAN_VERSION, connman_version[0],
			connman_version[1], connman_version[2]);
		return false;
	}

	plugin = g_try_new0(struct connman_plugin, 1);
	if (!plugin)
		return false;

	plugin->handle = handle;
	plugin->active = false;
	plugin->desc = desc;

	__connman_log_enable(desc->debug_start, desc->debug_stop);

	plugins = g_slist_insert_sorted(plugins, plugin, compare_priority);

	return true;
}

static bool check_plugin(struct connman_plugin_desc *desc,
				char **patterns, char **excludes)
{
	if (excludes) {
		for (; *excludes; excludes++)
			if (g_pattern_match_simple(*excludes, desc->name))
				break;
		if (*excludes) {
			DBG("Excluding %s", desc->description);
			return false;
		}
	}

	if (patterns) {
		for (; *patterns; patterns++)
			if (g_pattern_match_simple(*patterns, desc->name))
				break;
		if (!*patterns) {
			DBG("Ignoring %s", desc->description);
			return false;
		}
	}

	return true;
}

bool __connman_plugin_enabled(const char *name)
{
	GSList *list;

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;

		if (!g_strcmp0(plugin->desc->name, name))
			return true;
	}

	return false;
}

void __connman_plugin_foreach(void (*fn) (struct connman_plugin_desc *desc,
				int flags, void *user_data), void *user_data)
{
	GSList *list;

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;
		int flags = 0;

		if (!plugin->handle)
			flags |= CONNMAN_PLUGIN_FLAG_BUILTIN;

		if (plugin->active)
			flags |= CONNMAN_PLUGIN_FLAG_ACTIVE;

                fn(plugin->desc, flags, user_data);
	}
}

#include <builtin.h>

int __connman_plugin_init(const char *pattern, const char *exclude)
{
	gchar **patterns = NULL;
	gchar **excludes = NULL;
	GSList *list;
	GDir *dir;
	const gchar *file;
	gchar *filename;
	unsigned int i;

	DBG("");

	if (pattern)
		patterns = g_strsplit_set(pattern, ":, ", -1);

	if (exclude)
		excludes = g_strsplit_set(exclude, ":, ", -1);

	for (i = 0; __connman_builtin[i]; i++) {
		if (!check_plugin(__connman_builtin[i], patterns, excludes))
			continue;

		add_plugin(NULL, __connman_builtin[i]);
	}

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (dir) {
		while ((file = g_dir_read_name(dir))) {
			void *handle;
			struct connman_plugin_desc *desc;

			if (g_str_has_prefix(file, "lib") ||
					!g_str_has_suffix(file, ".so"))
				continue;

			filename = g_build_filename(PLUGINDIR, file, NULL);

			handle = dlopen(filename, RTLD_NOW);
			if (!handle) {
				connman_error("Can't load %s: %s",
							filename, dlerror());
				g_free(filename);
				continue;
			}

			g_free(filename);

			desc = dlsym(handle, "connman_plugin_desc");
			if (!desc) {
				connman_error("Can't load symbol: %s",
								dlerror());
				dlclose(handle);
				continue;
			}

			if (!check_plugin(desc, patterns, excludes)) {
				dlclose(handle);
				continue;
			}

			if (!add_plugin(handle, desc))
				dlclose(handle);
		}

		g_dir_close(dir);
	}

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;

		if (plugin->desc->init() < 0)
			continue;

		plugin->active = true;
	}

	g_strfreev(patterns);
	g_strfreev(excludes);

	return 0;
}

void __connman_plugin_cleanup(void)
{
	GSList *list;

	DBG("");

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;

		if (plugin->active && plugin->desc->exit)
			plugin->desc->exit();

		if (plugin->handle)
			dlclose(plugin->handle);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
