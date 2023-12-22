/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/inotify.h>

#include <glib.h>

#include "connman.h"

#define ETC_SYSCONFIG_CLOCK		"/etc/sysconfig/clock"
#define USR_SHARE_ZONEINFO		"/usr/share/zoneinfo"
#define USR_SHARE_ZONEINFO_MAP		USR_SHARE_ZONEINFO "/zone1970.tab"
#define USR_SHARE_ZONEINFO_MAP_OLD	USR_SHARE_ZONEINFO "/zone.tab"

static char *read_key_file(const char *pathname, const char *key)
{
	struct stat st;
	char *map, *ptr, *str;
	off_t ptrlen, keylen;
	int fd;

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!map || map == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	ptr = map;
	ptrlen = st.st_size;
	keylen = strlen(key);

	while (ptrlen > keylen + 1) {
		int cmp = strncmp(ptr, key, keylen);

		if (cmp == 0) {
			if (ptr == map)
				break;

			if (*(ptr - 1) == '\n' && *(ptr + keylen) == '=')
				break;
		}

		ptr = memchr(ptr + 1, key[0], ptrlen - 1);
		if (!ptr)
			break;

		ptrlen = st.st_size - (ptr - map);
	}

	if (ptr) {
		char *end, *val;

		ptrlen = st.st_size - (ptr - map);

		end = memchr(ptr, '\n', ptrlen);
		if (end)
			ptrlen = end - ptr;

		val = memchr(ptr, '"', ptrlen);
		if (val) {
			end = memchr(val + 1, '"', end - val - 1);
			if (end)
				str = g_strndup(val + 1, end - val - 1);
			else
				str = NULL;
		} else
			str = g_strndup(ptr + keylen + 1, ptrlen - keylen - 1);
	} else
		str = NULL;

	munmap(map, st.st_size);

	close(fd);

	return str;
}

static int compare_file(void *src_map, struct stat *src_st,
				const char *real_path, const char *pathname)
{
	struct stat dst_st;
	void *dst_map;
	int fd, result;

	DBG("real path %s path name %s", real_path, pathname);

	if (real_path && g_strcmp0(real_path, pathname))
		return -1;

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (fstat(fd, &dst_st) < 0) {
		close(fd);
		return -1;
	}

	if (src_st->st_size != dst_st.st_size) {
		close(fd);
		return -1;
	}

	dst_map = mmap(0, dst_st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!dst_map || dst_map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	result = memcmp(src_map, dst_map, src_st->st_size);

	munmap(dst_map, dst_st.st_size);

	close(fd);

	return result;
}

static char *find_origin(void *src_map, struct stat *src_st,
				const char* real_path, const char *basepath,
				const char *subpath)
{
	DIR *dir;
	struct dirent *d;
	char *str, pathname[PATH_MAX];
	struct stat buf;
	int ret;

	if (!subpath)
		strncpy(pathname, basepath, sizeof(pathname) - 1);
	else
		snprintf(pathname, sizeof(pathname),
					"%s/%s", basepath, subpath);

	dir = opendir(pathname);
	if (!dir)
		return NULL;

	while ((d = readdir(dir))) {
		if (strcmp(d->d_name, ".") == 0 ||
				strcmp(d->d_name, "..") == 0 ||
				strcmp(d->d_name, "posix") == 0 ||
				strcmp(d->d_name, "right") == 0)
			continue;

		switch (d->d_type) {
		case DT_REG:
			if (!subpath)
				snprintf(pathname, PATH_MAX,
						"%s/%s", basepath, d->d_name);
			else
				snprintf(pathname, PATH_MAX,
						"%s/%s/%s", basepath,
							subpath, d->d_name);

			if (compare_file(src_map, src_st, real_path, pathname)
									== 0) {
				if (!subpath)
					str = g_strdup(d->d_name);
				else
					str = g_strdup_printf("%s/%s",
							subpath, d->d_name);
				closedir(dir);
				return str;
			}
			break;
		case DT_UNKNOWN:
			/*
			 * If there is no d_type support use fstatat()
			 * to check if d_name is directory
			 */
			ret = fstatat(dirfd(dir), d->d_name, &buf, 0);
			if (ret < 0)
				continue;
			if ((buf.st_mode & S_IFDIR) == 0)
				continue;
			/* fall through */
		case DT_DIR:
			if (!subpath)
				strncpy(pathname, d->d_name, sizeof(pathname));
			else
				snprintf(pathname, sizeof(pathname),
						"%s/%s", subpath, d->d_name);

			str = find_origin(src_map, src_st, real_path, basepath,
						pathname);
			if (str) {
				closedir(dir);
				return str;
			}
			break;
		}
	}

	closedir(dir);

	return NULL;
}

/* TZ map file format: Countrycodes Coordinates TZ Comments */
enum tz_map_item {
	TZ_MAP_ITEM_ISO3166 = 0,
	TZ_MAP_ITEM_COORDINATE = 1,
	TZ_MAP_ITEM_TIMEZONE = 2,
	TZ_MAP_ITEM_COMMENT = 3,
};

static bool iso3166_matches(const char *codes, const char *iso3166)
{
	gchar **tokens;
	guint len;
	guint i;
	bool ret = false;

	if (!codes || !iso3166)
		return false;

	tokens = g_strsplit(codes, ",", -1);
	if (!tokens)
		return false;

	len = g_strv_length(tokens);
	if (len < 2) {
		g_strfreev(tokens);
		return false;
	}

	DBG("search %s from %s", iso3166, codes);

	for (i = 0; i < len; i++) {
		DBG("#%d %s", i, tokens[i]);

		if (!g_strcmp0(tokens[i], iso3166)) {
			ret = true;
			break;
		}
	}

	g_strfreev(tokens);

	return ret;
}

static char *get_timezone_alpha2(const char *zone, const char *mapfile,
						enum tz_map_item map_item)
{
	GIOChannel *channel;
	struct stat st;
	char **tokens;
	char *line;
	char *alpha2 = NULL;
	gsize len;
	bool found = false;
	int fd;

	if (!zone)
		return NULL;

	fd = open(mapfile, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		connman_warn("failed to open zoneinfo map %s", mapfile);
		return NULL;
	}

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		connman_warn("zoneinfo map does not exist/not regular file");
		close(fd);
		return NULL;
	}

	channel = g_io_channel_unix_new(fd);
	if (!channel) {
		connman_warn("failed to create io channel for %s", mapfile);
		close(fd);
		return NULL;
	}

	DBG("read %s for %s", mapfile, zone);
	g_io_channel_set_encoding(channel, "UTF-8", NULL);

	while (g_io_channel_read_line(channel, &line, &len, NULL, NULL) ==
							G_IO_STATUS_NORMAL) {
		found = false;

		if (!line || !*line || *line == '#' || *line == '\n') {
			g_free(line);
			continue;
		}

		tokens = g_strsplit_set(line, " \t", 4);
		if (!tokens) {
			connman_warn("line %s failed to parse", line);
			g_free(line);
			continue;
		}

		if (g_strv_length(tokens) >= 3) {
			switch (map_item) {
			case TZ_MAP_ITEM_ISO3166:

				if (!g_strcmp0(tokens[0], zone)) {
					found = true;
					break;
				}

				if (iso3166_matches(tokens[0], zone))
					found = true;
				break;
			case TZ_MAP_ITEM_COORDINATE:
				break;
			case TZ_MAP_ITEM_TIMEZONE:
				if (!g_strcmp0(g_strstrip(tokens[2]), zone))
					found = true;
				break;
			case TZ_MAP_ITEM_COMMENT:
				break;
			}

			/*
			 * Multiple country codes can be listed, use the first
			 * 2 chars as backends such as gsupplicant support only
			 * the main country code.
			 */
			if (found)
				alpha2 = g_strndup(g_strstrip(tokens[0]), 2);
		}

		g_strfreev(tokens);
		g_free(line);

		if (alpha2) {
			if (strlen(alpha2) != 2) {
				connman_warn("Invalid ISO3166 code %s", alpha2);
				g_free(alpha2);
				alpha2 = NULL;
			} else {
				DBG("Zone %s ISO3166 country code %s", zone,
									alpha2);
				break;
			}
		}
	}

	g_io_channel_unref(channel);
	close(fd);

	return alpha2;
}

static char *try_get_timezone_alpha2(const char *zone)
{
	char *alpha2;
	char *alpha2_old;

	/* First try the official map */
	alpha2 = get_timezone_alpha2(zone, USR_SHARE_ZONEINFO_MAP,
							TZ_MAP_ITEM_TIMEZONE);
	if (alpha2)
		return alpha2;

	DBG("%s not found in %s", zone, USR_SHARE_ZONEINFO_MAP);

	/* The zone was not found in official map, try with deprecated */
	alpha2_old = get_timezone_alpha2(zone, USR_SHARE_ZONEINFO_MAP_OLD,
							TZ_MAP_ITEM_TIMEZONE);
	if (!alpha2_old) {
		DBG("%s not found in %s", zone, USR_SHARE_ZONEINFO_MAP_OLD);
		return NULL;
	}

	/*
	 * Found from deprecated, try to get main region code from official new
	 * map using the iso3166 search. This is because some of the codes
	 * defined in the deprecated are not supported by the backends, e.g.,
	 * gsupplicant and the main code should be used.
	 */
	alpha2 = get_timezone_alpha2(alpha2_old, USR_SHARE_ZONEINFO_MAP,
							TZ_MAP_ITEM_ISO3166);

	DBG("%s -> ISO3166 %s found in %s as %s", zone, alpha2_old,
						USR_SHARE_ZONEINFO_MAP, alpha2);

	g_free(alpha2_old);

	return alpha2;
}

char *__connman_timezone_lookup(void)
{
	struct stat st;
	void *map;
	int fd;
	char *zone;
	char *alpha2;
	const char *local_time;
	char real_path[PATH_MAX];

	zone = read_key_file(ETC_SYSCONFIG_CLOCK, "ZONE");

	DBG("sysconfig zone %s", zone);

	local_time = connman_setting_get_string("Localtime");

	fd = open(local_time, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		g_free(zone);
		return NULL;
	}

	if (fstat(fd, &st) < 0)
		goto done;

	if (!realpath(local_time, real_path)) {
		connman_error("Failed to get real path of %s: %d/%s",
					local_time, errno, strerror(errno));
		g_free(zone);
		close(fd);

		return NULL;
	}

	if (S_ISREG(st.st_mode)) {
		map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (!map || map == MAP_FAILED) {
			g_free(zone);
			zone = NULL;

			goto done;
		}

		if (zone) {
			char pathname[PATH_MAX];

			snprintf(pathname, PATH_MAX, "%s/%s",
						USR_SHARE_ZONEINFO, zone);

			if (compare_file(map, &st, NULL, pathname) != 0) {
				g_free(zone);
				zone = NULL;
			}
		}

		if (!zone)
			zone = find_origin(map, &st, real_path,
						USR_SHARE_ZONEINFO, NULL);

		munmap(map, st.st_size);
	} else {
		g_free(zone);
		zone = NULL;
	}

done:
	close(fd);

	DBG("localtime zone %s", zone);

	if (connman_setting_get_bool("RegdomFollowsTimezone")) {
		alpha2 = try_get_timezone_alpha2(zone);
		if (alpha2) {
			DBG("change regdom to %s", alpha2);
			connman_technology_set_regdom(alpha2);
			g_free(alpha2);
		}
	}

	return zone;
}

static int write_file(void *src_map, struct stat *src_st, const char *pathname)
{
	struct stat st;
	int fd;
	ssize_t written;

	DBG("pathname %s", pathname);

	if (lstat(pathname, &st) == 0) {
		if (S_ISLNK(st.st_mode))
			unlink(pathname);
	}

	fd = open(pathname, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -EIO;

	written = write(fd, src_map, src_st->st_size);

	close(fd);

	if (written < 0)
		return -EIO;

	return 0;
}

int __connman_timezone_change(const char *zone)
{
	struct stat st;
	char *map, pathname[PATH_MAX];
	int fd, err;

	DBG("zone %s", zone);

	snprintf(pathname, PATH_MAX, "%s/%s", USR_SHARE_ZONEINFO, zone);

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -EINVAL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -EIO;
	}

	map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!map || map == MAP_FAILED) {
		close(fd);
		return -EIO;
	}

	err = write_file(map, &st, connman_setting_get_string("Localtime"));

	munmap(map, st.st_size);

	close(fd);

	return err;
}

static guint inotify_watch = 0;

static gboolean inotify_data(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	char buffer[256];
	void *ptr = buffer;
	GIOStatus status;
	gsize bytes_read;

	DBG("");

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		inotify_watch = 0;
		return FALSE;
	}

	status = g_io_channel_read_chars(channel, buffer, sizeof(buffer),
							&bytes_read, NULL);

	switch (status) {
	case G_IO_STATUS_NORMAL:
		break;
	case G_IO_STATUS_AGAIN:
		return TRUE;
	default:
		inotify_watch = 0;
		return FALSE;
	}

	DBG("bytes read %zd", bytes_read);

	while (bytes_read > 0) {
		struct inotify_event *event = ptr;

		if (bytes_read < sizeof(*event))
			break;

		ptr += sizeof(*event);
		bytes_read -= sizeof(*event);

		if (event->len == 0)
			continue;

		if (bytes_read < event->len)
			break;

		ptr += event->len;
		bytes_read -= event->len;

		if (g_strcmp0(event->name, "localtime") == 0)
			__connman_clock_update_timezone();
	}

	return TRUE;
}

int __connman_timezone_init(void)
{
	GIOChannel *channel;
	char *dirname;
	int fd, wd;

	DBG("");

	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		return -EIO;

	channel = g_io_channel_unix_new(fd);
	if (!channel) {
		close(fd);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	inotify_watch = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				inotify_data, NULL);

	g_io_channel_unref(channel);

	dirname = g_path_get_dirname(connman_setting_get_string("Localtime"));

	wd = inotify_add_watch(fd, dirname, IN_CREATE | IN_DONT_FOLLOW |
						IN_CLOSE_WRITE | IN_MOVED_TO);

	g_free(dirname);

	if (wd < 0)
		return -EIO;

	return 0;
}

void __connman_timezone_cleanup(void)
{
	DBG("");

	if (inotify_watch > 0) {
		g_source_remove(inotify_watch);
		inotify_watch = 0;
	}
}
