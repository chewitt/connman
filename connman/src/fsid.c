/*
 * Connection Manager
 *
 * Copyright (C) 2016 Jolla Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "connman.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/fsuid.h>

/* Parses "user[:group]" string and sets fs identity */
void __connman_set_fsid(const char *fs_identity)
{
	char *sep = strchr(fs_identity, ':');
	const char *user;
	char *tmp_user;
	const struct passwd *pw = NULL;
	const struct group *gr = NULL;

	if (sep) {
		/* Group */
		const char *group = sep + 1;

		gr = getgrnam(group);
		user = tmp_user = g_strndup(fs_identity, sep - fs_identity);

		if (!gr) {
			/* Try numeric */
			char *end = NULL;
			long n = strtol(group, &end, 0);
			if (end && end != group &&
					((n != LONG_MAX && n != LONG_MIN) ||
							errno != ERANGE)) {
				gr = getgrgid(n);
			}

			if (!gr) {
				fprintf(stderr, "Invalid group '%s'", group);
			}
		}
	} else {
		user = fs_identity;
                tmp_user = NULL;
	}

	/* User */
	pw = getpwnam(user);
	if (!pw) {
		/* Try numeric */
		char *end = NULL;
		long n = strtol(user, &end, 0);
		if (end && end != user && ((n != LONG_MAX && n != LONG_MIN) ||
							errno != ERANGE)) {
			pw = getpwuid(n);

			if (!pw) {
				fprintf(stderr, "Invalid user '%s'", user);
			}
		}
	}

	/* Set fs identity */
	if (pw) {
		errno = 0;
		setfsuid(pw->pw_uid);
		if (errno) {
			fprintf(stderr, "Failed to set fsuid to %d: %s\n",
						pw->pw_uid, strerror(errno));
		}
	}

	if (gr) {
		errno = 0;
		setfsgid(gr->gr_gid);
		if (errno) {
			fprintf(stderr, "Failed to set fsgid to %d: %s\n",
						gr->gr_gid, strerror(errno));
		}
	}

	g_free(tmp_user);
}
