/*
 *  ConnMan VPN daemon settings
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018-2019 Jolla Ltd. All rights reserved.
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

#include <connman/log.h>

#include "vpn.h"

#define DEFAULT_INPUT_REQUEST_TIMEOUT 300 * 1000

static struct {
	unsigned int timeout_inputreq;
} connman_vpn_settings  = {
	.timeout_inputreq		= DEFAULT_INPUT_REQUEST_TIMEOUT,
};

unsigned int __vpn_settings_get_timeout_inputreq()
{
	return connman_vpn_settings.timeout_inputreq;
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

void __vpn_settings_cleanup()
{
	return;
}
