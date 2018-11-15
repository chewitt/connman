/*
 *  Connection Manager
 *
 *  Copyright (C) 2018 Jolla Ltd. All rights reserved.
 *  Contact: David Llewellyn-Jones <david.llewellyn-jones@jolla.com>
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

#ifndef __CONNMAN_GLOBALPROXY_H
#define __CONNMAN_GLOBALPROXY_H

#include <stdbool.h>

#include <connman/service.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:globalproxy
 * @title: globalproxy premitives
 * @short_description: Functions for handling global proxy settings
 */

#define GLOBALPROXY_CONNMAN_INTERFACE	"org.sailfishos.connman.GlobalProxy"
#define GLOBALPROXY_DBUS_PATH "/"

#define GLOBAL_PROXY_NOTIFIER_PRIORITY_LOW       (-100)
#define GLOBAL_PROXY_NOTIFIER_PRIORITY_DEFAULT   (0)
#define GLOBAL_PROXY_NOTIFIER_PRIORITY_HIGH      (100)

struct global_proxy_notifier {
	const char *name;
	int priority;
	void (*active_changed) (bool enabled);
	void (*config_changed) ();
	void (*proxy_changed) ();

	/* Placeholders for future extensions */
	//void (*_reserved[10])(void);

	/* api_level will remain zero (and ignored) until we run out of
	 * the above placeholders. Hopefully, forever. */
	//int api_level;
};

// Externally exposed functions

gboolean global_proxy_get_active();
enum connman_service_proxy_method global_proxy_get_proxy_method();
char **global_proxy_get_proxy_servers();
char **global_proxy_get_proxy_excludes();
const char *global_proxy_get_proxy_url();
const char *global_proxy_get_proxy_autoconfig();

// Functions for registering notification modules

int global_proxy_notifier_register(struct global_proxy_notifier *notifier);
void global_proxy_notifier_unregister(struct global_proxy_notifier *notifier);

// Functions for use with pacrunner plugin, which return service or
// global proxy settings depending on whether the global proxy is
// active or not

enum connman_service_proxy_method service_or_global_proxy_get_proxy_method(struct connman_service *service);
char **service_or_global_proxy_get_proxy_servers(struct connman_service *service);
char **service_or_global_proxy_get_proxy_excludes(struct connman_service *service);
const char *service_or_global_proxy_get_proxy_url(struct connman_service *service);
const char *service_or_global_proxy_get_proxy_autoconfig(struct connman_service *service);

// Functions which return null if the global proxy is active, or the
// service value otherwise. The original service functions aren't
// specifically proxy-related functions.

char *service_or_global_proxy_get_interface(struct connman_service *service);
const char *service_or_global_proxy_get_domainname(struct connman_service *service);
char **service_or_global_get_nameservers(struct connman_service *service);


#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_GLOBALPROXY_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
