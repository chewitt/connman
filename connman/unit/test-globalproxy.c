/*
 *  Connection Manager
 *
 *  Copyright (C) 2018-2020  Jolla Ltd. All rights reserved.
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

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n.h>
#include "plugins/globalproxy.c"

#define POLICY_FAKE_POINTER (0x6E78B)

DBusMessage *test_message = NULL;
bool test_enabled = FALSE;
bool test_active_changed = FALSE;
bool test_config_changed = FALSE;
bool test_proxy_changed = FALSE;
gchar * test_directory = NULL;
GDBusMethodFunction get_property_dbus_call = NULL;
GDBusMethodFunction set_property_dbus_call = NULL;
void *user_data_dbus_call;
DA_ACCESS test_access = DA_ACCESS_DENY;
static DAPeer test_peer;

/*==========================================================================*
 * Dummy functions
 *==========================================================================*/

// Original version from src/service.c
enum connman_service_proxy_method connman_service_get_proxy_method(struct connman_service *service)
{
	return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;
}

// Original version from src/service.c
char **connman_service_get_proxy_servers(struct connman_service *service)
{
	return NULL;
}

// Original version from src/service.c
char **connman_service_get_proxy_excludes(struct connman_service *service)
{
	return NULL;
}

// Original version from src/service.c
const char *connman_service_get_proxy_url(struct connman_service *service)
{
	return NULL;
}

// Original version from src/service.c
const char *connman_service_get_proxy_autoconfig(
		struct connman_service *service)
{
	return NULL;
}

// Original version from src/service.c
char *connman_service_get_interface(struct connman_service *service)
{
	return NULL;
}

// Original version from src/service.c
const char *connman_service_get_domainname(struct connman_service *service)
{
	return NULL;
}

// Original version from src/service.c
char **connman_service_get_nameservers(struct connman_service *service)
{
	return NULL;
}

// Original version from gdbus/object.c
// Needed by global_proxy_init()
gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	int pos;

	// The dbus interface doesn't really exist (connection == NULL)
	g_assert_true(connection == NULL);
	g_assert_cmpstr(path, ==, "/");


	g_assert_true(methods);
	g_assert_true(signals);

	pos = 0;
	while (methods[pos].name != NULL) {
		if (g_strcmp0(methods[pos].name, "GetProperty") == 0) {
			get_property_dbus_call = methods[pos].function;
		}
		if (g_strcmp0(methods[pos].name, "SetProperty") == 0) {
			set_property_dbus_call = methods[pos].function;
		}
		pos++;
	}

	user_data_dbus_call = user_data;
	g_assert_true(get_property_dbus_call);
	g_assert_true(set_property_dbus_call);

	return TRUE;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	g_assert(connection);
	g_assert_cmpstr(path, ==, "/");

	return TRUE;
}

// Original version from gdbus/object.c
// Needed by dbus_property_changed_dict_variant()
// Needed by src/dbus.c
gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	g_assert_true(connection == NULL);
	g_assert_true(message != NULL);

	test_message = message;
	return TRUE;
}

/*==========================================================================*
 * Duplicated functions from files that can't be included or linked against
 *==========================================================================*/

// Copied from gdbus/object.c
// Needed by error_invalid_arguments()
DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	return reply;
}

// Copied from gdbus/object.c
// Needed by g_dbus_create_error()
DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	if (format)
		vsnprintf(str, sizeof(str), format, args);
	else
		str[0] = '\0';

	return dbus_message_new_error(message, name, str);
}

// Copied from gdbus/object.c
// Needed by src/dbus.c
gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = g_dbus_send_reply_valist(connection, message, type, args);

	va_end(args);

	return result;
}

// Copied from gdbus/object.c
// Needed by g_dbus_send_reply()
gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return FALSE;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return FALSE;
	}

	return g_dbus_send_message(connection, reply);
}

// Copied from gdbus/object.c
// Needed by g_dbus_create_reply()
DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return NULL;
	}

	return reply;
}

// Copied from gdbus/object.c
// Needed by set_configuration()
DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, type);

	reply = g_dbus_create_reply_valist(message, type, args);

	va_end(args);

	return reply;
}

gboolean g_dbus_send_message_with_reply(DBusConnection *connection,
					DBusMessage *message,
					DBusPendingCall **call, int timeout)
{
	return dbus_connection_send_with_reply(connection, message, call,
				timeout);
}

static guint watch_id = 123654798;

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy)
{
	return watch_id;
}

gboolean g_dbus_remove_watch(DBusConnection *connection, guint id)
{
	return id == watch_id;
}

// Replaces function from libdbusaccess/src/dbusaccess_policy.c
// Needed to control permissions independent of reality
DAPolicy* da_policy_new_full(const char* spec, const DA_ACTION* actions)
{
	// DAPolicy is an opaque structure
	return (DAPolicy*)POLICY_FAKE_POINTER;
}

// Replaces function from libdbusaccess/src/dbusaccess_policy.c
// Needed to control permissions independent of reality
void da_policy_unref(DAPolicy* policy)
{
	g_assert_cmphex(GPOINTER_TO_UINT(policy), ==, POLICY_FAKE_POINTER);
}

// Replaces function from libdbusaccess/src/dbusaccess_policy.c
// Needed to control permissions independent of reality
DA_ACCESS da_policy_check(const DAPolicy* policy, const DACred* cred,
			  guint action, const char* arg, DA_ACCESS def)
{
	g_assert_cmphex(GPOINTER_TO_UINT(policy), ==, POLICY_FAKE_POINTER);

	return test_access;
}

// Replaces function from libdbusaccess/src/dbusaccess_peer.c
// Needed to control permissions independent of reality
DAPeer* da_peer_get(DA_BUS bus, const char* name)
{
	// The contents doesn't matter, we just initialise it to broadly
	// sensible values
	test_peer.bus = DA_BUS_SYSTEM;
	test_peer.name = "nemo";
	test_peer.pid = 1000;
	test_peer.cred.euid = 1000;
	test_peer.cred.egid = 1000;
	test_peer.cred.groups = NULL;
	test_peer.cred.ngroups = 0;
	test_peer.cred.caps = 0;
	test_peer.cred.flags = 0;

	return &test_peer;
}

/*==========================================================================*
 * Convenience functions
 *==========================================================================*/

#define TEST_PATH_PREFIX "/tmp/connman_test"

static void setup_test_subdirectory(gchar * test_directory)
{
	gchar *sub_directory = NULL;

	sub_directory = g_strdup_printf("%s/connman/global_proxy",
					test_directory);

	g_assert_true(sub_directory);

	g_assert_true(g_mkdir_with_parents(sub_directory, 0700) >= 0);

	g_assert_true(g_file_test(sub_directory, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(sub_directory, G_FILE_TEST_IS_DIR));
	g_free(sub_directory);
}

static gchar *setup_test_directory()
{
	gchar *test_path = NULL;

	test_path = g_strdup_printf("%s.XXXXXX", TEST_PATH_PREFIX);

	g_assert_true(test_path);

	if(!g_file_test(test_path, G_FILE_TEST_EXISTS))
		test_path = g_mkdtemp(test_path);

	g_assert_true(g_file_test(test_path, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(test_path, G_FILE_TEST_IS_DIR));

	setup_test_subdirectory(test_path);

	return test_path;
}

static void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;

	if (g_file_test(test_path, G_FILE_TEST_IS_DIR)) {
		g_assert_true(!access(test_path, access_mode));
		g_rmdir(test_path);
	}
	g_free(test_path);
}

static void export_config(const char * leafname, const char * method,
			  const char * servers, const char * excludes,
			  const char * url)
{
	FILE * file;
	char * filename;

	filename = g_strdup_printf("%s/connman/global_proxy/%s",
				   test_directory, leafname);
	file = fopen(filename, "w");
	g_assert_true(file);

	if (file) {
		fprintf(file, "[global proxy]\n");
		fprintf(file, "Active=%s\n", "false");
		fprintf(file, "Proxy.Method=%s\n", method);
		fprintf(file, "Proxy.Servers=%s\n", servers);
		fprintf(file, "Proxy.Excludes=%s\n", excludes);
		fprintf(file, "Proxy.URL=%s\n", url);
		fclose(file);
	}

	g_assert_true(g_file_test(filename, G_FILE_TEST_EXISTS));
	g_assert_false(g_file_test(filename, G_FILE_TEST_IS_DIR));
	g_free(filename);
}

static void clear_dbus_message()
{
	if (test_message) {
		dbus_message_unref(test_message);
		test_message = NULL;
	}
}

static void clear_test_flags()
{
	test_enabled = FALSE;
	test_active_changed = FALSE;
	test_config_changed = FALSE;
	test_proxy_changed = FALSE;
}

static void notify_active_changed(bool enabled)
{
	test_active_changed = TRUE;
	test_enabled = enabled;
}

static void notify_config_changed(struct connman_service *service)
{
	test_config_changed = TRUE;
}

static void notify_proxy_changed(struct connman_service *service)
{
	test_proxy_changed = TRUE;
}

int strv_length(const char * const * str_array)
{
	int length = 0;
	if (str_array != NULL) {
		while (str_array[length] != NULL) {
			length++;
		}
	}
	return length;
}

static DBusMessage *construct_message_active(dbus_bool_t value_active)
{
	DBusMessage *msg;
	const char * key_active = "Active";
	DBusMessageIter iter, variant;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");

	dbus_message_iter_init_append(msg, &iter);

	// Add Boolean value
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key_active);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN,
				       &value_active);

	// Close everything off
	dbus_message_iter_close_container(&iter, &variant);

	dbus_message_set_serial (msg, 1);

	return msg;
}

static DBusMessage *construct_message_configuration_direct()
{
	DBusMessage *msg;
	const char * key_active = "Configuration";
	const char * value_method = "direct";
	DBusMessageIter iter, variant, dict;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key_active);
	connman_dbus_dict_open_variant(&iter, &variant);
	connman_dbus_dict_open(&variant, &dict);

	// Add "Method" key-value pair
	connman_dbus_dict_append_basic(&dict, "Method", DBUS_TYPE_STRING,
				       &value_method);

	// Close everything off
	connman_dbus_dict_close(&variant, &dict);
	connman_dbus_dict_close(&iter, &variant);

	dbus_message_set_serial (msg, 1);

	return msg;
}

static DBusMessage *construct_message_configuration_manual(
		const char * value_servers, const char * value_excludes)
{
	DBusMessage *msg;
	const char * key_configuration = "Configuration";
	const char * key_servers = "Servers";
	const char * key_excludes = "Excludes";
	const char * value_method = "manual";
	DBusMessageIter iter, variant, dict, entry, array, value;
	char ** servers_split;
	char ** excludes_split;
	int pos;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
				       &key_configuration);
	connman_dbus_dict_open_variant(&iter, &variant);
	connman_dbus_dict_open(&variant, &dict);

	// Add "Method" key-value pair
	connman_dbus_dict_append_basic(&dict, "Method", DBUS_TYPE_STRING,
				       &value_method);

	// Add "Servers" key-value pair
	servers_split = g_strsplit(value_servers, ";", -1);
	if (servers_split) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
						 NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &key_servers);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						 DBUS_TYPE_ARRAY_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING,
						 &value);
		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
						 DBUS_TYPE_STRING_AS_STRING,
						 &array);
		pos = 0;
		while (servers_split[pos] != NULL) {
			dbus_message_iter_append_basic(&array,
						       DBUS_TYPE_STRING,
						       &servers_split[pos]);
			pos++;
		}
		dbus_message_iter_close_container(&value, &array);
		dbus_message_iter_close_container(&entry, &value);
		dbus_message_iter_close_container(&dict, &entry);
	}

	// Add "Excludes" key-value pair
	excludes_split = g_strsplit(value_excludes, ";", -1);
	if (excludes_split) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
						 NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &key_excludes);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						 DBUS_TYPE_ARRAY_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING,
						 &value);
		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
						 DBUS_TYPE_STRING_AS_STRING,
						 &array);
		pos = 0;
		while (excludes_split[pos] != NULL) {
			dbus_message_iter_append_basic(&array,
						       DBUS_TYPE_STRING,
						       &excludes_split[pos]);
			pos++;
		}
		dbus_message_iter_close_container(&value, &array);
		dbus_message_iter_close_container(&entry, &value);
		dbus_message_iter_close_container(&dict, &entry);
	}

	// Close everything off
	connman_dbus_dict_close(&variant, &dict);
	connman_dbus_dict_close(&iter, &variant);

	dbus_message_set_serial (msg, 1);

	return msg;
}

static DBusMessage *construct_message_configuration_auto(const char * value_url)
{
	DBusMessage *msg;
	const char * key_configuration = "Configuration";
	const char * value_method = "auto";
	DBusMessageIter iter, variant, dict;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
				       &key_configuration);
	connman_dbus_dict_open_variant(&iter, &variant);
	connman_dbus_dict_open(&variant, &dict);

	// Add "Method" key-value pair
	connman_dbus_dict_append_basic(&dict, "Method", DBUS_TYPE_STRING,
				       &value_method);

	// Add "URL" key-value pair
	connman_dbus_dict_append_basic(&dict, "URL", DBUS_TYPE_STRING,
				       &value_url);

	// Close everything off
	connman_dbus_dict_close(&variant, &dict);
	connman_dbus_dict_close(&iter, &variant);

	dbus_message_set_serial (msg, 1);

	return msg;
}

static DBusMessage *construct_message_get_active()
{
	DBusMessage *msg;
	const char * key_active = "Active";
	DBusMessageIter iter;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "GetProperty");

	dbus_message_iter_init_append(msg, &iter);

	// Add Boolean value
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key_active);

	// Close everything off
	dbus_message_set_serial(msg, 1);

	return msg;
}

static bool deconstruct_reply_active(DBusMessage *reply)
{
	DBusMessageIter iter, value;
	dbus_bool_t value_active;

	g_assert_true(dbus_message_get_type(reply) ==
		 DBUS_MESSAGE_TYPE_METHOD_RETURN);

	g_assert_cmpstr(dbus_message_get_signature(reply), ==, "v");

	// Interpret result
	g_assert_true(dbus_message_iter_init(reply, &iter));
	g_assert_true(dbus_message_iter_get_arg_type(
			      &iter) == DBUS_TYPE_VARIANT);

	dbus_message_iter_recurse(&iter, &value);

	g_assert_true(dbus_message_iter_get_arg_type(
			      &value) == DBUS_TYPE_BOOLEAN);

	dbus_message_iter_get_basic(&value, &value_active);

	return value_active;
}

static DBusMessage *construct_message_get_configuration()
{
	DBusMessage *msg;
	const char * key_active = "Configuration";
	DBusMessageIter iter;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "GetProperty");

	dbus_message_iter_init_append(msg, &iter);

	// Add Boolean value
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key_active);

	// Close everything off
	dbus_message_set_serial (msg, 1);

	return msg;
}

static const char *deconstruct_reply_configuration_method(DBusMessage *reply)
{
	DBusMessageIter iter, dict, array;
	const char * value_method = NULL;

	g_assert_true(dbus_message_get_type(reply) ==
		 DBUS_MESSAGE_TYPE_METHOD_RETURN);

	g_assert_cmpstr(dbus_message_get_signature(reply), ==, "v");

	// Interpret result
	g_assert_true(dbus_message_iter_init(reply, &iter));
	g_assert_true(dbus_message_iter_get_arg_type(&iter) ==
		      DBUS_TYPE_VARIANT);

	dbus_message_iter_recurse(&iter, &array);

	g_assert_true(dbus_message_iter_get_arg_type(&array) ==
		      DBUS_TYPE_ARRAY);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_STRING);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_VARIANT);

		dbus_message_iter_recurse(&entry, &variant);

		if (g_str_equal(key, "Method")) {
			g_assert_true(dbus_message_iter_get_arg_type(
					      &variant) == DBUS_TYPE_STRING);

			dbus_message_iter_get_basic(&variant, &value_method);
		}

		dbus_message_iter_next(&dict);
	}

	return value_method;
}

static bool deconstruct_reply_configuration_servers_compare(DBusMessage *reply, const char * const * comparison)
{
	DBusMessageIter iter, dict, array;
	bool result = FALSE;
	int count;

	g_assert_true(dbus_message_get_type(reply) ==
		 DBUS_MESSAGE_TYPE_METHOD_RETURN);

	g_assert_cmpstr(dbus_message_get_signature(reply), ==, "v");

	// Interpret result
	g_assert_true(dbus_message_iter_init(reply, &iter));
	g_assert_true(dbus_message_iter_get_arg_type(&iter) ==
		      DBUS_TYPE_VARIANT);

	dbus_message_iter_recurse(&iter, &array);

	g_assert_true(dbus_message_iter_get_arg_type(&array) ==
		      DBUS_TYPE_ARRAY);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_STRING);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_VARIANT);

		dbus_message_iter_recurse(&entry, &variant);

		if (g_str_equal(key, "Servers")) {
			g_assert_true(dbus_message_iter_get_arg_type(
					      &variant) == DBUS_TYPE_ARRAY);

			DBusMessageIter str_array;

			dbus_message_iter_recurse(&variant, &str_array);

			// Unordered comparison
			count = 0;
			result = TRUE;
			while ((dbus_message_iter_get_arg_type(
					&str_array) == DBUS_TYPE_STRING)
					&& result) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (!g_strv_contains(comparison, val)) {
					result = FALSE;
				}

				count++;
				dbus_message_iter_next(&str_array);
			}

			if (dbus_message_iter_get_arg_type(
					&str_array) == DBUS_TYPE_STRING) {
				result = FALSE;
			}

			if (count != strv_length(comparison)) {
				result = FALSE;
			}
		}

		dbus_message_iter_next(&dict);
	}

	return result;
}

static bool deconstruct_reply_configuration_excludes_compare(
		DBusMessage *reply, const char * const * comparison)
{
	DBusMessageIter iter, dict, array;
	bool result = FALSE;
	int count;

	g_assert_true(dbus_message_get_type(reply) ==
		 DBUS_MESSAGE_TYPE_METHOD_RETURN);

	g_assert_cmpstr(dbus_message_get_signature(reply), ==, "v");

	// Interpret result
	g_assert_true(dbus_message_iter_init(reply, &iter));
	g_assert_true(dbus_message_iter_get_arg_type(
			      &iter) == DBUS_TYPE_VARIANT);

	dbus_message_iter_recurse(&iter, &array);

	g_assert_true(dbus_message_iter_get_arg_type(
			      &array) == DBUS_TYPE_ARRAY);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_STRING);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_VARIANT);

		dbus_message_iter_recurse(&entry, &variant);

		if (g_str_equal(key, "Excludes")) {
			g_assert_true(dbus_message_iter_get_arg_type(
					      &variant) == DBUS_TYPE_ARRAY);

			DBusMessageIter str_array;

			dbus_message_iter_recurse(&variant, &str_array);

			// Ordered comparison
			count = 0;
			result = TRUE;
			while (comparison[count] && result) {
				char *val = NULL;

				g_assert_true(dbus_message_iter_get_arg_type(
					&str_array) == DBUS_TYPE_STRING);
				dbus_message_iter_get_basic(&str_array, &val);

				if (g_strcmp0(comparison[count], val) != 0) {
					result = FALSE;
				}

				count++;
				dbus_message_iter_next(&str_array);
			}

			if (dbus_message_iter_get_arg_type(
					&str_array) == DBUS_TYPE_STRING) {
				result = FALSE;
			}

			if (count != strv_length(comparison)) {
				result = FALSE;
			}
		}

		dbus_message_iter_next(&dict);
	}

	return result;
}

static const char *deconstruct_reply_configuration_url(DBusMessage *reply)
{
	DBusMessageIter iter, dict, array;
	const char * value_url = NULL;

	g_assert_true(dbus_message_get_type(reply) ==
		 DBUS_MESSAGE_TYPE_METHOD_RETURN);

	g_assert_cmpstr(dbus_message_get_signature(reply), ==, "v");

	// Interpret result
	g_assert_true(dbus_message_iter_init(reply, &iter));
	g_assert_true(dbus_message_iter_get_arg_type(
			      &iter) == DBUS_TYPE_VARIANT);

	dbus_message_iter_recurse(&iter, &array);

	g_assert_true(dbus_message_iter_get_arg_type(
			      &array) == DBUS_TYPE_ARRAY);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_STRING);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		g_assert_true(dbus_message_iter_get_arg_type(
				      &entry) == DBUS_TYPE_VARIANT);

		dbus_message_iter_recurse(&entry, &variant);

		if (g_str_equal(key, "URL")) {
			g_assert_true(dbus_message_iter_get_arg_type(
					      &variant) == DBUS_TYPE_STRING);

			dbus_message_iter_get_basic(&variant, &value_url);
		}

		dbus_message_iter_next(&dict);
	}

	return value_url;
}

/*==========================================================================*
 * Tests
 *==========================================================================*/

static struct global_proxy_notifier test_global_proxy_notifier = {
	.name		= "test",
	.active_changed	= notify_active_changed,
	.config_changed	= notify_config_changed,
	.proxy_changed	= notify_proxy_changed,
};

static void test_global_proxy_notify_active()
{
	int result;

	result = global_proxy_init();
	g_assert_true(result == 0);

	global_proxy_set_active(FALSE);
	clear_test_flags();
	clear_dbus_message();

	result = global_proxy_notifier_register(&test_global_proxy_notifier);
	g_assert_true(result == 0);

	global_proxy_set_active(TRUE);
	g_assert_true(test_enabled == TRUE);
	g_assert_true(test_active_changed == TRUE);
	g_assert_true(test_config_changed == FALSE);
	g_assert_true(test_proxy_changed == TRUE);
	g_assert_true(test_message != NULL);
	clear_test_flags();
	clear_dbus_message();

	global_proxy_set_active(FALSE);
	g_assert_true(test_enabled == FALSE);
	g_assert_true(test_active_changed == TRUE);
	g_assert_true(test_config_changed == FALSE);
	g_assert_true(test_proxy_changed == TRUE);
	g_assert_true(test_message != NULL);
	clear_test_flags();
	clear_dbus_message();

	global_proxy_notifier_unregister(&test_global_proxy_notifier);

	global_proxy_set_active(TRUE);
	g_assert_true(test_enabled == FALSE);
	g_assert_true(test_active_changed == FALSE);
	g_assert_true(test_config_changed == FALSE);
	g_assert_true(test_proxy_changed == FALSE);
	g_assert_true(test_message != NULL);
	clear_test_flags();
	clear_dbus_message();

	global_proxy_set_active(FALSE);
	g_assert_true(test_enabled == FALSE);
	g_assert_true(test_active_changed == FALSE);
	g_assert_true(test_config_changed == FALSE);
	g_assert_true(test_proxy_changed == FALSE);
	g_assert_true(test_message != NULL);
	clear_test_flags();
	clear_dbus_message();

	global_proxy_exit();
}

static void test_global_proxy_invalid_arguments_no_key()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");
	dbus_message_set_serial (msg, 1);
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
				       ".InvalidArguments"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_invalid_arguments_invalid_key()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * key_invalid = "Stinky";
	const char * value_method = "direct";
	DBusMessageIter iter, variant, dict;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key_invalid);
	connman_dbus_dict_open_variant(&iter, &variant);
	connman_dbus_dict_open(&variant, &dict);

	// Add "Method" key-value pair
	connman_dbus_dict_append_basic(&dict, "Method", DBUS_TYPE_STRING,
				       &value_method);

	// Close everything off
	connman_dbus_dict_close(&variant, &dict);
	connman_dbus_dict_close(&iter, &variant);

	dbus_message_set_serial (msg, 1);

	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_invalid_arguments_method()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * key_active = "Configuration";
	const char * value_method = "snufkin";
	DBusMessageIter iter, variant, dict;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".GlobalProxy",
					   "/", CONNMAN_SERVICE ".GlobalProxy",
					   "SetProperty");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key_active);
	connman_dbus_dict_open_variant(&iter, &variant);
	connman_dbus_dict_open(&variant, &dict);

	// Add "Method" key-value pair
	connman_dbus_dict_append_basic(&dict, "Method", DBUS_TYPE_STRING,
				       &value_method);

	// Close everything off
	connman_dbus_dict_close(&variant, &dict);
	connman_dbus_dict_close(&iter, &variant);

	dbus_message_set_serial (msg, 1);

	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	// The result will depend on the user (access control)
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
		".InvalidArguments") || dbus_message_is_error(reply,
			CONNMAN_ERROR_INTERFACE ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_valid_arguments_active()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = construct_message_active(FALSE);
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_valid_arguments_configuration_direct()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = construct_message_configuration_direct();
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
				       ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_valid_arguments_configuration_manual()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = construct_message_configuration_manual("https://jolla.com",
						     "www.jolla.com");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
				       ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_valid_arguments_configuration_auto()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	msg = construct_message_configuration_auto(
				"https://jolla.com/auto.pac");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
				       ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_active_sticks()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	dbus_bool_t value_active;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Set active to false
	msg = construct_message_active(FALSE);
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check active is false
	msg = construct_message_get_active();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_active = deconstruct_reply_active(reply);
	g_assert_true(value_active == FALSE);
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Set active to true
	msg = construct_message_active(TRUE);
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check active is true
	msg = construct_message_get_active();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_active = deconstruct_reply_active(reply);
	// The result will depend on the user (access control)
	g_assert_true(value_active == TRUE);
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_configuration_method_sticks()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * value_method;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Set configuration to direct
	msg = construct_message_configuration_direct();
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check configuration is direct
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "direct");
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Set configuration to manual
	msg = construct_message_configuration_manual("https://jolla.com", "");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check configuration is manual
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply,
		CONNMAN_ERROR_INTERFACE ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "manual");
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Set configuration to auto
	msg = construct_message_configuration_auto("");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check configuration is auto
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "auto");
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_configuration_manual_sticks()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * value_method;
	const char * const servers_match[] = {
		"https://jolla.com",
		"http://www.merproject.org",
		NULL
	};
	const char * const servers_nomatch[] = {
		"https://jolla.com",
		NULL
	};
	const char * const excludes_match[] = {
		"jolla.com",
		"merproject.org",
		"example.org",
		NULL
	};
	const char * const excludes_nomatch[] = {
		"jolla.com",
		"merproject.org",
		NULL
	};

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Set configuration to manual
	msg = construct_message_configuration_manual(
				"http://www.merproject.org;https://jolla.com",
				"jolla.com;merproject.org;example.org");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check configuration is manual
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "manual");

	// Check Servers is set correctly
	g_assert_true(deconstruct_reply_configuration_servers_compare(reply,
							servers_match));
	g_assert_false(deconstruct_reply_configuration_servers_compare(reply,
							servers_nomatch));

	// Check Excludes is set correctly
	g_assert_true(deconstruct_reply_configuration_excludes_compare(reply,
							excludes_match));
	g_assert_false(deconstruct_reply_configuration_excludes_compare(reply,
							excludes_nomatch));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_configuration_auto_url_sticks()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * value_method;
	const char * value_url;

	// Privileged access allowed
	test_access = DA_ACCESS_ALLOW;

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Set configuration to auto
	msg = construct_message_configuration_auto(
				"https://jolla.com/config.pac");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check configuration is auto
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "auto");

	// Check URL is set correctly
	value_url = deconstruct_reply_configuration_url(reply);
	g_assert_cmpstr(value_url, ==, "https://jolla.com/config.pac");
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_configfile_read()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * value_method;

	// Privileged access denied
	test_access = DA_ACCESS_DENY;

	export_config("settings", "auto", "https://jolla.com",
		      "merproject.org",
		      "https://jolla.com/test.pac");

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Check configuration is manual
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));

	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "auto");
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();

	export_config("settings", "direct", "https://jolla.com",
		      "merproject.org", "https://jolla.com/test.pac");

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Check configuration is manual
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));

	value_method = deconstruct_reply_configuration_method(reply);
	g_assert_cmpstr(value_method, ==, "direct");
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_configfile_write()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	GKeyFile *keyfile;
	char * filename;

	// Privileged access denied
	test_access = DA_ACCESS_ALLOW;

	export_config("settings", "manual", "https://jolla.com",
		      "merproject.org", "https://jolla.com/test.pac");

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Set configuration to direct
	msg = construct_message_configuration_direct();
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();

	// Check config file was written out with new values
	filename = g_strdup_printf("%s/connman/global_proxy/%s",
				   test_directory, "settings");

	keyfile = g_key_file_new();

	result = g_key_file_load_from_file(keyfile, filename, 0, NULL);
	g_assert_true(result);

	g_assert_cmpstr(g_key_file_get_string(
				keyfile, CONFIG_GROUP_MAIN, CONFIG_KEY_METHOD,
				NULL), ==, "direct");
	g_key_file_unref(keyfile);
	g_free(filename);
}

static void test_global_proxy_active_access_denied()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	dbus_bool_t value_active;

	// Privileged access denied
	test_access = DA_ACCESS_DENY;

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Read current active status
	msg = construct_message_get_active();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_active = deconstruct_reply_active(reply);
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Attempt to set the same value
	msg = construct_message_active(value_active);
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	// Ensure we get an Access Denied response
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Attempt to change the value
	msg = construct_message_active(!value_active);
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	// Ensure we get an Access Denied response
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check it hasn't actually changed
	msg = construct_message_get_active();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	g_assert_cmpuint(value_active, ==, deconstruct_reply_active(reply));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

static void test_global_proxy_configuration_access_denied()
{
	int result;
	DBusMessage *msg;
	DBusMessage *reply;
	const char * value_method;

	// Privileged access denied
	test_access = DA_ACCESS_DENY;

	result = global_proxy_init();
	g_assert_true(result == 0);

	// Get the current configuration
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	value_method = deconstruct_reply_configuration_method(reply);
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Set configuration to direct
	msg = construct_message_configuration_direct();
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	// Ensure we get an Access Denied response
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					    ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check it hasn't actually changed
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	g_assert_cmpstr(value_method, ==, deconstruct_reply_configuration_method(reply));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Set configuration to manual
	msg = construct_message_configuration_manual("https://jolla.com", "");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	// Ensure we get an Access Denied response
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					    ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check it hasn't actually changed
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply,
		CONNMAN_ERROR_INTERFACE ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	g_assert_cmpstr(value_method, ==, deconstruct_reply_configuration_method(reply));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Set configuration to auto
	msg = construct_message_configuration_auto("");
	reply = set_property_dbus_call(NULL, msg, user_data_dbus_call);

	// Ensure we get an Access Denied response
	g_assert_true(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					    ".PermissionDenied"));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	// Check it hasn't actually changed
	msg = construct_message_get_configuration();
	reply = get_property_dbus_call(NULL, msg, user_data_dbus_call);
	g_assert_false(dbus_message_is_error(reply, CONNMAN_ERROR_INTERFACE
					     ".InvalidArguments"));
	g_assert_false(dbus_message_is_error(reply,CONNMAN_ERROR_INTERFACE
					     ".PermissionDenied"));
	g_assert_cmpstr(value_method, ==, deconstruct_reply_configuration_method(reply));
	dbus_message_unref(reply);
	dbus_message_unref(msg);

	global_proxy_exit();
}

#define PREFIX "/global_proxy/"

int main(int argc, char *argv[])
{
	int ret;
	g_test_init(&argc, &argv, NULL);

	test_directory = setup_test_directory();
	g_assert_cmpint(__connman_storage_init(test_directory, ".local", 0700,
								0600), ==, 0);
	__connman_inotify_init();

	g_test_add_func(PREFIX "active_changed", test_global_proxy_notify_active);
	g_test_add_func(PREFIX "invalid_arguments_for_no_key", test_global_proxy_invalid_arguments_no_key);
	g_test_add_func(PREFIX "invalid_arguments_for_invalid_key", test_global_proxy_invalid_arguments_invalid_key);
	g_test_add_func(PREFIX "invalid_arguments_for_invalid_method", test_global_proxy_invalid_arguments_method);
	g_test_add_func(PREFIX "valid_arguments_for_active", test_global_proxy_valid_arguments_active);
	g_test_add_func(PREFIX "valid_arguments_for_direct_configuration", test_global_proxy_valid_arguments_configuration_direct);
	g_test_add_func(PREFIX "valid_arguments_for_manual_configuration", test_global_proxy_valid_arguments_configuration_manual);
	g_test_add_func(PREFIX "valid_arguments_for_auto_configuration", test_global_proxy_valid_arguments_configuration_auto);
	g_test_add_func(PREFIX "active_sticks", test_global_proxy_active_sticks);
	g_test_add_func(PREFIX "method_sticks", test_global_proxy_configuration_method_sticks);
	g_test_add_func(PREFIX "auto_url_sticks", test_global_proxy_configuration_auto_url_sticks);
	g_test_add_func(PREFIX "manual_servers_sticks", test_global_proxy_configuration_manual_sticks);
	g_test_add_func(PREFIX "configfile_read", test_global_proxy_configfile_read);
	g_test_add_func(PREFIX "configfile_write", test_global_proxy_configfile_write);
	g_test_add_func(PREFIX "active_access_denied", test_global_proxy_active_access_denied);
	g_test_add_func(PREFIX "configuration_access_denied", test_global_proxy_configuration_access_denied);

	ret = g_test_run();

	__connman_inotify_cleanup();
	__connman_storage_cleanup();
	cleanup_test_directory(test_directory);
	test_directory = NULL;

	return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
