/*
 *  Connection Manager
 *
 *  Copyright (C) 2016-2018 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2016-2018 Slava Monich <slava.monich@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include "test_timenotify.h"

#include <glib-object.h>

typedef struct gutil_time_notify {
	GObject object;
} TestTimeNotify;

enum test_time_notify_signal {
	SIGNAL_TIME_CHANGED,
	SIGNAL_COUNT
};

#define SIGNAL_TIME_CHANGED_NAME   "time-changed"

static guint test_time_notify_signals[SIGNAL_COUNT] = { 0 };

typedef GObjectClass TestTimeNotifyClass;
G_DEFINE_TYPE(TestTimeNotify, test_time_notify, G_TYPE_OBJECT)
#define PARENT_CLASS test_time_notify_parent_class
#define TEST_TIME_NOTIFY_TYPE (test_time_notify_get_type())
#define TEST_TIME_NOTIFY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj),\
	TEST_TIME_NOTIFY_TYPE, TestTimeNotify))

TestTimeNotify *test_time_notify_new()
{
	/* There's no need to have more than one instance. */
	static TestTimeNotify *instance = NULL;
	if (instance) {
		test_time_notify_ref(instance);
	} else {
		instance = g_object_new(TEST_TIME_NOTIFY_TYPE, 0);
		g_object_add_weak_pointer(G_OBJECT(instance),
						(gpointer*)(&instance));
	}
	return instance;
}

TestTimeNotify *test_time_notify_ref(TestTimeNotify *self)
{
	if (G_LIKELY(self)) {
		g_object_ref(TEST_TIME_NOTIFY(self));
	}
	return self;
}

void test_time_notify_unref(TestTimeNotify *self)
{
	if (G_LIKELY(self)) {
		g_object_unref(TEST_TIME_NOTIFY(self));
	}
}

gulong test_time_notify_add_handler(TestTimeNotify *self,
				GUtilTimeNotifyFunc fn, void *arg)
{
	return (G_LIKELY(self) && G_LIKELY(fn)) ? g_signal_connect(self,
		SIGNAL_TIME_CHANGED_NAME, G_CALLBACK(fn), arg) : 0;
}

void test_time_notify_remove_handler(TestTimeNotify *self, gulong id)
{
	if (G_LIKELY(self) && G_LIKELY(id)) {
		g_signal_handler_disconnect(self, id);
	}
}

void test_time_notify_signal(TestTimeNotify *self)
{
	if (G_LIKELY(self)) {
		g_signal_emit(self, test_time_notify_signals
			[SIGNAL_TIME_CHANGED], 0);
	}
}

static void test_time_notify_init(TestTimeNotify *self)
{
}

static void test_time_notify_class_init(TestTimeNotifyClass *klass)
{
	test_time_notify_signals[SIGNAL_TIME_CHANGED] =
		g_signal_new(SIGNAL_TIME_CHANGED_NAME,
			G_OBJECT_CLASS_TYPE(klass), G_SIGNAL_RUN_FIRST,
			0, NULL, NULL, NULL, G_TYPE_NONE, 0);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
