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

#include "sailfish_datacounters.h"

#include "connman.h"

#include <gutil_misc.h>

typedef struct datacounters DataCounters;
struct datacounters_priv {
	char *ident;
	GSList *list;
	const char **counters;
};

typedef GObjectClass DataCountersClass;
G_DEFINE_TYPE(DataCounters, datacounters, G_TYPE_OBJECT)
#define PARENT_CLASS datacounters_parent_class
#define DATACOUNTERS_TYPE (datacounters_get_type())
#define DATACOUNTERS(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	DATACOUNTERS_TYPE, DataCounters))

enum datacounter_signal {
	SIGNAL_COUNTERS,
	SIGNAL_COUNT
};

#define SIGNAL_COUNTERS_NAME    "datacounters-counters"

static guint datacounters_signal[SIGNAL_COUNT];

/* Weak references to the instances of DataCounters */
static GHashTable *datacounters_table = NULL;

/*==========================================================================*
 * Implementation
 *==========================================================================*/

static struct datacounter *datacounters_find(struct datacounters_priv *priv,
							const char *name)
{
	GSList *l = priv->list;

	while (l) {
		struct datacounter *dc = l->data;

		if (!g_strcmp0(dc->name, name)) {
			return dc;
		}
		l = l->next;
	}
	return NULL;
}

static const char **datacounters_counter_names(struct datacounters_priv *priv)
{
	guint i;
	GSList *l;
	const guint n = g_slist_length(priv->list);
	const char **counters = g_new0(const char*, n+1);

	for (l = priv->list, i = 0; l && i < n; l = l->next, i++) {
		/*
		 * Assume that datacounter never reallocates its name and
		 * just store the pointer (could be an over-optimization?)
		 */
		struct datacounter *counter = l->data;
		counters[i] = counter->name;
	}
	counters[i] = NULL;
	return counters;
}

static void datacounters_destroyed(gpointer key, GObject *obj)
{
	DBG("%s", (char*)key);
	g_hash_table_remove(datacounters_table, key);
	if (g_hash_table_size(datacounters_table) == 0) {
		/* Delete the hashtable when we no longer need it */
		g_hash_table_unref(datacounters_table);
		datacounters_table = NULL;
	}
}

static void datacounters_counters_modified(struct datacounters *self)
{
	struct datacounters_priv *priv = self->priv;

	g_free(priv->counters);
	self->counters = priv->counters = datacounters_counter_names(priv);
	g_signal_emit(self, datacounters_signal[SIGNAL_COUNTERS], 0);
}

static void datacounters_counter_destroyed(gpointer arg, GObject *counter)
{
	struct datacounters *self = DATACOUNTERS(arg);
	struct datacounters_priv *priv = self->priv;

	priv->list = g_slist_remove(priv->list, counter);
	datacounters_counters_modified(self);
	datacounters_unref(self);
}

static void datacounters_append_counter(struct datacounters *self,
						struct datacounter *dc)
{
	struct datacounters_priv *priv = self->priv;

	priv->list = g_slist_append(priv->list, dc);
	datacounters_counters_modified(self);
}

static struct datacounters *datacounters_create(const char *ident)
{
	struct datacounters *self = g_object_new(DATACOUNTERS_TYPE, NULL);
	struct datacounters_priv *priv = self->priv;

	DBG("%s", ident);
	self->ident = priv->ident = g_strdup(ident);
	return self;
}

/*==========================================================================*
 * API
 *==========================================================================*/

struct datacounters *datacounters_new(const char *ident)
{
	struct datacounters *self = NULL;

	if (G_LIKELY(ident)) {
		if (datacounters_table) {
			self = g_hash_table_lookup(datacounters_table, ident);
		} else {
			datacounters_table = g_hash_table_new_full(g_str_hash,
						g_str_equal, g_free, NULL);
		}
		if (self) {
			datacounters_ref(self);
		} else {
			char *key = g_strdup(ident);

			self = datacounters_create(ident);
			g_hash_table_insert(datacounters_table, key, self);
			g_object_weak_ref(G_OBJECT(self),
					datacounters_destroyed, key);
		}
	}
	return self;
}

struct datacounters *datacounters_ref(struct datacounters *self)
{
	if (G_LIKELY(self)) {
		g_object_ref(DATACOUNTERS(self));
	}
	return self;
}

void datacounters_unref(struct datacounters *self)
{
	if (G_LIKELY(self)) {
		g_object_unref(DATACOUNTERS(self));
	}
}

struct datacounter *datacounters_get_counter(struct datacounters *self,
							const char *name)
{
	if (G_LIKELY(self) && G_LIKELY(name)) {
		struct datacounters_priv *priv = self->priv;
		struct datacounter *dc = datacounters_find(priv, name);

		if (dc) {
			datacounter_ref(dc);
		} else {
			/*
			 * Each datacounter created this way, implicitely
			 * holds a reference to datacounters. The reference
			 * gets released when datacounter is destroyed.
			 */
			dc = datacounter_new(self->ident, name);
			g_object_weak_ref(G_OBJECT(dc),
					datacounters_counter_destroyed,
					datacounters_ref(self));
			datacounters_append_counter(self, dc);
		}
		return dc;
	}
	return NULL;
}

void datacounters_reset_all_counters(struct datacounters *self)
{
	if (G_LIKELY(self)) {
		GSList *l;
		struct datacounters_priv *priv = self->priv;

		for (l = priv->list; l; l = l->next) {
			datacounter_reset(l->data);
		}
	}
}

gulong datacounters_add_counters_handler(struct datacounters *self,
				datacounters_cb_t cb, void *arg)
{
    return (G_LIKELY(self) && G_LIKELY(cb)) ? g_signal_connect(self,
        SIGNAL_COUNTERS_NAME, G_CALLBACK(cb), arg) : 0;
}

void datacounters_remove_handler(struct datacounters *self, gulong id)
{
	if (G_LIKELY(self) && G_LIKELY(id)) {
		g_signal_handler_disconnect(self, id);
	}
}

void datacounters_remove_handlers(struct datacounters *self,
						gulong *ids, guint count)
{
	gutil_disconnect_handlers(self, ids, count);
}

/*==========================================================================*
 * Internals
 *==========================================================================*/

static void datacounters_init(struct datacounters *self)
{
	struct datacounters_priv *priv = G_TYPE_INSTANCE_GET_PRIVATE(self,
				DATACOUNTERS_TYPE, struct datacounters_priv);

	priv->counters = g_new0(const char*, 1);
	self->priv = priv;
	self->counters = priv->counters;
}

static void datacounters_finalize(GObject *object)
{
	struct datacounters *self = DATACOUNTERS(object);
	struct datacounters_priv *priv = self->priv;

	DBG("%s", priv->ident);
	g_free(priv->ident);
	g_free(priv->counters);
	G_OBJECT_CLASS(PARENT_CLASS)->finalize(object);
}

static void datacounters_class_init(DataCountersClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	object_class->finalize = datacounters_finalize;

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_type_class_add_private(klass, sizeof(struct datacounters_priv));
	G_GNUC_END_IGNORE_DEPRECATIONS

	datacounters_signal[SIGNAL_COUNTERS] =
		g_signal_new(SIGNAL_COUNTERS_NAME, G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_FIRST, 0, NULL, NULL, NULL,
			G_TYPE_NONE, 0);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
