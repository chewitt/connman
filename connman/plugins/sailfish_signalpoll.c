/*
 *  Connection Manager
 *
 *  Copyright (C) 2015-2017 Jolla Ltd. All rights reserved.
 *  Contact: Slava Monich <slava.monich@jolla.com>
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

#include "sailfish_signalpoll.h"
#include "log.h"

#include <gsupplicant_interface.h>
#include <gutil_history.h>
#include <mce_display.h>

#define SIGNALPOLL_HISTORY_SIZE  (10)  /* Number of history entries */
#define SIGNALPOLL_HISTORY_SECS  (10)  /* Max history depth in seconds */
#define SIGNALPOLL_INTERVAL_SECS (2)   /* Interval between polls */

enum signalpoll_display_events {
	DISPLAY_EVENT_VALID,
	DISPLAY_EVENT_STATE,
	DISPLAY_EVENT_COUNT
};

struct signalpoll_priv {
	GSupplicantInterface *iface;    /* Interface we are polling */
	GCancellable *pending;          /* To cancel the D-Bus call */
	guint timer_id;                 /* Timer ID */
	GUtilIntHistory *history;       /* Signal strength history */
	MceDisplay *display;
	gulong display_event_id[DISPLAY_EVENT_COUNT];
	signalpoll_rssi_to_strength_func fn_strength;
};

typedef GObjectClass SignalPollClass;
G_DEFINE_TYPE(SignalPoll, signalpoll, G_TYPE_OBJECT)
#define SIGNALPOLL_TYPE (signalpoll_get_type())
#define SIGNALPOLL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
        SIGNALPOLL_TYPE, SignalPoll))

enum signalpoll_signal {
	SIGNAL_AVERAGE_CHANGED,
	SIGNAL_COUNT
};

#define SIGNAL_AVERAGE_CHANGED_NAME "signalpoll-average-changed"

static guint signalpoll_signals[SIGNAL_COUNT];

static void signalpoll_update(struct signalpoll *self, guint8 strength)
{
	struct signalpoll_priv *priv = self->priv;
	/* It's actually a median but it doesn't really matter */
	guint average = gutil_int_history_add(priv-> history, strength);

	DBG("%u", average);
	if (self->average != average) {
		self->average = average;
		g_signal_emit(self, signalpoll_signals
					[SIGNAL_AVERAGE_CHANGED], 0);
	}
}

static void signalpoll_done(GSupplicantInterface *iface, GCancellable *cancel,
	const GError *error, const GSupplicantSignalPoll *poll, void *data)
{
	struct signalpoll *self = SIGNALPOLL(data);
	struct signalpoll_priv *priv = self->priv;

	priv->pending = NULL;
	if (poll) {
		DBG("rssi %d linkspeed %d noise %d frequency %u", poll->rssi,
			poll->linkspeed, poll->noise, poll->frequency);
		if (poll->rssi > 1000 || poll->rssi < -1000) {
			DBG("ignoring bogus rssi value");
		} else {
			signalpoll_update(self, priv->fn_strength(poll->rssi));
		}
	} else {
		DBG("error %s", error ? error->message : "????");
	}
}

static void signalpoll_poll(struct signalpoll *self)
{
	struct signalpoll_priv *priv = self->priv;

	if (priv->pending) {
		DBG("SignalPoll is already pending");
		g_cancellable_cancel(priv->pending);
	}
	priv->pending = gsupplicant_interface_signal_poll(priv->iface,
						signalpoll_done, self);
}

static gboolean signalpoll_poll_timer(gpointer data)
{
	signalpoll_poll(SIGNALPOLL(data));
	return G_SOURCE_CONTINUE;
}

static gboolean signalpoll_display_on(MceDisplay *display)
{
	return display && display->valid &&
				display->state != MCE_DISPLAY_STATE_OFF;
}

static void signalpoll_check(struct signalpoll *self)
{
	struct signalpoll_priv *priv = self->priv;

	if (signalpoll_display_on(priv->display)) {
		/* Need polling */
		if (!priv->timer_id) {
			DBG("starting poll timer");
			priv->timer_id =
				g_timeout_add_seconds(SIGNALPOLL_INTERVAL_SECS,
						signalpoll_poll_timer, self);
			signalpoll_poll(self);
		}
	} else {
		/* Stop poll timer */
		if (priv->timer_id) {
			DBG("stopping poll timer");
			g_source_remove(priv->timer_id);
			priv->timer_id = 0;
		}
	}
}

static void signalpoll_display_event(MceDisplay *display, void *data)
{
	signalpoll_check(SIGNALPOLL(data));
}

struct signalpoll *signalpoll_new(GSupplicantInterface *iface,
					signalpoll_rssi_to_strength_func fn)
{
	if (iface && fn) {
		struct signalpoll *self = g_object_new(SIGNALPOLL_TYPE, NULL);
		struct signalpoll_priv *priv = self->priv;

		priv->fn_strength = fn;
		priv->iface = gsupplicant_interface_ref(iface);
		signalpoll_check(self);
		return self;
	}
	return NULL;
}

struct signalpoll *signalpoll_ref(struct signalpoll *self)
{
	if (self) {
		g_object_ref(SIGNALPOLL(self));
		return self;
	}
	return NULL;
}

void signalpoll_unref(struct signalpoll *self)
{
	if (self) {
		g_object_unref(SIGNALPOLL(self));
	}
}

gulong signalpoll_add_average_changed_handler(struct signalpoll *self,
				signalpoll_event_func fn, void *data)
{
	return self && fn ? g_signal_connect(self,
		SIGNAL_AVERAGE_CHANGED_NAME, G_CALLBACK(fn), data) : 0;
}

void signalpoll_remove_handler(struct signalpoll *self, gulong id)
{
	if (self && id) {
		g_signal_handler_disconnect(self, id);
	}
}

static void signalpoll_init(struct signalpoll *self)
{
	struct signalpoll_priv *priv = G_TYPE_INSTANCE_GET_PRIVATE(self,
			SIGNALPOLL_TYPE, struct signalpoll_priv);

	self->priv = priv;
	priv->history = gutil_int_history_new(SIGNALPOLL_HISTORY_SIZE,
				SIGNALPOLL_HISTORY_SECS * GUTIL_HISTORY_SEC);
	priv->display = mce_display_new();
	priv->display_event_id[DISPLAY_EVENT_VALID] =
		mce_display_add_valid_changed_handler(priv->display,
				signalpoll_display_event, self);
	priv->display_event_id[DISPLAY_EVENT_STATE] =
		mce_display_add_state_changed_handler(priv->display,
				signalpoll_display_event, self);
}

static void signalpoll_finalize(GObject *object)
{
	struct signalpoll *self = SIGNALPOLL(object);
	struct signalpoll_priv *priv = self->priv;

	if (priv->timer_id) {
		g_source_remove(priv->timer_id);
	}
	if (priv->pending) {
		g_cancellable_cancel(priv->pending);
	}
	gsupplicant_interface_unref(priv->iface);
	mce_display_remove_handlers(priv->display, priv->display_event_id,
				G_N_ELEMENTS(priv->display_event_id));
	mce_display_unref(priv->display);
	gutil_int_history_unref(priv->history);
	G_OBJECT_CLASS(signalpoll_parent_class)->finalize(object);
}

static void signalpoll_class_init(SignalPollClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = signalpoll_finalize;

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_type_class_add_private(klass, sizeof(struct signalpoll_priv));
	G_GNUC_END_IGNORE_DEPRECATIONS

        signalpoll_signals[SIGNAL_AVERAGE_CHANGED] =
		g_signal_new(SIGNAL_AVERAGE_CHANGED_NAME,
			G_OBJECT_CLASS_TYPE(klass), G_SIGNAL_RUN_FIRST,
			0, NULL, NULL, NULL, G_TYPE_NONE, 0);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
