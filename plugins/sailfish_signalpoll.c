/*
 *  Connection Manager
 *
 *  Copyright (C) 2015-2020 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2020 Open Mobile Platform LLC.
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
#include <gutil_macros.h>
#include <mce_display.h>

#define SIGNALPOLL_HISTORY_SIZE  (10)  /* Number of history entries */
#define SIGNALPOLL_HISTORY_SECS  (10)  /* Max history depth in seconds */
#define SIGNALPOLL_INTERVAL_SECS (2)   /* Interval between polls */

enum signalpoll_display_events {
	DISPLAY_EVENT_VALID,
	DISPLAY_EVENT_STATE,
	DISPLAY_EVENT_COUNT
};

typedef struct signalpoll_object {
	GObject object;
	struct signalpoll pub;          /* Public part */
	GSupplicantInterface *iface;    /* Interface we are polling */
	GCancellable *pending;          /* To cancel the D-Bus call */
	guint timer_id;                 /* Timer ID */
	GUtilIntHistory *history;       /* RSSI history */
	MceDisplay *display;
	gulong display_event_id[DISPLAY_EVENT_COUNT];
	signalpoll_rssi_to_strength_func fn_strength;
} SignalPoll;

typedef GObjectClass SignalPollClass;
G_DEFINE_TYPE(SignalPoll, signalpoll, G_TYPE_OBJECT)
#define SIGNALPOLL_TYPE (signalpoll_get_type())
#define SIGNALPOLL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
        SIGNALPOLL_TYPE, SignalPoll))

typedef struct signalpoll_closure {
	GCClosure cclosure;
	signalpoll_event_func func;
	void *user_data;
} SignalPollClosure;

#define signalpoll_closure_new() ((SignalPollClosure*) \
    g_closure_new_simple(sizeof(SignalPollClosure), NULL))

enum signalpoll_signal {
	SIGNAL_AVERAGE_CHANGED,
	SIGNAL_COUNT
};

#define SIGNAL_AVERAGE_CHANGED_NAME "signalpoll-average-changed"

static guint signalpoll_signals[SIGNAL_COUNT];

static inline SignalPoll *signalpoll_cast(struct signalpoll *poll)
{
	return poll ? SIGNALPOLL(G_CAST(poll,SignalPoll,pub)) : NULL;
}

static void signalpoll_closure_cb(SignalPoll *self, SignalPollClosure *closure)
{
	closure->func(&self->pub, closure->user_data);
}

static void signalpoll_update(SignalPoll *self, int rssi)
{
	const int average_rssi = gutil_int_history_add(self->history, rssi);
	struct signalpoll *pub = &self->pub;

	DBG("%d (%u%%)", average_rssi, self->fn_strength(average_rssi));
	if (pub->average_rssi != average_rssi) {
		pub->average_rssi = average_rssi;
		pub->average = self->fn_strength(average_rssi);
		g_signal_emit(self, signalpoll_signals
					[SIGNAL_AVERAGE_CHANGED], 0);
	}
}

static void signalpoll_done(GSupplicantInterface *iface, GCancellable *cancel,
	const GError *error, const GSupplicantSignalPoll *poll, void *data)
{
	SignalPoll *self = SIGNALPOLL(data);

	self->pending = NULL;
	if (poll) {
		DBG("rssi %d linkspeed %d noise %d frequency %u", poll->rssi,
			poll->linkspeed, poll->noise, poll->frequency);
		if (poll->rssi > 1000 || poll->rssi < -1000) {
			DBG("ignoring bogus rssi value");
		} else {
			signalpoll_update(self, poll->rssi);
		}
	} else {
		DBG("error %s", error ? error->message : "????");
	}
}

static void signalpoll_poll(SignalPoll *self)
{
	if (self->pending) {
		DBG("SignalPoll is already pending");
		g_cancellable_cancel(self->pending);
	}
	self->pending = gsupplicant_interface_signal_poll(self->iface,
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

static void signalpoll_check(SignalPoll *self)
{
	if (signalpoll_display_on(self->display)) {
		/* Need polling */
		if (!self->timer_id) {
			DBG("starting poll timer");
			self->timer_id =
				g_timeout_add_seconds(SIGNALPOLL_INTERVAL_SECS,
						signalpoll_poll_timer, self);
			signalpoll_poll(self);
		}
	} else {
		/* Stop poll timer */
		if (self->timer_id) {
			DBG("stopping poll timer");
			g_source_remove(self->timer_id);
			self->timer_id = 0;
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
		SignalPoll *self = g_object_new(SIGNALPOLL_TYPE, NULL);

		self->fn_strength = fn;
		self->iface = gsupplicant_interface_ref(iface);
		signalpoll_check(self);
		return &self->pub;
	}
	return NULL;
}

struct signalpoll *signalpoll_ref(struct signalpoll *poll)
{
	SignalPoll *self = signalpoll_cast(poll);

	if (self) {
		g_object_ref(self);
		return &self->pub;
	}
	return NULL;
}

void signalpoll_unref(struct signalpoll *poll)
{
	SignalPoll *self = signalpoll_cast(poll);

	if (self) {
		g_object_unref(self);
	}
}

gulong signalpoll_add_average_changed_handler(struct signalpoll *poll,
				signalpoll_event_func fn, void *user_data)
{
	SignalPoll *self = signalpoll_cast(poll);

	if (self && fn) {
		SignalPollClosure *closure = signalpoll_closure_new();
		GCClosure *cc = &closure->cclosure;

		cc->closure.data = closure;
		cc->callback = G_CALLBACK(signalpoll_closure_cb);
		closure->func = fn;
		closure->user_data = user_data;
		return g_signal_connect_closure_by_id(self, signalpoll_signals
			[SIGNAL_AVERAGE_CHANGED], 0, &cc->closure, FALSE);
	}
	return 0;
}

void signalpoll_remove_handler(struct signalpoll *poll, gulong id)
{
	SignalPoll *self = signalpoll_cast(poll);

	if (self && id) {
		g_signal_handler_disconnect(self, id);
	}
}

static void signalpoll_init(SignalPoll *self)
{
	self->history = gutil_int_history_new(SIGNALPOLL_HISTORY_SIZE,
				SIGNALPOLL_HISTORY_SECS * GUTIL_HISTORY_SEC);
	self->display = mce_display_new();
	self->display_event_id[DISPLAY_EVENT_VALID] =
		mce_display_add_valid_changed_handler(self->display,
				signalpoll_display_event, self);
	self->display_event_id[DISPLAY_EVENT_STATE] =
		mce_display_add_state_changed_handler(self->display,
				signalpoll_display_event, self);
}

static void signalpoll_finalize(GObject *object)
{
	SignalPoll *self = SIGNALPOLL(object);

	if (self->timer_id) {
		g_source_remove(self->timer_id);
	}
	if (self->pending) {
		g_cancellable_cancel(self->pending);
	}
	gsupplicant_interface_unref(self->iface);
	mce_display_remove_all_handlers(self->display, self->display_event_id);
	mce_display_unref(self->display);
	gutil_int_history_unref(self->history);
	G_OBJECT_CLASS(signalpoll_parent_class)->finalize(object);
}

static void signalpoll_class_init(SignalPollClass *klass)
{
	klass->finalize = signalpoll_finalize;
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
