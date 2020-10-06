/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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
#include <string.h>
#include <strings.h>

#include <glib.h>
#include <systemd/sd-login.h>

#include "connman.h"

#define DEFAULT_SEAT "seat0"

enum sd_session_state {
	/* Invalid and for handling future states, which are ignored. */
	SD_SESSION_UNDEF,
	/* user not logged in */
	SD_SESSION_OFFLINE,
	/* user not logged in, but some user services running */
	SD_SESSION_LINGERING,
	/*
	 * non-documented state - apparently preceeds session active state.
	 * https://github.com/systemd/systemd/blob/master/src/login/
	 * logind-user.c#L878
	 */
	SD_SESSION_OPENING,
	/*
	 * user logged in, but not active, i.e. has no session in the
	 * foreground
	 */
	SD_SESSION_ONLINE,
	/*
	 * user logged in, and has at least one active session, i.e. one
	 * session in the foreground.
	 */
	SD_SESSION_ACTIVE,
	/*
	 * user not logged in, and not lingering, but some processes are still
	 * around.
	 */
	SD_SESSION_CLOSING,
};

/*
 * The state machine used here contains 7 different states:
 *  0. idle (SL_IDLE),
 *  1. systemd initialized (SL_SD_INITIALIZED)
 *  2. connected (SL_CONNECTED)
 *  3. initial status check (SL_INITIAL_STATUS_CHECK)
 *  4. status check (SL_STATUS_CHECK)
 *  5. waiting for user change reply (SL_WAITING_USER_CHANGE_REPLY)
 *  6. waiting for user change reply with a delayed status check
 *     (SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED)
 *
 * The initial status check (3.) is always done at initialization and only in
 * initialization. Depending on the current active user id (uid) the state is
 * changed either back to systemd initialized (1.) or to waiting for user
 * change reply (5.).
 *
 * If the initial status check (3.) completes without any change before the
 * GIOChannel listener for the systemd login fd is created state is changed
 * back to initialized. After this the state is changed to connected (2.) if
 * the systemd login fd listener can be created. If not, the change to
 * connected state (2.) is delayed until the listener is established. State
 * changes back to idle (0.) when re-establishing the listener in order to make
 * sure that the systemd login connection is working.
 *
 * If there is a uid change while waiting for a reply to initial request (5.)
 * the listener for the systemd login fd has been created using GIOChannel. The
 * state transfer depends on this, and if there is activity in the fd while
 * waiting for reply (5.) state is transferred to waiting for reply with a
 * delayed status check (6.). There can be only one delayed status check as
 * the most recent status of the user will be retrieved with the check and
 * further status checks are not necessary.
 *
 * After the systemd login fd listener is created and in connected state the
 * events on the fd will trigger a change to status check state (4.) and if
 * there is a change on the uid state is transferred to waiting for reply (5.).
 * In this state, similarly when transferring from initial status check (3.)
 * other fd events create a delayed status check and state is changed (to 6.).
 * Either without change to uid or after a reply state is changed back to
 * connected (2.).
 *
 * The key difference between initial status check (3.) and status check (4.)
 * is that initial status check (3.) will get 2 replies and change to connmand
 * active uid is immident, and a reply from connman-vpnd is expected. The
 * initial status check (3.) does only preparation for connmand since at the
 * time of the check the other components normally involved in the user change
 * are not initialized yet. The regular status check (4.) will behave as if the
 * user change would have become via D-Bus API. One reply is expected and after
 * this the state changes back to connected (2.).
 *
 * The following depicts the state transition diagram with additional
 * clarifications on certain state changes:
 *
 *      |===================|
 *      |                   |
 *      |    0. SL_IDLE     |
 *      |                   |
 *      |===================|
 *           ^         |
 *          / \        |
 *           |        \ /
 *           |         v
 *      |======================|  [initialized]  |============================|
 *      |                      |---------------->|                            |
 *      | 1. SL_SD_INITIALIZED |                 | 3. SL_INITIAL_STATUS_CHECK |
 *      |                      |    [!change]    |                            |
 *      |======================|<----------------|============================|
 *           ^      |      ^                                 |
 *          / \     |     / \                                |
 *           |      |      |   [reply && !fd listener]       | [change]
 *           |      |      \-------------------------\       |
 *           |     \ /                               |      \ /
 *           |      v                                |       v
 *      |===================|                |================================|
 *      |                   | [reply &&      |                                |
 *  /-->|  2. SL_CONNECTED  |  fd listener ] | 5.SL_WAITING_USER_CHANGE_REPLY |
 *  |   |                   |<---------------|                                |
 *  |   |===================|                |================================|
 *  |           ^      |                            ^       |
 *  |          / \     |                           / \      |
 *  | [!change] |      | [fd triggered]             |       | [!reply &&
 *  |           |     \ /                           |       |  new fd trigger]
 *  |           |      v                            |       |
 *  |   |====================|                      |       |
 *  |   |                    |       [change]       |       |
 *  |   | 4. SL_STATUS_CHECK |-----------------------/      |
 *  |   |                    |                              |
 *  |   |====================|                             \ /
 *  |                                                       v
 *  |                           |=============================================|
 *  |          [reply]          |                                             |
 *  \---------------------------| 6. SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED |
 *                              |                                             |
 *                              |=============================================|
*/

enum sl_state {
	SL_IDLE						= 0x0000, // 0
	SL_SD_INITIALIZED				= 0x0001, // 1
	SL_CONNECTED					= 0x0002, // 2
	SL_INITIAL_STATUS_CHECK				= 0x0004, // 3
	SL_STATUS_CHECK					= 0x0008, // 4
	SL_WAITING_USER_CHANGE_REPLY			= 0x0010, // 5
	SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED	= 0x0020, // 6
};

struct systemd_login_data {
	enum sl_state state;
	enum sl_state old_state;
	uid_t active_uid;
	sd_login_monitor *login_monitor;
	guint iochannel_in_id;
	guint restore_sd_connection_id;
	guint delayed_status_check_id;
	bool prepare_only;
	unsigned int pending_replies;
};

struct systemd_login_data *login_data = NULL;

static const char *state2string(enum sl_state state)
{
	switch (state) {
	case SL_IDLE:
		return "idle";
	case SL_SD_INITIALIZED:
		return "initialized";
	case SL_CONNECTED:
		return "connected";
	case SL_INITIAL_STATUS_CHECK:
		return "initial status check";
	case SL_STATUS_CHECK:
		return "status check";
	case SL_WAITING_USER_CHANGE_REPLY:
		return "waiting reply";
	case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
		return "waiting reply and delayed";
	}

	return "invalid state";
}

/*
 * To ease debugging, have state numbers as integers. Return the index of the
 * first bit set.
 */
static int state2int(enum sl_state state)
{
	return ffs((int)state);
}

static bool change_state(struct systemd_login_data *login_data,
			enum sl_state new_state, bool change, bool force)
{
	enum sl_state old_state;

	if (!login_data)
		return false;

	if (login_data->state == new_state) {
		DBG("no change");
		return true;
	}

	if (force && change) {
		DBG("force state change %d:%-26s -> %d:%s",
					state2int(login_data->state),
					state2string(login_data->state),
					state2int(new_state),
					state2string(new_state));

		/* Drop history when forced */
		login_data->old_state = new_state;
		login_data->state = new_state;

		return true;
	}

	old_state = login_data->old_state;

	switch (login_data->state) {
	case SL_IDLE:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			break;
		default:
			goto err;
		}

		break;
	case SL_SD_INITIALIZED:
		switch (new_state) {
		case SL_IDLE:
			if (old_state & ~(SL_INITIAL_STATUS_CHECK |
						SL_CONNECTED |
						SL_WAITING_USER_CHANGE_REPLY))
				goto err;

			break;
		case SL_CONNECTED:
			if (old_state & ~(SL_IDLE | SL_INITIAL_STATUS_CHECK |
						SL_WAITING_USER_CHANGE_REPLY))
				goto err;

			break;
		case SL_INITIAL_STATUS_CHECK:
			if (old_state != SL_IDLE)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_CONNECTED:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			if (old_state & (SL_IDLE | SL_INITIAL_STATUS_CHECK))
				goto err;

			break;
		case SL_STATUS_CHECK:
			if (old_state & (SL_IDLE | SL_INITIAL_STATUS_CHECK))
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_INITIAL_STATUS_CHECK:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			if (old_state != SL_SD_INITIALIZED)
				goto err;

			break;
		case SL_WAITING_USER_CHANGE_REPLY:
			if (old_state != SL_SD_INITIALIZED)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_STATUS_CHECK:
		switch (new_state) {
		case SL_CONNECTED:
			if (old_state != SL_CONNECTED)
				goto err;

			break;
		case SL_WAITING_USER_CHANGE_REPLY:
			if (old_state != SL_CONNECTED)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_WAITING_USER_CHANGE_REPLY:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			if (old_state != SL_INITIAL_STATUS_CHECK)
				goto err;

			break;
		case SL_CONNECTED:
			/*
			 * While waiting for reply connection may have been
			 * established if in initial status check state.
			 */
			if (old_state & ~(SL_INITIAL_STATUS_CHECK |
						SL_STATUS_CHECK))
				goto err;

			break;
		case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
			if (old_state & ~(SL_INITIAL_STATUS_CHECK |
						SL_STATUS_CHECK))
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
		switch (new_state) {
		case SL_CONNECTED:
			if (old_state != SL_WAITING_USER_CHANGE_REPLY)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	}

	if (change) {
		DBG("state %d:%-26s -> %d:%s",state2int(login_data->state),
					state2string(login_data->state),
					state2int(new_state),
					state2string(new_state));

		login_data->old_state = login_data->state;
		login_data->state = new_state;
	}

	return true;

err:
	DBG("invalid state change %d:%-26s -> %d:%s (old state %d:%s)",
				state2int(login_data->state),
				state2string(login_data->state),
				state2int(new_state), state2string(new_state),
				state2int(old_state), state2string(old_state));

	return false;
}

static bool is_preparing(struct systemd_login_data *login_data)
{
	if (!login_data)
		return false;

	return login_data->prepare_only && !login_data->iochannel_in_id;
}

static enum sd_session_state get_session_state(const char *state)
{
	if (!g_strcmp0(state, "online"))
		return SD_SESSION_ONLINE;

	if (!g_strcmp0(state, "active"))
		return SD_SESSION_ACTIVE;

	if (!g_strcmp0(state, "closing"))
		return SD_SESSION_CLOSING;

	if (!g_strcmp0(state, "offline"))
		return SD_SESSION_OFFLINE;

	if (!g_strcmp0(state, "lingering"))
		return SD_SESSION_LINGERING;

	if (!g_strcmp0(state, "opening"))
		return SD_SESSION_OPENING;

	connman_warn("unknown sd_login state %s", state);

	return SD_SESSION_UNDEF;
}

/*
 * This may report -ENOENT, which is not necessarily an error but an indication
 * that the session is not ready yet, which must be handled by caller.
 */
static int get_session_uid_and_state(uid_t *uid,
					enum sd_session_state *session_state)
{
	char *session = NULL;
	char *state = NULL;
	int err;

	DBG("");

	*uid = 0;
	*session_state = SD_SESSION_UNDEF;

	err = sd_seat_get_active(DEFAULT_SEAT, &session, uid);
	if (err < 0) {
		/* No not regard -ENOENT as error, session is not ready yet */
		if (err != -ENOENT)
			connman_warn("err %d failed to get active session "
						"and/or user for seat %s", err,
						DEFAULT_SEAT);

		goto out;
	}

	if (!session) {
		DBG("no session");
		err = -EINVAL;
		goto out;
	}

	if (sd_session_is_remote(session) == 1) {
		DBG("ignore remote session %s", session);
		err = -EREMOTE;
		goto out;
	}

	err = sd_uid_get_state(*uid, &state);
	if (err < 0) {
		connman_warn("err %d failed to get state for uid %d "
					"session %s", err, *uid, session);
		goto out;
	}

	*session_state = get_session_state(state);

out:
	g_free(session);
	g_free(state);

	if (err)
		return err;

	return (*session_state != SD_SESSION_UNDEF && *uid != 0) ? 0 : -EINVAL;
}

static int init_delayed_status_check(struct systemd_login_data *login_data);

static void user_change_result_cb(uid_t uid, int err, void *user_data)
{
	struct systemd_login_data *login_data = user_data;

	if (login_data->state & ~(SL_WAITING_USER_CHANGE_REPLY |
				SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED)) {
		DBG("invalid state %d:%s", state2int(login_data->state),
					state2string(login_data->state));
		return;
	}

	if (!change_state(login_data, is_preparing(login_data) ?
				SL_SD_INITIALIZED : SL_CONNECTED, false,
				false)) {
		DBG("cannot change state");
		return;
	}

	if (!login_data->pending_replies) {
		connman_warn("not expecting a reply on user change result");
		return;
	}

	login_data->pending_replies--;

	DBG("pending_replies %d", login_data->pending_replies);

	/*
	 * In case there is an error the user change is not done and the
	 * active uid should be changed what is reported back. Usually
	 * storage reverts back to using root as user.
	 */
	switch (err) {
	case 0:
		connman_info("user changed to %u", uid);
		break;
	case -EINPROGRESS:
		if (login_data->pending_replies) {
			DBG("user change to %u is pending for reply", uid);
			return;
		}

		/*
		 * If there are no reply is pending the next reply would be
		 * ignored anyways. Change state to appropriate one.
		 */
		goto out;
	case -ETIMEDOUT:
		/* In case of D-Bus timeout try to initialize delayed check */
		init_delayed_status_check(login_data);
		goto out;
	case -EALREADY:
		/* User is already set, clear pending count and stop */
		connman_info("user already set to %u", uid);
		login_data->pending_replies = 0;
		goto out;
	default:
		connman_warn("user change to %u not successful %d:%s",
					login_data->active_uid, err,
					strerror(-err));
	}

	if (uid != login_data->active_uid) {
		connman_warn("changed to different user %d than "
					"requested (%d)", uid,
					login_data->active_uid);
		login_data->active_uid = uid;
	}

out:
	change_state(login_data, is_preparing(login_data) ?
				SL_SD_INITIALIZED : SL_CONNECTED, true, false);
}

static int check_session_status(struct systemd_login_data *login_data)
{
	enum sd_session_state state;
	uid_t uid;
	int err = 0;

	DBG("");

	if (login_data->state & ~(SL_SD_INITIALIZED | SL_CONNECTED)) {
		DBG("invalid state %d:%s", state2int(login_data->state),
					state2string(login_data->state));
		return -EINVAL;
	}

	if (!change_state(login_data, is_preparing(login_data) ?
				SL_INITIAL_STATUS_CHECK : SL_STATUS_CHECK,
				true, false)) {
		DBG("invalid state change");
		return -EINVAL;
	}

	err = get_session_uid_and_state(&uid, &state);
	switch (err) {
	case 0:
		break;
	case -ENOENT:
		/* Session is not proabably ready yet */
		DBG("session not ready yet");
		goto out;
	default:
		DBG("failed to get uid %u and/or state %d", uid, state);
		err = -EINVAL;
		goto out;
	}

	switch (state) {
	case SD_SESSION_OFFLINE:
		DBG("user %u is offline", uid);
		goto out;
	case SD_SESSION_LINGERING:
		DBG("user %u is lingering", uid);
		goto out;
	case SD_SESSION_OPENING:
		DBG("user %u is opening session", uid);

		/*
		 * The system main user (root) is in use prior to user change
		 * is in effect. This ensures that all technologies are off
		 * when logging in also after boot. get_session_uid_and_state()
		 * ignores remote sessions so this is not triggered by, e.g.,
		 * new ssh connection.
		 */
		__connman_technology_disable_all();
		goto out;
	case SD_SESSION_ACTIVE:
		if (uid == login_data->active_uid) {
			DBG("user %u already active", uid);
			goto out;
		}

		DBG("active user changed, change to uid %d", uid);
		login_data->active_uid = uid;
		goto reply;
	case SD_SESSION_ONLINE:
		if (uid == login_data->active_uid)
			DBG("user %u left foreground, wait for logout", uid);

		DBG("uid %u is online", uid);
		goto out;
	case SD_SESSION_CLOSING:
		DBG("logout, go to root");
		login_data->active_uid = 0;
		goto reply;
	case SD_SESSION_UNDEF:
		DBG("unsupported status");
		err = -EINVAL;
		goto out;
	}

reply:
	/*
	 * Change state before because when doing initial check.
	 * __connman_storage_change_user() calls the result cb immediately.
	 */
	if (!change_state(login_data, SL_WAITING_USER_CHANGE_REPLY, true,
				false)) {
		DBG("invalid state change");
		err = -EINVAL;
		goto out;
	}

	/* Initial check expects 2 replies */
	login_data->pending_replies = login_data->prepare_only ? 2 : 1;

	err = __connman_storage_change_user(login_data->active_uid,
				user_change_result_cb, login_data,
				login_data->prepare_only);
	/* In case of error change state */
	if (err && err != -EINPROGRESS)
		goto out;

	return err;

out:
	if (!change_state(login_data, is_preparing(login_data) ?
				SL_SD_INITIALIZED : SL_CONNECTED, true,
				false)) {
		DBG("invalid state change");
		err = -EINVAL;
	}

	return err;
}

static gboolean delayed_status_check(gpointer user_data);
static void clean_delayed_status_check(gpointer user_data);

static int do_session_status_check(struct systemd_login_data *login_data)
{
	int err;

	DBG("");

	if (!login_data)
		return -ENOENT;

	switch (login_data->state) {
	case SL_IDLE:
		DBG("invalid state %d:%s", state2int(login_data->state),
					state2string(login_data->state));
		return -ENOTCONN;
	case SL_SD_INITIALIZED:
		DBG("initial session status check");
		login_data->prepare_only = true;
		return check_session_status(login_data);
	case SL_CONNECTED:
		DBG("check session status");
		login_data->prepare_only = false;
		return check_session_status(login_data);
	case SL_INITIAL_STATUS_CHECK:
		/* fall through */
	case SL_STATUS_CHECK:
		return -EINPROGRESS;
	case SL_WAITING_USER_CHANGE_REPLY:

		DBG("user change is pending");

		err = init_delayed_status_check(login_data);
		if (err)
			return err;

		if (!change_state(login_data,
				SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED,
				true, false))
			return -EINVAL;

		return -EINPROGRESS;
	case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
		return -EINPROGRESS;
	}

	return 0;
}

static gboolean delayed_status_check(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	int err;

	DBG("");

	if (login_data->state == SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED) {
		DBG("reply pending and check already delayed, continue");
		return G_SOURCE_CONTINUE;
	}

	if (login_data->state != SL_CONNECTED) {
		DBG("invalid state %d:%s - continue",
					state2int(login_data->state),
					state2string(login_data->state));
		return G_SOURCE_CONTINUE;
	}

	err = do_session_status_check(login_data);
	switch (err) {
	case 0:
		break;
	case -EINPROGRESS:
		break;
	case -ENOENT:
		/* Session is not ready yet, keep in loop */
		return G_SOURCE_CONTINUE;
	default:
		DBG("failed to check session status: %d:%s", err,
					strerror(-err));
	}

	login_data->delayed_status_check_id = 0;
	return G_SOURCE_REMOVE;
}

#define DELAYED_STATUS_CHECK_TIMEOUT 100

static int init_delayed_status_check(struct systemd_login_data *login_data)
{
	DBG("");

	if (!login_data)
		return -ENOENT;

	if (login_data->delayed_status_check_id) {
		DBG("delayed_status_check_id exists");
		return -EINPROGRESS;
	}

	login_data->delayed_status_check_id = g_timeout_add_full(
				G_PRIORITY_DEFAULT,
				DELAYED_STATUS_CHECK_TIMEOUT,
				delayed_status_check, login_data,
				clean_delayed_status_check);

	return 0;
}

static void clean_delayed_status_check(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	guint id;

	DBG("");

	if (login_data->delayed_status_check_id) {
		/*
		 * g_source_remove() calls this function as well and it is
		 * required to set the id to zero before this happens to avoid
		 * double removal.
		 */
		id = login_data->delayed_status_check_id;
		login_data->delayed_status_check_id = 0;
		g_source_remove(id);
	}
}

#define RESTORE_CONNETION_TIMEOUT 500

static gboolean restore_sd_connection(gpointer user_data);
static int init_restore_sd_connection(struct systemd_login_data *login_data);
static void clean_restore_sd_connection(gpointer user_data);
static void close_io_channel(struct systemd_login_data *login_data);

static gboolean io_channel_cb(GIOChannel *source, GIOCondition condition,
			gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	int err;

	DBG("");

	if (login_data->state < SL_CONNECTED) {
		DBG("invalid state %d:%s", state2int(login_data->state),
					state2string(login_data->state));
		return -EINVAL;
	}

	if (condition && G_IO_IN) {
		err = init_delayed_status_check(login_data);
		if (err && err != -EINPROGRESS)
			DBG("failed to check session status");

		if (sd_login_monitor_flush(login_data->login_monitor) < 0)
			connman_warn("failed to flush systemd login monitor");

	} else if (condition && G_IO_ERR) {
		DBG("iochannel error, closing");

		/* Clean the id to avoid double removal before closing */
		login_data->iochannel_in_id= 0;
		close_io_channel(login_data);

		err = init_restore_sd_connection(login_data);
		if (err == -EALREADY || err == -EINPROGRESS)
			DBG("re-connection pending");

		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int init_io_channel(struct systemd_login_data *login_data)
{
	GIOChannel *io_channel_in;
	int fd;

	DBG("");

	if (!login_data || !login_data->login_monitor)
		return -ENOENT;

	if (login_data->iochannel_in_id)
		return -EALREADY;

	if (login_data->state < SL_SD_INITIALIZED) {
		DBG("invalid state %d:%s", state2int(login_data->state),
					state2string(login_data->state));
		return -EINVAL;
	}

	if (!change_state(login_data, SL_CONNECTED, false, false)) {
		DBG("invalid state change");
		return -EINVAL;
	}

	fd = sd_login_monitor_get_fd(login_data->login_monitor);
	if (fd < 0) {
		connman_error("cannot init connection to systemd logind");
		return -ECONNABORTED;
	}

	/* GIOChannel is released when the watch source is removed */
	io_channel_in = g_io_channel_unix_new(fd);
	login_data->iochannel_in_id = g_io_add_watch(io_channel_in,
				G_IO_IN | G_IO_ERR, io_channel_cb, login_data);

	/* user_change_result_cb() will set to SL_CONNECTED after completed */
	if (login_data->state != SL_WAITING_USER_CHANGE_REPLY)
		change_state(login_data, SL_CONNECTED, true, false);

	return 0;
}

static void close_io_channel(struct systemd_login_data *login_data)
{
	guint id;

	DBG("");

	/* Ignore invalid state */
	if (login_data->state < SL_CONNECTED)
		DBG("invalid state %d:%s - state change is forced",
					state2int(login_data->state),
					state2string(login_data->state));

	if (login_data->iochannel_in_id) {
		id = login_data->iochannel_in_id;
		login_data->iochannel_in_id = 0;
		g_source_remove(id);
	}

	change_state(login_data, SL_SD_INITIALIZED, true, true);
}

static int init_sd_login_monitor(struct systemd_login_data *login_data)
{
	int err;

	DBG("");

	if (!login_data)
		return -ENOENT;

	if (login_data->login_monitor)
		return -EALREADY;

	if (login_data->state > SL_SD_INITIALIZED) {
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));
		return -EINVAL;
	}

	if (!change_state(login_data, SL_SD_INITIALIZED, false, false)) {
		DBG("invalid state change");
		return -EINVAL;
	}

	err = sd_login_monitor_new("session", &login_data->login_monitor);
	if (err < 0) {
		connman_error("failed to init systemd login monitor %d:%s)",
					err, strerror(-err));
		login_data->login_monitor = NULL;
		err = -ECONNABORTED;
	}

	change_state(login_data, SL_SD_INITIALIZED, true, false);

	return err;
}

static void close_sd_login_monitor(struct systemd_login_data *login_data)
{
	DBG("");

	if (!login_data || !login_data->login_monitor)
		return;

	/* When closing ignore the state and go to idle */
	if (login_data->state > SL_SD_INITIALIZED)
		DBG("invalid state %d:%s - state change is forced",
					state2int(login_data->state),
					state2string(login_data->state));

	/* sd_login_monitor_unref returns NULL according to C API. */
	login_data->login_monitor =
			sd_login_monitor_unref(login_data->login_monitor);

	change_state(login_data, SL_IDLE, true, true);
}

static gboolean restore_sd_connection(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	int err;

	DBG("");

	if (login_data->state < SL_SD_INITIALIZED) {
		DBG("invalid state %d:%s", state2int(login_data->state),
					state2string(login_data->state));
		return G_SOURCE_CONTINUE;
	}

	if (login_data->login_monitor)
		close_sd_login_monitor(login_data);

	err = init_sd_login_monitor(login_data);
	switch (err) {
	case 0:
		break;
	case -ENOENT:
		connman_error("failed to initialize sd login monitor, "
					"missing data, stop retry");
		break;
	case -EINVAL:
		/*
		 * State machine in invalid state, force state change and
		 * initialize systemd login monitor at next call.
		 */
		change_state(login_data, SL_IDLE, true, true);
	default:
		DBG("failed to initialize sd login monitor, retry");
		return G_SOURCE_CONTINUE; /* Try again later */
	}

	err = init_io_channel(login_data);
	switch (err) {
	case 0:
		break;
	case -ENOENT:
		connman_error("failed to initialize sd login monitor io "
					"channel (missing data) stop retry");
		break;
	case -EINVAL:
		/*
		 * State machine in invalid state, force state change and
		 * initialize systemd login monitor at next call.
		 */
		change_state(login_data, SL_SD_INITIALIZED, true, true);
	default:
		DBG("failed to init io channel, retry");
		close_io_channel(login_data);
		return G_SOURCE_CONTINUE; /* Try again later */
	}

	login_data->restore_sd_connection_id = 0;
	return G_SOURCE_REMOVE;
}

static int init_restore_sd_connection(struct systemd_login_data *login_data)
{
	DBG("");

	if (!login_data)
		return -EINVAL;

	if (login_data->restore_sd_connection_id) {
		DBG("restore_sd_connection_id exists");
		return -EALREADY;
	}

	login_data->restore_sd_connection_id = g_timeout_add_full(
				G_PRIORITY_DEFAULT, RESTORE_CONNETION_TIMEOUT,
				restore_sd_connection, login_data,
				clean_restore_sd_connection);

	return -EINPROGRESS;
}

static void clean_restore_sd_connection(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	gint id;

	if (login_data->restore_sd_connection_id) {
		id = login_data->restore_sd_connection_id;
		login_data->restore_sd_connection_id = 0;
		g_source_remove(id);
	}
}

static void uid_changed(uid_t uid)
{
	if (!login_data)
		return;

	DBG("uid change from %u to %u", login_data->active_uid, uid);

	login_data->active_uid = uid;
}

static struct connman_notifier systemd_login_notifier = {
	.name			= "systemd_login",
	.priority		= CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.storage_uid_changed	= uid_changed
};

int __systemd_login_init()
{
	int err;

	DBG("");

	if (login_data)
		return -EALREADY;

	login_data = g_new0(struct systemd_login_data, 1);
	connman_notifier_register(&systemd_login_notifier);

	err = init_sd_login_monitor(login_data);
	if (err) {
		connman_warn("failed to initialize login monitor");
		goto delayed;
	}

	/*
	 * With early, initial call do only preparing steps for user change
	 * since everything is not initialized yet. Both connmand and vpnd
	 * will return replies in this case.
	 */
	login_data->prepare_only = true;

	err = do_session_status_check(login_data);
	if (err && err != -EINPROGRESS)
		DBG("failed to get initial user login status");

	err = init_io_channel(login_data);
	if (err) {
		connman_warn("failed to initialize io channel");
		goto delayed;
	}

	return 0;

delayed:
	DBG("do delayed start");

	return init_restore_sd_connection(login_data);
}

void __systemd_login_cleanup()
{
	DBG("");

	if (!login_data)
		return;

	clean_restore_sd_connection(login_data);
	clean_delayed_status_check(login_data);

	close_io_channel(login_data);
	close_sd_login_monitor(login_data);

	connman_notifier_unregister(&systemd_login_notifier);

	g_free(login_data);
	login_data = NULL;
}

