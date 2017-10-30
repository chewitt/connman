/*
 *  Connection Manager
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <connman/storage.h>
#include <connman/wakeup_timer.h>
#include "connman.h"

#include "sailfish_signalpoll.h"

#include <gsupplicant.h>
#include <gsupplicant_bss.h>
#include <gsupplicant_error.h>
#include <gsupplicant_interface.h>
#include <gsupplicant_network.h>
#include <gsupplicant_util.h>

#include <mce_display.h>
#include <mce_tklock.h>
#include <mce_log.h>

#include <gutil_history.h>
#include <gutil_misc.h>
#include <gutil_log.h>

#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>

#define WIFI_SERVICE_PREFIX "wifi_"
#define NETWORK_BGSCAN "simple:30:-65:300"
#define WIFI_BSSID_LEN 6
#define MAX_HANDSHAKE_RETRIES 5

#define WIFI_SCAN_START_TIMEOUT_MS (1000)
#define WIFI_BSS_REMOVE_TIMEOUT_MS (1000)
#define WIFI_AUTOSCAN_MIN_SEC (5)
#define WIFI_AUTOSCAN_MAX_SEC (300)
#define WIFI_AUTOSCAN_MULTIPLIER (2)
#define WIFI_HIDDEN_CONNECT_TIMEOUT_SEC (300)
#define WIFI_HIDDEN_CONNECT_SCAN_SEC (2)
#define WIFI_WPS_CONNECT_TIMEOUT_SEC (30)
#define WIFI_DISCONNECT_TIMEOUT_MS (5000)

#define WIFI_BSS_SIGNAL_HISTORY_SIZE (20)
#define WIFI_BSS_SIGNAL_HISTORY_SEC (10)

/* Access point (tethering) configuration */
#define WIFI_AP_FREQUENCY (2412)
#define WIFI_AP_SECURITY  GSUPPLICANT_SECURITY_PSK
#define WIFI_AP_PROTOCOL  GSUPPLICANT_PROTOCOL_RSN
#define WIFI_AP_CIPHER    GSUPPLICANT_CIPHER_CCMP

/* These are hardcoded all over connman, must not be changed */
#define NETWORK_KEY_WIFI_SSID                   "WiFi.SSID"
#define NETWORK_KEY_WIFI_SECURITY               "WiFi.Security"
#define NETWORK_KEY_WIFI_WPS                    "WiFi.WPS"
#define NETWORK_KEY_WIFI_USE_WPS                "WiFi.UseWPS"
#define NETWORK_KEY_WIFI_PIN_WPS                "WiFi.PinWPS"
#define NETWORK_KEY_WIFI_MODE                   "WiFi.Mode"
#define NETWORK_KEY_WIFI_EAP                    "WiFi.EAP"
#define NETWORK_KEY_WIFI_IDENTITY               "WiFi.Identity"
#define NETWORK_KEY_WIFI_AGENT_IDENTITY         "WiFi.AgentIdentity"
#define NETWORK_KEY_WIFI_PASSPHRASE             "WiFi.Passphrase"
#define NETWORK_KEY_WIFI_ANONYMOUS_IDENTITY     "WiFi.AnonymousIdentity"
#define NETWORK_KEY_WIFI_CA_CERT_FILE           "WiFi.CACertFile"
#define NETWORK_KEY_WIFI_SUBJECT_MATCH          "WiFi.SubjectMatch"
#define NETWORK_KEY_WIFI_ALT_SUBJECT_MATCH      "WiFi.AltSubjectMatch"
#define NETWORK_KEY_WIFI_DOMAIN_SUFFIX_MATCH    "WiFi.DomainSuffixMatch"
#define NETWORK_KEY_WIFI_DOMAIN_MATCH           "WiFi.DomainMatch"
#define NETWORK_KEY_WIFI_CLIENT_CERT_FILE       "WiFi.ClientCertFile"
#define NETWORK_KEY_WIFI_PRIVATE_KEY_FILE       "WiFi.PrivateKeyFile"
#define NETWORK_KEY_WIFI_PRIVATE_KEY_PASSPHRASE "WiFi.PrivateKeyPassphrase"
#define NETWORK_KEY_WIFI_PHASE2                 "WiFi.Phase2"

#define NETWORK_EAP_DEFAULT                     "default"

enum supplicant_events {
	SUPPLICANT_EVENT_VALID,
	SUPPLICANT_EVENT_COUNT
};

enum device_interface_events {
	DEVICE_INTERFACE_EVENT_VALID,
	DEVICE_INTERFACE_EVENT_PRESENT,
	DEVICE_INTERFACE_EVENT_COUNTRY,
	DEVICE_INTERFACE_EVENT_SCANNING,
	DEVICE_INTERFACE_EVENT_BSSS,
	DEVICE_INTERFACE_EVENT_COUNT
};

enum network_interface_events {
	NETWORK_INTERFACE_EVENT_VALID,
	NETWORK_INTERFACE_EVENT_PRESENT,
	NETWORK_INTERFACE_EVENT_STATE,
	NETWORK_INTERFACE_EVENT_BSS,
	NETWORK_INTERFACE_EVENT_COUNT
};

enum bss_events {
	BSS_EVENT_VALID,
	BSS_EVENT_PRESENT,
	BSS_EVENT_WPS_CAPS,
	BSS_EVENT_WPA,
	BSS_EVENT_RSN,
	BSS_EVENT_SSID,
	BSS_EVENT_FREQUENCY,
	BSS_EVENT_SIGNAL,
	BSS_EVENT_COUNT
};

enum display_events {
	DISPLAY_EVENT_VALID,
	DISPLAY_EVENT_STATE,
	DISPLAY_EVENT_COUNT
};

enum tklock_events {
	TKLOCK_EVENT_VALID,
	TKLOCK_EVENT_MODE,
	TKLOCK_EVENT_COUNT
};

struct wifi_create_interface_params {
	GSupplicantCreateInterfaceParams params;
	char *ifname;
};

struct wifi_device_bss_data {
	struct wifi_device *dev;
	struct wifi_bss *bss;
};

struct wifi_bss {
	GSupplicantBSS *bss;
	GBytes *ssid;
	gulong event_id[BSS_EVENT_COUNT];
	guint remove_timeout_id;
	GUtilIntHistory *history;       /* Signal strength history */
	guint strength;                 /* Median strength */
};

typedef enum wifi_network_state {
	WIFI_NETWORK_IDLE,
	WIFI_NETWORK_PREPARING_TO_CONNECT,
	WIFI_NETWORK_CONNECTING,
	WIFI_NETWORK_WAITING_FOR_COMPLETE,
	WIFI_NETWORK_CONNECTED,
	WIFI_NETWORK_DISCONNECTING
} WIFI_NETWORK_STATE;

struct wifi_network {
	struct wifi_device *dev;
	struct connman_network *network;
	struct signalpoll *signalpoll;
	gulong signalpoll_average_id;
	guint disconnect_timer_id;
	char *ident;
	GSupplicantInterface *iface;    /* Interface we are connected to */
	GSupplicantBSS *connecting_to;  /* BSS we are connecting to */
	GSupplicantBSS *current_bss;    /* BSS we are connected to */
	gulong iface_event_id[NETWORK_INTERFACE_EVENT_COUNT];
	GSUPPLICANT_INTERFACE_STATE interface_states[3];
	GList *bss_list;                /* Contains wifi_bss */
	int remove_in_process;          /* See wifi_device_remove_network */
	GCancellable *pending;          /* Pending call */
	WIFI_NETWORK_STATE state;
	int handshake_retries;
	char *last_passphrase;
};

struct wifi_hidden_connect {
	enum connman_service_security security;
	GBytes *ssid;
	char *identity;
	char *passphrase;
	void *user_data;
	guint scan_id;
	guint timeout_id;
};

typedef enum wifi_device_state {
	WIFI_DEVICE_OFF,
	WIFI_DEVICE_ON,
	WIFI_DEVICE_TETHERING_ON,
	WIFI_DEVICE_TURNING_ON,
	WIFI_DEVICE_TURNING_TETHERING_ON,
	WIFI_DEVICE_TURNING_OFF,
	WIFI_DEVICE_UNDEFINED
} WIFI_DEVICE_STATE;

struct wifi_device_tp {
	GSupplicantNetworkParams np;
	char *ifname;
	char *passphrase;
};

struct wifi_device {
	GSupplicant *supplicant;
	GSupplicantInterface *iface;
	gulong iface_event_id[DEVICE_INTERFACE_EVENT_COUNT];
	struct connman_device *device;
	struct wifi_hidden_connect *hidden_connect;
	struct wifi_network *selected;      /* Selected network */
	struct wifi_network *connect_next;  /* Next network to connect */
	GList *networks;                    /* List of wifi_network */
	GHashTable *bss_pending;            /* BSS path -> wifi_bss */
	GHashTable *bssid_map;              /* BSSID -> GSList(wifi_bss) */
	GHashTable *bss_net;                /* BSS path -> wifi_network */
	GHashTable *ident_net;              /* Ident -> wifi_network */
	int ifi;                            /* Interface index */
	unsigned int iff;                   /* Interface flags */
	WIFI_DEVICE_STATE state;            /* Device state */
	struct wifi_device_tp *tp;          /* Tethering parameters */
	GCancellable *pending;              /* Cancels the transition */
	gboolean screen_active;
	MceDisplay *mce_display;
	MceTklock *mce_tklock;
	gulong mce_display_event_id[DISPLAY_EVENT_COUNT];
	gulong mce_tklock_event_id[TKLOCK_EVENT_COUNT];
	guint connect_next_id;
	guint scan_start_timeout_id;
	guint autoscan_interval_sec;
	guint autoscan_start_timer_id;
	guint autoscan_holdoff_timer_id;
	gboolean autoscan_requested;
	GSList *active_scans;
	unsigned int watch;
	struct connman_technology *tethering;
	gboolean bridged;
	char *bridge;
};

struct wifi_plugin {
	GSupplicant *supplicant;
	gulong supplicant_event_id[SUPPLICANT_EVENT_COUNT];
	struct connman_technology *tech;
	gboolean running;
	GSList *devices;
};

#define NDBG(n,fmt,args...) DBG("%p %s " fmt, (n)->network, (n)->ident, ##args)

static void wifi_device_scan_check(struct wifi_device *dev);
static void wifi_device_active_scan_add(struct wifi_device *dev, GBytes *ssid);
static void wifi_device_connect_next_schedule(struct wifi_device *dev);

/*==========================================================================*
 * Logging
 *==========================================================================*/

static void wifi_log_notify(GLogModule *log, struct connman_debug_desc *desc)
{
	if (desc->flags & CONNMAN_DEBUG_FLAG_PRINT) {
		log->level = log->max_level;
	} else {
		log->level = gutil_log_default.level;
	}
	DBG("%s log level %d", log->name, log->level);
}

static void wifi_gsupplicant_log_notify(struct connman_debug_desc *desc)
{
	static struct connman_debug_desc debug_desc CONNMAN_DEBUG_ATTR = {
		.name = "gsupplicant",
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_DEFAULT,
		.notify = wifi_gsupplicant_log_notify
	};

	wifi_log_notify(&gsupplicant_log, &debug_desc);
}

static void wifi_mce_debug_notify(struct connman_debug_desc *desc)
{
	static struct connman_debug_desc debug_desc CONNMAN_DEBUG_ATTR = {
		.name  = "mce",
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_DEFAULT,
		.notify = wifi_mce_debug_notify
	};

	wifi_log_notify(&mce_log, &debug_desc);
}

/*==========================================================================*
 * Utilities
 *==========================================================================*/

static enum connman_service_security wifi_security(const char *security)
{
	if (security) {
		if (!g_ascii_strcasecmp(security, "none")) {
			return CONNMAN_SERVICE_SECURITY_NONE;
		} else if (!g_ascii_strcasecmp(security, "wep")) {
			return CONNMAN_SERVICE_SECURITY_WEP;
		} else if (!g_ascii_strcasecmp(security, "psk") ||
			   !g_ascii_strcasecmp(security, "wpa") ||
			   !g_ascii_strcasecmp(security, "rsn")) {
			return CONNMAN_SERVICE_SECURITY_PSK;
		} else if (!g_ascii_strcasecmp(security, "ieee8021x")) {
			return CONNMAN_SERVICE_SECURITY_8021X;
		}
	}
	return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static enum connman_service_security wifi_bss_security(GSupplicantBSS *bss)
{
	switch (gsupplicant_bss_security(bss)) {
	case GSUPPLICANT_SECURITY_NONE:
		return CONNMAN_SERVICE_SECURITY_NONE;
	case GSUPPLICANT_SECURITY_WEP:
		return CONNMAN_SERVICE_SECURITY_WEP;
	case GSUPPLICANT_SECURITY_PSK:
		return CONNMAN_SERVICE_SECURITY_PSK;
	case GSUPPLICANT_SECURITY_EAP:
		return CONNMAN_SERVICE_SECURITY_8021X;
	}
	return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static const char *wifi_bss_enc_mode(GSupplicantBSS *bss)
{
	GSUPPLICANT_CIPHER pairwise;

	switch (wifi_bss_security(bss)) {
	case CONNMAN_SERVICE_SECURITY_PSK:
	case CONNMAN_SERVICE_SECURITY_8021X:
		pairwise = gsupplicant_bss_pairwise(bss);
		if ((pairwise & GSUPPLICANT_CIPHER_CCMP) &&
		    (pairwise & GSUPPLICANT_CIPHER_TKIP)) {
			return "mixed";
		} else if (pairwise & GSUPPLICANT_CIPHER_CCMP) {
			return "aes";
		} else if (pairwise & GSUPPLICANT_CIPHER_TKIP) {
			return "tkip";
		}
	default:
		return NULL;
	case CONNMAN_SERVICE_SECURITY_WEP:
		return "wep";
	case CONNMAN_SERVICE_SECURITY_NONE:
		return "none";
	}
}

static GString *wifi_bss_ident_append_suffix(GString *str, GSupplicantBSS *bss)
{
	const char *security =
		__connman_service_security2string(wifi_bss_security(bss));

	switch (bss->mode) {
	case GSUPPLICANT_BSS_MODE_INFRA:
		g_string_append(str, "_managed");
		break;
	case GSUPPLICANT_BSS_MODE_AD_HOC:
		g_string_append(str, "_adhoc");
		break;
	default:
		break;
	}

	if (security) {
		g_string_append_printf(str, "_%s", security);
	}

	return str;
}

static char *wifi_bss_ident(struct wifi_bss *bss_data)
{
	GString *str;
	gsize id_len = 0;
	GSupplicantBSS *bss = bss_data->bss;
	const guint8 *id_data = NULL;

	GASSERT(bss->valid && bss->present);
	if (bss_data->ssid && g_bytes_get_size(bss_data->ssid) > 0) {
		id_data = g_bytes_get_data(bss_data->ssid, &id_len);
	} else if (bss->bssid) {
		id_data = g_bytes_get_data(bss->bssid, &id_len);
	}

	str = g_string_sized_new(id_len*2 + 24);
	if (id_len > 0) {
		guint i;
		for (i = 0; i < id_len; i++) {
			g_string_append_printf(str, "%02x", id_data[i]);
		}
	} else {
		g_string_append_printf(str, "hidden");
	}

	return g_string_free(wifi_bss_ident_append_suffix(str, bss), FALSE);
}

static guint wifi_rssi_strength(int rssi)
{
	int strength = 120 + rssi;

	if (strength > 100) {
		strength = 100;
	} else if (strength < 0) {
		strength = 0;
	}

	return (guint8)strength;
}

static void wifi_bytes_unref(gpointer data)
{
	if (data) {
		g_bytes_unref(data);
	}
}

static gboolean wifi_bytes_equal(GBytes *b1, GBytes *b2)
{
	if (b1 == b2) {
		return TRUE;
	} else if (!b1) {
		return !g_bytes_get_size(b2);
	} else if (!b2) {
		return !g_bytes_get_size(b1);
	} else {
		return g_bytes_equal(b1, b2);
	}
}

/*==========================================================================*
 * Hidden connect
 *==========================================================================*/

static void wifi_hidden_connect_free(struct wifi_hidden_connect *connect);

static gboolean wifi_hidden_connect_timeout(gpointer data)
{
	struct wifi_device *dev = data;

	DBG("");
	GASSERT(dev->hidden_connect);
	if (dev->hidden_connect) {
		dev->hidden_connect->timeout_id = 0;
		wifi_hidden_connect_free(dev->hidden_connect);
		dev->hidden_connect = NULL;
	}
	return G_SOURCE_REMOVE;
}

static gboolean wifi_hidden_connect_scan(gpointer data)
{
	struct wifi_device *dev = data;

	DBG("");
	GASSERT(dev->hidden_connect);
	if (dev->hidden_connect) {
		wifi_device_active_scan_add(dev, dev->hidden_connect->ssid);
		wifi_device_scan_check(dev);
	}
	return G_SOURCE_CONTINUE;
}

static struct wifi_hidden_connect *wifi_hidden_connect_new(GBytes *ssid,
			const char *identity, const char *passphrase,
			const char *security, void *user_data,
			struct wifi_device *dev)
{
	struct wifi_hidden_connect *connect =
		g_slice_new0(struct wifi_hidden_connect);

	connect->ssid = g_bytes_ref(ssid);
	connect->user_data = user_data;
	connect->identity = g_strdup(identity);
	connect->passphrase = g_strdup(passphrase);
	connect->security = wifi_security(security);
	connect->timeout_id = connman_wakeup_timer_add_seconds(
				WIFI_HIDDEN_CONNECT_TIMEOUT_SEC,
				wifi_hidden_connect_timeout, dev);
	connect->scan_id = connman_wakeup_timer_add_seconds(
				WIFI_HIDDEN_CONNECT_SCAN_SEC,
				wifi_hidden_connect_scan, dev);
	wifi_device_active_scan_add(dev, ssid);
	wifi_device_scan_check(dev);
	return connect;
}

static void wifi_hidden_connect_free(struct wifi_hidden_connect *connect)
{
	if (connect) {
		if (connect->timeout_id) {
			g_source_remove(connect->timeout_id);
		}
		if (connect->scan_id) {
			g_source_remove(connect->scan_id);
		}
		if (connect->user_data) {
			connman_network_clear_hidden(connect->user_data);
		}
		g_bytes_unref(connect->ssid);
		g_free(connect->identity);
		g_free(connect->passphrase);
		g_slice_free(struct wifi_hidden_connect, connect);
	}
}

/*==========================================================================*
 * BSS
 *==========================================================================*/

static void wifi_bss_free(struct wifi_bss *bss_data, struct wifi_device *dev)
{
	if (dev && bss_data->bss && bss_data->bss->bssid) {
		GBytes *bssid = bss_data->bss->bssid;
		GSList *bssid_list = g_slist_remove(g_hash_table_lookup(
					dev->bssid_map, bssid), bss_data);

		if (bssid_list) {
			GASSERT(!g_slist_find(bssid_list, bss_data));
			g_hash_table_replace(dev->bssid_map,
					g_bytes_ref(bssid), bssid_list);
		} else {
			g_hash_table_remove(dev->bssid_map, bssid);
		}
	}

	if (bss_data->remove_timeout_id) {
		g_source_remove(bss_data->remove_timeout_id);
	}
	gsupplicant_bss_remove_handlers(bss_data->bss, bss_data->event_id,
					G_N_ELEMENTS(bss_data->event_id));
	gsupplicant_bss_unref(bss_data->bss);
	if (bss_data->ssid) {
		g_bytes_unref(bss_data->ssid);
	}
	gutil_int_history_unref(bss_data->history);
	g_slice_free(struct wifi_bss, bss_data);
}

static void wifi_bss_free_value(gpointer key, gpointer value, gpointer data)
{
	wifi_bss_free(value, NULL);
}

static void wifi_slist_free_value(gpointer key, gpointer value, gpointer data)
{
	g_slist_free(value);
}

/*==========================================================================*
 * Network
 *==========================================================================*/

static int wifi_network_disconnect(struct wifi_network *net);

static void wifi_network_disconnect_timeout_cancel(struct wifi_network *net)
{
	if (net->disconnect_timer_id) {
		g_source_remove(net->disconnect_timer_id);
		net->disconnect_timer_id = 0;
	}
}

static void wifi_network_drop_interface(struct wifi_network *net)
{
	if (net->iface) {
		gsupplicant_interface_remove_handlers(net->iface,
				net->iface_event_id,
				G_N_ELEMENTS(net->iface_event_id));
		gsupplicant_interface_unref(net->iface);
		net->iface = NULL;
	}
	wifi_network_disconnect_timeout_cancel(net);
}

static void wifi_network_signalpoll(struct signalpoll *poll, void *data)
{
	struct wifi_network *net = data;

	connman_network_set_strength(net->network, poll->average);
}

static inline gboolean wifi_network_state_connecting(WIFI_NETWORK_STATE state)
{
	switch (state) {
	case WIFI_NETWORK_PREPARING_TO_CONNECT:
	case WIFI_NETWORK_CONNECTING:
	case WIFI_NETWORK_WAITING_FOR_COMPLETE:
		return TRUE;
	case WIFI_NETWORK_IDLE:
	case WIFI_NETWORK_CONNECTED:
	case WIFI_NETWORK_DISCONNECTING:
		break;
	}
	return FALSE;
}

static const char *wifi_network_state_name(WIFI_NETWORK_STATE state)
{
	switch (state) {
	case WIFI_NETWORK_IDLE:                 return "Idle";
	case WIFI_NETWORK_PREPARING_TO_CONNECT: return "PreparingToConnect";
	case WIFI_NETWORK_CONNECTING:           return "Connecting";
	case WIFI_NETWORK_WAITING_FOR_COMPLETE: return "WaitingForComplete";
	case WIFI_NETWORK_CONNECTED:            return "Connected";
	case WIFI_NETWORK_DISCONNECTING:        return "Disconnecting";
	}
	return "UNKNOWN";
}

static gboolean wifi_network_connecting(struct wifi_network *net)
{
	return wifi_network_state_connecting(net->state);
}

static void wifi_network_set_state(struct wifi_network *net,
						WIFI_NETWORK_STATE state)
{
	if (net->state != state) {
		struct wifi_device *dev = net->dev;

		NDBG(net, "%s -> %s", wifi_network_state_name(net->state),
					wifi_network_state_name(state));
		net->state = state;
		wifi_device_scan_check(dev);
		if (wifi_network_state_connecting(state)) {
			/*
			 * Cancel the disconnect timeout when entering
			 * the connecting state.
			 */
			wifi_network_disconnect_timeout_cancel(net);
		} else {
			/* Not connecting anymore */
			if (net->connecting_to) {
				gsupplicant_bss_unref(net->connecting_to);
				net->connecting_to = NULL;
			}
		}
		if (state == WIFI_NETWORK_IDLE ||
				state == WIFI_NETWORK_CONNECTED) {
			/* Nothing should be pending on one of these states */
			if (net->pending) {
				g_cancellable_cancel(net->pending);
				net->pending = NULL;
			}
		}

		/* Poll signal strength when connected */
		if (state == WIFI_NETWORK_CONNECTED) {
			if (!net->signalpoll) {
				net->signalpoll = signalpoll_new(net->iface,
							wifi_rssi_strength);
				net->signalpoll_average_id =
					signalpoll_add_average_changed_handler(
						net->signalpoll,
						wifi_network_signalpoll, net);
			}
		} else {
			if (net->signalpoll) {
				signalpoll_remove_handler(net->signalpoll,
						net->signalpoll_average_id);
				signalpoll_unref(net->signalpoll);
				net->signalpoll = NULL;
			}
		}

		switch (state) {
		case WIFI_NETWORK_IDLE:
			/*
			 * Only one network should have its interface index
			 * set. Otherwise the (inactive) network disappearing
			 * from the list may cancel the connectivity check
			 * for the selected network.
			 */
			connman_network_set_index(net->network, -1);
			/* No need for interface events in the idle state */
			gsupplicant_interface_remove_all_networks(net->iface,
								NULL, NULL);
			wifi_network_drop_interface(net);
			if (dev->selected == net) {
				dev->selected = NULL;
				wifi_device_connect_next_schedule(dev);
			}
			connman_network_set_associating(net->network, FALSE);
			connman_network_set_connected(net->network, FALSE);
			break;
		case WIFI_NETWORK_CONNECTED:
			/*
			 * Reset the handshake retry count so that the next
			 * time we get disconnected and fail to connect, we
			 * start counting failures from zero and don't bail
			 * out too early.
			 */
			net->handshake_retries = 0;
			connman_network_set_associating(net->network, FALSE);
			connman_network_set_connected(net->network, TRUE);
			break;
		case WIFI_NETWORK_PREPARING_TO_CONNECT:
		case WIFI_NETWORK_CONNECTING:
		case WIFI_NETWORK_WAITING_FOR_COMPLETE:
			break;
		case WIFI_NETWORK_DISCONNECTING:
			connman_network_set_connected(net->network, FALSE);
			break;
		}
	}
}

static gboolean wifi_network_disconnect_timeout(void *data)
{
	struct wifi_network *net = data;

	NDBG(net, "");
	net->disconnect_timer_id = 0;
	wifi_network_disconnect(net);
	return G_SOURCE_REMOVE;
}

static void wifi_network_interface_scanning(struct wifi_network *net)
{
	/* Ignore the Scanning state when we are connecting */
	if (!wifi_network_connecting(net)) {
		/*
		 * The interface can enter the Scanning state soon after
		 * WPS connection has been established.
		 */
		if (net->interface_states[1] ==
				GSUPPLICANT_INTERFACE_STATE_ASSOCIATED) {
			NDBG(net, "ignored (associated,scanning)");
		} else if (net->interface_states[1] ==
				GSUPPLICANT_INTERFACE_STATE_DISCONNECTED &&
				net->interface_states[2] ==
				GSUPPLICANT_INTERFACE_STATE_ASSOCIATED) {
			NDBG(net, "ignored (associated,disconnected,scanning)");
		} else if (!net->disconnect_timer_id) {
			/*
			 * Don't reset the disconnect timeout if it's already
			 * running but start it if it's not running yet.
			 */
			net->disconnect_timer_id =
				connman_wakeup_timer_add(
					WIFI_DISCONNECT_TIMEOUT_MS,
					wifi_network_disconnect_timeout, net);
		}
	}
}

static void wifi_network_interface_disconnected(struct wifi_network *net)
{
	/*
	 * Depending on the security, authentication failures may look
	 * like this:
	 *
	 * PSK: associating -> [associated ->] 4way_handshake -> disconnected
	 * EAP: associating ->  associated -> disconnected
	 */
	const GSUPPLICANT_INTERFACE_STATE prev = net->interface_states[1];
	if ((prev == GSUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE ||
			prev == GSUPPLICANT_INTERFACE_STATE_ASSOCIATED) &&
			gsupplicant_bss_security(net->connecting_to) !=
						GSUPPLICANT_SECURITY_NONE) {
		struct connman_service *service =
			connman_service_lookup_from_network(net->network);
		const gboolean user_connect = service &&
			__connman_service_get_connect_reason(service) ==
					CONNMAN_SERVICE_CONNECT_REASON_USER;

		/*
		 * Note that we can't really tell whether we have
		 * lost the signal or credentials didn't match. If
		 * we are connecting automatically (i.e. silently)
		 * we need to try several times before we can assume
		 * that credentials are wrong.
		 */
		NDBG(net, "%s connect", user_connect ? "user" : "auto");
		if (!user_connect) {
			net->handshake_retries++;
			NDBG(net, "handshake retry %d", net->handshake_retries);
		}

		if (user_connect ||
			net->handshake_retries >= MAX_HANDSHAKE_RETRIES) {

			/*
			 * For interactive connects, this will (hopefully)
			 * make connman query WiFi password again. For
			 * automatic connects this disables subsequent
			 * connect attempts (if we have exceeded the
			 * maximum number of retries).
			 */
			connman_network_set_error(net->network,
					CONNMAN_NETWORK_ERROR_INVALID_KEY);
			return;
		}
	} else {
		net->handshake_retries = 0;
	}

	/*
	 * We will mark network as disconnected if it stays
	 * longer than WIFI_DISCONNECT_TIMEOUT_MS milliseconds
	 * in one of the disconnected states.
	 */
	wifi_network_disconnect_timeout_cancel(net);
	net->disconnect_timer_id =
		connman_wakeup_timer_add(WIFI_DISCONNECT_TIMEOUT_MS,
				wifi_network_disconnect_timeout, net);
}

static void wifi_network_interface_completed(struct wifi_network *net)
{
	wifi_network_disconnect_timeout_cancel(net);
	if (net->state == WIFI_NETWORK_WAITING_FOR_COMPLETE) {
		wifi_network_set_state(net, WIFI_NETWORK_CONNECTED);
	}
}

static void wifi_network_handle_interface_state(struct wifi_network *net)
{
	/*
	 * net->interface_states[0] is the current state
	 * net->interface_states[1..2] are the previous state
	 */
	switch (net->interface_states[0]) {
	case GSUPPLICANT_INTERFACE_STATE_SCANNING:
		wifi_network_interface_scanning(net);
		break;

	case GSUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		wifi_network_interface_disconnected(net);
		break;

	case GSUPPLICANT_INTERFACE_STATE_COMPLETED:
		wifi_network_interface_completed(net);
		break;

	case GSUPPLICANT_INTERFACE_STATE_AUTHENTICATING:
	case GSUPPLICANT_INTERFACE_STATE_ASSOCIATING:
	case GSUPPLICANT_INTERFACE_STATE_ASSOCIATED:
	case GSUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE:
	case GSUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE:
		wifi_network_disconnect_timeout_cancel(net);
		break;

	case GSUPPLICANT_INTERFACE_STATE_INACTIVE:
	case GSUPPLICANT_INTERFACE_STATE_UNKNOWN:
		break;
	}
}

static void wifi_network_update_interface_state(struct wifi_network *net)
{
	GSupplicantInterface *iface = net->iface;
	GSUPPLICANT_INTERFACE_STATE state = (iface->present && iface->valid) ?
		iface->state : GSUPPLICANT_INTERFACE_STATE_UNKNOWN;

	if (state != net->interface_states[0]) {
		guint i;

		for (i = G_N_ELEMENTS(net->interface_states)-1; i > 0; i--) {
			net->interface_states[i] = net->interface_states[i-1];
		}
		net->interface_states[0] = state;
		NDBG(net, "%s", gsupplicant_interface_state_name(state));
		wifi_network_handle_interface_state(net);
	}
}

static void wifi_network_reset_interface_states(struct wifi_network *net)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS(net->interface_states); i++) {
		net->interface_states[i] = GSUPPLICANT_INTERFACE_STATE_UNKNOWN;
	}
}

static void wifi_network_interface_changed(GSupplicantInterface *iface,
								void *data)
{
	struct wifi_network *net = data;

	GASSERT(net->iface == iface);
	wifi_network_update_interface_state(net);
}

static GSupplicantBSS *wifi_network_current_bss(struct wifi_network *net)
{
	if (net->connecting_to && net->connecting_to->valid) {
		return net->connecting_to;
	} else if (net->current_bss && net->current_bss->valid) {
		return net->current_bss;
	} else {
		struct wifi_bss *best = net->bss_list->data;

		return best->bss;
	}
}

static void wifi_network_update_bssid(struct wifi_network *net)
{
	GBytes *bssid = wifi_network_current_bss(net)->bssid;
	gsize bssid_len;
	const void *bssid_data = g_bytes_get_data(bssid, &bssid_len);

	if (bssid_len == WIFI_BSSID_LEN) {
		connman_network_set_bssid(net->network, bssid_data);
	}
}

static void wifi_network_update_frequency(struct wifi_network *net)
{
	connman_network_set_frequency(net->network,
				wifi_network_current_bss(net)->frequency);
}

static gboolean wifi_network_update_current_bss(struct wifi_network *net)
{
	gboolean changed = FALSE;

	if (net->iface && net->iface->current_bss) {
		const char *path = net->iface->current_bss;

		if (!net->current_bss) {
			/* There was no current BSS */
			net->current_bss = gsupplicant_bss_new(path);
			changed = TRUE;
		} else if (strcmp(net->current_bss->path, path)) {
			/* Current BSS has changed */
			gsupplicant_bss_unref(net->current_bss);
			net->current_bss = gsupplicant_bss_new(path);
			changed = TRUE;
		}
	} else if (net->current_bss) {
		/* No more current BSS */
		gsupplicant_bss_unref(net->current_bss);
		net->current_bss = NULL;
		changed = TRUE;
	}

	if (changed) {
		wifi_network_update_bssid(net);
		wifi_network_update_frequency(net);
	}

	return changed;
}

static void wifi_network_current_bss_changed(GSupplicantInterface *iface,
								void *data)
{
	struct wifi_network *net = data;

	wifi_network_update_current_bss(net);
}

static void wifi_network_update_wps_caps_from_bss(struct wifi_network *net,
						GSupplicantBSS *bss)
{
	const GSUPPLICANT_WPS_CAPS wps = bss ? bss->wps_caps :
						GSUPPLICANT_WPS_NONE;

	connman_network_set_bool(net->network, NETWORK_KEY_WIFI_WPS,
				(wps & GSUPPLICANT_WPS_CONFIGURED) != 0);
	connman_network_set_bool(net->network, NETWORK_KEY_WIFI_USE_WPS,
				(wps & GSUPPLICANT_WPS_CONFIGURED) &&
				(wps & (GSUPPLICANT_WPS_PUSH_BUTTON |
					GSUPPLICANT_WPS_PIN)) &&
				(wps & GSUPPLICANT_WPS_REGISTRAR));
}

static void wifi_network_update_wps_caps(struct wifi_network *net)
{
	wifi_network_update_wps_caps_from_bss(net,
					wifi_network_current_bss(net));
}

static void wifi_network_save_network_param(struct wifi_network *net,
							const char *param)
{
	struct connman_service *service =
		connman_service_lookup_from_network(net->network);

	if (__connman_service_update_value_from_network(service, net->network,
								param)) {
		__connman_service_save(service);
	}
}

static void wifi_network_init_connect_params(struct wifi_network *net,
		struct wifi_bss *bss_data, GSupplicantNetworkParams *params)
{
	const char *eap;

	memset(params, 0, sizeof(*params));
	params->ssid = bss_data->ssid;
	params->scan_ssid = 1;
	params->bgscan = NETWORK_BGSCAN;
	params->mode = GSUPPLICANT_OP_MODE_INFRA;
	params->security = gsupplicant_bss_security(bss_data->bss);

	eap = connman_network_get_string(net->network, NETWORK_KEY_WIFI_EAP);
	if (eap) {
		if (!g_ascii_strcasecmp(eap, "tls")) {
			params->eap = GSUPPLICANT_EAP_METHOD_TLS;
		} else if (!g_ascii_strcasecmp(eap, "ttls")) {
			params->eap = GSUPPLICANT_EAP_METHOD_TTLS;
		} else {
			params->eap = GSUPPLICANT_EAP_METHOD_PEAP;
		}
		if (params->eap != GSUPPLICANT_EAP_METHOD_TLS ||
				params->eap != GSUPPLICANT_EAP_METHOD_PEAP) {
			const char *phase2 =
				connman_network_get_string(net->network,
					NETWORK_KEY_WIFI_PHASE2);
			params->phase2 = !phase2 ?
				GSUPPLICANT_EAP_METHOD_NONE :
				!g_ascii_strcasecmp(phase2, "mschapv2") ?
				GSUPPLICANT_EAP_METHOD_MSCHAPV2 :
				!g_ascii_strcasecmp(eap, "md5") ?
				GSUPPLICANT_EAP_METHOD_MD5 :
				!g_ascii_strcasecmp(eap, "peap") ?
				GSUPPLICANT_EAP_METHOD_PEAP :
				!g_ascii_strcasecmp(eap, "tls") ?
				GSUPPLICANT_EAP_METHOD_TLS :
				!g_ascii_strcasecmp(eap, "leap") ?
				GSUPPLICANT_EAP_METHOD_LEAP :
				!g_ascii_strcasecmp(eap, "gtc") ?
				GSUPPLICANT_EAP_METHOD_GTC :
				GSUPPLICANT_EAP_METHOD_NONE;
		}
		params->identity = connman_network_get_string(net->network,
					NETWORK_KEY_WIFI_IDENTITY);
		if (params->identity) {
			NDBG(net, "identity \"%s\"", params->identity);
		} else {
			/* Use WiFi.AgentIdentity as a backup */
			params->identity =
				connman_network_get_string(net->network,
					NETWORK_KEY_WIFI_AGENT_IDENTITY);
			if (params->identity) {
				NDBG(net, "agent identity \"%s\"",
							params->identity);
				connman_network_set_string(net->network,
						NETWORK_KEY_WIFI_IDENTITY,
						params->identity);
				wifi_network_save_network_param(net,
						NETWORK_KEY_WIFI_IDENTITY);
			}
		}
		params->client_cert_file =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_CLIENT_CERT_FILE);
		params->private_key_file =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_PRIVATE_KEY_FILE);
		params->private_key_passphrase =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_PRIVATE_KEY_PASSPHRASE);
		params->ca_cert_file =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_CA_CERT_FILE);
		params->anonymous_identity =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_ANONYMOUS_IDENTITY);
		params->subject_match =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_SUBJECT_MATCH);
		params->altsubject_match =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_ALT_SUBJECT_MATCH);
		params->domain_suffix_match =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_DOMAIN_SUFFIX_MATCH);
		params->domain_match =
			connman_network_get_string(net->network,
				NETWORK_KEY_WIFI_DOMAIN_MATCH);
	}

	params->passphrase = connman_network_get_string(net->network,
					NETWORK_KEY_WIFI_PASSPHRASE);

	/* Reset the number of retries if the passphrase has changed */
	if (g_strcmp0(net->last_passphrase, params->passphrase)) {
		g_free(net->last_passphrase);
		net->last_passphrase = g_strdup(params->passphrase);
		net->handshake_retries = 0;
	}
}

static void wifi_network_connect_finished(struct wifi_network *net,
				GCancellable *cancel, const GError *error,
				enum connman_network_error network_error)
{
	GASSERT(net->state == WIFI_NETWORK_CONNECTING);
	GASSERT(net->pending == cancel);
	net->pending = NULL;

	if (error) {
		NDBG(net, "error: %s", error->message);
		connman_network_set_error(net->network, network_error);
		wifi_network_set_state(net, WIFI_NETWORK_IDLE);
	} else {
		wifi_network_set_state(net, (net->iface->state ==
			GSUPPLICANT_INTERFACE_STATE_COMPLETED) ?
				WIFI_NETWORK_CONNECTED :
				WIFI_NETWORK_WAITING_FOR_COMPLETE);
	}
}

static void wifi_network_wps_started_pbc(GSupplicantInterface *iface,
				GCancellable *cancel, const GError *error,
				const char *pin, void *data)
{
	struct wifi_network *net = data;

	if (!error && pin) {
		connman_network_set_string(net->network,
					NETWORK_KEY_WIFI_PIN_WPS, pin);
	}

	wifi_network_connect_finished(net, cancel, error,
				CONNMAN_NETWORK_ERROR_INVALID_KEY);
}

static void wifi_network_wps_started_pin(GSupplicantInterface *iface,
				GCancellable *cancel, const GError *error,
				const char *pin, void *data)
{
	wifi_network_connect_finished((struct wifi_network *)data, cancel,
				error, CONNMAN_NETWORK_ERROR_INVALID_KEY);
}

static void wifi_network_connected(GSupplicantInterface *iface,
				GCancellable *cancel, const GError *error,
				const char *path, void *data)
{
	wifi_network_connect_finished((struct wifi_network *)data, cancel,
				error, CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);
}

static GCancellable *wifi_network_connect_wps(struct wifi_network *net,
							const char *pin)
{
	GSupplicantWPSParams wps;
	GSupplicantInterfaceStringResultFunc cb;

	memset(&wps, 0, sizeof(wps));
	wps.role = GSUPPLICANT_WPS_ROLE_ENROLLEE;
	if (pin && pin[0]) {
		wps.pin = pin;
		wps.auth = GSUPPLICANT_WPS_AUTH_PIN;
		cb = wifi_network_wps_started_pin;
	} else {
		wps.auth = GSUPPLICANT_WPS_AUTH_PUSH_BUTTON;
		cb = wifi_network_wps_started_pbc;
	}
	return gsupplicant_interface_wps_connect_full(net->iface, NULL, &wps,
		WIFI_WPS_CONNECT_TIMEOUT_SEC, cb, NULL, net);
}

static int wifi_network_connect(struct wifi_network *net)
{
	if (net->state == WIFI_NETWORK_CONNECTED) {
		NDBG(net, "already connected");
		return 0;
	} else if (net->state == WIFI_NETWORK_CONNECTING ||
			net->state == WIFI_NETWORK_WAITING_FOR_COMPLETE) {
		NDBG(net, "already connecting");
		GASSERT(net->pending);
		return (-EINPROGRESS);
	} else {
		struct wifi_bss *bss_data = net->bss_list->data;
		GSupplicantBSS *bss = bss_data->bss;
		int err = (-EFAULT);

		/* Cleanup after the previous state */
		if (net->pending) {
			GASSERT(net->state == WIFI_NETWORK_DISCONNECTING);
			g_cancellable_cancel(net->pending);
			net->pending = NULL;
		}

		wifi_network_drop_interface(net);
		net->iface = gsupplicant_interface_ref(bss->iface);

		/* Start the connection sequence */
		wifi_network_update_wps_caps_from_bss(net, bss);
		if ((bss->wps_caps & GSUPPLICANT_WPS_CONFIGURED) &&
			(bss->wps_caps & GSUPPLICANT_WPS_PUSH_BUTTON) &&
			(bss->wps_caps & GSUPPLICANT_WPS_REGISTRAR)) {
			/* WPS button */
			NDBG(net, "WPS button detected");
			net->pending = wifi_network_connect_wps(net, NULL);
		} else if ((bss->wps_caps & GSUPPLICANT_WPS_CONFIGURED) &&
			(bss->wps_caps & GSUPPLICANT_WPS_PIN) &&
			(bss->wps_caps & GSUPPLICANT_WPS_REGISTRAR)) {
			/* Connect with WPS pin */
			const char *pin =
				connman_network_get_string(net->network,
					NETWORK_KEY_WIFI_PASSPHRASE);
			if (pin && pin[0]) {
				NDBG(net, "connecting with WPS pin");
				net->pending = wifi_network_connect_wps(net,
									pin);
			} else {
				NDBG(net, "no WPS pin");
				connman_network_set_error(net->network,
					CONNMAN_NETWORK_ERROR_INVALID_KEY);
				err = (-ENOKEY);
			}
		} else {
			GSupplicantNetworkParams np;
			if (net->connecting_to != bss) {
				gsupplicant_bss_unref(net->connecting_to);
				net->connecting_to = gsupplicant_bss_ref(bss);
			}
			wifi_network_init_connect_params(net, bss_data, &np);
			net->pending =
				gsupplicant_interface_add_network(net->iface,
					&np, GSUPPLICANT_ADD_NETWORK_SELECT |
					GSUPPLICANT_ADD_NETWORK_DELETE_OTHER |
					GSUPPLICANT_ADD_NETWORK_ENABLE,
					wifi_network_connected, net);
		}

		if (net->pending) {
			wifi_network_set_state(net, WIFI_NETWORK_CONNECTING);
			wifi_network_reset_interface_states(net);
			wifi_network_update_interface_state(net);
			wifi_network_update_current_bss(net);

			/*
			 * Start watching the interface state changes.
			 * While interface is being connected, they are
			 * just being recorded but not handled.
			 */
			net->iface_event_id[NETWORK_INTERFACE_EVENT_VALID] =
				gsupplicant_interface_add_handler(net->iface,
					GSUPPLICANT_INTERFACE_PROPERTY_VALID,
					wifi_network_interface_changed, net);
			net->iface_event_id[NETWORK_INTERFACE_EVENT_PRESENT] =
				gsupplicant_interface_add_handler(net->iface,
					GSUPPLICANT_INTERFACE_PROPERTY_PRESENT,
					wifi_network_interface_changed, net);
			net->iface_event_id[NETWORK_INTERFACE_EVENT_STATE] =
				gsupplicant_interface_add_handler(net->iface,
					GSUPPLICANT_INTERFACE_PROPERTY_STATE,
					wifi_network_interface_changed, net);

			/* And watch the current BSS too */
			net->iface_event_id[NETWORK_INTERFACE_EVENT_BSS] =
				gsupplicant_interface_add_handler(net->iface,
				GSUPPLICANT_INTERFACE_PROPERTY_CURRENT_BSS,
				wifi_network_current_bss_changed, net);

			return (-EINPROGRESS);
		} else {
			wifi_network_drop_interface(net);
			wifi_network_set_state(net, WIFI_NETWORK_IDLE);
			return err;
		}
	}
}

static void wifi_network_disconnected(GSupplicantInterface *iface,
		GCancellable *cancel, const GError *error, void *data)
{
	struct wifi_network *net = data;

	GASSERT(net->iface == iface);
	GASSERT(net->pending == cancel);
	GASSERT(net->state == WIFI_NETWORK_DISCONNECTING);

	/* Ignore the error */
	if (error) {
		NDBG(net, "%s", error->message);
	}

	net->pending = NULL;
	wifi_network_set_state(net, WIFI_NETWORK_IDLE);
}

static int wifi_network_disconnect(struct wifi_network *net)
{
	switch (net->state) {
	case WIFI_NETWORK_IDLE:
		return 0;
	case WIFI_NETWORK_DISCONNECTING:
		GASSERT(net->pending);
		return (-EINPROGRESS);
	default:
		if (net->pending) {
			GASSERT(net->state == WIFI_NETWORK_CONNECTING);
			g_cancellable_cancel(net->pending);
			net->pending = NULL;
		}
		if (net->iface) {
			net->pending = gsupplicant_interface_disconnect(
				net->iface, wifi_network_disconnected, net);
			if (net->pending) {
				wifi_network_set_state(net,
						WIFI_NETWORK_DISCONNECTING);
				return (-EINPROGRESS);
			} else {
				wifi_network_set_state(net, WIFI_NETWORK_IDLE);
				return (-EFAULT);
			}
		}
		wifi_network_set_state(net, WIFI_NETWORK_IDLE);
		return 0;
	}
}

static void wifi_network_bss_update_strength(gpointer data, gpointer user_data)
{
	struct wifi_bss *bss_data = data;

	bss_data->strength = gutil_int_history_size(bss_data->history) ?
		(guint)gutil_int_history_median(bss_data->history, 0) :
		wifi_rssi_strength(bss_data->bss->signal);
}

static gint wifi_network_bss_sort_func(gconstpointer a, gconstpointer b)
{
	const struct wifi_bss *d1 = a;
	const struct wifi_bss *d2 = b;
	GSupplicantBSS *b1 = d1->bss;
	GSupplicantBSS *b2 = d2->bss;

	if (b2->valid != b1->valid) {
		return (gint)b2->valid - (gint)b1->valid;
	} else if (b2->present != b1->present) {
		return (gint)b2->present - (gint)b1->present;
	} else {
		return d2->strength - d1->strength;
	}
}

static void wifi_network_update_strength(struct wifi_network *net)
{
	struct wifi_bss *best;

	/* Update the median values before sorting */
	g_list_foreach(net->bss_list, wifi_network_bss_update_strength, NULL);
	net->bss_list = g_list_sort(net->bss_list, wifi_network_bss_sort_func);
	best = net->bss_list->data;
	NDBG(net, "best bss %s", best->bss->path);
	GASSERT(best->bss->valid && best->bss->present);
	connman_network_set_strength(net->network, best->strength);
}

static struct wifi_bss *wifi_network_get_bss_data(struct wifi_network *net,
						GSupplicantBSS *bss)
{
	if (net) {
		GList *l;

		for (l = net->bss_list; l; l = l->next) {
			struct wifi_bss *data = l->data;

			if (data->bss == bss) {
				return data;
			}
		}
	}
	return NULL;
}

static void wifi_network_init(struct wifi_network *net, struct wifi_bss *data)
{
	GSupplicantBSS *bss = data->bss;
	const char *enc_mode = wifi_bss_enc_mode(bss);
	const char *network_name = NULL;
	char *tmp = NULL;
	GBytes *ssid = NULL;

	/*
	 * If we are initializing a hidden network for which we just
	 * figured SSID (by actively scanning for it), bss->ssid is
	 * empty and data->ssid points to the real SSID. If both SSIDs
	 * are non-empty, they should be equal.
	 *
	 * In other words, when in doubt, use data->ssid
	 */
	if (data->ssid && g_bytes_get_size(data->ssid) > 0) {
		ssid = data->ssid;
	}

	if (bss->ssid_str && g_bytes_get_size(bss->ssid) > 0) {
		/*
		 * This is just an optimization, to avoid unnnecessary
		 * allocation of the network name. If both SSIDs are
		 * non-empty, they are equal and in that case we can
		 * use the name allocated by GSupplicantBSS.
		 */
		network_name = bss->ssid_str;
	}

	if (ssid && !network_name) {
		network_name = tmp = gsupplicant_utf8_from_bytes(ssid);
	}

	net->network = connman_network_create(net->ident,
						CONNMAN_NETWORK_TYPE_WIFI);
	connman_network_set_data(net->network, net);
	if (network_name && network_name[0]) {
		/* Don't set the name (even empty) for the hidden networks */
		connman_network_set_name(net->network, network_name);
	}
	if (ssid) {
		gsize len = 0;
		const guint8 *data = g_bytes_get_data(ssid, &len);
		connman_network_set_blob(net->network, NETWORK_KEY_WIFI_SSID,
								data, len);
	}
	connman_network_set_string(net->network, NETWORK_KEY_WIFI_SECURITY,
		 __connman_service_security2string(wifi_bss_security(bss)));
	if (gsupplicant_bss_security(bss) == GSUPPLICANT_SECURITY_EAP) {
		/*
		 * update_from_network() will replace the special default
		 * value with the actual configured EAP method.
		 */
		connman_network_set_string(net->network, NETWORK_KEY_WIFI_EAP,
					NETWORK_EAP_DEFAULT);
	}

	wifi_network_update_wps_caps_from_bss(net, bss);
	connman_network_set_frequency(net->network, bss->frequency);
	connman_network_set_maxrate(net->network, bss->maxrate);
	connman_network_set_enc_mode(net->network, enc_mode);
	if (bss->bssid) {
		guint8 bssid[WIFI_BSSID_LEN];
		gsize len = 0;
		const guint8 *data = g_bytes_get_data(bss->bssid, &len);
		GASSERT(len == WIFI_BSSID_LEN);
		if (len > WIFI_BSSID_LEN) {
			len = WIFI_BSSID_LEN;
		} else if (len < WIFI_BSSID_LEN) {
			memset(bssid, 0, sizeof(bssid));
		}
		memcpy(bssid, data, len);
		connman_network_set_bssid(net->network, bssid);
	}

	connman_network_set_string(net->network, NETWORK_KEY_WIFI_MODE,
								enc_mode);
	connman_network_set_available(net->network, TRUE);

	/*
	 * Despite its innocent name, connman_network_set_group
	 * actually creates the service for this network:
	 *
	 *     __connman_service_create_from_network (service.c)
	 *     network_probe (network.c)
	 *     connman_network_set_group (network.c)
	 */
	connman_network_set_group(net->network, net->ident);
	g_free(tmp);
}

static void wifi_network_free_bss(gpointer data, gpointer user_data)
{
	struct wifi_network *net = user_data;

	wifi_bss_free(data, net->dev);
}

static void wifi_network_delete(struct wifi_network *net)
{
	if (connman_network_get_connected(net->network)) {
		connman_network_set_connected(net->network, FALSE);
	}
	if (connman_network_get_associating(net->network)) {
		connman_network_set_associating(net->network, FALSE);
	}
	if (net->pending) {
		g_cancellable_cancel(net->pending);
		net->pending = NULL;
	}
	wifi_network_drop_interface(net);
	signalpoll_remove_handler(net->signalpoll, net->signalpoll_average_id);
	signalpoll_unref(net->signalpoll);
	connman_network_unref(net->network);
	gsupplicant_bss_unref(net->connecting_to);
	gsupplicant_bss_unref(net->current_bss);
	g_list_foreach(net->bss_list, wifi_network_free_bss, net);
	g_list_free(net->bss_list);
	g_free(net->ident);
	g_free(net->last_passphrase);
	g_slice_free(struct wifi_network, net);
}

/*==========================================================================*
 * Tethering params
 *==========================================================================*/

static struct wifi_device_tp *wifi_device_tp_new(char *ifname,
                               const char *ssid, const char *passphrase)
{
       struct wifi_device_tp *tp = g_slice_new0(struct wifi_device_tp);

       /* Caller allocates ifname */
       tp->ifname = ifname;
       tp->np.passphrase = tp->passphrase = g_strdup(passphrase);
       tp->np.mode = GSUPPLICANT_OP_MODE_AP;
       tp->np.frequency = WIFI_AP_FREQUENCY;
       tp->np.security = WIFI_AP_SECURITY;
       tp->np.protocol = WIFI_AP_PROTOCOL;
       tp->np.pairwise = WIFI_AP_CIPHER;
       tp->np.group = WIFI_AP_CIPHER;
       if (ssid) {
               tp->np.ssid = g_bytes_new(ssid, strlen(ssid));
       }
       return tp;
}

static void wifi_device_tp_free(struct wifi_device_tp *tp)
{
       if (tp) {
               if (tp->np.ssid) {
                       g_bytes_unref(tp->np.ssid);
               }
               g_free(tp->passphrase);
               g_free(tp->ifname);
               g_slice_free(struct wifi_device_tp, tp);
       }
}

/*==========================================================================*
 * Device
 *==========================================================================*/

static void wifi_device_bss_add(struct wifi_device *dev, GSupplicantBSS *bss);
static void wifi_device_autoscan_perform(struct wifi_device *dev);
static void wifi_device_active_scan_perform(struct wifi_device *dev);
static void wifi_device_active_scan_schedule(struct wifi_device *dev);
static void wifi_device_set_state(struct wifi_device *dev,
						WIFI_DEVICE_STATE state);

static int wifi_device_connect_next(struct wifi_device *dev)
{
	if (dev->connect_next_id) {
		g_source_remove(dev->connect_next_id);
		dev->connect_next_id = 0;
	}

	if (dev->selected) {
		/* wifi_network_disconnect may clear dev->selected */
		wifi_network_disconnect(dev->selected);
		if (dev->selected &&
				dev->selected->state == WIFI_NETWORK_IDLE) {
			dev->selected = NULL;
		}
	}

	if (dev->connect_next) {
		struct wifi_network *net = dev->connect_next;
		if (!dev->selected) {
			if (dev->hidden_connect) {
				wifi_hidden_connect_free(dev->hidden_connect);
				dev->hidden_connect = NULL;
			}
			dev->connect_next = NULL;
			dev->selected = net;
			connman_network_set_index(net->network, dev->ifi);
			return wifi_network_connect(net);
		} else {
			/* Previous device is still disconnecting */
			NDBG(net, "waiting for %p %s to disconnect",
					dev->selected, dev->selected->ident);
			return (-EINPROGRESS);
		}
	} else {
		DBG("nothing to connect");
		wifi_device_scan_check(dev);
		return (-EINVAL);
	}
}

static gboolean wifi_device_connect_next_proc(gpointer data)
{
	struct wifi_device *dev = data;

	dev->connect_next_id = 0;
	wifi_device_connect_next(dev);
	return G_SOURCE_REMOVE;
}

static void wifi_device_connect_next_schedule(struct wifi_device *dev)
{
	/* Schedule wifi_device_connect_next() on the fresh stack */
	if (!dev->connect_next_id) {
		dev->connect_next_id =
			g_idle_add(wifi_device_connect_next_proc, dev);
	}
}

static gboolean wifi_device_find_hidden_network(gpointer key,
					gpointer value, gpointer user_data)
{
	struct wifi_network *net = value;
	GList *l;

	for (l = net->bss_list; l; l = l->next) {
		struct wifi_bss *bss_data = l->data;
		GSupplicantBSS *bss = bss_data->bss;

		if (!bss->ssid || !g_bytes_get_size(bss->ssid)) {
			DBG("found hidden bss: %s", bss->path);
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean wifi_device_have_hidden_networks(struct wifi_device *dev)
{
	return g_hash_table_find(dev->ident_net,
				wifi_device_find_hidden_network, dev) != NULL;
}

static void wifi_device_reset(struct wifi_device *dev)
{
	wifi_device_set_state(dev, WIFI_DEVICE_OFF);
}

static void wifi_device_delete_network(struct wifi_device *dev,
						struct wifi_network *net)
{
	if (dev->connect_next == net) {
		dev->connect_next = NULL;
	}
	if (dev->selected == net) {
		dev->selected = NULL;
		wifi_device_connect_next_schedule(dev);
	}
	wifi_network_delete(net);
}

static void wifi_device_remove_all_networks_cb(gpointer netp, gpointer devp)
{
	struct wifi_network *net = netp;
	struct wifi_device *dev = devp;

	/*
	 * Make sure that wifi_device_remove_network doesn't do anything
	 * if it gets invoked like this:
	 *
	 *     wifi_device_remove_network (sailfish_wifi.c)
	 *     wifi_network_driver_remove (sailfish_wifi.c)
	 *     network_remove (network.c)
	 *     __connman_network_set_device (network.c)
	 *     free_network (device.c)
	 *     g_hash_table_remove (ghash.c)
	 *     connman_device_remove_network (device.c)
	 *     wifi_device_remove_all_networks_cb (sailfish_wifi.c)
	 *     g_list_foreach (glist.c:1005)
	 *     wifi_device_remove_all_networks (sailfish_wifi.c)
	 */
	GASSERT(!net->remove_in_process);
	net->remove_in_process++;
	connman_device_remove_network(dev->device, net->network);
	net->remove_in_process--;
	wifi_device_delete_network(dev, net);
}

static void wifi_device_remove_all_networks(struct wifi_device *dev)
{
	g_hash_table_foreach(dev->bss_pending, wifi_bss_free_value, NULL);
	g_hash_table_foreach(dev->bssid_map, wifi_slist_free_value, NULL);
	g_hash_table_remove_all(dev->bss_pending);
	g_hash_table_remove_all(dev->bssid_map);
	g_hash_table_remove_all(dev->bss_net);
	g_hash_table_remove_all(dev->ident_net);
	g_list_foreach(dev->networks, wifi_device_remove_all_networks_cb, dev);
	g_list_free(dev->networks);
	dev->networks = NULL;
	dev->selected = NULL;
	dev->connect_next = NULL;
	wifi_device_scan_check(dev);
}

static gboolean wifi_device_is_scanning(struct wifi_device *dev)
{
	return (dev->iface && dev->iface->valid &&
			dev->iface->present && dev->iface->scanning) ||
			dev->scan_start_timeout_id;
}

static void wifi_device_update_scanning(struct wifi_device *dev)
{
	gboolean scanning;

	wifi_device_scan_check(dev);

	scanning = wifi_device_is_scanning(dev) &&
		/* Don't indicate scanning when we are connecting */
		(!dev->selected || !wifi_network_connecting(dev->selected));

	if (connman_device_get_scanning(dev->device) != scanning) {
		connman_device_set_scanning(dev->device,
				CONNMAN_SERVICE_TYPE_WIFI, scanning);
		if (scanning) {
			/*
			 * For whatever reason, connman_device_set_scanning
			 * marks all networks as unavailable if scanning
			 * is TRUE. Conveniently, there is another function
			 * called connman_device_reset_scanning which marks
			 * networks as available. It makes little sense but
			 * well, this is connman.
			 */
			connman_device_reset_scanning(dev->device);
		}
	}
}

static void wifi_device_drop_interface(struct wifi_device *dev)
{
	dev->autoscan_requested = FALSE;
	if (dev->scan_start_timeout_id) {
		g_source_remove(dev->scan_start_timeout_id);
		dev->scan_start_timeout_id = 0;
	}
	if (dev->iface) {
		gsupplicant_interface_remove_handlers(dev->iface,
				dev->iface_event_id,
				G_N_ELEMENTS(dev->iface_event_id));
		gsupplicant_interface_unref(dev->iface);
		dev->iface = NULL;
	}
	wifi_device_update_scanning(dev);
}

static void wifi_device_scanning_changed(GSupplicantInterface *iface,
								void *data)
{
	struct wifi_device *dev = data;

	DBG("%s", iface->scanning ? "on" : "off");
	GASSERT(dev->state == WIFI_DEVICE_ON);
	if (iface->scanning && dev->scan_start_timeout_id) {
		g_source_remove(dev->scan_start_timeout_id);
		dev->scan_start_timeout_id = 0;
	}
	wifi_device_update_scanning(dev);
}

static void wifi_device_country_changed(GSupplicantInterface *iface,
								void *data)
{
	struct wifi_device *dev = data;

	DBG("%s", iface->country);
	connman_device_regdom_notify(dev->device, 0, iface->country);
}

static void wifi_device_interface_presence_changed(GSupplicantInterface *iface,
								void *data)
{
	if (!iface->present || !iface->valid) {
		struct wifi_device *dev = data;

		DBG("interface %s invalid!", iface->path);
		wifi_device_reset(dev);
	}
}

static gboolean wifi_device_can_scan(struct wifi_device *dev)
{
	/* Really basic requirements for any kind of scan */
	return !dev->tethering && dev->iface && dev->iface->valid &&
		dev->iface->present && !wifi_device_is_scanning(dev);
}

static gboolean wifi_device_can_active_scan(struct wifi_device *dev)
{
	return wifi_device_can_scan(dev) &&
		/* Do not scan when network is connecting */
		(!dev->selected || !wifi_network_connecting(dev->selected) ||
		/* Unless we are connecting to a hidden network */
		dev->hidden_connect);
}

static gboolean wifi_device_can_autoscan(struct wifi_device *dev)
{
	return wifi_device_can_scan(dev) &&
		/* Do not autoscan too often */
		!dev->autoscan_holdoff_timer_id &&
		/* Do not autoscan when network is connecting */
		(!dev->selected || !wifi_network_connecting(dev->selected));
}

static void wifi_device_autoscan_stop(struct wifi_device *dev)
{
	if (dev->autoscan_start_timer_id) {
		g_source_remove(dev->autoscan_start_timer_id);
		dev->autoscan_start_timer_id = 0;
	}
}

static void wifi_device_autoscan_reset(struct wifi_device *dev)
{
	DBG("resetting autoscan");
	wifi_device_autoscan_stop(dev);
	dev->autoscan_interval_sec = WIFI_AUTOSCAN_MIN_SEC;
}

static void wifi_device_scan_check(struct wifi_device *dev)
{
	if (dev->active_scans && wifi_device_can_active_scan(dev)) {
		wifi_device_active_scan_perform(dev);
	}
	if (dev->autoscan_requested && wifi_device_can_autoscan(dev)) {
		DBG("performing delayed scan");
		wifi_device_autoscan_perform(dev);
	}
}

static gboolean wifi_device_scan_start_timeout(gpointer data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->scan_start_timeout_id);
	dev->scan_start_timeout_id = 0;
	wifi_device_update_scanning(dev);
	return G_SOURCE_REMOVE;
}

static gboolean wifi_device_autoscan_holdoff_timer_expired(gpointer data)
{
	struct wifi_device *dev = data;

	dev->autoscan_holdoff_timer_id = 0;
	wifi_device_scan_check(dev);
	return G_SOURCE_REMOVE;
}

static void wifi_device_scan_requested(struct wifi_device *dev)
{
	/*
	 * scan_start_timeout_id tells us that we have started the scan.
	 * It may take some for the request to reach wpa_supplicant and
	 * for the Scanning property to turn true.
	 */
	if (dev->scan_start_timeout_id) {
		g_source_remove(dev->scan_start_timeout_id);
	}
	dev->scan_start_timeout_id = connman_wakeup_timer_add(
					WIFI_SCAN_START_TIMEOUT_MS,
					wifi_device_scan_start_timeout, dev);
	wifi_device_update_scanning(dev);
}

static void wifi_device_autoscan_request(struct wifi_device *dev)
{
	if (wifi_device_can_autoscan(dev)) {
		wifi_device_autoscan_perform(dev);
	} else if (!dev->autoscan_requested) {
		/* Scan requests are being submitted too fast */
		DBG("holding off...");
		dev->autoscan_requested = TRUE;
	} else {
		DBG("autoscan already scheduled");
	}
}

static gboolean wifi_device_autoscan_repeat(gpointer data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->autoscan_start_timer_id);
	dev->autoscan_start_timer_id = 0;

	/*
	 * AP that doesn't broadcast its SSID won't necessarily respond
	 * to the very first scan. Therefore, it we have some hidden
	 * network in range, we have no choice but to periodically
	 * perform active scan.
	 */
	if (wifi_device_have_hidden_networks(dev)) {
		wifi_device_active_scan_schedule(dev);
	}

	wifi_device_autoscan_request(dev);
	return G_SOURCE_REMOVE;
}

static void wifi_device_active_scan_perform(struct wifi_device *dev)
{
	if (dev->active_scans) {
		GSupplicantScanParams sp;
		GPtrArray *ssids =
			g_ptr_array_new_with_free_func(wifi_bytes_unref);
		guint max_ssids = (dev->iface->caps.max_scan_ssid > 0) ?
			dev->iface->caps.max_scan_ssid : 1;

		/* Pull up to max_ssids SSIDs from the active_scans queue */
		while (dev->active_scans && ssids->len < max_ssids) {
			GSList *link = dev->active_scans;
			dev->active_scans = link->next;
			/* ssids takes ownership */
			g_ptr_array_add(ssids, link->data);
			g_slist_free_1(link);
		}
		/* NULL terminate the array */
		g_ptr_array_add(ssids, NULL);

		/* Prepare parameters for the active scan */
		memset(&sp, 0, sizeof(sp));
		sp.type = GSUPPLICANT_SCAN_TYPE_ACTIVE;
		sp.ssids = (GBytes**)ssids->pdata;
		if (gsupplicant_interface_scan(dev->iface, &sp, NULL, NULL)) {
			DBG("requested active scan, %u ssid(s)", ssids->len-1);
			wifi_device_scan_requested(dev);
		}
		g_ptr_array_unref(ssids);
	}
}

static void wifi_device_autoscan_perform(struct wifi_device *dev)
{
	if (dev->scan_start_timeout_id) {
		g_source_remove(dev->scan_start_timeout_id);
		dev->scan_start_timeout_id = 0;
	}
	if (dev->autoscan_start_timer_id) {
		g_source_remove(dev->autoscan_start_timer_id);
		dev->autoscan_start_timer_id = 0;
	}
	if (gsupplicant_interface_scan(dev->iface, NULL, NULL, NULL)) {
		DBG("requested passive scan, next in %u sec",
					dev->autoscan_interval_sec);
		dev->autoscan_requested = FALSE;
		wifi_device_scan_requested(dev);

		/*
		 * Hold-off timer prevents autoscan requests from being
		 * submitted too fast.
		 */
		GASSERT(!dev->autoscan_holdoff_timer_id);
		dev->autoscan_holdoff_timer_id =
			connman_wakeup_timer_add_seconds(WIFI_AUTOSCAN_MIN_SEC,
				wifi_device_autoscan_holdoff_timer_expired,
				dev);

		/* Schedule the next scan */
		dev->autoscan_start_timer_id =
			connman_wakeup_timer_add_seconds(
				dev->autoscan_interval_sec,
				wifi_device_autoscan_repeat, dev);

		/* Increase the timeout */
		dev->autoscan_interval_sec *= WIFI_AUTOSCAN_MULTIPLIER;
		if (dev->autoscan_interval_sec > WIFI_AUTOSCAN_MAX_SEC) {
			dev->autoscan_interval_sec = WIFI_AUTOSCAN_MAX_SEC;
		}
	}
}

static void wifi_device_autoscan_restart(struct wifi_device *dev)
{
	wifi_device_autoscan_reset(dev);
	wifi_device_autoscan_request(dev);
}

static void wifi_device_active_scan_add(struct wifi_device *dev, GBytes *ssid)
{
	GSList *l;

	for (l = dev->active_scans; l; l = l->next) {
		if (wifi_bytes_equal(ssid, l->data)) {
			return;
		}
	}

	dev->active_scans = g_slist_prepend(dev->active_scans,
					g_bytes_ref(ssid));
	DBG("\"%.*s\"", (int)g_bytes_get_size(ssid),
					(char*)g_bytes_get_data(ssid, NULL));
}

static void wifi_device_hidden_network_cb(struct connman_service *service,
								void *data)
{
	if (connman_service_get_type(service) == CONNMAN_SERVICE_TYPE_WIFI &&
			__connman_service_is_really_hidden(service)) {
		struct wifi_device *dev = data;
		GBytes* ssid = __connman_service_get_ssid(service);

		if (ssid) {
			wifi_device_active_scan_add(dev, ssid);
		}
	}
}

static void wifi_device_active_scan_schedule(struct wifi_device *dev)
{
	__connman_service_foreach(wifi_device_hidden_network_cb, dev);
	wifi_device_scan_check(dev);
}

static void wifi_device_remove_bss(gpointer bssp, gpointer devp)
{
	struct wifi_bss *bss_data = bssp;
	struct wifi_device *dev = devp;
	GVERIFY(g_hash_table_remove(dev->bss_net, bss_data->bss->path));
}

static void wifi_device_remove_network(struct wifi_device *dev,
						struct wifi_network *net)
{
	/*
	 * wifi_device_remove_network() is being invoked recursively
	 * like this:
	 *
	 * =>  wifi_device_remove_network (sailfish_wifi.c)
	 *     wifi_network_driver_remove (sailfish_wifi.c)
	 *     network_remove (network.c)
	 *     __connman_network_set_device (network.c)
	 *     free_network (device.c)
	 *     g_hash_table_remove (ghash.c)
	 *     connman_device_remove_network (device.c)
	 * =>  wifi_device_remove_network (sailfish_wifi.c)
	 *     ...
	 */
	if (!(net->remove_in_process++)) {
		dev->networks = g_list_remove(dev->networks, net);
		connman_device_remove_network(dev->device, net->network);
		g_hash_table_remove(dev->ident_net, net->ident);
		g_list_foreach(net->bss_list, wifi_device_remove_bss, dev);
		wifi_device_delete_network(dev, net);
	} else {
		net->remove_in_process--;
	}
}

static struct wifi_network *wifi_device_network_for_bss(
				struct wifi_device *dev, GSupplicantBSS *bss)
{
	return bss ? g_hash_table_lookup(dev->bss_net, bss->path) : NULL;
}

static struct wifi_bss *wifi_device_get_bss_data(struct wifi_device *dev,
						GSupplicantBSS *bss)
{
	return wifi_network_get_bss_data(wifi_device_network_for_bss(dev, bss),
									bss);
}

static void wifi_device_remove_bss_from_network2(struct wifi_device *dev,
				struct wifi_network *net, GSupplicantBSS *bss)
{
	GList *l;

	DBG("removing %s from %s", bss->path, net->ident);
	g_hash_table_remove(dev->bss_net, bss->path);

	for (l = net->bss_list; l; l = l->next) {
		struct wifi_bss *data = l->data;

		if (data->bss == bss) {
			net->bss_list = g_list_delete_link(net->bss_list, l);
			wifi_bss_free(data, dev);
			if (net->bss_list && !net->signalpoll) {
				/* Best BSS may be gone, update the strength */
				wifi_network_update_strength(net);
			}
			break;
		}
	}

	if (!net->bss_list) {
		/* The last BSS is gone, kill the network */
		DBG("removing %s", net->ident);
		wifi_device_remove_network(dev, net);
	}
}

static void wifi_device_remove_bss_from_network(struct wifi_device *dev,
						GSupplicantBSS *bss)
{
	struct wifi_network *net = wifi_device_network_for_bss(dev, bss);

	if (net) {
		wifi_device_remove_bss_from_network2(dev, net, bss);
	}
}

static void wifi_device_steal_bss_data_from_network(struct wifi_device *dev,
						struct wifi_bss *bss_data)
{
	GSupplicantBSS *bss = bss_data->bss;
	struct wifi_network *net = wifi_device_network_for_bss(dev, bss);

	if (net) {
		DBG("stealing %s from %s", bss->path, net->ident);
		g_hash_table_remove(dev->bss_net, bss->path);
		net->bss_list = g_list_remove(net->bss_list, bss_data);

		if (net->bss_list) {
			if (!net->signalpoll) {
				/* Best BSS may be gone, update the strength */
				wifi_network_update_strength(net);
			}
		} else {
			/* The last BSS is gone, kill the network */
			DBG("removing %s", net->ident);
			wifi_device_remove_network(dev, net);
		}
	}
}

static void wifi_device_cleanup_bss_list(struct wifi_device *dev,
			struct wifi_network *net, struct wifi_bss *keep)
{
	GList *l;
	GSupplicantBSS *bss = keep->bss;

	for (l = net->bss_list; l; l = l->next) {
		struct wifi_bss *data = l->data;

		if (data != keep &&
			wifi_bytes_equal(data->bss->bssid, bss->bssid) &&
			wifi_bytes_equal(data->bss->ssid, bss->ssid)) {

			/*
			 * This is most likely the dead BSS that we kept
			 * around waiting for the WiFi network to reappear.
			 *
			 * Note that we can have here two BSSes with the
			 * same BSSID - one produced by the passive scan
			 * and one by the active one. The former will
			 * have empty SSID.
			 */
			GSupplicantBSS *dump = data->bss;

			DBG("dumping %s", dump->path);
			if (data->remove_timeout_id) {
				g_source_remove(data->remove_timeout_id);
				data->remove_timeout_id = 0;
			}
			wifi_device_remove_bss_from_network2(dev, net, dump);
			break;
		}
	}
}

static gboolean wifi_device_bss_remove_timer(void *user_data)
{
	struct wifi_device_bss_data *data = user_data;

	GASSERT(data->bss->remove_timeout_id);
	data->bss->remove_timeout_id = 0;
	wifi_device_remove_bss_from_network(data->dev, data->bss->bss);
	return G_SOURCE_REMOVE;
}

static void wifi_device_bss_presence_changed(GSupplicantBSS *bss, void *data)
{
	struct wifi_device *dev = data;

	/*
	 * Schedule BSS for removal when it becomes invalid. Still keep
	 * it around for WIFI_BSS_REMOVE_TIMEOUT_MS so that connman networks
	 * don't get removed and re-created too often.
	 *
	 * Quite often WiFi networks disappear from the scan results and
	 * then quickly re-appear with a different path. When that happens
	 * we detect duplicates (by comparing BSSID), get rid of the dead
	 * BSS and replace it with the brand new one. Connman won't even
	 * notice because we keep connman network alive. Once the timeout
	 * experes, the dead BSS actually goes away, possibly taking down
	 * the entire connman network (if it was the last BSS associated
	 * with the network).
	 */
	if (!bss->valid || !bss->present) {
		struct wifi_bss *bss_data = wifi_device_get_bss_data(dev, bss);

		GASSERT(bss_data);
		if (bss_data) {
			if (!bss_data->remove_timeout_id) {
				struct wifi_device_bss_data *timer_data =
					g_new(struct wifi_device_bss_data, 1);

				DBG("%s is gone", bss->path);
				timer_data->dev = dev;
				timer_data->bss = bss_data;
				bss_data->remove_timeout_id =
					connman_wakeup_timer_add_full(
						G_PRIORITY_DEFAULT,
						WIFI_BSS_REMOVE_TIMEOUT_MS,
						wifi_device_bss_remove_timer,
						timer_data, g_free);
			}
		}
	} else if (bss->valid && bss->present) {
		struct wifi_bss *bss_data = wifi_device_get_bss_data(dev, bss);

		DBG("%s reappeared", bss->path);
		GASSERT(bss_data);
		if (bss_data) {
			GASSERT(bss_data->remove_timeout_id);
			if (bss_data->remove_timeout_id) {
				g_source_remove(bss_data->remove_timeout_id);
				bss_data->remove_timeout_id = 0;
			}
		}
	}
}

static void wifi_device_bss_signal_changed(GSupplicantBSS *bss, void *data)
{
	struct wifi_device *dev = data;
	struct wifi_network *net = wifi_device_network_for_bss(dev, bss);
	struct wifi_bss *bss_data = wifi_device_get_bss_data(dev, bss);

	bss_data->strength = gutil_int_history_add(bss_data->history,
					wifi_rssi_strength(bss->signal));

	/* If signal strength is being polled, don't update it here */
	if (!net->signalpoll) {
		wifi_network_update_strength(net);
	}
}

static void wifi_device_bss_frequency_changed(GSupplicantBSS *bss, void *data)
{
	wifi_network_update_frequency(wifi_device_network_for_bss(data, bss));
}

static void wifi_device_bss_wps_caps_changed(GSupplicantBSS *bss, void *data)
{
	DBG("%s WPS caps 0x%02x", bss->path, bss->wps_caps);
	wifi_network_update_wps_caps(wifi_device_network_for_bss(data, bss));
}

static void wifi_device_bss_ident_changed(GSupplicantBSS *bss, void *data)
{
	struct wifi_device *dev = data;
	struct wifi_network *net = wifi_device_network_for_bss(dev, bss);
	struct wifi_bss *bss_data = wifi_network_get_bss_data(net, bss);

	DBG("%s security %s ssid %s", bss->path,
		__connman_service_security2string(wifi_bss_security(bss)),
		bss->ssid_str);

	GASSERT(net && bss_data);
	if (net && bss_data) {
		char *ident = wifi_bss_ident(bss_data);

		if (strcmp(ident, net->ident)) {
			/*
			 * Network identifier has changed (because it
			 * includes the security and ssid). Remove it
			 * and associate this BSS with the new network.
			 */
			wifi_device_remove_bss_from_network(dev, bss);
			wifi_device_bss_add(dev, bss);
		}
		g_free(ident);
	}
}

static void wifi_device_bss_add_3(struct wifi_device *dev,
						struct wifi_bss *bss_data)
{
	GSupplicantBSS *bss = bss_data->bss;
	GBytes *bssid = bss->bssid;
	GBytes *ssid = bss_data->ssid;
	char *ident = wifi_bss_ident(bss_data);
	struct wifi_network *net = g_hash_table_lookup(dev->ident_net, ident);
	GSList *bssid_list;

	GASSERT(bss->valid && bss->present);

	/*
	 * Attach signal handlers if it's not done yet. It's enough to
	 * check just one event id - they are either all zero or all
	 * non-zero. Since BSS_EVENT_VALID is used elsewhere, we better
	 * check something else (e.g. BSS_EVENT_SIGNAL).
	 */
	if (!bss_data->event_id[BSS_EVENT_SIGNAL]) {
		GASSERT(!bss_data->event_id[BSS_EVENT_VALID]);
		bss_data->event_id[BSS_EVENT_VALID] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_VALID,
				wifi_device_bss_presence_changed, dev);
		bss_data->event_id[BSS_EVENT_PRESENT] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_PRESENT,
				wifi_device_bss_presence_changed, dev);
		bss_data->event_id[BSS_EVENT_WPS_CAPS] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_WPS_CAPS,
				wifi_device_bss_wps_caps_changed, dev);
		bss_data->event_id[BSS_EVENT_WPA] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_WPA,
				wifi_device_bss_ident_changed, dev);
		bss_data->event_id[BSS_EVENT_RSN] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_RSN,
				wifi_device_bss_ident_changed, dev);
		bss_data->event_id[BSS_EVENT_SSID] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_SSID,
				wifi_device_bss_ident_changed, dev);
		bss_data->event_id[BSS_EVENT_FREQUENCY] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_FREQUENCY,
				wifi_device_bss_frequency_changed, dev);
		bss_data->event_id[BSS_EVENT_SIGNAL] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_SIGNAL,
				wifi_device_bss_signal_changed, dev);
	}

	/*
	 * Initialize the signal strength history. Note that if we are
	 * re-initializing a hidden network, we already have the history.
	 * Hence the check.
	 */
	if (!bss_data->history) {
		bss_data->history =
			gutil_int_history_new(WIFI_BSS_SIGNAL_HISTORY_SIZE,
				WIFI_BSS_SIGNAL_HISTORY_SEC*GUTIL_HISTORY_SEC);
		bss_data->strength = gutil_int_history_add(bss_data->history,
					wifi_rssi_strength(bss->signal));
	}

	if (net) {
		DBG("adding %s to %s", bss->path, ident);
		g_free(ident);
	} else {
		struct connman_service *service;

		DBG("creating network %s for %s", ident, bss->path);
		net = g_slice_new0(struct wifi_network);
		net->ident = ident;
		net->dev = dev;
		dev->networks = g_list_append(dev->networks, net);
		g_hash_table_replace(dev->ident_net, g_strdup(ident), net);
		wifi_network_init(net, bss_data);
		connman_device_add_network(dev->device, net->network);

		/*
		 * Make sure that the service has its ipconfig initialized,
		 * otherwise autoconnect barfs.
		 */
		service = connman_service_lookup_from_network(net->network);
		GASSERT(service);
		if (service) {
			connman_service_create_ip4config(service, dev->ifi);
			connman_service_create_ip6config(service, dev->ifi);
		}
	}

	g_hash_table_replace(dev->bss_net, g_strdup(bss->path), net);
	net->bss_list = g_list_append(net->bss_list, bss_data);

	/*
	 * There's usually only one network in this list, sometimes two,
	 * so linear search isn't much of an overhead here. Besides, when
	 * we are assigning SSID to a hidden network, it's already in the
	 * list, we need to make sure that we don't put it in there twice.
	 */
	bssid_list = g_hash_table_lookup(dev->bssid_map, bssid);
	if (!g_slist_find(bssid_list, bss_data)) {
		bssid_list = g_slist_prepend(bssid_list, bss_data);
		g_hash_table_replace(dev->bssid_map, g_bytes_ref(bssid),
							bssid_list);
	}

	wifi_device_cleanup_bss_list(dev, net, bss_data);
	if (!wifi_network_update_current_bss(net)) {
		wifi_network_update_bssid(net);
		wifi_network_update_frequency(net);
	}
	if (!net->signalpoll) {
		wifi_network_update_strength(net);
	}

	/* Check if this is the hidden network we are trying to connect to. */
	if (dev->hidden_connect && wifi_bss_security(bss) ==
			dev->hidden_connect->security &&
			wifi_bytes_equal(ssid, dev->hidden_connect->ssid)) {
		struct wifi_hidden_connect *connect = dev->hidden_connect;

		DBG("Hello, %.*s", (int)g_bytes_get_size(ssid),
					(char*)g_bytes_get_data(ssid, NULL));
		dev->hidden_connect = NULL;
		connman_network_connect_hidden(net->network, connect->identity,
				connect->passphrase, connect->user_data);
		connect->user_data = NULL;
		wifi_hidden_connect_free(connect);
	} else if (!ssid || !g_bytes_get_size(ssid)) {
		wifi_device_active_scan_schedule(dev);
	}
}

static struct wifi_bss *wifi_device_named_bss(struct wifi_device *dev,
							GBytes *bssid)
{
	GSList *l;

	for (l = g_hash_table_lookup(dev->bssid_map, bssid); l; l = l->next) {
		struct wifi_bss *data = l->data;

		GASSERT(wifi_bytes_equal(data->bss->bssid, bssid));
		if (data->ssid) {
			GASSERT(g_bytes_get_size(data->ssid));
			return data;
		}
	}

	return NULL;
}

static struct wifi_bss *wifi_device_unnamed_bss(struct wifi_device *dev,
							GBytes *bssid)
{
	GSList *l;

	for (l = g_hash_table_lookup(dev->bssid_map, bssid); l; l = l->next) {
		struct wifi_bss *data = l->data;

		GASSERT(wifi_bytes_equal(data->bss->bssid, bssid));
		if (!data->ssid) {
			return data;
		}
	}

	return NULL;
}

static void wifi_device_bss_add_2(struct wifi_device *dev,
						struct wifi_bss *bss_data)
{
	GSupplicantBSS *bss = bss_data->bss;

	GASSERT(bss->valid);
	if (bss->present && bss->bssid) {
		if (bss->ssid && g_bytes_get_size(bss->ssid)) {
			struct wifi_bss *hidden = wifi_device_unnamed_bss(dev,
								bss->bssid);
			bss_data->ssid = g_bytes_ref(bss->ssid);
			if (hidden) {
				/* Found SSID for a hidden network */
				DBG("%s -> %s", bss->path, hidden->bss->path);
				wifi_device_steal_bss_data_from_network(dev,
								hidden);

				/* Assign SSID and add put it back */
				hidden->ssid = g_bytes_ref(bss->ssid);
				wifi_device_bss_add_3(dev, hidden);
			}
		} else {
			/* No SSID broadcast */
			struct wifi_bss *named = wifi_device_named_bss(dev,
								bss->bssid);
			if (named) {
				/* We already know SSID for this network */
				bss_data->ssid = g_bytes_ref(named->ssid);
				DBG("%s -> \"%.*s\"", bss->path,
					(int)g_bytes_get_size(named->ssid),
					(char*)g_bytes_get_data(named->ssid,
								NULL));
			}
		}
		wifi_device_bss_add_3(dev, bss_data);
	} else {
		DBG("BSS %s gone?", bss->path);
		wifi_bss_free(bss_data, dev);
	}
}

static void wifi_device_bss_add_1(GSupplicantBSS *bss, void *data)
{
	if (bss->valid) {
		struct wifi_device *dev = data;
		struct wifi_bss *bss_data =
			g_hash_table_lookup(dev->bss_pending, bss->path);

		GASSERT(bss_data);
		if (bss_data) {
			GASSERT(bss_data->bss == bss);
			g_hash_table_remove(dev->bss_pending, bss->path);
			gsupplicant_bss_remove_handlers(bss_data->bss,
				bss_data->event_id + BSS_EVENT_VALID, 1);
			wifi_device_bss_add_2(dev, bss_data);
		}
	}
}

static void wifi_device_bss_add(struct wifi_device *dev, GSupplicantBSS *bss)
{
	struct wifi_bss *bss_data = g_slice_new0(struct wifi_bss);

	DBG("%s", bss->path);
	bss_data->bss = gsupplicant_bss_ref(bss);
	if (bss->valid) {
		wifi_device_bss_add_2(dev, bss_data);
	} else {
		/*
		 * We are using the path owned by GSupplicantBSS
		 * as the key in the hashtable. This allows us
		 * to avoid copying the key.
		 */
		g_hash_table_replace(dev->bss_pending,
					(gpointer)bss->path, bss_data);
		bss_data->event_id[BSS_EVENT_VALID] =
			gsupplicant_bss_add_handler(bss,
				GSUPPLICANT_BSS_PROPERTY_VALID,
				wifi_device_bss_add_1, dev);
	}
}

static void wifi_device_bss_add_path(struct wifi_device *dev, const char *path)
{
	GSupplicantBSS *bss = gsupplicant_bss_new(path);

	if (bss) {
		wifi_device_bss_add(dev, bss);
		gsupplicant_bss_unref(bss);
	}
}

static void wifi_device_update_bss_list(struct wifi_device *dev)
{
	const GStrV *list = NULL;

	if (dev->iface) {
		list = dev->iface->bsss;
	}
	if (list) {
		while (*list) {
			const char *path = *list++;
			if (!g_hash_table_contains(dev->bss_pending, path) &&
				!g_hash_table_contains(dev->bss_net, path)) {
				wifi_device_bss_add_path(dev, path);
			}
		}
	}
}

static int wifi_device_scan(struct wifi_device *dev,
			const char *ssid, unsigned int ssid_len,
			const char *identity, const char *passphrase,
			const char *security, void *user_data)
{
	if (dev->tethering) {
		DBG("tethering on!");
		return 0;
	} else if (ssid && ssid_len) {
		GBytes *ssid_bytes = g_bytes_new(ssid, ssid_len);

		/*
		 * This isn't really a scan, it's connman trying
		 * to connect a hidden WiFi network. The identity,
		 * passphrase and user_data parameters have to be
		 * passed to connman_network_connect_hidden() once
		 * we get BSSID of the network in question.
		 */
		DBG("\"%.*s\"", ssid_len, ssid);
		wifi_hidden_connect_free(dev->hidden_connect);
		dev->hidden_connect = wifi_hidden_connect_new(ssid_bytes,
			identity, passphrase, security, user_data, dev);

		/*
		 * Now we just wait for the requested SSID to
		 * appear in the BSS list. Once that happens,
		 * we can continue connecting this network.
		 */
		g_bytes_unref(ssid_bytes);
		return 0;
	} else if (connman_device_get_scanning(dev->device)) {
		DBG("already scanning!");
		return (-EALREADY);
	} else if (!ssid || !ssid_len) {
		if (wifi_device_have_hidden_networks(dev)) {
			wifi_device_active_scan_schedule(dev);
		}
		DBG("restarting autoscan");
		wifi_device_autoscan_restart(dev);
		return 0;
	}
	return (-EINVAL);
}

static void wifi_device_bsss_changed(GSupplicantInterface *iface, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->state == WIFI_DEVICE_ON && !dev->pending);
	wifi_device_update_bss_list(dev);

	/*
	 * If the list of WiFi network is changing, request scans
	 * more often as long as the screen is on. Don't bother if
	 * the screen is off and locked, or if we are happily connected
	 * to the particular network.
	 */
	if (dev->screen_active && (!dev->selected ||
			dev->selected->state != WIFI_NETWORK_CONNECTED)) {
		wifi_device_autoscan_restart(dev);
	}
}

static gboolean wifi_device_init_cip(struct wifi_device *dev,
				struct wifi_create_interface_params *cip)
{
	memset(cip, 0, sizeof(*cip));
	cip->ifname = connman_inet_ifname(dev->ifi);

	if (cip->ifname) {
		cip->params.ifname = cip->ifname;
		cip->params.driver = connman_option_get_string("wifi");
		return TRUE;
	} else {
		DBG("no interface!");
		return FALSE;
	}
}

static void wifi_device_cleanup_cip(struct wifi_create_interface_params *cip)
{
	if (cip->ifname) {
		g_free(cip->ifname);
		cip->params.ifname = cip->ifname = NULL;
	}
}

static void wifi_device_on_ok(struct wifi_device *dev)
{
	wifi_device_set_state(dev, WIFI_DEVICE_ON);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_VALID] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_VALID,
			wifi_device_interface_presence_changed, dev);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_PRESENT] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_PRESENT,
			wifi_device_interface_presence_changed, dev);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_SCANNING] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_SCANNING,
			wifi_device_scanning_changed, dev);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_COUNTRY] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_COUNTRY,
			wifi_device_country_changed, dev);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_BSSS] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_BSSS,
			wifi_device_bsss_changed, dev);
	if (!connman_device_get_powered(dev->device)) {
		connman_device_set_powered(dev->device, TRUE);
	}
	wifi_device_autoscan_request(dev);
	wifi_device_update_bss_list(dev);
}

static void wifi_device_on_5(struct wifi_device *dev)
{
	GSupplicantInterface *iface = dev->iface;

	/* The interface has been created and has become valid */
	GASSERT(iface->valid);
	if (iface->present) {
		wifi_device_on_ok(dev);
	} else {
		DBG("interface %s not present?", iface->path);
		wifi_device_reset(dev);
	}
}

static void wifi_device_on_4(GSupplicantInterface *iface, void *data)
{
	if (iface->valid) {
		struct wifi_device *dev = data;

		/* remove_handlers also zeros the event id */
		gsupplicant_interface_remove_handlers(dev->iface,
			dev->iface_event_id +
			DEVICE_INTERFACE_EVENT_VALID, 1);

		wifi_device_on_5(dev);
	}
}

static void wifi_device_on_3(GSupplicant *supplicant, GCancellable *cancel,
			const GError *error, const char *path, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	/* gsupplicant_interface_new gracefully fails if path is NULL */
	dev->iface = gsupplicant_interface_new(path);
	if (dev->iface) {
		if (dev->iface->valid) {
			wifi_device_on_5(dev);
		} else {
			/* Have to wait */
			dev->iface_event_id[DEVICE_INTERFACE_EVENT_VALID] =
				gsupplicant_interface_add_handler(dev->iface,
					GSUPPLICANT_INTERFACE_PROPERTY_VALID,
					wifi_device_on_4, dev);
		}
	} else {
		DBG("error %s", error ? error->message : "????");
		wifi_device_set_state(dev, WIFI_DEVICE_UNDEFINED);
	}
}

static void wifi_device_on_2(GSupplicant *supplicant, GCancellable *cancel,
			const GError *error, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	if (gsupplicant_is_error(error, GSUPPLICANT_ERROR_INTERFACE_UNKNOWN) ||
								!error) {
		struct wifi_create_interface_params cip;
		if (wifi_device_init_cip(dev, &cip)) {
			DBG("creating interface %s", cip.ifname);
			dev->pending = gsupplicant_create_interface(
				dev->supplicant, &cip.params,
				wifi_device_on_3, dev);
			wifi_device_cleanup_cip(&cip);
		}
	}
	if (!dev->pending) {
		DBG("failed to enable device");
		wifi_device_set_state(dev, WIFI_DEVICE_UNDEFINED);
	}
}

static void wifi_device_on_1(GSupplicant *supplicant, GCancellable *cancel,
			const GError *error, const char *path, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	/*
	 * We expect either success or fi.w1.wpa_supplicant1.InterfaceUnknown
	 * error. Abort the initialization on any other error.
	 */
	if (gsupplicant_is_error(error, GSUPPLICANT_ERROR_INTERFACE_UNKNOWN)) {
		struct wifi_create_interface_params cip;
		if (wifi_device_init_cip(dev, &cip)) {
			DBG("creating interface %s", cip.ifname);
			dev->pending = gsupplicant_create_interface(
				dev->supplicant, &cip.params,
				wifi_device_on_3, dev);
			wifi_device_cleanup_cip(&cip);
		}
	} else if (path) {
		DBG("removing %s", path);
		dev->pending = gsupplicant_remove_interface(dev->supplicant,
					path, wifi_device_on_2, dev);
	} else {
		DBG("error %s", error ? error->message : "????");
	}

	if (!dev->pending) {
		DBG("failed to enable device");
		wifi_device_set_state(dev, WIFI_DEVICE_UNDEFINED);
	}
}

static int wifi_device_on_start(struct wifi_device *dev)
{
	int ret;
	char *ifname = connman_inet_ifname(dev->ifi);

	if (ifname) {
		/*
		 * Start transition to the ON state:
		 *
		 * 1. Get the supplicant interface path
		 * 2. Delete the supplicant interface (if one exists)
		 * 3. Create a fresh new supplicant interface.
		 * 4. Wait for the supplicant interface to get ready
		 *
		 * Connman core gives us 4 seconds to complete the
		 * process (but doesn't notify us when the timeout
		 * expires).
		 */
		GCancellable *pending =
			gsupplicant_get_interface(dev->supplicant, ifname,
						wifi_device_on_1, dev);
		if (pending) {
			if (dev->pending) {
				g_cancellable_cancel(dev->pending);
			}
			dev->pending = pending;
			wifi_device_set_state(dev, WIFI_DEVICE_TURNING_ON);
			DBG("checking %s", ifname);
			ret = (-EINPROGRESS);
		} else {
			DBG("failed to enable device");
			ret = (-EFAULT);
		}
		g_free(ifname);
	} else {
		DBG("no interface!");
		ret = (-ENODEV);
	}
	return ret;
}

static void wifi_tether_failed(struct wifi_device *dev)
{
	DBG("failed to enable tethering");
	wifi_device_on_start(dev);
}

static void wifi_device_tether_ok(struct wifi_device *dev)
{
	wifi_device_set_state(dev, WIFI_DEVICE_TETHERING_ON);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_VALID] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_VALID,
			wifi_device_interface_presence_changed, dev);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_PRESENT] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_PRESENT,
			wifi_device_interface_presence_changed, dev);
	dev->iface_event_id[DEVICE_INTERFACE_EVENT_COUNTRY] =
		gsupplicant_interface_add_handler(dev->iface,
			GSUPPLICANT_INTERFACE_PROPERTY_COUNTRY,
			wifi_device_country_changed, dev);
}

static void wifi_device_tether_8(GSupplicantInterface *iface,
			GCancellable *cancel, const GError *error,
			const char *path, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	if (!error) {
		DBG("%s", path);
		wifi_device_tether_ok(dev);
	} else {
		DBG("error %s", error->message);
		wifi_tether_failed(dev);
	}
}

static void wifi_device_tether_7(GSupplicantInterface *iface,
		GCancellable *cancel, const GError *error, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	if (!error) {
		/*
		 * When using IBSS or AP mode, ap_scan=2 mode can force
		 * the new network to be created immediately regardless
		 * of scan results.
		 */
		gsupplicant_interface_set_ap_scan(iface, 2);
		DBG("creating network");
		dev->pending =
			gsupplicant_interface_add_network(iface, &dev->tp->np,
				GSUPPLICANT_ADD_NETWORK_SELECT |
				GSUPPLICANT_ADD_NETWORK_ENABLE,
				wifi_device_tether_8, dev);
	} else {
		DBG("error %s", error->message);
	}

	if (!dev->pending) {
		wifi_tether_failed(dev);
	}
}

static void wifi_device_tether_6(struct wifi_device *dev)
{
	GSupplicantInterface *iface = dev->iface;

	/* The interface has been created and has become valid */
	GASSERT(iface->valid);
	if (iface->present) {
		DBG("removing all networks");
		GASSERT(!dev->pending);
		dev->pending = gsupplicant_interface_remove_all_networks(iface,
						wifi_device_tether_7, dev);
	} else {
		DBG("interface %s not present?", iface->path);
		wifi_tether_failed(dev);
	}
}

static void wifi_device_tether_5(GSupplicantInterface *iface, void *data)
{
	if (iface->valid) {
		struct wifi_device *dev = data;

		/* remove_handlers also zeros the event id */
		gsupplicant_interface_remove_handlers(dev->iface,
			dev->iface_event_id +
			DEVICE_INTERFACE_EVENT_VALID, 1);

		wifi_device_tether_6(dev);
	}
}

static void wifi_device_tether_4(GSupplicant *supplicant, GCancellable *cancel,
			const GError *error, const char *path, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	/* gsupplicant_interface_new gracefully fails if path is NULL */
	dev->iface = gsupplicant_interface_new(path);
	if (dev->iface) {
		if (dev->iface->valid) {
			wifi_device_tether_6(dev);
		} else {
			/* Have to wait */
			dev->iface_event_id[DEVICE_INTERFACE_EVENT_VALID] =
				gsupplicant_interface_add_handler(dev->iface,
					GSUPPLICANT_INTERFACE_PROPERTY_VALID,
						wifi_device_tether_5, dev);
		}
	} else {
		DBG("error %s", error ? error->message : "????");
		wifi_tether_failed(dev);
	}
}

static GCancellable *wifi_device_tether_3(struct wifi_device *dev)
{
	GSupplicantCreateInterfaceParams params;

	/* This creates the bridge (at least attempts to) */
	connman_technology_tethering_notify(dev->tethering, TRUE);

	/*
	 * Assuming that the above call succeeds, we can create
	 * wpa_supplicant interface for it.
	 */
	memset(&params, 0, sizeof(params));
	params.ifname = dev->tp->ifname;
	params.bridge_ifname = dev->bridge;
	params.driver = connman_option_get_string("wifi");

	DBG("creating interface %s/%s", params.ifname, params.bridge_ifname);
	return gsupplicant_create_interface(dev->supplicant, &params,
						wifi_device_tether_4, dev);
}

static void wifi_device_tether_2(GSupplicant *supplicant, GCancellable *cancel,
			const GError *error, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	if (gsupplicant_is_error(error, GSUPPLICANT_ERROR_INTERFACE_UNKNOWN) ||
								!error) {
		dev->pending = wifi_device_tether_3(dev);
	} else {
		DBG("error %s", error->message);
	}

	if (!dev->pending) {
		wifi_tether_failed(dev);
	}
}

static void wifi_device_tether_1(GSupplicant *supplicant, GCancellable *cancel,
			const GError *error, const char *path, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	/*
	 * We expect either success or fi.w1.wpa_supplicant1.InterfaceUnknown
	 * error. Abort the initialization on any other error.
	 */
	if (gsupplicant_is_error(error, GSUPPLICANT_ERROR_INTERFACE_UNKNOWN)) {
		dev->pending = wifi_device_tether_3(dev);
	} else if (path) {
		DBG("removing %s", path);
		dev->pending = gsupplicant_remove_interface(dev->supplicant,
					path, wifi_device_tether_2, dev);
	} else {
		DBG("error %s", error ? error->message : "????");
	}

	if (!dev->pending) {
		wifi_tether_failed(dev);
	}
}

static int wifi_device_tether_start(struct wifi_device *dev,
			struct connman_technology *tech, const char *bridge,
			const char *ssid, const char *passphrase)
{
	int ret;
	char *ifname = connman_inet_ifname(dev->ifi);

	if (ifname) {
		/*
		 * Start transition to the TETHERING state:
		 *
		 * 1. Get the supplicant interface path
		 * 2. Delete the supplicant interface (if one exists)
		 * 3. Create a fresh new interface with the right BridgeIfname
		 * 4. Wait for the supplicant interface to get ready
		 * 5. Configure the network.
		 *
		 * While we are doing it, we are keeping the tethering
		 * parameters in the wifi_device_tp structure. We will
		 * need most of them at the very last step.
		 */
		GCancellable *pending =
			gsupplicant_get_interface(dev->supplicant, ifname,
						wifi_device_tether_1, dev);
		if (pending) {
			wifi_device_remove_all_networks(dev);
			wifi_device_drop_interface(dev);
			wifi_device_tp_free(dev->tp);
			/* dev->tp takes ownership of ifname */
			dev->tp = wifi_device_tp_new(ifname, ssid, passphrase);
			if (dev->pending) {
				g_cancellable_cancel(dev->pending);
			}
			dev->pending = pending;
			dev->tethering = tech;
			wifi_device_autoscan_reset(dev);
			if (g_strcmp0(dev->bridge, bridge)) {
				g_free(dev->bridge);
				dev->bridge = g_strdup(bridge);
			}
			wifi_device_set_state(dev,
					WIFI_DEVICE_TURNING_TETHERING_ON);
			DBG("checking %s", ifname);
			ret = (-EINPROGRESS);
		} else {
			DBG("failed to enable tethering");
			ret = (-EFAULT);
			g_free(ifname);
		}
	} else {
		DBG("no interface!");
		ret = (-ENODEV);
	}
	return ret;
}

static int wifi_device_enable(struct wifi_device *dev)
{
	switch (dev->state) {
	case WIFI_DEVICE_ON:
		DBG("already enabled");
		return (-EALREADY);
	case WIFI_DEVICE_TURNING_ON:
		DBG("already being enabled");
		return (-EINPROGRESS);
	default:
		return wifi_device_on_start(dev);
	}
}

static void wifi_device_disable_done(GSupplicant *supplicant,
		GCancellable *cancel, const GError *error, void *data)
{
	struct wifi_device *dev = data;

	GASSERT(dev->pending == cancel);
	dev->pending = NULL;

	if (error) {
		DBG("error %s", error ? error->message : "????");
	}

	GASSERT(dev->state == WIFI_DEVICE_TURNING_OFF);
	wifi_device_set_state(dev, WIFI_DEVICE_OFF);
	if (connman_device_get_powered(dev->device)) {
		connman_device_set_powered(dev->device, FALSE);
	}
}

static int wifi_device_disable(struct wifi_device *dev)
{
	switch (dev->state) {
	case WIFI_DEVICE_OFF:
		DBG("already disabled");
		return (-EALREADY);
	case WIFI_DEVICE_TURNING_OFF:
		DBG("already being disabled");
		return (-EINPROGRESS);
	default:
		if (dev->pending) {
			g_cancellable_cancel(dev->pending);
			dev->pending = NULL;
		}
		wifi_device_set_state(dev, WIFI_DEVICE_TURNING_OFF);
		if (dev->iface) {
			dev->pending = gsupplicant_remove_interface(
					dev->supplicant, dev->iface->path,
					wifi_device_disable_done, dev);
		}
		if (dev->pending) {
			return (-EINPROGRESS);
		} else {
			wifi_device_set_state(dev, WIFI_DEVICE_OFF);
			return 0;
		}
	}
}

static const char *wifi_device_state_name(WIFI_DEVICE_STATE state)
{
	switch (state) {
	case WIFI_DEVICE_OFF:                   return "Off";
	case WIFI_DEVICE_ON:                    return "On";
	case WIFI_DEVICE_TETHERING_ON:          return "TetheringOn";
	case WIFI_DEVICE_TURNING_ON:            return "TurningOn";
	case WIFI_DEVICE_TURNING_TETHERING_ON:  return "TurningTetheringOn";
	case WIFI_DEVICE_TURNING_OFF:           return "TurningOff";
	case WIFI_DEVICE_UNDEFINED:             return "Undefined";
	}
	return "UNKNOWN";
}

static void wifi_device_set_state(struct wifi_device *dev,
						WIFI_DEVICE_STATE state)
{
	if (dev->state != state) {
		DBG("%s -> %s", wifi_device_state_name(dev->state),
			wifi_device_state_name(state));
		dev->state = state;

		/* Sanity checking */
		if (state == WIFI_DEVICE_OFF ||
					state == WIFI_DEVICE_UNDEFINED) {
			/*
			 * Shouldn't have the interface in one of those
			 * states.
			 */
			wifi_device_drop_interface(dev);
		}

		if (state != WIFI_DEVICE_TURNING_TETHERING_ON) {
			/*
			 * Tethering parameters are only used when we are
			 * turning tethering on.
			 */
			if (dev->tp) {
				wifi_device_tp_free(dev->tp);
				dev->tp = NULL;
			}
		}

		if (state != WIFI_DEVICE_ON) {
			/*
			 * Hidden connect can only be happening on the ON
			 * state. Cancel it otherwise.
			 */
			if (dev->hidden_connect) {
				wifi_hidden_connect_free(dev->hidden_connect);
				dev->hidden_connect = NULL;
			}

			/* No networks if we are not ON */
			wifi_device_remove_all_networks(dev);

			/* No interface notifications in this state */
			gsupplicant_interface_remove_handlers(dev->iface,
				dev->iface_event_id,
				G_N_ELEMENTS(dev->iface_event_id));
		}

		/*
		 * Autoscan is only happening when we are in the ON state
		 */
		wifi_device_autoscan_reset(dev);
		if (state == WIFI_DEVICE_ON) {
			wifi_device_autoscan_request(dev);
		}

		if (state == WIFI_DEVICE_ON ||
					state == WIFI_DEVICE_TETHERING_ON) {
			/*
			 * If we are on, make sure that connman device is
			 * marked as powered.
			 */
			if (!connman_device_get_powered(dev->device)) {
				connman_device_set_powered(dev->device, TRUE);
			}
		}

		if (state != WIFI_DEVICE_TETHERING_ON &&
				state != WIFI_DEVICE_TURNING_TETHERING_ON) {
			/*
			 * Clean up tethering stuff
			 */
			if (dev->bridge && dev->bridged) {
				connman_inet_remove_from_bridge(dev->ifi,
								dev->bridge);
			}
			g_free(dev->bridge);
			dev->bridge = NULL;
			dev->bridged = FALSE;

			if (dev->tethering) {
				struct connman_technology *t = dev->tethering;

				dev->tethering = NULL;
				wifi_device_scan_check(dev);
				connman_technology_tethering_notify(t, FALSE);
			}
		}

		if (state == WIFI_DEVICE_OFF ||
				state == WIFI_DEVICE_UNDEFINED) {
			/*
			 * If we are off, make sure that connman device is
			 * marked as powered off.
			 */
			if (!connman_device_get_powered(dev->device)) {
				connman_device_set_powered(dev->device, FALSE);
			}
		}
	}
}

static void wifi_device_newlink(unsigned int flags, unsigned int change,
								void *data)
{
	struct wifi_device *dev = data;
	const unsigned int old_flags = dev->iff;

	dev->iff = flags;
	if ((old_flags & IFF_UP) != (flags & IFF_UP)) {
		DBG("interface %s", (flags & IFF_UP) ? "up" : "down");
	}
	if ((old_flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			DBG("carrier on");
			if (dev->tethering && dev->bridge && !dev->bridged) {
				DBG("index %d bridge %s", dev->ifi,
								dev->bridge);
				if (connman_inet_add_to_bridge(dev->ifi,
							dev->bridge) == 0) {
					dev->bridged = TRUE;
				}
			}
		} else {
			DBG("carrier off");
		}
	}
}

static void wifi_device_update_screen_state(struct wifi_device *dev)
{
	const gboolean active =
		(dev->mce_display->state != MCE_DISPLAY_STATE_OFF) ||
		(dev->mce_tklock->mode != MCE_TKLOCK_MODE_LOCKED);

	if (dev->screen_active != active) {
		DBG("screen %sactive", active ? "" : "in");
		dev->screen_active = active;
		if (active) {
			wifi_device_active_scan_schedule(dev);
			wifi_device_autoscan_restart(dev);
		}
	}
}

static void wifi_device_display_event(MceDisplay *display, void *data)
{
	wifi_device_update_screen_state(data);
}

static void wifi_device_tklock_event(MceTklock *tklock, void *data)
{
	wifi_device_update_screen_state(data);
}

static struct wifi_device *wifi_device_new(GSupplicant *supplicant,
						struct connman_device *device)
{
	int index = connman_device_get_index(device);
	if (index >= 0) {
		struct wifi_device *dev = g_slice_new0(struct wifi_device);

		connman_device_set_data(device, dev);
		dev->supplicant = gsupplicant_ref(supplicant);
		dev->device = connman_device_ref(device);
		dev->autoscan_interval_sec = WIFI_AUTOSCAN_MIN_SEC;
		dev->bss_pending = g_hash_table_new(g_str_hash, g_str_equal);
		dev->bssid_map = g_hash_table_new_full(g_bytes_hash,
					g_bytes_equal, wifi_bytes_unref, NULL);
		dev->bss_net = g_hash_table_new_full(g_str_hash,
					g_str_equal, g_free, NULL);
		dev->ident_net = g_hash_table_new_full(g_str_hash,
					g_str_equal, g_free, NULL);
		dev->ifi = index;
		dev->watch = connman_rtnl_add_newlink_watch(index,
						wifi_device_newlink, dev);

		/* Track display state */
		dev->mce_display = mce_display_new();
		dev->mce_display_event_id[DISPLAY_EVENT_VALID] =
			mce_display_add_valid_changed_handler(dev->mce_display,
				wifi_device_display_event, dev);
		dev->mce_display_event_id[DISPLAY_EVENT_STATE] =
			mce_display_add_state_changed_handler(dev->mce_display,
				wifi_device_display_event, dev);

		/* Track lock state */
		dev->mce_tklock = mce_tklock_new();
		dev->mce_tklock_event_id[TKLOCK_EVENT_VALID] =
			mce_tklock_add_valid_changed_handler(dev->mce_tklock,
				wifi_device_tklock_event, dev);
		dev->mce_tklock_event_id[TKLOCK_EVENT_MODE] =
			mce_tklock_add_mode_changed_handler(dev->mce_tklock,
				wifi_device_tklock_event, dev);

		wifi_device_update_screen_state(dev);
		return dev;
	} else {
		DBG("no index!");
		return NULL;
	}
}

static void wifi_device_delete(struct wifi_device *dev)
{
	wifi_device_reset(dev);
	wifi_device_remove_all_networks(dev);
	wifi_device_autoscan_stop(dev);
	wifi_device_drop_interface(dev);
	wifi_device_tp_free(dev->tp);
	connman_rtnl_remove_watch(dev->watch);
	if (dev->device) {
		connman_device_set_powered(dev->device, FALSE);
		connman_device_set_data(dev->device, NULL);
		connman_device_unref(dev->device);
	}
	if (dev->connect_next_id) {
		g_source_remove(dev->connect_next_id);
	}
	if (dev->scan_start_timeout_id) {
		g_source_remove(dev->scan_start_timeout_id);
	}
	if (dev->autoscan_holdoff_timer_id) {
		g_source_remove(dev->autoscan_holdoff_timer_id);
	}
	if (dev->pending) {
		g_cancellable_cancel(dev->pending);
	}
	mce_display_remove_handlers(dev->mce_display,
		dev->mce_display_event_id, DISPLAY_EVENT_COUNT);
	mce_display_unref(dev->mce_display);
	mce_tklock_remove_handlers(dev->mce_tklock,
		dev->mce_tklock_event_id, TKLOCK_EVENT_COUNT);
	mce_tklock_unref(dev->mce_tklock);
	gsupplicant_unref(dev->supplicant);
	g_hash_table_destroy(dev->bss_pending);
	g_hash_table_destroy(dev->bssid_map);
	g_hash_table_destroy(dev->bss_net);
	g_hash_table_destroy(dev->ident_net);
	g_slist_free_full(dev->active_scans, wifi_bytes_unref);
	g_free(dev->bridge);
	g_slice_free(struct wifi_device, dev);
}

static void wifi_device_delete1(gpointer dev)
{
	wifi_device_delete(dev);
}

/*==========================================================================*
 * Network driver
 *==========================================================================*/

static int wifi_network_driver_probe(struct connman_network *network)
{
	DBG("network %p", network);
	return 0;
}

static void wifi_network_driver_remove(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);

	DBG("network %p device %p", network, device);
	if (device) {
		struct wifi_device *dev = connman_device_get_data(device);
		struct wifi_network *net = connman_network_get_data(network);
		if (dev && net) {
			wifi_device_remove_network(dev, net);
		}
	}
}

static int wifi_network_driver_connect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);

	DBG("network %p device %p", network, device);
	if (device) {
		struct wifi_device *dev = connman_device_get_data(device);
		struct wifi_network *net = connman_network_get_data(network);
		if (dev && net) {
			if (dev->selected == net) {
				return wifi_network_connect(net);
			} else {
				if (dev->connect_next != net) {
					/*
					 * A different network was scheduled
					 * to connect. Drop it.
					 */
					if (dev->connect_next) {
						wifi_network_disconnect(
							dev->connect_next);
					}
				}
				dev->connect_next = net;
				wifi_network_set_state(net,
					WIFI_NETWORK_PREPARING_TO_CONNECT);
				return wifi_device_connect_next(dev);
			}
		}
	}
	return (-ENODEV);
}

static int wifi_network_driver_disconnect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);

	DBG("network %p device %p", network, device);
	if (device) {
		struct wifi_device *dev = connman_device_get_data(device);
		struct wifi_network *net = connman_network_get_data(network);
		if (dev && net) {
			if (dev->connect_next == net) {
				/* It never actually started to connect */
				dev->connect_next = NULL;
			}
			return wifi_network_disconnect(net);
		}
	}
	return (-ENODEV);
}

static struct connman_network_driver wifi_network_driver = {
	.name		= "wifi",
	.type		= CONNMAN_NETWORK_TYPE_WIFI,
	.priority	= CONNMAN_NETWORK_PRIORITY_LOW,
	.probe		= wifi_network_driver_probe,
	.remove		= wifi_network_driver_remove,
	.connect	= wifi_network_driver_connect,
	.disconnect	= wifi_network_driver_disconnect,
};

/*==========================================================================*
 * Device driver
 *==========================================================================*/

static int wifi_device_driver_probe(struct connman_device *device);
static void wifi_device_driver_remove(struct connman_device *device);

static int wifi_device_driver_enable(struct connman_device *device)
{
	struct wifi_device *dev = connman_device_get_data(device);

	if (!dev) {
		return (-ENODEV);
	} else {
		return wifi_device_enable(dev);
	}
}

static int wifi_device_driver_disable(struct connman_device *device)
{
	struct wifi_device *dev = connman_device_get_data(device);

	if (!dev) {
		return (-ENODEV);
	} else {
		return wifi_device_disable(dev);
	}
}

static int wifi_device_driver_scan(enum connman_service_type type,
			struct connman_device *device,
			const char *ssid, unsigned int ssid_len,
			const char *identity, const char *passphrase,
			const char *security, void *user_data)
{
	struct wifi_device *dev = connman_device_get_data(device);

	if (!dev) {
		return (-ENODEV);
	} else if (type != CONNMAN_SERVICE_TYPE_WIFI &&
				type != CONNMAN_SERVICE_TYPE_UNKNOWN) {
		DBG("only WiFi scans are supported");
		return (-EINVAL);
	} else {
		return wifi_device_scan(dev, ssid, ssid_len, identity,
					passphrase, security, user_data);
	}
}

static int wifi_device_driver_set_regdom(struct connman_device *device,
							const char *country)
{
	struct wifi_device *dev = connman_device_get_data(device);

	if (!dev) {
		return (-ENODEV);
	} else if (!gsupplicant_interface_set_country(dev->iface, country)) {
		return (-EINVAL);
	} else {
		return 0;
	}
}

static struct connman_device_driver wifi_device_driver = {
	.name		= "wifi",
	.type		= CONNMAN_DEVICE_TYPE_WIFI,
	.priority	= CONNMAN_DEVICE_PRIORITY_LOW,
	.probe		= wifi_device_driver_probe,
	.remove		= wifi_device_driver_remove,
	.enable		= wifi_device_driver_enable,
	.disable	= wifi_device_driver_disable,
	.scan		= wifi_device_driver_scan,
	.set_regdom	= wifi_device_driver_set_regdom
};

/*==========================================================================*
 * Plugin
 *==========================================================================*/

static int wifi_plugin_set_tethering(struct wifi_plugin *plugin,
				const char *ssid, const char *passphrase,
				const char *bridge, bool enabled)
{
	GSList *l;

	if (enabled) {
		struct wifi_device *ap_dev = NULL;

		for (l = plugin->devices; l && !ap_dev; l = l->next) {
			struct wifi_device *dev = l->data;

			if (dev->supplicant->valid && (dev->supplicant->caps &
						GSUPPLICANT_CAPS_AP)) {
				ap_dev = dev;
			}
		}

		if (!ap_dev) {
			DBG("tethering not supported");
			return (-EOPNOTSUPP);
		} else if (ap_dev->state == WIFI_DEVICE_TETHERING_ON) {
			DBG("already tethering");
			return (-EALREADY);
		} else {
			/* Start tethering */
			return wifi_device_tether_start(ap_dev, plugin->tech,
						bridge, ssid, passphrase);
		}
	} else {
		for (l = plugin->devices; l; l = l->next) {
			struct wifi_device *dev = l->data;

			dev->tethering = NULL;
			wifi_device_scan_check(dev);
			wifi_device_on_start(dev);
		}
		connman_technology_tethering_notify(plugin->tech, FALSE);
		return 0;
	}
}

static void wifi_plugin_update_running(struct wifi_plugin *plugin)
{
	if (plugin->running && !plugin->supplicant->valid) {
		/* wpa_supplicant has gone south */
		DBG("wpa_supplicant is gone");
		if (plugin->running) {
			plugin->running = FALSE;
			connman_device_driver_unregister(&wifi_device_driver);
		}
	} else if (!plugin->running && plugin->supplicant->valid) {
		/* wpa_supplicant has become ready */
		DBG("wpa_supplicant is ready");
		if (connman_device_driver_register(&wifi_device_driver) >= 0) {
			plugin->running = TRUE;
		}
	}
}

static void wifi_supplicant_valid_changed(GSupplicant *wpa, void *plugin)
{
	DBG("%d", wpa->valid);
	wifi_plugin_update_running(plugin);
}

static struct wifi_plugin *wifi_plugin_new(void)
{
	struct wifi_plugin *plugin = g_new0(struct wifi_plugin, 1);
	plugin->supplicant = gsupplicant_new();
	plugin->supplicant_event_id[SUPPLICANT_EVENT_VALID] =
		gsupplicant_add_handler(plugin->supplicant,
			GSUPPLICANT_PROPERTY_VALID,
			wifi_supplicant_valid_changed, plugin);
	return plugin;
}

static void wifi_plugin_delete(struct wifi_plugin *plugin)
{
	if (plugin) {
		g_slist_free_full(plugin->devices, wifi_device_delete1);
		gsupplicant_remove_handlers(plugin->supplicant,
			plugin->supplicant_event_id, SUPPLICANT_EVENT_COUNT);
		gsupplicant_unref(plugin->supplicant);
		g_free(plugin);
	}
}

/*==========================================================================*
 * The code below requires access to the global variable
 *==========================================================================*/

static struct wifi_plugin *wifi_plugin;

static int wifi_device_driver_probe(struct connman_device *device)
{
	GASSERT(wifi_plugin);
	if (wifi_plugin) {
		struct wifi_device *dev =
			wifi_device_new(wifi_plugin->supplicant, device);

		if (dev) {
			wifi_plugin->devices =
				g_slist_append(wifi_plugin->devices, dev);
			return 0;
		}
		return (-ENODEV);
	}
	return (-EFAULT);
}

static void wifi_device_driver_remove(struct connman_device *device)
{
	struct wifi_device *dev = connman_device_get_data(device);

	DBG("device %p wifi %p", device, dev);
	GASSERT(wifi_plugin);
	if (wifi_plugin && dev) {
		wifi_plugin->devices =
			g_slist_remove(wifi_plugin->devices, dev);
		wifi_device_delete(dev);
	}
}

static int wifi_tech_driver_probe(struct connman_technology *tech)
{
	if (wifi_plugin) {
		GASSERT(!wifi_plugin->tech);
		wifi_plugin->tech = tech;
		return 0;
	}
	return (-EFAULT);
}

static void wifi_tech_driver_remove(struct connman_technology *tech)
{
	if (wifi_plugin) {
		wifi_plugin->tech = NULL;
	}
}

static int wifi_tech_driver_set_tethering(struct connman_technology *tech,
				const char *ident, const char *passphrase,
				const char *bridge, bool enabled)
{
	if (wifi_plugin && wifi_plugin->tech) {
		GASSERT(wifi_plugin->tech == tech);
		return wifi_plugin_set_tethering(wifi_plugin, ident,
					passphrase, bridge, enabled);
	}
	return (-EFAULT);
}

static struct connman_technology_driver wifi_tech_driver = {
	.name		= "wifi",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.probe		= wifi_tech_driver_probe,
	.remove		= wifi_tech_driver_remove,
	.set_tethering	= wifi_tech_driver_set_tethering
};

static int sailfish_wifi_init(void)
{
	int err;

	if (__connman_plugin_enabled("wifi")) {
		connman_info("wifi plugin is used instead of sailfish_wifi");
		return (-EOPNOTSUPP);
	}

	DBG("");
	wifi_gsupplicant_log_notify(NULL);
	wifi_mce_debug_notify(NULL);

	GASSERT(!wifi_plugin);
	wifi_plugin = wifi_plugin_new();
	err = connman_network_driver_register(&wifi_network_driver);
	if (err >= 0) {
		err = connman_technology_driver_register(&wifi_tech_driver);
		if (err >= 0) {
			wifi_plugin_update_running(wifi_plugin);
			return 0;
		}
		connman_network_driver_unregister(&wifi_network_driver);
	}

	wifi_plugin_delete(wifi_plugin);
	wifi_plugin = NULL;
	return err;
}

static void sailfish_wifi_exit(void)
{
	DBG("");
	GASSERT(wifi_plugin);
	connman_technology_driver_unregister(&wifi_tech_driver);
	connman_device_driver_unregister(&wifi_device_driver);
	connman_network_driver_unregister(&wifi_network_driver);
	wifi_plugin_delete(wifi_plugin);
	wifi_plugin = NULL;
}

CONNMAN_PLUGIN_DEFINE(sailfish_wifi, "Sailfish WiFi plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		sailfish_wifi_init, sailfish_wifi_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
