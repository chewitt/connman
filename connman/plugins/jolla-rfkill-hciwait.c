/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015 Jolla Ltd.
 *  Contact: Hannu Mallat <hannu.mallat@jollamobile.com>
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

/* Notify systemd when a BT HCI interface (any of them) is available */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

int debug = 0;

enum hci_status {
	HCI_ERROR = -1,
	HCI_CONTINUE = 0,
	HCI_DONE = 1,
};

static void ERROR(const char *format, ...)
{
	va_list v;
	va_start(v, format);
	vsyslog(LOG_ERR, format, v);
	va_end(v);
}

static void INFO(const char *format, ...)
{
	va_list v;
	va_start(v, format);
	vsyslog(LOG_INFO, format, v);
	va_end(v);
}

static void DEBUG(const char *format, ...)
{
	if (debug) {
		va_list v;
		va_start(v, format);
		vsyslog(LOG_DEBUG, format, v);
		va_end(v);
	}
}

/* Return the index of the first found adapter, or -1 if there are none.
 *
 * For our purposes it doesn't matter which or how many adapters there
 * are present, as long as there's one.
 */
static int hci_adapter_index(void)
{
	struct hci_dev_list_req *dev_list_req = NULL;
	int hci_socket = -1;
	int index = -1;

	hci_socket = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (hci_socket < 0) {
		ERROR("Can't open socket: %s (%d).", strerror(errno), errno);
		goto out;
	}

	dev_list_req = calloc(sizeof(struct hci_dev_req) + sizeof(uint16_t), 1);
	if (!dev_list_req) {
		ERROR("Can't allocate buffer: %s (%d).",
			strerror(errno), errno);
		goto out;
	}

	dev_list_req->dev_num = 1;
	if (ioctl(hci_socket, HCIGETDEVLIST, dev_list_req) < 0) {
		ERROR("Can't get device list: %s (%d).", strerror(errno), errno);
		goto out;
	}

	DEBUG("%s a device.", dev_list_req->dev_num > 0
		? "Found"
		: "Did not find");

	if (dev_list_req->dev_num)
		index = dev_list_req->dev_req->dev_id;

out:
	if (hci_socket >= 0)
		close(hci_socket);

	if (dev_list_req)
		free(dev_list_req);

	return index;
}

/* Set up a file descriptor for listening for adapter appearance */
static int hci_listener_setup(void)
{
	struct sockaddr_hci hci_addr;
	struct hci_filter hci_filter;
	int hci_socket = -1;

	DEBUG("Setting up HCI event listener.");

	hci_socket = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (hci_socket < 0) {
		ERROR("Can't open socket: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	hci_filter_clear(&hci_filter);
	hci_filter_set_ptype(HCI_EVENT_PKT, &hci_filter);
	hci_filter_set_event(EVT_STACK_INTERNAL, &hci_filter);
	if (setsockopt(hci_socket, SOL_HCI, HCI_FILTER, &hci_filter,
			sizeof(hci_filter)) < 0) {
		ERROR("Can't set filter: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	memset(&hci_addr, 0, sizeof(hci_addr));
	hci_addr.hci_family = AF_BLUETOOTH;
	hci_addr.hci_dev = HCI_DEV_NONE;
	if (bind(hci_socket, (struct sockaddr *)&hci_addr,
			sizeof(hci_addr)) < 0) {
		ERROR("Can't bind HCI socket: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	DEBUG("HCI event listener set up.");

	return hci_socket;

fail:
	if (hci_socket >= 0)
		close(hci_socket);

	return -1;
}

static enum hci_status hci_event(int hci_socket)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_stack_internal *stack_internal = NULL;
	evt_si_device *device = NULL;
	ssize_t len;

	DEBUG("Reading a HCI event");

	len = read(hci_socket, buf, sizeof(buf));
	if (len < 0) {
		if (errno == EAGAIN)
			return HCI_CONTINUE;

		ERROR("Cannot read HCI socket: %s (%d)", strerror(errno), errno);
		return HCI_ERROR;
	}

	if (*ptr != HCI_EVENT_PKT)
		return HCI_CONTINUE;
	ptr++;

	if (((hci_event_hdr *) ptr)->evt != EVT_STACK_INTERNAL)
		return HCI_CONTINUE;
	ptr += HCI_EVENT_HDR_SIZE;

	stack_internal = (evt_stack_internal *) ptr;
	if (stack_internal->type == EVT_SI_DEVICE) {
		device = (evt_si_device *)&stack_internal->data;
		if (device->event == HCI_DEV_REG) {
			DEBUG("HCI device %d registered", device->dev_id);
			return HCI_DONE;
		}
	}

	return HCI_CONTINUE;
}

int main(int argc, char *argv[])
{
	char *id = NULL;
	int hci_socket = -1;
	int e = EXIT_FAILURE;
	int log_flags = LOG_PID;
	int opt;

	while ((opt = getopt(argc, argv, "ds")) != -1) {
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 's':
			log_flags |= LOG_PERROR;
			break;
		}
	}

	openlog("jolla-rfkill-hciwait", log_flags, LOG_USER);

	id = getenv("ID");
	if (!id || strcmp(id, "sbj")) {
		INFO("Not waiting for HCI events, ID='%s' not sbj",
			id ? id : "<null>");
		goto ready;
	}

	hci_socket = hci_listener_setup();
	if (hci_socket < 0)
		goto out;

	if (hci_adapter_index() >= 0)
		goto ready;

	INFO("Waiting for HCI events");

	while (1) {
		fd_set read_set;

		FD_ZERO(&read_set);
		FD_SET(hci_socket, &read_set);

		if (select(hci_socket + 1, &read_set, NULL, NULL, NULL) < 0) {
			ERROR("Cannot listen for events: %s (%d)",
				strerror(errno), errno);
			goto out;
		}

		switch (hci_event(hci_socket)) {
		case HCI_DONE:
			DEBUG("HCI interface registration seen, done.");
			goto ready;
		case HCI_CONTINUE:
			DEBUG("Continuing.");
			break;
		case HCI_ERROR:
			goto out;
		}
	}

ready:
	e = EXIT_SUCCESS;

out:
	if (hci_socket >= 0)
		close(hci_socket);

	closelog();

	exit(e);
}
