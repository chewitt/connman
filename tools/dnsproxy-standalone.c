#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <glib.h>

#include "connman.h"

/*
 * This is a minimal connman setup  that only runs the internal dnsproxy
 * component for testing. The advantage is that we can do a full integration
 * test of the dnsproxy logic without requiring root privileges or setting up
 * other complexities like D-Bus access etc.
 */

static GMainLoop *main_loop = NULL;

static void usage(const char *prog)
{
	fprintf(stderr, "%s: <listen-port> <dns-domain> <dns-server>\n", prog);
	exit(1);
}

static unsigned int to_uint(const char *s)
{
	char *end = NULL;
	unsigned int ret;

	ret = strtoul(s, &end, 10);

	if (*end != '\0') {
		fprintf(stderr, "invalid argument: %s", s);
		exit(1);
	}

	return ret;
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		printf("Terminating due to signal\n");
		g_main_loop_quit(main_loop);
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

int main(int argc, const char **argv)
{
	unsigned int port = 0;
	const char *domain = argv[2];
	const char *server = argv[3];
	guint signal = 0;

	if (argc != 4)
	{
		usage(argv[0]);
	}

	port = to_uint(argv[1]);

	__connman_util_init();
	printf("Listening on local port %u\n", port);
	__connman_dnsproxy_set_listen_port(port);

	if (__connman_dnsproxy_init() < 0) {
		fprintf(stderr, "failed to initialize dnsproxy\n");
		return 1;
	}

	printf("Using DNS server %s on domain %s\n", server, domain);

	if (__connman_dnsproxy_append(-1, domain, server) < 0) {
		fprintf(stderr, "failed to add DNS server\n");
		return 1;
	}

	/* we need to trick a bit to make the server entry enter "enabled"
	 * state in dnsproxy. Appending and removing an arbitrary entry causes
	 * "enable_fallback()" to be called which does what we want. Doesn't
	 * make much sense but it is good enough for the standalone server at
	 * the moment.
	 */
	__connman_dnsproxy_append(15, domain, server);
	__connman_dnsproxy_remove(15, domain, server);

	signal = setup_signalfd();

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	__connman_dnsproxy_cleanup();
	__connman_util_cleanup();
	g_source_remove(signal);

	return 0;
}
