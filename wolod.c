/* */

/*
 * Copyright (c) 2018, 2020 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This code was written by David Gwynne <dlg@uq.edu.au> as part
 * of the Information Technology Infrastructure Group (ITIG) in the
 * Faculty of Engineering, Architecture and Information Technology
 * (EAIT) at the University of Queensland (UQ).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include "dhcp.h"

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-u] [-p port] [-l addr]"
	    " -h eaddr relay [rport]\n", __progname);

	exit(1);
}

static int
dhcp_connect(int s, const char *rhost, const char *rport,
    struct in_addr *giaddr)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int connected = 0;
	struct sockaddr_in *sin;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	error = getaddrinfo(rhost, rport, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	for (res = res0; res != NULL; res = res->ai_next) {
		if (res->ai_family != PF_INET)
			continue;

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1)
			continue;

		sin = (struct sockaddr_in *)res->ai_addr;
		*giaddr = sin->sin_addr;

		connected = 1;
		break;
	}

	freeaddrinfo(res0);

	if (!connected)
		return (-1);

	return (0);
}

static int
dhcp_connection(const char *lhost, const char *lport,
    const char *rhost, const char *rport,
    struct in_addr *siaddr, struct in_addr *giaddr)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int serrno = 0;
	int s = -1;
	const char *cause = NULL;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(lhost, lport, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			serrno = errno;
			continue;
		}

		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			serrno = errno;
			close(s);
			s = -1;
			continue;
		}

		if (dhcp_connect(s, rhost, rport, giaddr) == -1) {
			cause = "connect";
			serrno = errno;
			close(s);
			s = -1;
			continue;
		}

		break;
	}

	if (s == -1)
		errc(1, serrno, "%s", cause);

	freeaddrinfo(res0);

	if (getsockname(s, (struct sockaddr *)&sin, &slen) == -1)
		err(1, "getsockname");

	if (sin.sin_family != PF_INET)
		errx(1, "unexpected family");

	*siaddr = sin.sin_addr;

	return (s);
}

#define WOL_EA_NUM 17

#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))

static void
dhcp_send_wol(int s, const struct ether_addr *ea,
    const struct in_addr *siaddr, const struct in_addr *giaddr,
    uint16_t flags)
{
	struct iovec iov[4];
	struct dhcp_packet p;
	uint8_t dho[] = { DHO_DHCP_MESSAGE_TYPE, 1, DHCPINFORM };
	uint8_t wol[2 + (WOL_EA_NUM * sizeof(*ea))];
	uint8_t end[] = { DHO_END, 0 };
	unsigned int i;
	uint8_t *t;

	memset(&p, 0, sizeof(p));

	p.op = BOOTREPLY;
	p.htype = HTYPE_ETHER;
	p.hlen = sizeof(*ea);
	p.hops = 1;
	p.xid = htonl(arc4random());
	p.secs = htons(7);
	p.flags = htons(flags);
	//p.ciaddr = 0;
	//p.yiaddr = 0;
	p.siaddr = *siaddr;
	p.giaddr = *giaddr;
	memcpy(p.chaddr, ea, sizeof(*ea));
	memcpy(p.cookie, DHCP_OPTIONS_COOKIE, DHCP_OPTIONS_COOKIE_LEN);

	wol[0] = DHO_VENDOR_ENCAPSULATED_OPTIONS;
	wol[1] = sizeof(*ea) * WOL_EA_NUM;

	t = wol + 2;

	/* the first address is the broadcast address */
	memset(t, 0xff, sizeof(*ea));
	t += sizeof(*ea);
	for (i = 1; i < WOL_EA_NUM; i++) {
		memcpy(t, ea, sizeof(*ea));
		t += sizeof(*ea);
	}

	iov[0].iov_base = &p;
	iov[0].iov_len = sizeof(p);
	iov[1].iov_base = dho;
	iov[1].iov_len = sizeof(dho);
	iov[2].iov_base = wol;
	iov[2].iov_len = sizeof(wol);
	iov[3].iov_base = end;
	iov[3].iov_len = sizeof(end);

	if (writev(s, iov, nitems(iov)) == -1)
		err(1, "write");
}

int
main(int argc, char *argv[])
{
	int ch;

	const char *ehost = NULL;
	const char *lhost = NULL;
	const char *lport = "bootps";
	const char *rhost = NULL;
	const char *rport = "bootps";
	struct in_addr siaddr, giaddr;
	const struct ether_addr *ea;
	uint16_t flags = BOOTP_BROADCAST;

	int s;

	while ((ch = getopt(argc, argv, "h:l:p:u")) != -1) {
		switch (ch) {
		case 'h':
			ehost = optarg;
			break;
		case 'l':
			lhost = optarg;
			break;
		case 'p':
			lport = optarg;
			break;
		case 'u':
			flags = 0;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (ehost == NULL)
		usage();

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 2:
		rport = argv[1];
		/* FALLTHROUGH */
	case 1:
		rhost = argv[0];
		break;
	default:
		usage();
		/* NOTREACHED */
	}

	s = dhcp_connection(lhost, lport, rhost, rport, &siaddr, &giaddr);
	/* error handled by dhcp_connection */

	ea = ether_aton(ehost);
	if (ea == NULL)
		err(1, "%s", ehost);

	dhcp_send_wol(s, ea, &siaddr, &giaddr, flags);

	return (0);
}
