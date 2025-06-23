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
#include <assert.h>
#include <pwd.h>

#include "dhcp.h"

#define DHCP_USER "_dhcp"

struct bootp_packet {
	uint8_t		op;		/* Message opcode/type */
	uint8_t		htype;		/* Hardware addr type */
	uint8_t		hlen;		/* Hardware addr length */
	uint8_t		hops;
	uint32_t	xid;		/* Transaction ID */
	uint16_t	secs;
	uint16_t	flags;		/* Flag bits */
	struct in_addr	ciaddr;		/* Client IP address */
	struct in_addr	yiaddr;		/* Your client IP address */
	struct in_addr	siaddr;		/* Server IP address */
	struct in_addr	giaddr;		/* Gateway IP address */
	unsigned char	chaddr[16];	/* Client hardware address */
	char		sname[64];	/* Server name */
	char		file[128];	/* Boot filename */
	char		vend[64];	/* Vendor specific area */
};

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-BLu] [-c client-address] [-H chaddr]\n",
	    __progname);
	fprintf(stderr, "\t[-l local-addr] [-p local-port] [-P relay-port]\n");
	fprintf(stderr, "\t[-s siaddr] [-t type] [-T lt]"
	    " -r relay -h mac-addr\n");

	exit(1);
}

static int
dhcp_connect(int s, const char *rhost, const char *rport)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int connected = 0;

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
    const char *rhost, const char *rport, int bindany)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int serrno = 0;
	int s = -1;
	const char *cause = NULL;

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

		if (bindany && setsockopt(s, SOL_SOCKET, SO_BINDANY,
		    &bindany, sizeof(bindany)) == -1) {
			cause = "bindany";
			serrno = errno;
			close(s);
			s = -1;
			continue;
		}

		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			serrno = errno;
			close(s);
			s = -1;
			continue;
		}

		if (dhcp_connect(s, rhost, rport) == -1) {
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

	return (s);
}

static void
ip_resolve(const char *name, struct in_addr *addr)
{
	struct addrinfo hints, *res, *res0;
	struct sockaddr_in *sin = NULL;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(name, NULL, &hints, &res0);
	if (error)
		errx(1, "client address %s: %s", name, gai_strerror(error));

	for (res = res0; res != NULL; res = res->ai_next) {
		if (res->ai_family != PF_INET)
			continue;

		sin = (struct sockaddr_in *)res->ai_addr;
		break;
	}

	if (sin == NULL)
		errx(1, "client addresss %s: not found", name);

	*addr = sin->sin_addr;

	freeaddrinfo(res0);
}

#define WOL_EA_NUM 17

#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))

static void
dhcp_send_wol(int s, const struct ether_addr *Ha, const struct ether_addr *ea,
    const struct in_addr *yiaddr, const struct in_addr *siaddr,
    const struct in_addr *giaddr, uint16_t flags, uint8_t dtype, uint32_t tm)
{
	struct iovec iov[6];
	struct dhcp_packet p;
	uint8_t dho[] = { DHO_DHCP_MESSAGE_TYPE, 1, dtype };
	uint8_t sid[2 + sizeof(*siaddr)];
	uint8_t lt[2 + sizeof(tm)];
	uint8_t wol[2 + (WOL_EA_NUM * sizeof(*ea))];
	uint8_t end[] = { DHO_END, 0 };
	unsigned int i;
	uint8_t *t;

	memset(&p, 0, sizeof(p));

	p.op = BOOTREPLY;
	p.htype = HTYPE_ETHER;
	p.hlen = sizeof(*Ha);
	p.hops = 1;
	p.xid = htonl(arc4random());
	p.secs = htons(7);
	p.flags = htons(flags);
	//p.ciaddr = 0;
	p.yiaddr = *yiaddr;
	p.siaddr = *siaddr;
	p.giaddr = *giaddr;
	memcpy(p.chaddr, Ha, sizeof(*Ha));
	memcpy(p.cookie, DHCP_OPTIONS_COOKIE, DHCP_OPTIONS_COOKIE_LEN);

	sid[0] = DHO_DHCP_SERVER_IDENTIFIER;
	sid[1] = sizeof(*siaddr);
	memcpy(sid + 2, siaddr, sizeof(*siaddr));

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

	i = 0;
	iov[i].iov_base = &p;
	iov[i].iov_len = sizeof(p);
	i++;

	iov[i].iov_base = dho;
	iov[i].iov_len = sizeof(dho);
	i++;

	iov[i].iov_base = sid;
	iov[i].iov_len = sizeof(sid);
	i++;

	if (tm != htonl(0)) {
		lt[0] = DHO_DHCP_LEASE_TIME;
		lt[1] = sizeof(tm);
		memcpy(lt + 2, &tm, sizeof(tm));

		iov[i].iov_base = lt;
		iov[i].iov_len = sizeof(lt);
		i++;
	}

	iov[i].iov_base = wol;
	iov[i].iov_len = sizeof(wol);
	i++;

	iov[i].iov_base = end;
	iov[i].iov_len = sizeof(end);
	i++;

	assert(i <= nitems(iov));

	if (writev(s, iov, i) == -1)
		err(1, "dhcp send");
}

static void
bootp_send_wol(int s, const struct ether_addr *Ha, const struct ether_addr *ea,
    const struct in_addr *yiaddr, const struct in_addr *siaddr,
    const struct in_addr *giaddr, uint16_t flags)
{
	struct iovec iov[2];
	struct bootp_packet p;
	struct ether_addr wol[WOL_EA_NUM];
	size_t i;

	memset(&p, 0, sizeof(p));

	p.op = BOOTREPLY;
	p.htype = HTYPE_ETHER;
	p.hlen = sizeof(*Ha);
	p.hops = 1;
	p.xid = htonl(arc4random());
	p.secs = htons(7);
	p.flags = htons(flags);
	/* p.ciaddr = htonl(0); */
	p.yiaddr = *yiaddr;
	p.siaddr = *siaddr;
	p.giaddr = *giaddr;
	memcpy(p.chaddr, Ha, sizeof(*Ha));

	/* the first address is the broadcast address */
	memset(&wol[0], 0xff, sizeof(wol[0]));
	for (i = 1; i < nitems(wol); i++) {
		wol[i] = *ea;
	}

	iov[0].iov_base = &p;
	iov[0].iov_len = sizeof(p);
	iov[1].iov_base = wol;
	iov[1].iov_len = sizeof(wol);

	if (writev(s, iov, nitems(iov)) == -1)
		err(1, "bootp send");
}


#define streq(_a, _b) (strcmp((_a), (_b)) == 0)

static uint8_t
dhcp_type(const char *arg)
{
	uint8_t rv;
	const char *errstr;

	if (streq(arg, "discover"))
		return (DHCPDISCOVER);
	if (streq(arg, "offer"))
		return (DHCPOFFER);
	if (streq(arg, "request"))
		return (DHCPREQUEST);
	if (streq(arg, "decline"))
		return (DHCPDECLINE);
	if (streq(arg, "ack"))
		return (DHCPACK);
	if (streq(arg, "nak") || streq(arg, "nack"))
		return (DHCPNAK);
	if (streq(arg, "release"))
		return (DHCPRELEASE);
	if (streq(arg, "inform"))
		return (DHCPINFORM);

	rv = strtonum(arg, 0, 0xff, &errstr);
	if (errstr != NULL)
		errx(1, "DHCP type %s: %s", arg, errstr);

	return (rv);
}

static uint32_t
lease_time(const char *arg)
{
	uint32_t rv;
	const char *errstr;

	rv = strtonum(arg, 0, 60 * 60 * 24 * 7, &errstr);
	if (errstr != NULL)
		errx(1, "lease time %s: %s", arg, errstr);

	return (htonl(rv));
}

static int
ether_resolve(struct ether_addr *res, const char *name)
{
	struct ether_addr *ea;

	ea = ether_aton(name);
	if (ea == NULL)
		return (-1);

	*res = *ea;

	return (0);
}

int
main(int argc, char *argv[])
{
	int ch;

	const char *yhost = NULL;
	const char *ehost = NULL;
	const char *Hhost = NULL;
	const char *lhost = NULL;
	const char *lport = "0";
	const char *rhost = NULL;
	const char *shost = NULL;
	const char *rport = "bootps";
	struct sockaddr_in sin;
	socklen_t slen;
	struct in_addr siaddr, giaddr, yiaddr = { 0 };
	struct ether_addr ea, Ha;
	uint16_t flags = BOOTP_BROADCAST;
	uint8_t dtype = 0xff;
	uint32_t lt = htonl(0);
	int dhcp = 1;
	int bindany = 0;
	int uid;
	struct passwd *pw = NULL;

	uid = geteuid();

	int s;

	while ((ch = getopt(argc, argv, "Bc:h:H:Ll:p:P:r:s:t:T:u")) != -1) {
		switch (ch) {
		case 'B':
			dhcp = 0;
			break;
		case 'c':
			yhost = optarg;
			break;
		case 'h':
			ehost = optarg;
			break;
		case 'H':
			Hhost = optarg;
			break;
		case 'L':
			if (uid != 0)
				errx(1, "must be root to use bindany");
			bindany = 1;
			break;
		case 'l':
			lhost = optarg;
			break;
		case 'p':
			lport = optarg;
			break;
		case 'P':
			rport = optarg;
			break;
		case 'r':
			rhost = optarg;
			break;
		case 's':
			shost = optarg;
			break;
		case 't':
			dtype = dhcp_type(optarg);
			break;
		case 'T':
			lt = lease_time(optarg);
			break;
		case 'u':
			flags = 0;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (ehost == NULL || rhost == NULL)
		usage();

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();

	if (Hhost != NULL && flags == 0)
		errx(1, "-H and -u are incompatible");

	if (uid == 0) {
		pw = getpwnam(DHCP_USER);
		if (pw == NULL)
			errx(1, "no %s user", DHCP_USER);
	}

	s = dhcp_connection(lhost, lport, rhost, rport, bindany);
	/* error handled by dhcp_connection */

	if (shutdown(s, SHUT_RD) == -1)
		err(1, "shutdown dhcp recv");

	if (pw != NULL) {
		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			err(1, "unable to revoke privs to %s", DHCP_USER);
	}

	if (yhost != NULL) {
		ip_resolve(yhost, &yiaddr);
		/* ip_resolve exits on errors */
	}

	if (ether_resolve(&ea, ehost) == -1)
		err(1, "%s", ehost);

	if (Hhost == NULL)
		Ha = ea;
	else if (ether_resolve(&Ha, Hhost) == -1)
		err(1, "%s", Hhost);

	if (shost == NULL) {
		slen = sizeof(sin);
		if (getsockname(s, (struct sockaddr *)&sin, &slen) == -1)
			err(1, "getsockname");
		siaddr = sin.sin_addr;
	} else
		ip_resolve(shost, &siaddr);

	slen = sizeof(sin);
	if (getpeername(s, (struct sockaddr *)&sin, &slen) == -1)
		err(1, "getsockname");
	giaddr = sin.sin_addr;

	if (dhcp) {
		dhcp_send_wol(s, &Ha, &ea, &yiaddr, &siaddr, &giaddr,
		    flags, dtype, lt);
	} else {
		bootp_send_wol(s, &Ha, &ea, &yiaddr, &siaddr, &giaddr,
		    flags);
	}

	return (0);
}
