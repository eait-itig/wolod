PROG=wolod
SRCS=wolod.c
MAN=wolod.1
DEBUG=-g
WARNINGS=yes

BINDIR?=/opt/local/sbin
MANDIR?=/opt/local/share/man/man

.include <bsd.prog.mk>
