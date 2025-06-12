PROG=wolod
SRCS=wolod.c
MAN=wolod.1
DEBUG=-g
WARNINGS=yes

BINOWN=root
BINGRP=_wolod
BINMODE=4550

BINDIR?=/opt/local/sbin
MANDIR?=/opt/local/share/man/man

.include <bsd.prog.mk>
