#
# Copyright (C) 2014-2021 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

VERSION=0.02.08
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2

#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8
BASHDIR=/usr/share/bash-completion/completions

OBJS = smemstat.o 

smemstat: $(OBJS) Makefile
	$(CC) $(CFLAGS) $(OBJS) -lm -lncursesw -o $@ $(LDFLAGS)

smemstat.8.gz: smemstat.8
	gzip -c $< > $@

dist:
	rm -rf smemstat-$(VERSION)
	mkdir smemstat-$(VERSION)
	cp -rp Makefile smemstat.c smemstat.8 COPYING README scripts \
		snap .travis.yml bash-completion smemstat-$(VERSION)
	tar -Jcf smemstat-$(VERSION).tar.xz smemstat-$(VERSION)
	rm -rf smemstat-$(VERSION)

clean:
	rm -f smemstat smemstat.o smemstat.8.gz
	rm -f smemstat-$(VERSION).tar.xz
	rm -f $(OBJS)

install: smemstat smemstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp smemstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp smemstat.8.gz ${DESTDIR}${MANDIR}
	mkdir -p ${DESTDIR}${BASHDIR}
	cp bash-completion/smemstat ${DESTDIR}${BASHDIR}
