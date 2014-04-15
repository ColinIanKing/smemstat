VERSION=0.01.04
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' 

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

OBJS = smemstat.o 

smemstat: $(OBJS) Makefile
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

smemstat.8.gz: smemstat.8
	gzip -c $< > $@

dist:
	rm -rf smemstat-$(VERSION)
	mkdir smemstat-$(VERSION)
	cp -rp Makefile smemstat.c smemstat.8 COPYING scripts smemstat-$(VERSION)
	tar -zcf smemstat-$(VERSION).tar.gz smemstat-$(VERSION)
	rm -rf smemstat-$(VERSION)

clean:
	rm -f smemstat smemstat.o smemstat.8.gz
	rm -f smemstat-$(VERSION).tar.gz
	rm -f $(OBJS)

install: smemstat smemstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp smemstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp smemstat.8.gz ${DESTDIR}${MANDIR}
