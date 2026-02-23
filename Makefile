PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/sbin
MANDIR  ?= $(PREFIX)/share/man
DBDIR   ?= /var/neighbot

CC      ?= cc
CFLAGS  ?= -O2 -pipe
CFLAGS  += -std=c11
CFLAGS  += -Wall -Wextra -Wpedantic
LDFLAGS += -lpcap

# _GNU_SOURCE needed on Linux for strptime(3) and daemon(3)
_GNU_SOURCE != [ "$$(uname -s)" = Linux ] && echo -D_GNU_SOURCE || true
CFLAGS  += $(_GNU_SOURCE)

SRCS = neighbot.c log.c db.c parse.c notify.c capture.c oui.c probe.c
OBJS = $(SRCS:.c=.o)
BIN  = neighbot

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(BIN) $(OBJS)

oui.txt:
	curl -sL https://standards-oui.ieee.org/oui/oui.txt | \
	awk '/\(hex\)/ { gsub(/-/, ":", $$1); v=""; \
	for (i=3; i<=NF; i++) v = v (i>3?" ":"") $$i; \
	print tolower($$1) " " v }' > oui.txt

oui-update:
	rm -f oui.txt
	$(MAKE) oui.txt

install: $(BIN) oui.txt
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 neighbot.8 $(DESTDIR)$(MANDIR)/man8/neighbot.8
	install -d $(DESTDIR)$(DBDIR)
	install -m 644 oui.txt $(DESTDIR)$(DBDIR)/oui.txt

install-systemd: install
	install -d $(DESTDIR)/etc/systemd/system
	install -m 644 neighbot.service $(DESTDIR)/etc/systemd/system/neighbot.service

install-rcd: install
	install -m 755 neighbot.rc $(DESTDIR)/etc/rc.d/neighbot

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(MANDIR)/man8/neighbot.8
	rm -f $(DESTDIR)$(DBDIR)/oui.txt
	rm -f $(DESTDIR)/etc/systemd/system/neighbot.service
	rm -f $(DESTDIR)/etc/rc.d/neighbot

.PHONY: all clean install install-systemd install-rcd oui-update uninstall
