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
DEPS = $(SRCS:.c=.d)
BIN  = neighbot

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -c $<

-include $(DEPS)

clean:
	rm -f $(BIN) $(OBJS) $(DEPS) fuzz_parse fuzz_dbload fuzz_ouiload
	rm -f tests/test_parse tests/test_dbload tests/test_ouiload

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

# Fuzz targets (requires clang with libFuzzer support)
FUZZ_CC      = clang
FUZZ_CFLAGS  = -std=c11 -g -O1 -fno-omit-frame-pointer $(_GNU_SOURCE)
FUZZ_CFLAGS += -fsanitize=fuzzer,address,undefined
FUZZ_LDFLAGS = -fsanitize=fuzzer,address,undefined -lpcap

fuzz: fuzz_parse fuzz_dbload fuzz_ouiload

fuzz_parse: fuzz/fuzz_parse.c parse.c db.c log.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_parse.c parse.c db.c log.c $(FUZZ_LDFLAGS)

fuzz_dbload: fuzz/fuzz_dbload.c db.c log.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_dbload.c db.c log.c $(FUZZ_LDFLAGS)

fuzz_ouiload: fuzz/fuzz_ouiload.c oui.c log.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_ouiload.c oui.c log.c $(FUZZ_LDFLAGS)

fuzz-clean:
	rm -f fuzz_parse fuzz_dbload fuzz_ouiload

# Test harnesses (for valgrind, no sanitizers)
test: tests/test_parse tests/test_dbload tests/test_ouiload

tests/test_parse: tests/test_parse.c parse.c db.c log.c
	$(CC) $(CFLAGS) -o $@ tests/test_parse.c parse.c db.c log.c $(LDFLAGS)

tests/test_dbload: tests/test_dbload.c db.c log.c
	$(CC) $(CFLAGS) -o $@ tests/test_dbload.c db.c log.c $(LDFLAGS)

tests/test_ouiload: tests/test_ouiload.c oui.c log.c
	$(CC) $(CFLAGS) -o $@ tests/test_ouiload.c oui.c log.c $(LDFLAGS)

test-clean:
	rm -f tests/test_parse tests/test_dbload tests/test_ouiload

.PHONY: all clean install install-systemd install-rcd oui-update uninstall
.PHONY: fuzz fuzz_parse fuzz_dbload fuzz_ouiload fuzz-clean
.PHONY: test test-clean
