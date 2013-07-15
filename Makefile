CC=gcc
CFLAGS=-Wall -Werror
SRC=helodnscheck.c
BIN=helodnscheck
TESTBIN=testhelo
PLUGINSDIR=/var/qmail/plugins


all: $(BIN)

$(BIN):
	$(CC) $(CFLAGS) $(SRC) -lresolv -o $@

$(TESTBIN):
	$(CC) -DTEST $(CFLAGS) $(SRC) -lresolv -o $@

test: $(TESTBIN)
	python ./test/test_helodnscheck.py

install:
	install $(BIN) $(PLUGINSDIR)

clean:
	rm -f $(BIN) $(TESTBIN)

.PHONY: all
