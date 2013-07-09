CC=gcc
CFLAGS=-Wall -Werror
SRC=helodnscheck.c
BIN=helodnscheck
PLUGINSDIR=/var/qmail/plugins


all: $(BIN)

$(BIN):
	$(CC) $(CFLAGS) $(SRC) -lresolv -o $@

test:
	$(CC) -DTEST $(CFLAGS) $(SRC) -lresolv -o testhelo
	python ./test_helodnscheck.py

install:
	install $(BIN) $(PLUGINSDIR)

clean:
	rm -f $(BIN)

.PHONY: all
