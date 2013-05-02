CC=gcc
CFLAGS=-Wall -Werror
SRC=helodnscheck.c
BIN=helodnscheck
PLUGINSDIR=/var/qmail/plugins


all: $(BIN)

$(BIN):
	$(CC) $(CFLAGS) $(SRC) -lresolv -o $@

install:
	install $(BIN) $(PLUGINSDIR)

clean:
	rm -f $(BIN)

.PHONY: all
