CC=gcc
CFLAGS=-Wall -Werror
SRC=helodnscheck.c
BIN=helodnscheck

all: $(BIN)

$(BIN):
	$(CC) $(CFLAGS) $(SRC) -lresolv -o $@

clean:
	rm -f $(BIN)

.PHONY: all
