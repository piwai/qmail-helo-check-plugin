CC=gcc
CFLAGS=-Wall -Werror
SRC=helodnscheck.c

all: helodnscheck

helodnscheck:
	$(CC) $(CFLAGS) $(SRC) -lresolv -o $@

.PHONY: all
