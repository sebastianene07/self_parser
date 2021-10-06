CC := gcc
CFLAGS := -Wall -g
OUT := self_parser sinject

all: self_parser sinject

self_parser: self_parser.c
	$(CC) $^ $(CFLAGS) -o $@

sinject: sinject.c
	$(CC) $^ $(CFLAGS) -o $@

clean:
	rm -f $(OUT)
