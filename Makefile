CC := gcc
CFLAGS := -Wall -g
OUT := self_parser sinject target payload

all: self_parser sinject payload target

self_parser: self_parser.c
	$(CC) $^ $(CFLAGS) -o $@

target: target.c
	$(CC) $< $(CFLAGS) -o $@

sinject: sinject.c
	$(CC) $< $(CFLAGS) -o $@

payload: payload.c
	$(CC)  -fPIC -nolibc -nostdlib $< -o $@

.PHONY: clean
clean:
	rm -f $(OUT)

