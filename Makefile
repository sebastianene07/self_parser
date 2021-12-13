CC := gcc
CFLAGS := -Wall -g
OUT := self_parser sinject target_shellcode

all: self_parser sinject target_shellcode shellcode

target_shellcode: target_shellcode.c
	$(CC) $^ -m32 -z nodeflib -L /usr/lib/debug/lib/libc6-prof/x86_64-linux-gnu/  $(CFLAGS) -o $@

shellcode: shellcode.s
	$(CC) $^ -m32 -nostartfiles -nodefaultlibs $(CFLAGS) -o $@
	#xxd -s0x1000 -i -l0x30 shellcode > shell.h

self_parser: self_parser.c
	$(CC) $^ $(CFLAGS) -o $@

sinject: sinject.c
	$(CC) $^ $(CFLAGS) -o $@

clean:
	rm -f $(OUT)
