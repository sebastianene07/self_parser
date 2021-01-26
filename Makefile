CC := gcc
CFLAGS := -Wall -g
OUT := self_parser
SRCS := self_parser.c

all:
	$(CC) $(SRCS) $(CFLAGS) -o $(OUT)

clean:
	rm -f $(OUT)
