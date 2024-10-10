#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stddef.h>

#define NOP \
        __asm__ __volatile__(\
                "nop"\
                :\
                :\
                :);

#define END_PADDING\
    NOP\
    NOP\
    NOP\
    NOP

static int my_write(int fd, const void *buf, size_t size)
{
    long result;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
        : "cc", "rcx", "r11", "memory");
    return result;
}

void _start(void)
{
        char txt[] = {'h','a','c','k','e','d','\0'};

        my_write(1, txt, 7);

        /* This is the instruction that we will patch to go to the original entry point */
        END_PADDING
}
