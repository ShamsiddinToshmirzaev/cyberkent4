#include "session.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 * SROP helper material baked into the binary:
 *   phantom_syscall : `syscall ; ret`
 *   phantom_pop_rax : `pop rax ; ret`
 *   phantom_binsh   : the string "/bin/sh"
 * None of these are reachable through normal control flow; they exist only so
 * a sigreturn frame can be assembled entirely from binary (PIE) addresses.
 */
__asm__(
    ".text\n"
    ".globl phantom_pop_rax\n"
    "phantom_pop_rax:\n"
    "    pop %rax\n"
    "    ret\n"
    ".globl phantom_syscall\n"
    "phantom_syscall:\n"
    "    syscall\n"
    "    ret\n"
);
char phantom_binsh[] = "/bin/sh";

static int read_exact(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static void write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return;
        p += w; n -= (size_t)w;
    }
}

static uint32_t rd32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

/*
 * Op loop with a fixed scratch buffer.  Ops:
 *   0x01 PEEK n : echo n bytes from buf   (BUG: n not bounded -> OOB read/leak)
 *   0x02 LOAD n : read n bytes into buf   (BUG: n not bounded -> stack overflow)
 *   0x03 QUIT   : return
 */
void session(int fd)
{
    unsigned char buf[256];
    memset(buf, 0, sizeof(buf));

    for (;;) {
        unsigned char op;
        if (read_exact(fd, &op, 1) < 0) return;

        if (op == 0x03) return;              /* QUIT -> function returns */

        unsigned char h[4];
        if (read_exact(fd, h, 4) < 0) return;
        uint32_t n = rd32(h);

        if (op == 0x01) {                    /* PEEK: over-read leak */
            write_all(fd, buf, n);
        } else if (op == 0x02) {             /* LOAD: over-write overflow */
            if (read_exact(fd, buf, n) < 0) return;
            unsigned char ack = 0;
            write_all(fd, &ack, 1);
        } else {
            unsigned char e = 0xff;
            write_all(fd, &e, 1);
        }
    }
}
