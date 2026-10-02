#include "protocol.h"
#include "../jit/jit.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const uint8_t *p)
{ uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i); return v; }

/*
 * Protocol:
 *   u16 n_ops
 *   n_ops * { u8 op, u64 imm, u32 target }   (13 bytes each)
 * Response:
 *   u8 status (0 ok / 1 error); if ok: s64 result
 */
void handle_client(int fd)
{
    uint8_t hdr[2];
    if (read_exact(fd, hdr, 2) < 0) return;
    uint16_t n = rd16(hdr);
    if (n == 0 || n > MAX_OPS) { uint8_t s = 1; write_all(fd, &s, 1); return; }

    static jit_op_t ops[MAX_OPS];
    for (uint16_t i = 0; i < n; i++) {
        uint8_t rec[13];
        if (read_exact(fd, rec, 13) < 0) return;
        ops[i].op     = rec[0];
        ops[i].imm    = rd64(rec + 1);
        ops[i].target = rd32(rec + 9);
    }

    char err[128];
    jit_fn fn = jit_compile(ops, n, err, sizeof(err));
    if (!fn) {
        uint8_t s = 1;
        write_all(fd, &s, 1);
        uint8_t el = (uint8_t)strlen(err);
        write_all(fd, &el, 1);
        write_all(fd, err, el);
        return;
    }

    long result = fn();

    uint8_t s = 0;
    write_all(fd, &s, 1);
    write_all(fd, &result, 8);
}
