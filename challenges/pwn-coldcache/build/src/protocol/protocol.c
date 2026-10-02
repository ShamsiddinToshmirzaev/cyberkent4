#include "protocol.h"
#include "../cache/cache.h"

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

static uint32_t rd32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void st(int fd, uint8_t s) { write_all(fd, &s, 1); }
static void w32(int fd, uint32_t v)
{ uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) }; write_all(fd, b, 4); }

void handle_client(int fd)
{
    static uint8_t buf[NOTE_MAX + 16];

    for (;;) {
        uint8_t op;
        if (read_exact(fd, &op, 1) < 0) return;
        if (op == OP_QUIT) return;

        if (op == OP_ADD) {
            uint8_t h[8];
            if (read_exact(fd, h, 8) < 0) return;
            uint32_t i = rd32(h), size = rd32(h + 4);
            st(fd, note_add(i, size) == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_DEL) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            st(fd, note_del(rd32(h)) == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_VIEW) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            long n = note_view(rd32(h), buf);
            if (n < 0) { st(fd, ST_ERR); }
            else { st(fd, ST_OK); w32(fd, (uint32_t)n); write_all(fd, buf, (size_t)n); }

        } else if (op == OP_EDIT) {
            uint8_t h[8];
            if (read_exact(fd, h, 8) < 0) return;
            uint32_t i = rd32(h), n = rd32(h + 4);
            if (n > NOTE_MAX) { st(fd, ST_ERR); continue; }
            if (n && read_exact(fd, buf, n) < 0) return;
            st(fd, note_edit(i, buf, n) == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_HANDLER) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            st(fd, handler_add(rd32(h)) == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_CALL) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            handler_t *hd = handler_get(rd32(h));
            if (hd && hd->cb) { hd->cb(fd); st(fd, ST_OK); }
            else st(fd, ST_ERR);

        } else {
            st(fd, ST_ERR);
        }
    }
}
