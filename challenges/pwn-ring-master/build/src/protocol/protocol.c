#include "protocol.h"
#include "../ring/ring.h"

#include <stdint.h>
#include <stdlib.h>
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
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st(int fd, uint8_t s) { write_all(fd, &s, 1); }
static void w32(int fd, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    write_all(fd, b, 4);
}

void handle_client(int fd)
{
    for (;;) {
        uint8_t op;
        if (read_exact(fd, &op, 1) < 0) return;

        if (op == OP_QUIT) return;

        if (op == OP_CREATE) {
            uint8_t h[8];
            if (read_exact(fd, h, 8) < 0) return;
            rm_lock();
            int rc = rm_create(rd32(h), rd32(h + 4));
            rm_unlock();
            st(fd, rc == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_PUB) {
            uint8_t h[8];
            if (read_exact(fd, h, 8) < 0) return;
            uint32_t id = rd32(h), len = rd32(h + 4);

            rm_lock();
            channel_t *c = rm_get(id);
            if (!c || len > c->cap) { rm_unlock(); st(fd, ST_ERR); continue; }
            uint8_t *p = c->data;      /* capture backing pointer */
            c->len = len;
            rm_unlock();               /* release lock across slow client I/O */

            /* BUG: p is read into while the channel lock is NOT held; a
             * concurrent RESIZE/DESTROY can free (and reallocate) it. */
            if (read_exact(fd, p, len) < 0) return;
            st(fd, ST_OK);

        } else if (op == OP_RESIZE) {
            uint8_t h[8];
            if (read_exact(fd, h, 8) < 0) return;
            uint32_t id = rd32(h), newcap = rd32(h + 4);
            rm_lock();
            channel_t *c = rm_get(id);
            int rc = -1;
            if (c && newcap > 0 && newcap <= 0x1000) {
                free(c->data);
                c->data = malloc(newcap);
                c->cap = newcap;
                c->len = 0;
                rc = c->data ? 0 : -1;
            }
            rm_unlock();
            st(fd, rc == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_READ) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            uint32_t id = rd32(h);
            rm_lock();
            channel_t *c = rm_get(id);
            if (!c) { rm_unlock(); st(fd, ST_ERR); continue; }
            uint32_t n = c->cap;
            st(fd, ST_OK);
            w32(fd, n);
            write_all(fd, c->data, n);
            rm_unlock();

        } else if (op == OP_DESTROY) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            rm_lock();
            int rc = rm_destroy(rd32(h));
            rm_unlock();
            st(fd, rc == 0 ? ST_OK : ST_ERR);

        } else if (op == OP_DELIVER) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) return;
            uint32_t id = rd32(h);
            rm_lock();
            channel_t *c = rm_get(id);
            if (c && c->on_deliver) c->on_deliver(fd, c->data, c->len);
            rm_unlock();
            st(fd, ST_OK);

        } else {
            st(fd, ST_ERR);
        }
    }
}
