#include "protocol.h"
#include "../store/store.h"

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

static uint16_t rd16(const uint8_t *p){ return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t rd32(const uint8_t *p){
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void st(int fd, uint8_t s){ write_all(fd, &s, 1); }
static void w32(int fd, uint32_t v){
    uint8_t b[4]={(uint8_t)v,(uint8_t)(v>>8),(uint8_t)(v>>16),(uint8_t)(v>>24)};
    write_all(fd,b,4);
}

void handle_client(int fd)
{
    static uint8_t val[MAX_VAL + 16];
    static uint8_t out[MAX_VAL + 16];

    for (;;) {
        uint8_t op;
        if (read_exact(fd, &op, 1) < 0) break;

        if (op == OP_SET) {
            uint8_t h[6];
            if (read_exact(fd, h, 6) < 0) break;
            uint16_t klen = rd16(h);
            uint32_t vlen = rd32(h + 2);
            if (klen >= 32 || vlen > MAX_VAL) { st(fd, ST_ERR); continue; }
            char key[32];
            if (klen && read_exact(fd, key, klen) < 0) break;
            if (vlen && read_exact(fd, val, vlen) < 0) break;
            int id = store_set(key, klen, val, vlen);
            if (id < 0) { st(fd, ST_ERR); }
            else { st(fd, ST_OK); w32(fd, (uint32_t)id); }
        } else if (op == OP_GET) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) break;
            long n = store_get(rd32(h), out, sizeof(out));
            if (n < 0) { st(fd, ST_ERR); }
            else { st(fd, ST_OK); w32(fd, (uint32_t)n); write_all(fd, out, (size_t)n); }
        } else if (op == OP_RAW) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) break;
            long n = store_raw(rd32(h), out);
            if (n < 0) { st(fd, ST_ERR); }
            else { st(fd, ST_OK); w32(fd, (uint32_t)n); write_all(fd, out, (size_t)n); }
        } else if (op == OP_COMPACT) {
            uint8_t h[4];
            if (read_exact(fd, h, 4) < 0) break;
            int rc = store_compact(rd32(h));
            st(fd, rc == 0 ? ST_OK : ST_ERR);
        } else if (op == OP_PATCH) {
            uint8_t h[8];
            if (read_exact(fd, h, 8) < 0) break;
            uint32_t id = rd32(h);
            uint16_t off = rd16(h + 4);
            uint16_t dlen = rd16(h + 6);
            uint8_t data[0x1000];
            if (dlen > sizeof(data)) { st(fd, ST_ERR); continue; }
            if (dlen && read_exact(fd, data, dlen) < 0) break;
            int rc = store_patch(id, off, data, dlen);
            st(fd, rc == 0 ? ST_OK : ST_ERR);
        } else if (op == OP_SNAP) {
            store_snapshot(fd);
            st(fd, ST_OK);
        } else if (op == OP_QUIT) {
            break;
        } else {
            st(fd, ST_ERR);
        }
    }
}
