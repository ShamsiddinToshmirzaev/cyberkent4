#include "protocol.h"
#include "../alloc/alloc.h"
#include "../sandbox/sandbox.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#define ARM_MAGIC 0x5347314e756c3121ULL  /* "SG1Nul1!" */

/* The debug-exec facility is disabled until armed. volatile: only ever flipped
 * out-of-band, so the compiler must not assume it stays zero. */
static volatile uint64_t g_armed;

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
    while (n) { ssize_t w = write(fd, p, n); if (w <= 0) return; p += w; n -= (size_t)w; }
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void st(int fd, uint8_t s) { write_all(fd, &s, 1); }

struct handle { void *p; uint32_t size; uint8_t used; };

void handle_client(int fd)
{
    struct handle h[NHANDLE];
    memset(h, 0, sizeof(h));

    for (;;) {
        uint8_t op;
        if (read_exact(fd, &op, 1) < 0) goto done;

        if (op == OP_QUIT) goto done;

        else if (op == OP_ALLOC) {
            uint8_t b[2];
            if (read_exact(fd, b, 2) < 0) goto done;
            uint16_t size = rd16(b);
            int idx = -1;
            for (int i = 0; i < NHANDLE; i++) if (!h[i].used) { idx = i; break; }
            void *p = (idx >= 0) ? xalloc(size) : NULL;
            if (!p) { st(fd, ST_ERR); continue; }
            h[idx].p = p; h[idx].size = size; h[idx].used = 1;
            st(fd, ST_OK);
            uint8_t hb = (uint8_t)idx; write_all(fd, &hb, 1);
        }

        else if (op == OP_FREE) {
            uint8_t b[1];
            if (read_exact(fd, b, 1) < 0) goto done;
            int i = b[0];
            if (i < 0 || i >= NHANDLE || !h[i].used) { st(fd, ST_ERR); continue; }
            xfree(h[i].p);
            /* BUG: the handle keeps pointing at the freed chunk */
            st(fd, ST_OK);
        }

        else if (op == OP_WRITE) {
            uint8_t b[3];
            if (read_exact(fd, b, 3) < 0) goto done;
            int i = b[0];
            uint16_t n = rd16(b + 1);
            if (i < 0 || i >= NHANDLE || !h[i].used) { st(fd, ST_ERR); continue; }
            if (n > h[i].size) n = h[i].size;
            uint8_t tmp[0x400];
            if (n && read_exact(fd, tmp, n) < 0) goto done;
            memcpy(h[i].p, tmp, n);
            st(fd, ST_OK);
        }

        else if (op == OP_READ) {
            uint8_t b[3];
            if (read_exact(fd, b, 3) < 0) goto done;
            int i = b[0];
            uint16_t n = rd16(b + 1);
            if (i < 0 || i >= NHANDLE || !h[i].used) { st(fd, ST_ERR); continue; }
            if (n > h[i].size) n = h[i].size;
            st(fd, ST_OK);
            write_all(fd, h[i].p, n);
        }

        else if (op == OP_EXEC) {
            uint8_t hdr[4];
            if (read_exact(fd, hdr, 4) < 0) goto done;
            uint32_t len = rd32(hdr);
            if (g_armed != ARM_MAGIC) { st(fd, ST_ERR); continue; }
            if (len == 0 || len > MAX_CODE) { st(fd, ST_ERR); continue; }
            void *page = mmap(NULL, MAX_CODE, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page == MAP_FAILED) { st(fd, ST_ERR); continue; }
            if (read_exact(fd, page, len) < 0) goto done;
            st(fd, ST_OK);
            if (install_sandbox() != 0) goto done;
            ((void (*)(void))page)();   /* control leaves C for good */
            goto done;
        }

        else {
            st(fd, ST_ERR);
        }
    }

done:
    return;
}
