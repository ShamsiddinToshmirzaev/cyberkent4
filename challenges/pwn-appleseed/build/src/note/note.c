#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 * appleseed - a note service. Buffered stdio I/O over the socket.
 *
 * Deliberate flaw: DELETE frees a note but keeps the pointer and size, so
 * VIEW/EDIT remain usable afterwards (use-after-free). Modern glibc (2.35) has
 * no malloc/free hooks, so turning the resulting primitives into code execution
 * is the interesting part.
 */

#define NNOTE 16

static void *g_ptr[NNOTE];
static size_t g_sz[NNOTE];

static int read_exact(int fd, void *buf, size_t n)
{
    unsigned char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static void out(const void *b, size_t n) { ssize_t w; const unsigned char *p = b; while (n) { w = write(1, p, n); if (w <= 0) break; p += w; n -= (size_t)w; } }
static void st(unsigned char s) { (void)!write(1, &s, 1); }

enum { OP_ADD = 1, OP_DEL = 2, OP_EDIT = 3, OP_VIEW = 4, OP_QUIT = 5 };

void run(void)
{
    static const char banner[] = "appleseed: notes for the modern heap\n";
    out(banner, sizeof(banner) - 1);

    for (;;) {
        unsigned char op;
        if (read_exact(0, &op, 1) < 0) return;

        if (op == OP_QUIT) return;

        else if (op == OP_ADD) {
            unsigned char h[3];
            if (read_exact(0, h, 3) < 0) return;
            int i = h[0]; uint16_t sz = rd16(h + 1);
            if (i < 0 || i >= NNOTE || sz == 0 || sz > 0x1000) { st(1); continue; }
            void *p = malloc(sz);
            if (!p) { st(1); continue; }
            if (read_exact(0, p, sz) < 0) return;
            g_ptr[i] = p; g_sz[i] = sz;
            st(0);
        }

        else if (op == OP_DEL) {
            unsigned char h[1];
            if (read_exact(0, h, 1) < 0) return;
            int i = h[0];
            if (i < 0 || i >= NNOTE) { st(1); continue; }
            free(g_ptr[i]);
            /* flaw: pointer + size kept -> use-after-free via VIEW/EDIT */
            st(0);
        }

        else if (op == OP_EDIT) {
            unsigned char h[3];
            if (read_exact(0, h, 3) < 0) return;
            int i = h[0]; uint16_t n = rd16(h + 1);
            if (i < 0 || i >= NNOTE || !g_ptr[i]) { st(1); continue; }
            if (n > g_sz[i]) n = (uint16_t)g_sz[i];
            if (n && read_exact(0, g_ptr[i], n) < 0) return;
            st(0);
        }

        else if (op == OP_VIEW) {
            unsigned char h[1];
            if (read_exact(0, h, 1) < 0) return;
            int i = h[0];
            if (i < 0 || i >= NNOTE || !g_ptr[i]) { st(1); continue; }
            st(0);
            out(g_ptr[i], g_sz[i]);
        }

        else {
            st(1);
        }
    }
}
