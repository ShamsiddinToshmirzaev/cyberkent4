#include "alloc.h"

#define ARENA_SZ 0x8000
#define NBIN     64

/* The arena is a plain global -> it lives at a fixed offset from the image base. */
static uint8_t g_arena[ARENA_SZ];
static size_t  g_top;
static void   *g_bin[NBIN];

static size_t roundup(size_t n) { return (n + 15) & ~((size_t)15); }

uintptr_t arena_base(void) { return (uintptr_t)g_arena; }

/*
 * Chunk layout:  [ size:u64 ][ user bytes... ]
 * When a chunk is free, its first user word threads the segregated free list.
 */
void *xalloc(size_t size)
{
    if (size == 0 || size > 0x400) return NULL;
    size_t r = roundup(size);
    int bin = (int)(r / 16);

    if (bin < NBIN && g_bin[bin]) {
        void *u = g_bin[bin];
        g_bin[bin] = *(void **)u;      /* unlink head */
        return u;
    }

    size_t need = 8 + r;
    if (g_top + need > ARENA_SZ) return NULL;
    uint8_t *chunk = g_arena + g_top;
    *(uint64_t *)chunk = r;
    g_top += need;
    return chunk + 8;
}

void xfree(void *u)
{
    if (!u) return;
    uint64_t r = *(uint64_t *)((uint8_t *)u - 8);
    int bin = (int)(r / 16);
    if (bin < 0 || bin >= NBIN) return;
    *(void **)u = g_bin[bin];          /* push onto free list */
    g_bin[bin] = u;
}

size_t xchunk_size(void *u)
{
    return (size_t)(*(uint64_t *)((uint8_t *)u - 8));
}
