#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static entry_t g_entries[MAX_ENTRIES];
static uint32_t g_count;

/*
 * Estimated compressed size for a value of length n. The store assumes typical
 * config blobs compress ~2x, so it provisions n/2 + a small header slack.
 */
static size_t rle_estimate(size_t n)
{
    return (n >> 1) + 16;
}

/*
 * Run-length encode src into dst (capacity `cap`). Format: [count:u8][byte].
 * If the encoded stream would not fit the provisioned capacity, the value is
 * deemed "incompressible" and copied verbatim.
 *
 * BUG: the verbatim fallback copies the *logical* length without re-checking it
 * against the provisioned capacity. rle_estimate() undershoots for
 * incompressible input, so the fallback overflows the allocation by
 * (n - cap) bytes of fully attacker-controlled data.
 */
static size_t rle_encode(const uint8_t *src, size_t n, uint8_t *dst, size_t cap)
{
    size_t o = 0, i = 0;
    while (i < n) {
        size_t run = 1;
        while (i + run < n && src[i + run] == src[i] && run < 255)
            run++;
        if (o + 2 > cap)                 /* would not fit -> give up */
            goto fallback;
        dst[o++] = (uint8_t)run;
        dst[o++] = src[i];
        i += run;
    }
    return o;

fallback:
    /* "incompressible": store raw. */
    memcpy(dst, src, n);                 /* <-- overflow: n may exceed cap */
    return n;
}

static size_t rle_decode(const uint8_t *src, size_t n, uint8_t *dst, size_t cap)
{
    size_t o = 0, i = 0;
    while (i + 1 < n) {
        uint8_t run = src[i];
        uint8_t b = src[i + 1];
        i += 2;
        for (uint8_t k = 0; k < run && o < cap; k++)
            dst[o++] = b;
    }
    return o;
}

int store_set(const char *key, uint16_t klen, const uint8_t *val, uint32_t vlen)
{
    if (g_count >= MAX_ENTRIES)
        return -1;
    if (klen >= sizeof(g_entries[0].key))
        return -1;

    size_t cap = rle_estimate(vlen);
    uint8_t *buf = malloc(cap);
    if (!buf)
        return -1;

    size_t written = rle_encode(val, vlen, buf, cap);
    int raw = (written == vlen && vlen > cap);

    uint32_t id = g_count++;
    entry_t *e = &g_entries[id];
    e->used = 1;
    memcpy(e->key, key, klen);
    e->key[klen] = '\0';
    e->buf = buf;
    e->cap = cap;
    e->stored = written;
    e->vlen = vlen;
    e->raw = raw;
    return (int)id;
}

long store_get(uint32_t id, uint8_t *out, size_t outcap)
{
    if (id >= g_count || !g_entries[id].used)
        return -1;
    entry_t *e = &g_entries[id];
    if (e->raw) {
        size_t n = e->vlen < outcap ? e->vlen : outcap;
        memcpy(out, e->buf, n);
        return (long)n;
    }
    return (long)rle_decode(e->buf, e->stored, out, outcap);
}

/*
 * Raw export of the backing allocation. Copies exactly `cap` bytes so that
 * operators can inspect on-disk representation. (Returns whatever currently
 * occupies the allocation, including slack the writer never touched.)
 */
long store_raw(uint32_t id, uint8_t *out)
{
    if (id >= g_count || !g_entries[id].used)
        return -1;
    entry_t *e = &g_entries[id];
    memcpy(out, e->buf, e->cap);
    return (long)e->cap;
}

/*
 * "compact" an entry: give its backing allocation back to the allocator so a
 * long-lived-but-idle key stops occupying memory. The handle is intentionally
 * kept valid so the key can be re-materialised later.
 *
 * BUG: the freed pointer is neither cleared nor marked, so the entry keeps
 * referencing released memory (use-after-free) and a second compact double-frees
 * it.
 */
int store_compact(uint32_t id)
{
    if (id >= g_count || !g_entries[id].used)
        return -1;
    free(g_entries[id].buf);
    return 0;
}

/* Patch raw bytes of an entry's backing store in place. */
int store_patch(uint32_t id, uint32_t off, const uint8_t *data, uint32_t dlen)
{
    if (id >= g_count || !g_entries[id].used)
        return -1;
    entry_t *e = &g_entries[id];
    if ((uint64_t)off + dlen > e->cap)
        return -1;
    memcpy(e->buf + off, data, dlen);
    return 0;
}

void store_snapshot(int client_fd)
{
    dprintf(client_fd, "[snapshot] %u entries\n", g_count);
    /* Flush every open stream to persist the snapshot. */
    fflush(NULL);
}
