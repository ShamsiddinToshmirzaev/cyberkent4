#ifndef NINELIVES_STORE_H
#define NINELIVES_STORE_H

#include <stddef.h>
#include <stdint.h>

/*
 * nine-lives config store.
 *
 * Design philosophy of the (fictional) service: "free() is a premature
 * optimization". Nothing is ever released; the store only ever appends.
 * Values are kept in a lightweight run-length-encoded form to save memory.
 */

#define MAX_ENTRIES 512

typedef struct {
    int      used;
    char     key[32];
    uint8_t *buf;      /* backing allocation (RLE or raw)             */
    size_t   cap;      /* size of the backing allocation              */
    size_t   stored;   /* bytes actually written into buf             */
    size_t   vlen;     /* logical (decompressed) length               */
    int      raw;      /* 1 if the RLE path fell back to a raw copy   */
} entry_t;

/* returns entry id, or -1 */
int    store_set(const char *key, uint16_t klen,
                 const uint8_t *val, uint32_t vlen);

/* decompress into out (caller buffer >= vlen); returns bytes, or -1 */
long   store_get(uint32_t id, uint8_t *out, size_t outcap);

/* raw export: copies up to `cap` backing bytes; returns cap, or -1 */
long   store_raw(uint32_t id, uint8_t *out);

/* "compact": release an entry's backing store to reclaim memory */
int    store_compact(uint32_t id);

/* overwrite bytes of an existing entry in place */
int    store_patch(uint32_t id, uint32_t off, const uint8_t *data, uint32_t dlen);

/* write a textual snapshot of every entry and flush all streams */
void   store_snapshot(int client_fd);

#endif
