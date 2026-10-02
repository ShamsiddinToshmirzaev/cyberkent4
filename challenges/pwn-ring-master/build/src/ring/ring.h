#ifndef RM_RING_H
#define RM_RING_H

#include <stdint.h>
#include <stddef.h>

#define MAX_CHANNELS 64

typedef void (*deliver_fn)(int fd, const uint8_t *data, uint32_t len);

/*
 * Channel control block.  Layout is chosen so on_deliver sits at offset 16,
 * i.e. clear of the tcache fd (offset 0) and key (offset 8) that glibc writes
 * into a freed chunk -- the callback pointer therefore survives a free().
 */
typedef struct {
    uint32_t   cap;          /* 0  */
    uint32_t   len;          /* 4  */
    uint8_t   *data;         /* 8  */
    deliver_fn on_deliver;   /* 16 */
    uint64_t   tag;          /* 24 */
} channel_t;                 /* 32 -> chunk 0x30 */

void      rm_init(void);
int       rm_create(uint32_t id, uint32_t cap);
channel_t *rm_get(uint32_t id);
int       rm_destroy(uint32_t id);

void default_deliver(int fd, const uint8_t *data, uint32_t len);
void flag_reader(int fd, const uint8_t *data, uint32_t len);

/* global lock helpers */
void rm_lock(void);
void rm_unlock(void);

#endif
