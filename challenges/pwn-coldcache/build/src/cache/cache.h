#ifndef CC_CACHE_H
#define CC_CACHE_H

#include <stdint.h>
#include <stddef.h>

#define MAX_NOTES    32
#define MAX_HANDLERS 16
#define NOTE_MAX     0x800

typedef struct {
    uint64_t   a;               /* 0  */
    uint64_t   b;               /* 8  */
    void     (*cb)(int fd);     /* 16 -- survives tcache fd/key at 0/8 */
    uint64_t   c;               /* 24 */
} handler_t;                    /* 32 -> chunk 0x30 */

int  note_add(uint32_t i, uint32_t size);
int  note_del(uint32_t i);
long note_view(uint32_t i, uint8_t *out);
int  note_edit(uint32_t i, const uint8_t *data, uint32_t n);

int  handler_add(uint32_t j);
handler_t *handler_get(uint32_t j);

void default_handler(int fd);
void flag_reader(int fd);

#endif
