#ifndef WD_ALLOC_H
#define WD_ALLOC_H

#include <stddef.h>
#include <stdint.h>

/* A tiny bump + segregated-free-list allocator over a static arena. */
void  *xalloc(size_t size);
void   xfree(void *u);
size_t xchunk_size(void *u);        /* recorded size of a live chunk */
uintptr_t arena_base(void);         /* runtime base of the arena (for reference) */

#endif
