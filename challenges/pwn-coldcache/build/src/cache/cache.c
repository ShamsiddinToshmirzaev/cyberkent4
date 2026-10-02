#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint8_t   *g_notes[MAX_NOTES];
static uint32_t   g_sizes[MAX_NOTES];
static handler_t *g_handlers[MAX_HANDLERS];

void default_handler(int fd) { dprintf(fd, "handler ready\n"); }

void flag_reader(int fd)
{
    const char *path = getenv("FLAG_PATH");
    if (!path) path = "/flag";
    FILE *f = fopen(path, "r");
    if (!f) { dprintf(fd, "flag unavailable\n"); return; }
    char buf[256];
    while (fgets(buf, sizeof(buf), f))
        dprintf(fd, "%s", buf);
    fclose(f);
}

/* Allocate a note buffer.  It is left uninitialised (fill it with EDIT). */
int note_add(uint32_t i, uint32_t size)
{
    if (i >= MAX_NOTES || g_notes[i]) return -1;
    if (size == 0 || size > NOTE_MAX) return -1;
    uint8_t *p = malloc(size);
    if (!p) return -1;
    g_notes[i] = p;
    g_sizes[i] = size;
    return 0;
}

/* BUG: frees the backing buffer but keeps the pointer (use-after-free). */
int note_del(uint32_t i)
{
    if (i >= MAX_NOTES || !g_notes[i]) return -1;
    free(g_notes[i]);
    return 0;               /* g_notes[i] deliberately NOT cleared */
}

long note_view(uint32_t i, uint8_t *out)
{
    if (i >= MAX_NOTES || !g_notes[i]) return -1;
    memcpy(out, g_notes[i], g_sizes[i]);
    return (long)g_sizes[i];
}

int note_edit(uint32_t i, const uint8_t *data, uint32_t n)
{
    if (i >= MAX_NOTES || !g_notes[i]) return -1;
    if (n > g_sizes[i]) return -1;
    memcpy(g_notes[i], data, n);
    return 0;
}

int handler_add(uint32_t j)
{
    if (j >= MAX_HANDLERS || g_handlers[j]) return -1;
    handler_t *h = malloc(sizeof(handler_t));
    if (!h) return -1;
    memset(h, 0, sizeof(*h));
    h->cb = default_handler;
    g_handlers[j] = h;
    return 0;
}

handler_t *handler_get(uint32_t j)
{
    if (j >= MAX_HANDLERS) return NULL;
    return g_handlers[j];
}
