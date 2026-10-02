#include "ring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static channel_t *g_channels[MAX_CHANNELS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void rm_lock(void)   { pthread_mutex_lock(&g_lock); }
void rm_unlock(void) { pthread_mutex_unlock(&g_lock); }

void rm_init(void)
{
    memset(g_channels, 0, sizeof(g_channels));
}

void default_deliver(int fd, const uint8_t *data, uint32_t len)
{
    (void)data;
    dprintf(fd, "delivered %u bytes\n", len);
}

void flag_reader(int fd, const uint8_t *data, uint32_t len)
{
    (void)data; (void)len;
    const char *path = getenv("FLAG_PATH");
    if (!path) path = "/flag";
    FILE *f = fopen(path, "r");
    if (!f) { dprintf(fd, "flag unavailable\n"); return; }
    char buf[256];
    while (fgets(buf, sizeof(buf), f))
        dprintf(fd, "%s", buf);
    fclose(f);
}

/* caller holds g_lock */
int rm_create(uint32_t id, uint32_t cap)
{
    if (id >= MAX_CHANNELS || g_channels[id]) return -1;
    if (cap == 0 || cap > 0x1000) return -1;
    channel_t *c = malloc(sizeof(channel_t));
    if (!c) return -1;
    c->cap = cap;
    c->len = 0;
    c->data = malloc(cap);
    if (!c->data) { free(c); return -1; }
    c->on_deliver = default_deliver;
    c->tag = 0x52494e4700000000ULL | id;   /* "RING" | id */
    g_channels[id] = c;
    return 0;
}

/* caller holds g_lock */
channel_t *rm_get(uint32_t id)
{
    if (id >= MAX_CHANNELS) return NULL;
    return g_channels[id];
}

/* caller holds g_lock */
int rm_destroy(uint32_t id)
{
    if (id >= MAX_CHANNELS || !g_channels[id]) return -1;
    channel_t *c = g_channels[id];
    /* free the control block first, then its data buffer */
    uint8_t *d = c->data;
    free(c);
    free(d);
    g_channels[id] = NULL;
    return 0;
}
