/* C03 "Minerva FM" — DRM manifest signer (internal service, C + OpenSSL).
 *
 * Signs a caller-supplied 32-byte hash with ECDSA/P-256 using a fresh random
 * nonce k. The scalar multiplication is constant-time, but a pre-signing
 * "normalization" step does work proportional to bitlen(k) — a faithful model of
 * the Minerva leak: a tiny, secret-dependent timing signal about the nonce's
 * effective length. It is genuine compute (never sleep), so a single measurement
 * is base + W*bitlen(k) + (network jitter added by the gateway).
 *
 * env: SIGNER_PORT, SIGNER_D (private scalar hex), WORK_FACTOR (W), SIGNER_BIND
 * wire (gateway<->signer): request [u32 len][32-byte z]; response [32-byte r][32-byte s]
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static EC_GROUP *g_group;
static BIGNUM *g_d, *g_n;
static long g_work = 40;
static long g_offset = 224;   /* only bitlen above this costs time (concentrates the tail signal) */

static int readn(int fd, uint8_t *b, size_t n) {
    size_t g = 0;
    while (g < n) { ssize_t r = read(fd, b + g, n - g); if (r <= 0) return 0; g += (size_t)r; }
    return 1;
}
static int writen(int fd, const uint8_t *b, size_t n) {
    size_t p = 0;
    while (p < n) { ssize_t r = write(fd, b + p, n - p); if (r <= 0) return 0; p += (size_t)r; }
    return 1;
}

/* deterministic compute-bound work ~ proportional to max(0, bitlen(k)-offset).
 * Shorter nonces (smaller bitlen) => less work => faster: the Minerva signal. */
static void normalize_work(int bits) {
    long units = (long)bits - g_offset;
    if (units < 0) units = 0;
    long iters = units * g_work;
    volatile uint64_t h = 1469598103934665603ULL;
    for (long i = 0; i < iters; i++) { h ^= (uint64_t)i; h *= 1099511628211ULL; h ^= h >> 13; }
    (void)h;
}

/* sign z (32 bytes) -> r,s (32 bytes each). Returns 1 on success. */
static int do_sign(const uint8_t *z, uint8_t *out_r, uint8_t *out_s) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k = BN_new(), *r = BN_new(), *s = BN_new();
    BIGNUM *zbn = BN_new(), *kinv = BN_new(), *rd = BN_new(), *x = BN_new();
    EC_POINT *R = EC_POINT_new(g_group);
    int ok = 0;
    do {
        if (!BN_rand_range(k, g_n) || BN_is_zero(k)) break;
        normalize_work(BN_num_bits(k));                 /* the leak */
        if (!EC_POINT_mul(g_group, R, k, NULL, NULL, ctx)) break;
        if (!EC_POINT_get_affine_coordinates(g_group, R, x, NULL, ctx)) break;
        if (!BN_nnmod(r, x, g_n, ctx) || BN_is_zero(r)) break;
        BN_bin2bn(z, 32, zbn);
        if (!BN_mod_inverse(kinv, k, g_n, ctx)) break;
        if (!BN_mod_mul(rd, r, g_d, g_n, ctx)) break;   /* r*d */
        if (!BN_mod_add(rd, rd, zbn, g_n, ctx)) break;  /* z + r*d */
        if (!BN_mod_mul(s, kinv, rd, g_n, ctx)) break;  /* k^-1 (z + r*d) */
        if (BN_is_zero(s)) break;
        BN_bn2binpad(r, out_r, 32);
        BN_bn2binpad(s, out_s, 32);
        ok = 1;
    } while (0);
    EC_POINT_free(R);
    BN_free(k); BN_free(r); BN_free(s); BN_free(zbn);
    BN_free(kinv); BN_free(rd); BN_free(x);
    BN_CTX_free(ctx);
    return ok;
}

static void *handle(void *arg) {
    int fd = (int)(intptr_t)arg;
    for (;;) {
        uint8_t lb[4];
        if (!readn(fd, lb, 4)) break;
        uint32_t len = (uint32_t)lb[0] << 24 | lb[1] << 16 | lb[2] << 8 | lb[3];
        if (len != 32) break;
        uint8_t z[32], out[64];
        if (!readn(fd, z, 32)) break;
        if (!do_sign(z, out, out + 32)) { memset(out, 0, 64); }
        if (!writen(fd, out, 64)) break;
    }
    close(fd);
    return NULL;
}

int main(void) {
    const char *port_s = getenv("SIGNER_PORT");
    const char *d_s = getenv("SIGNER_D");
    const char *w_s = getenv("WORK_FACTOR");
    const char *off_s = getenv("SIGNER_OFFSET");
    const char *bind_s = getenv("SIGNER_BIND");
    if (!port_s || !d_s) { fprintf(stderr, "signer: need SIGNER_PORT, SIGNER_D\n"); return 2; }
    int port = atoi(port_s);
    if (w_s) g_work = atol(w_s);
    if (off_s) g_offset = atol(off_s);
    if (!bind_s) bind_s = "127.0.0.1";

    g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    g_n = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP_get_order(g_group, g_n, ctx);
    g_d = NULL;
    BN_hex2bn(&g_d, d_s);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, bind_s, &a.sin_addr);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 2; }
    listen(srv, 128);
    fprintf(stderr, "signer: listening %s:%d work=%ld\n", bind_s, port, g_work);
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        int one2 = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one2, sizeof one2);
        pthread_t th;
        pthread_create(&th, NULL, handle, (void *)(intptr_t)fd);
        pthread_detach(th);
    }
}
