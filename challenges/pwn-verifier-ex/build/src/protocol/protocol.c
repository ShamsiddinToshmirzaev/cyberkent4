#include "protocol.h"
#include "../vm/vm.h"
#include "../vm/verifier.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int read_exact(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static void write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return;
        p += w; n -= (size_t)w;
    }
}

/*
 * Protocol:
 *
 * Client sends:
 *   [u16 data_len] [data_len bytes of initial data memory]
 *   [u16 n_insns]  [n_insns * 8 bytes of instructions]
 *
 * Server responds:
 *   [u8 status]  0=ok, 1=verify_fail, 2=exec_error
 *   If status==0:
 *     [u16 out_len] [out_len bytes of EMIT output]
 *     then verdict message on the text channel
 *   If status==1:
 *     [u16 err_len] [err_len bytes of error message]
 */

void handle_client(int fd)
{
    /* Read initial data */
    uint16_t data_len;
    if (read_exact(fd, &data_len, 2) < 0) return;
    if (data_len > DATA_SZ) { uint8_t s = 2; write_all(fd, &s, 1); return; }

    uint8_t data_buf[DATA_SZ];
    memset(data_buf, 0, sizeof(data_buf));
    if (data_len > 0 && read_exact(fd, data_buf, data_len) < 0) return;

    /* Read program */
    uint16_t n_insns;
    if (read_exact(fd, &n_insns, 2) < 0) return;
    if (n_insns == 0 || n_insns > MAX_INSNS) {
        uint8_t s = 2; write_all(fd, &s, 1); return;
    }

    insn_t prog[MAX_INSNS];
    if (read_exact(fd, prog, (size_t)n_insns * sizeof(insn_t)) < 0) return;

    /* Verify */
    char err_msg[256];
    err_msg[0] = '\0';
    if (verify_program(prog, n_insns, err_msg, sizeof(err_msg)) < 0) {
        uint8_t s = 1;
        write_all(fd, &s, 1);
        uint16_t elen = (uint16_t)strlen(err_msg);
        write_all(fd, &elen, 2);
        write_all(fd, err_msg, elen);
        return;
    }

    /* Execute */
    vm_state_t *vm = calloc(1, sizeof(vm_state_t));
    if (!vm) { uint8_t s = 2; write_all(fd, &s, 1); return; }
    vm_init(vm, fd, default_verdict);
    memcpy(vm->data, data_buf, data_len);

    vm_exec(vm, prog, n_insns);

    uint8_t s = 0;
    write_all(fd, &s, 1);
    uint16_t olen = (uint16_t)vm->out_len;
    write_all(fd, &olen, 2);
    if (olen > 0)
        write_all(fd, vm->output, olen);

    free(vm);
}
