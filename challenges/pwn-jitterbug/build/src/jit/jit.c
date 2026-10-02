#include "jit.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/*
 * Tiny stack-machine JIT.  Each op is translated to x86-64 and emitted into a
 * single RWX page.  op_off[i] records the code byte-offset where op i begins,
 * so BC_GOTO can be resolved to a relative jump.
 *
 * BUG: BC_GOTO's target is a RAW code byte offset supplied by the program and
 * is only bounds-checked against the emitted code length -- it is NOT checked
 * to land on an instruction boundary.  BC_PUSH emits `48 B8 <imm:8> 50`
 * (mov rax, imm ; push rax), so the eight attacker-controlled immediate bytes
 * sit verbatim in the executable page.  A GOTO into the middle of an immediate
 * executes those bytes as instructions -> arbitrary code (JIT spray).
 */

static size_t emit(uint8_t *code, size_t o, const void *bytes, size_t n)
{
    memcpy(code + o, bytes, n);
    return o + n;
}

jit_fn jit_compile(const jit_op_t *ops, size_t n_ops, char *err, size_t err_sz)
{
    if (n_ops == 0 || n_ops > MAX_OPS) {
        snprintf(err, err_sz, "bad op count");
        return NULL;
    }

    uint8_t *code = mmap(NULL, CODE_CAP, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        snprintf(err, err_sz, "mmap failed");
        return NULL;
    }

    size_t off = 0;
    size_t op_off[MAX_OPS];

    /* prologue: nothing (leaf) */
    for (size_t i = 0; i < n_ops; i++) {
        op_off[i] = off;
        if (off + 32 > CODE_CAP) { snprintf(err, err_sz, "code overflow"); goto fail; }

        switch (ops[i].op) {
        case BC_PUSH: {
            uint8_t b[11] = { 0x48, 0xB8 };          /* mov rax, imm64 */
            memcpy(b + 2, &ops[i].imm, 8);
            b[10] = 0x50;                            /* push rax */
            off = emit(code, off, b, 11);
            break;
        }
        case BC_ADD: {
            uint8_t b[] = { 0x59, 0x58, 0x48, 0x01, 0xC8, 0x50 }; /* pop rcx;pop rax;add rax,rcx;push rax */
            off = emit(code, off, b, sizeof(b));
            break;
        }
        case BC_SUB: {
            uint8_t b[] = { 0x59, 0x58, 0x48, 0x29, 0xC8, 0x50 }; /* pop rcx;pop rax;sub rax,rcx;push rax */
            off = emit(code, off, b, sizeof(b));
            break;
        }
        case BC_MUL: {
            uint8_t b[] = { 0x59, 0x58, 0x48, 0x0F, 0xAF, 0xC1, 0x50 }; /* pop rcx;pop rax;imul rax,rcx;push rax */
            off = emit(code, off, b, sizeof(b));
            break;
        }
        case BC_DUP: {
            uint8_t b[] = { 0x58, 0x50, 0x50 };      /* pop rax;push rax;push rax */
            off = emit(code, off, b, sizeof(b));
            break;
        }
        case BC_GOTO: {
            /* jmp rel32 to raw byte offset ops[i].target */
            uint32_t tgt = ops[i].target;
            if (tgt >= CODE_CAP) { snprintf(err, err_sz, "goto out of range"); goto fail; }
            uint8_t b[5] = { 0xE9 };
            int32_t rel = (int32_t)tgt - (int32_t)(off + 5);  /* BUG: tgt not boundary-checked */
            memcpy(b + 1, &rel, 4);
            off = emit(code, off, b, 5);
            break;
        }
        case BC_RET: {
            uint8_t b[] = { 0x58, 0xC3 };            /* pop rax;ret */
            off = emit(code, off, b, sizeof(b));
            break;
        }
        default:
            snprintf(err, err_sz, "bad op 0x%02x", ops[i].op);
            goto fail;
        }
    }
    (void)op_off;

    return (jit_fn)code;

fail:
    munmap(code, CODE_CAP);
    return NULL;
}
