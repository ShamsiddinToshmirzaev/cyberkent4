#ifndef JB_JIT_H
#define JB_JIT_H

#include <stdint.h>
#include <stddef.h>

#define MAX_OPS      1024
#define CODE_CAP     0x4000     /* RWX code page size */

/* Bytecode ops (stack machine). */
enum {
    BC_PUSH = 0x01,   /* u64 imm  -> mov rax,imm ; push rax          */
    BC_ADD  = 0x02,   /* pop b; pop a; push a+b                       */
    BC_SUB  = 0x03,   /* pop b; pop a; push a-b                       */
    BC_MUL  = 0x04,   /* pop b; pop a; push a*b                       */
    BC_DUP  = 0x05,   /* push top                                     */
    BC_GOTO = 0x06,   /* u32 target -> jmp to code byte-offset target */
    BC_RET  = 0xff,   /* pop rax ; ret                               */
};

typedef struct {
    uint8_t  op;
    uint64_t imm;     /* for BC_PUSH */
    uint32_t target;  /* for BC_GOTO (raw code byte offset)          */
} jit_op_t;

/* Compile ops into an RWX buffer. Returns entry function pointer or NULL. */
typedef long (*jit_fn)(void);
jit_fn jit_compile(const jit_op_t *ops, size_t n_ops, char *err, size_t err_sz);

#endif
