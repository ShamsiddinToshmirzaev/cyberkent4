#ifndef VEX_VM_H
#define VEX_VM_H

#include <stdint.h>
#include <stddef.h>

#define NUM_REGS     8
#define MAX_INSNS    256
#define MAP_SLOTS    16
#define MAP_VAL_SZ   64
#define DATA_SZ      512
#define MAX_STEPS    8192

/* --- instruction encoding (8 bytes each) ---
 *  byte 0     : opcode
 *  byte 1     : dst_reg (high nibble) | src_reg (low nibble)
 *  bytes 2-3  : offset (i16)
 *  bytes 4-7  : imm (i32)
 */
typedef struct {
    uint8_t  op;
    uint8_t  regs;
    int16_t  off;
    int32_t  imm;
} __attribute__((packed)) insn_t;

static inline uint8_t insn_dst(const insn_t *i) { return (i->regs >> 4) & 0x7; }
static inline uint8_t insn_src(const insn_t *i) { return i->regs & 0x7; }

enum vex_op {
    OP_NOP      = 0x00,
    OP_MOV_IMM  = 0x01,   /* dst = (int64_t)imm                       */
    OP_MOV_REG  = 0x02,   /* dst = src                                */
    OP_ADD_IMM  = 0x03,   /* dst += (int64_t)imm  (scalar only)        */
    OP_ADD_REG  = 0x04,   /* dst += src  (ptr += scalar, or scalar+scalar) */
    OP_SUB_IMM  = 0x05,   /* dst -= (int64_t)imm  (scalar only)        */
    OP_AND_IMM  = 0x07,   /* dst &= (uint32_t)imm                      */
    OP_RSH_IMM  = 0x08,   /* dst >>= imm (logical)                     */
    OP_MAP_GET  = 0x11,   /* dst = &map[src].value  (src < MAP_SLOTS)  */
    OP_LD_8     = 0x28,   /* dst = *(u8 *)(src + off)                  */
    OP_LD_32    = 0x29,   /* dst = *(u32*)(src + off)                  */
    OP_LD_64    = 0x2a,   /* dst = *(u64*)(src + off)                  */
    OP_ST_8     = 0x20,   /* *(u8 *)(dst + off) = src                  */
    OP_ST_32    = 0x21,   /* *(u32*)(dst + off) = src                  */
    OP_ST_64    = 0x22,   /* *(u64*)(dst + off) = src                  */
    OP_JEQ_IMM  = 0x30,   /* if dst == imm goto pc+1+off               */
    OP_JNE_IMM  = 0x31,   /* if dst != imm goto pc+1+off               */
    OP_JLT_IMM  = 0x32,   /* if dst <  (u32)imm goto pc+1+off          */
    OP_JGE_IMM  = 0x33,   /* if dst >= (u32)imm goto pc+1+off          */
    OP_EMIT     = 0x40,   /* append dst (u64) to output                */
    OP_EXIT     = 0xff,   /* halt; verdict = on_verdict(fd, r0)        */
};

/* Map backing store, followed immediately by the verdict context. */
typedef struct {
    uint8_t  used;
    uint8_t  val[MAP_VAL_SZ];
} map_entry_t;

typedef void (*verdict_fn)(int fd, int code);

typedef struct {
    verdict_fn on_verdict;      /* offset 0 within vctx */
    int32_t    client_fd;
    int32_t    _pad;
    uint64_t   canary;
} verdict_ctx_t;

#define VERDICT_CANARY  0x5645584352544cULL   /* "VEXCRTL" */

typedef struct {
    uint64_t      regs[NUM_REGS];
    uint8_t       data[DATA_SZ];
    map_entry_t   map[MAP_SLOTS];
    verdict_ctx_t vctx;
    uint8_t       output[4096];
    size_t        out_len;
    int           halted;
} vm_state_t;

void vm_init(vm_state_t *vm, int client_fd, verdict_fn on_done);
int  vm_exec(vm_state_t *vm, const insn_t *prog, size_t n_insns);

void default_verdict(int fd, int code);
void flag_reader(int fd, int code);

#endif
