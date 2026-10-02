#include "verifier.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/*
 * Abstract-interpretation verifier for VEX bytecode.
 *
 * Per-register tracked state:
 *   type: UNSET | SCALAR | PTR_MAP_VAL
 *   SCALAR:      unsigned range [lo, hi]
 *   PTR_MAP_VAL: offset range [off_lo, off_hi] into a MAP_VAL_SZ object
 *
 * Pointer loads/stores are only allowed through PTR_MAP_VAL with a verified
 * offset range: off_lo >= 0 and off_hi + access_size <= MAP_VAL_SZ.
 *
 * Pointer arithmetic (ptr += scalar) widens the offset range by the scalar's
 * range, so an unbounded scalar makes the pointer unusable for access.
 *
 * ---------------------------------------------------------------------------
 * BUG: unsafe control-flow join.
 *
 * The verifier is a straightforward DFS. When it reaches a basic block that
 * has ALREADY been verified (states[target].visited), it assumes the earlier
 * verification subsumes the current path and simply returns success WITHOUT
 * merging the two register states or re-verifying with the widened state.
 *
 * A real verifier must widen/merge abstract states at join points (or prove
 * the incoming state is subsumed).  Skipping the merge means the register
 * state used to verify a join block is whichever path DFS happened to reach
 * it by first.  A second path can arrive with completely different register
 * contents (e.g. a huge scalar) that are never checked against the code in
 * the join block.
 *
 * At runtime the discarded path can be the one actually taken, smuggling an
 * out-of-range scalar into pointer arithmetic in the join block -> OOB
 * read/write relative to a map value, reaching the adjacent verdict context.
 * ---------------------------------------------------------------------------
 */

enum reg_type { REG_UNSET, REG_SCALAR, REG_PTR_MAP_VAL };

typedef struct {
    enum reg_type type;
    uint64_t lo, hi;          /* scalar range           */
    int64_t  off_lo, off_hi;  /* pointer offset range   */
    size_t   ptr_size;
} reg_state_t;

typedef struct {
    reg_state_t regs[NUM_REGS];
    bool visited;
} vstate_t;

static vstate_t states[MAX_INSNS + 1];

static void set_scalar(reg_state_t *r, uint64_t lo, uint64_t hi)
{
    r->type = REG_SCALAR; r->lo = lo; r->hi = hi;
    r->off_lo = r->off_hi = 0; r->ptr_size = 0;
}

static void set_ptr(reg_state_t *r, size_t sz)
{
    r->type = REG_PTR_MAP_VAL; r->lo = r->hi = 0;
    r->off_lo = r->off_hi = 0; r->ptr_size = sz;
}

static int check_access(const reg_state_t *r, int16_t off, size_t asz,
                        char *err, size_t es)
{
    if (r->type != REG_PTR_MAP_VAL) {
        snprintf(err, es, "access through non-pointer");
        return -1;
    }
    int64_t lo = r->off_lo + off;
    int64_t hi = r->off_hi + off + (int64_t)asz;
    if (lo < 0 || hi > (int64_t)r->ptr_size) {
        snprintf(err, es, "OOB access: off_range[%lld,%lld]+%d sz=%zu limit=%zu",
                 (long long)r->off_lo, (long long)r->off_hi, off, asz, r->ptr_size);
        return -1;
    }
    return 0;
}

static int verify_at(const insn_t *prog, size_t n, size_t pc,
                     vstate_t *cur, char *err, size_t es);

static int branch_to(const insn_t *prog, size_t n, size_t target,
                     vstate_t *st, char *err, size_t es)
{
    if (target >= n) { snprintf(err, es, "branch target OOB"); return -1; }
    if (states[target].visited)
        return 0;                         /* BUG: no merge, no recheck */
    states[target] = *st;
    states[target].visited = true;
    return verify_at(prog, n, target, &states[target], err, es);
}

static int verify_at(const insn_t *prog, size_t n, size_t pc,
                     vstate_t *cur, char *err, size_t es)
{
    while (pc < n) {
        const insn_t *ip = &prog[pc];
        uint8_t d = insn_dst(ip), s = insn_src(ip);
        reg_state_t *rd = &cur->regs[d];
        reg_state_t *rs = &cur->regs[s];

        switch (ip->op) {
        case OP_NOP: break;

        case OP_MOV_IMM:
            set_scalar(rd, (uint64_t)(int64_t)ip->imm, (uint64_t)(int64_t)ip->imm);
            break;

        case OP_MOV_REG:
            if (rs->type == REG_UNSET) { snprintf(err, es, "mov from unset r%u", s); return -1; }
            *rd = *rs;
            break;

        case OP_ADD_IMM:
            if (rd->type != REG_SCALAR) { snprintf(err, es, "add_imm non-scalar r%u", d); return -1; }
            rd->lo += (uint64_t)(int64_t)ip->imm;
            rd->hi += (uint64_t)(int64_t)ip->imm;
            break;

        case OP_ADD_REG:
            if (rd->type == REG_PTR_MAP_VAL && rs->type == REG_SCALAR) {
                rd->off_lo += (int64_t)rs->lo;
                rd->off_hi += (int64_t)rs->hi;
            } else if (rd->type == REG_SCALAR && rs->type == REG_SCALAR) {
                rd->lo += rs->lo; rd->hi += rs->hi;
            } else {
                snprintf(err, es, "bad add_reg types at pc %zu", pc); return -1;
            }
            break;

        case OP_SUB_IMM:
            if (rd->type != REG_SCALAR) { snprintf(err, es, "sub non-scalar r%u", d); return -1; }
            rd->lo -= (uint64_t)(int64_t)ip->imm;
            rd->hi -= (uint64_t)(int64_t)ip->imm;
            break;

        case OP_AND_IMM:
            if (rd->type != REG_SCALAR) { snprintf(err, es, "and non-scalar r%u", d); return -1; }
            set_scalar(rd, 0, (uint64_t)(uint32_t)ip->imm);
            break;

        case OP_RSH_IMM:
            if (rd->type != REG_SCALAR) { snprintf(err, es, "rsh non-scalar r%u", d); return -1; }
            if (ip->imm >= 0 && ip->imm < 64) { rd->lo >>= ip->imm; rd->hi >>= ip->imm; }
            break;

        case OP_MAP_GET:
            if (rs->type != REG_SCALAR) { snprintf(err, es, "map_get slot non-scalar"); return -1; }
            if (rs->hi >= MAP_SLOTS) { snprintf(err, es, "map_get slot may exceed bound"); return -1; }
            set_ptr(rd, MAP_VAL_SZ);
            break;

        case OP_LD_8:  if (check_access(rs, ip->off, 1, err, es) < 0) return -1; set_scalar(rd, 0, 0xff); break;
        case OP_LD_32: if (check_access(rs, ip->off, 4, err, es) < 0) return -1; set_scalar(rd, 0, 0xffffffff); break;
        case OP_LD_64: if (check_access(rs, ip->off, 8, err, es) < 0) return -1; set_scalar(rd, 0, UINT64_MAX); break;

        case OP_ST_8:
            if (check_access(rd, ip->off, 1, err, es) < 0) return -1;
            if (rs->type != REG_SCALAR) { snprintf(err, es, "store non-scalar value"); return -1; }
            break;
        case OP_ST_32:
            if (check_access(rd, ip->off, 4, err, es) < 0) return -1;
            if (rs->type != REG_SCALAR) { snprintf(err, es, "store non-scalar value"); return -1; }
            break;
        case OP_ST_64:
            if (check_access(rd, ip->off, 8, err, es) < 0) return -1;
            if (rs->type != REG_SCALAR) { snprintf(err, es, "store non-scalar value"); return -1; }
            break;

        case OP_JEQ_IMM: {
            size_t tgt = pc + 1 + ip->off;
            vstate_t br = *cur;
            if (rd->type == REG_SCALAR)
                set_scalar(&br.regs[d], (uint64_t)(int64_t)ip->imm, (uint64_t)(int64_t)ip->imm);
            if (branch_to(prog, n, tgt, &br, err, es) < 0) return -1;
            break;
        }
        case OP_JNE_IMM: {
            size_t tgt = pc + 1 + ip->off;
            vstate_t br = *cur;
            if (branch_to(prog, n, tgt, &br, err, es) < 0) return -1;
            if (rd->type == REG_SCALAR)
                set_scalar(rd, (uint64_t)(int64_t)ip->imm, (uint64_t)(int64_t)ip->imm);
            break;
        }
        case OP_JLT_IMM: {
            size_t tgt = pc + 1 + ip->off;
            uint64_t bound = (uint64_t)(uint32_t)ip->imm;
            vstate_t br = *cur;
            if (rd->type == REG_SCALAR && bound > 0 && bound - 1 < br.regs[d].hi)
                br.regs[d].hi = bound - 1;
            if (branch_to(prog, n, tgt, &br, err, es) < 0) return -1;
            if (rd->type == REG_SCALAR && bound > rd->lo) rd->lo = bound;
            break;
        }
        case OP_JGE_IMM: {
            size_t tgt = pc + 1 + ip->off;
            uint64_t bound = (uint64_t)(uint32_t)ip->imm;
            vstate_t br = *cur;
            if (rd->type == REG_SCALAR && bound > br.regs[d].lo)
                br.regs[d].lo = bound;
            if (branch_to(prog, n, tgt, &br, err, es) < 0) return -1;
            if (rd->type == REG_SCALAR && bound > 0 && bound - 1 < rd->hi)
                rd->hi = bound - 1;
            break;
        }

        case OP_EMIT:
            if (rd->type != REG_SCALAR) { snprintf(err, es, "emit non-scalar r%u at pc %zu", d, pc); return -1; }
            break;

        case OP_EXIT:
            return 0;

        default:
            snprintf(err, es, "unknown opcode 0x%02x at pc %zu", ip->op, pc);
            return -1;
        }
        pc++;
    }
    snprintf(err, es, "program falls off the end (no EXIT)");
    return -1;
}

int verify_program(const insn_t *prog, size_t n_insns, char *err, size_t err_sz)
{
    if (n_insns == 0 || n_insns > MAX_INSNS) {
        snprintf(err, err_sz, "invalid program length %zu", n_insns);
        return -1;
    }
    if (prog[n_insns - 1].op != OP_EXIT) {
        snprintf(err, err_sz, "last instruction must be EXIT");
        return -1;
    }

    memset(states, 0, sizeof(states));
    states[0].visited = true;
    for (int i = 0; i < NUM_REGS; i++)
        states[0].regs[i].type = REG_UNSET;
    set_scalar(&states[0].regs[0], 0, 0);   /* r0 = 0 (return code) */

    return verify_at(prog, n_insns, 0, &states[0], err, err_sz);
}
