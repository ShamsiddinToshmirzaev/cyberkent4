#include "vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *g_flag_path;

void default_verdict(int fd, int code)
{
    dprintf(fd, "VERDICT code=%d\n", code);
}

void flag_reader(int fd, int code)
{
    (void)code;
    const char *path = g_flag_path ? g_flag_path : "/flag";
    FILE *f = fopen(path, "r");
    if (!f) { dprintf(fd, "flag unavailable\n"); return; }
    char buf[256];
    while (fgets(buf, sizeof(buf), f))
        dprintf(fd, "%s", buf);
    fclose(f);
}

void vm_init(vm_state_t *vm, int client_fd, verdict_fn on_done)
{
    memset(vm, 0, sizeof(*vm));
    vm->vctx.on_verdict = on_done;
    vm->vctx.client_fd  = client_fd;
    vm->vctx.canary     = VERDICT_CANARY;
    g_flag_path = getenv("FLAG_PATH");
}

int vm_exec(vm_state_t *vm, const insn_t *prog, size_t n_insns)
{
    if (n_insns > MAX_INSNS) return -1;

    size_t pc = 0;
    int steps = 0;

    while (pc < n_insns && !vm->halted && steps++ < MAX_STEPS) {
        const insn_t *ip = &prog[pc];
        uint8_t d = insn_dst(ip);
        uint8_t s = insn_src(ip);

        switch (ip->op) {
        case OP_NOP: break;

        case OP_MOV_IMM: vm->regs[d] = (uint64_t)(int64_t)ip->imm; break;
        case OP_MOV_REG: vm->regs[d] = vm->regs[s]; break;
        case OP_ADD_IMM: vm->regs[d] += (uint64_t)(int64_t)ip->imm; break;
        case OP_ADD_REG: vm->regs[d] += vm->regs[s]; break;
        case OP_SUB_IMM: vm->regs[d] -= (uint64_t)(int64_t)ip->imm; break;
        case OP_AND_IMM: vm->regs[d] &= (uint64_t)(uint32_t)ip->imm; break;
        case OP_RSH_IMM:
            if (ip->imm >= 0 && ip->imm < 64) vm->regs[d] >>= ip->imm;
            break;

        case OP_MAP_GET: {
            uint32_t slot = (uint32_t)vm->regs[s];
            if (slot >= MAP_SLOTS) { vm->regs[d] = 0; break; }
            vm->map[slot].used = 1;
            vm->regs[d] = (uint64_t)(uintptr_t)vm->map[slot].val;
            break;
        }

        case OP_LD_8: {
            uint8_t *p = (uint8_t *)(uintptr_t)vm->regs[s];
            vm->regs[d] = p[ip->off];
            break;
        }
        case OP_LD_32: {
            uint8_t *p = (uint8_t *)(uintptr_t)vm->regs[s];
            uint32_t v; memcpy(&v, p + ip->off, 4); vm->regs[d] = v;
            break;
        }
        case OP_LD_64: {
            uint8_t *p = (uint8_t *)(uintptr_t)vm->regs[s];
            uint64_t v; memcpy(&v, p + ip->off, 8); vm->regs[d] = v;
            break;
        }

        case OP_ST_8: {
            uint8_t *p = (uint8_t *)(uintptr_t)vm->regs[d];
            p[ip->off] = (uint8_t)vm->regs[s];
            break;
        }
        case OP_ST_32: {
            uint8_t *p = (uint8_t *)(uintptr_t)vm->regs[d];
            uint32_t v = (uint32_t)vm->regs[s]; memcpy(p + ip->off, &v, 4);
            break;
        }
        case OP_ST_64: {
            uint8_t *p = (uint8_t *)(uintptr_t)vm->regs[d];
            uint64_t v = vm->regs[s]; memcpy(p + ip->off, &v, 8);
            break;
        }

        case OP_JEQ_IMM:
            if (vm->regs[d] == (uint64_t)(int64_t)ip->imm) pc += ip->off;
            break;
        case OP_JNE_IMM:
            if (vm->regs[d] != (uint64_t)(int64_t)ip->imm) pc += ip->off;
            break;
        case OP_JLT_IMM:
            if (vm->regs[d] < (uint64_t)(uint32_t)ip->imm) pc += ip->off;
            break;
        case OP_JGE_IMM:
            if (vm->regs[d] >= (uint64_t)(uint32_t)ip->imm) pc += ip->off;
            break;

        case OP_EMIT:
            if (vm->out_len + 8 <= sizeof(vm->output)) {
                memcpy(vm->output + vm->out_len, &vm->regs[d], 8);
                vm->out_len += 8;
            }
            break;

        case OP_EXIT: vm->halted = 1; break;

        default: return -1;
        }
        pc++;
    }

    int code = (int)(vm->regs[0] & 0xffffffff);
    if (vm->vctx.canary == VERDICT_CANARY && vm->vctx.on_verdict)
        vm->vctx.on_verdict(vm->vctx.client_fd, code);
    return code;
}
