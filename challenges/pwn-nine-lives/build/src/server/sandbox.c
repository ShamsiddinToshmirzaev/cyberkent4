#include "sandbox.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

/*
 * Denylist: process-creation and program-execution syscalls are killed, so a
 * shell is impossible and the flag must be read with open/read/write. Anything
 * else is allowed (so the C library's own error/abort machinery stays intact).
 */
static const int denied[] = {
    SYS_ptrace,
};

void install_sandbox(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("no_new_privs");
        _exit(1);
    }

    size_t n = sizeof(denied) / sizeof(denied[0]);
    struct sock_filter filter[3 + 1 + 2 * (sizeof(denied) / sizeof(denied[0])) + 1];
    size_t k = 0;

    /* enforce x86-64 ABI (blocks x32/i386 execve smuggling) */
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, arch));
    filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                    AUDIT_ARCH_X86_64, 1, 0);
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    filter[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, nr));

    for (size_t i = 0; i < n; i++) {
        filter[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                        (unsigned int)denied[i], 0, 1);
        filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    }
    filter[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { .len = (unsigned short)k, .filter = filter };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        perror("seccomp");
        _exit(1);
    }
}
