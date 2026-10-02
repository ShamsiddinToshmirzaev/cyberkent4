#include "sandbox.h"

#include <stddef.h>
#include <stdint.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/*
 * Syscall denylist. The dangerous file/exec entry points are blocked by number.
 * mmap and friends stay available so payloads can still get scratch memory.
 */
int install_sandbox(void)
{
    struct sock_filter filter[] = {
        /* load syscall number (no architecture guard) */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read,      7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write,     6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open,      5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,    4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 437 /*openat2*/,3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve,    2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat,  1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) return -1;
    return 0;
}
