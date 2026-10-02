#ifndef NINELIVES_SANDBOX_H
#define NINELIVES_SANDBOX_H
/* Installs a seccomp-BPF whitelist. execve/execveat and process creation are
 * denied, so a shell is impossible: the flag must be read with open/read/write. */
void install_sandbox(void);
#endif
