#ifndef VEX_VERIFIER_H
#define VEX_VERIFIER_H

#include "vm.h"

int verify_program(const insn_t *prog, size_t n_insns, char *err, size_t err_sz);

#endif
