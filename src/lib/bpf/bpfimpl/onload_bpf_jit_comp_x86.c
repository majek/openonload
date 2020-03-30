/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifdef __x86_64__

#include "bpfimpl_kernel_config.h"

#ifdef __KERNEL__
struct static_key;
/* Misc extra includes beyond nospec-branch, to ensure sufficient declarations
 * are in scope */
# include <linux/string.h>
# include <linux/bitops.h>
# include <asm/nospec-branch.h>
#else
# include <ci/kcompat.h>
#endif /* __KERNEL__ */

#ifndef RETPOLINE_RAX_BPF_JIT_SIZE
# define RETPOLINE_RAX_BPF_JIT_SIZE    2
# define RETPOLINE_RAX_BPF_JIT()                               \
      EMIT2(0xFF, 0xE0);       /* jmp *%rax */
#endif

#include "bpf_kernel_compat.h"
#include <linux/netdevice.h>
#include <linux/filter.h>

#if ! defined __KERNEL__ && defined __x86_64__
/* Evil and filthy: There is (what I would call) a bug on line 861 in the
 * jmp/call case: it computes the relative distance to jump from the JITted
 * code to the helper function, which must fit in a 32-bit for opcode reasons.
 * The first time through this function, however, it's not actually generating
 * code, it's merely working out how much code it would generate so that it
 * can allocate correctly (and so that other variable-length stuff works).
 * It indicates that it's not generating code by making 'image'=NULL. The
 * kernel gets away with this because the kernel is always mapped in to the
 * last 2GB of address space, therefore 'helper-NULL' is always small. Not so
 * for us, so we need to hack out the 'return' statement in such cases using
 * this filth. */

#define __bpf_call_base     (image ? __bpf_call_base : NULL)
#endif

#include "kernel/bpf_jit_comp_x86.c"

#endif
