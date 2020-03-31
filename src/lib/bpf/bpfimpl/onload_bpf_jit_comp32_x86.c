/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifdef __i386__

#include "bpfimpl_kernel_config.h"
#include <ci/kcompat.h>
#include "bpf_kernel_compat.h"
#include <linux/netdevice.h>
#include <linux/filter.h>

#ifndef RETPOLINE_EDX_BPF_JIT
# define RETPOLINE_EDX_BPF_JIT()                               \
      EMIT2(0xFF, 0xE2)        /* jmp *%edx */
#endif

#define ALIGN CI_ROUND_UP

#include "kernel/bpf_jit_comp32_x86.c"

#endif
