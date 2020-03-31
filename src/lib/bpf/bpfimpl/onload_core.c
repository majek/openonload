/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include "bpfimpl_kernel_config.h"

#ifndef __KERNEL__
# include <net/if.h>
# include <ci/kcompat.h>
# pragma GCC diagnostic ignored "-Wpointer-arith"
# pragma GCC diagnostic ignored "-Wunused-value"
#endif /* !__KERNEL__ */

#include "bpf_disable_exports.h"
#include "bpf_kernel_compat.h"

/* The bpf_jit_charge_init function is used in the kernel as pure_initcall(),
 * which we can't do, so don't moan about it.
 *
 * FIXME I'm not addressing the lack of initialisation as the limit
 * depends on jit work that we haven't done yet.
 */
# pragma GCC diagnostic ignored "-Wunused-function"
#include "kernel/core.c"

