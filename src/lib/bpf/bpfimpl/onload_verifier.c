/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include "bpfimpl_kernel_config.h"

#ifndef __KERNEL__
# include <net/if.h>
# include <ci/kcompat.h>
# pragma GCC diagnostic ignored "-Wpointer-arith"

struct task_struct* current;
#endif /* !__KERNEL__ */

#include "bpf_disable_exports.h"
#include "bpf_kernel_compat.h"

/* Pull in bpf-cgroup.h because that contains stub implementations for use
 * when building without CONFIG_CGROUP_BPF (which we are).
 */
#include <linux/bpf-cgroup.h>

#ifdef CONFIG_BPF_LIRC_MODE2
/* This config option causes BPF to use a non-exported symbol. The feature
 * isn't important for ABI compatibility - it's only an extra prog type */
#undef CONFIG_BPF_LIRC_MODE2
#endif

#include "bpfimpl.h"

#include "kernel/verifier.c"


/* This function is implemented here to avoid duplicating bpf_verifier_ops */
int is_bpf_func_kernel_only(enum bpf_prog_type prog_type,
                            enum bpf_func_id func_id, struct bpf_prog* prog)
{
  const struct bpf_verifier_ops* ops = bpf_verifier_ops[prog_type];
  const struct oo_bpf_func_proto* proto =
          (const struct oo_bpf_func_proto*)ops->get_func_proto(func_id, prog);
  return proto && proto->kernel_only;
}
