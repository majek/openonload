/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This header file has stuff which is shared only within files living in the
 * 'fake backported kernel' world (unlike bpf_internal.h, which lives in both
 * worlds) */
#ifndef ONLOAD_BPFIMPL_H_
#define ONLOAD_BPFIMPL_H_

#include <onload/bpf_internal.h>
#include <linux/bpf.h>

struct oo_bpf_func_proto {
  struct bpf_func_proto kern;   /* must be first */
  ci_uint8 kernel_only;
};

int is_bpf_func_kernel_only(enum bpf_prog_type prog_type,
                            enum bpf_func_id func_id, struct bpf_prog* prog);

#endif
