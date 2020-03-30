/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*************************************************************************
 * This file contains the stub implementations of kernel functionality that
 * is required to build our kernel eBPF components but not used for the
 * subset of programs we support.
 *
 * Stubs fall into two categories, those that are exported by the kernel, but
 * only in certain versions, and internal kernel functions.
 *
 * The version compat stubs are only used in the kernel build as the
 * userspace compat lib provides userspace implementations of exported
 * kernel functions.
 *
 * The stubs for internal funtionality are required for both user and kernel
 * builds.
 *************************************************************************/

#include "bpfimpl_kernel_config.h"

#ifndef __KERNEL__
#include <ci/kcompat.h>
#else
#include "bpf_kernel_compat.h"
#endif

#include <ci/tools.h>
#include <linux/bpf.h>

#ifdef __KERNEL__

#ifndef EFRM_HAVE_SKB_METADATA
struct sk_buff;
unsigned char skb_metadata_len(const struct sk_buff *skb)
{
  ci_assert(0);
  return 0;
}
#endif

#ifndef EFRM_HAVE_READ_SEQCOUNT_LATCH
int raw_read_seqcount_latch(seqcount_t *s)
{
  ci_assert(0);
  return -1;
}
#endif

#ifndef EFRM_HAVE_WRITE_SEQCOUNT_LATCH
void raw_write_seqcount_latch(seqcount_t *s)
{
  ci_assert(0);
}
#endif

#ifndef EFRM_HAVE_RBTREE
#include <linux/rbtree.h>
void rb_link_node_rcu(struct rb_node *node, struct rb_node *parent,
                      struct rb_node **rb_link)
{
  struct rb_node* fake_link;
  rb_link_node(node, parent, &fake_link);
  rcu_assign_pointer(*rb_link, fake_link);
}
#endif

#ifndef EFRM_HAVE_BIN2HEX
char *bin2hex(char *dst, const void *src, size_t count) {
  ci_hex_dump_format_octets(dst, src, 0, 0, count);
  return dst;
}
#endif

#ifndef EFRM_HAVE_ALLSYMS_SHOW_VALUE
int kallsyms_show_value(void)
{
  ci_assert(0);
  return 0;
}
#endif

#ifndef EFRM_HAVE_PRANDOM_INIT_ONCE
/* This is used if the eBPF program calls the get_prandom_u32 function */
void prandom_init_once(void* arg)
{
  ci_assert(0);
}
#endif

#ifndef EFRM_HAVE_PRANDOM_U32_STATE
u32 prandom_u32_state(struct rnd_state *state)
{
  ci_assert(0);
  return 0;
}
#endif

#ifndef EFRM_PRANDOM_SEED_FULL_EXPORT
struct rnd_state;
void prandom_seed_full_state(struct rnd_state __percpu *pcpu_state)
{
  ci_assert(0);
}
#endif

/* bpf_prog_[put|get] are used from the BPF_MAP_TYPE_PROG_ARRAY implementation,
 * which we don't use, but is pulled in with support for
 * BPF_MAP_TYPE_PERF_EVENT_ARRAY.
 */
#ifndef EFRM_HAVE_BPF_PROG_PUT
void bpf_prog_put(struct bpf_prog* prog)
{
  ci_assert(0);
}
#endif

struct bpf_prog* bpf_prog_get(u32 ufd)
{
  ci_assert(0);
  return ERR_PTR(-EOPNOTSUPP);
}

struct qdisc_skb_cb* qdisc_skb_cb(const struct sk_buff *skb)
{
  ci_assert(0);
  return NULL;
}

#endif

void bpf_prog_offload_destroy(struct bpf_prog *prog)
{
  ci_assert(0);
}

int bpf_prog_offload_compile(struct bpf_prog *prog)
{
  ci_assert(0);
  return -ENODEV;
}

int bpf_prog_offload_verify_insn(struct bpf_verifier_env *env,
                                 int insn_idx, int prev_insn_idx)
{
  ci_assert(0);
  return -ENODEV;
}

int bpf_prog_offload_verifier_prep(struct bpf_verifier_env *env)
{
  ci_assert(0);
  return -ENODEV;
}

bool bpf_offload_prog_map_match(struct bpf_prog *prog, struct bpf_map *map)
{
  ci_assert(0);
  return false;
}

int bpf_prog_offload_finalize(struct bpf_verifier_env *env)
{
  ci_assert(0);
  return -ENODEV;
}

bool bpf_sock_is_valid_access(int off, int size, enum bpf_access_type type,
                              struct bpf_insn_access_aux *info)
{
  ci_assert(0);
  return false;
}

u32 bpf_sock_convert_ctx_access(enum bpf_access_type type,
                                const struct bpf_insn *si,
                                struct bpf_insn *insn_buf,
                                struct bpf_prog *prog, u32 *target_size)
{
  ci_assert(0);
  return 0;
}

const struct bpf_verifier_ops sk_filter_verifier_ops = {};
const struct bpf_verifier_ops cg_skb_verifier_ops = {};
const struct bpf_verifier_ops cg_sock_verifier_ops = {};
const struct bpf_verifier_ops lwt_in_verifier_ops = {};
const struct bpf_verifier_ops lwt_out_verifier_ops = {};
const struct bpf_verifier_ops lwt_xmit_verifier_ops = {};
const struct bpf_verifier_ops sock_ops_verifier_ops = {};
const struct bpf_verifier_ops sk_skb_verifier_ops = {};
const struct bpf_verifier_ops sk_msg_verifier_ops = {};
const struct bpf_verifier_ops cg_sock_addr_verifier_ops = {};
const struct bpf_verifier_ops lwt_seg6local_verifier_ops = {};
const struct bpf_verifier_ops flow_dissector_verifier_ops = {};
const struct bpf_verifier_ops sk_reuseport_verifier_ops = {};
const struct bpf_verifier_ops tracepoint_verifier_ops = {};
const struct bpf_verifier_ops raw_tracepoint_verifier_ops = {};
const struct bpf_verifier_ops perf_event_verifier_ops = {};
const struct bpf_verifier_ops kprobe_verifier_ops = {};
const struct bpf_verifier_ops tc_cls_act_verifier_ops = {};

const struct bpf_map_ops bpf_map_offload_ops = {};
