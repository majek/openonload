/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*************************************************************************
 * This file contains the onload implementation of the XDP specific eBPF
 * functionality.
 *************************************************************************/

#ifdef __KERNEL__
#include "bpf_kernel_compat.h"
#else
#include <limits.h>
#include <net/if.h>
#include <ci/kcompat.h>
#endif /* __KERNEL__ */

#include <linux/bpf.h>
#include <linux/filter.h>

#include <ci/internal/xdp_buff.h>
#include <ci/tools.h>
#include <onload/bpf_internal.h>
#include "bpfimpl.h"

#ifdef __i386__
# define CAST_KBPF_HELPER(f) ((void*)(f))

# define OO_BPF_CALL_x(x, name, ...)                                   \
  static __always_inline                                               \
  u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__)); \
   OO_BPF_JIT_FUNC_ATTR                                                 \
  u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));       \
   OO_BPF_JIT_FUNC_ATTR                                                 \
  u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))        \
  {                                                                    \
   return ____##name(__BPF_MAP(x,__BPF_CAST,__BPF_N,__VA_ARGS__));    \
  }                                                                    \
  static __always_inline                                               \
  u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))

# define OO_BPF_CALL_0(name, ...)  OO_BPF_CALL_x(0, name, __VA_ARGS__)
# define OO_BPF_CALL_1(name, ...)  OO_BPF_CALL_x(1, name, __VA_ARGS__)
# define OO_BPF_CALL_2(name, ...)  OO_BPF_CALL_x(2, name, __VA_ARGS__)
# define OO_BPF_CALL_3(name, ...)  OO_BPF_CALL_x(3, name, __VA_ARGS__)
# define OO_BPF_CALL_4(name, ...)  OO_BPF_CALL_x(4, name, __VA_ARGS__)
# define OO_BPF_CALL_5(name, ...)  OO_BPF_CALL_x(5, name, __VA_ARGS__)

/* undefine these solely so we get a compile error if a mistake is made */
# undef BPF_CALL_0
# undef BPF_CALL_1
# undef BPF_CALL_2
# undef BPF_CALL_3
# undef BPF_CALL_4
# undef BPF_CALL_5

#else
# define CAST_KBPF_HELPER(f) (f)
# define OO_BPF_CALL_0   BPF_CALL_0
# define OO_BPF_CALL_1   BPF_CALL_1
# define OO_BPF_CALL_2   BPF_CALL_2
# define OO_BPF_CALL_3   BPF_CALL_3
# define OO_BPF_CALL_4   BPF_CALL_4
# define OO_BPF_CALL_5   BPF_CALL_5
#endif


OO_BPF_CALL_0(bpfhelper_ktime_get_ns)
{
#ifdef __KERNEL__
  /* Gratuitous wrapper function is needed because we live in fake-kernel
   * land in this file. The definitions might not be compatible */
  return ook_bpf_ktime_get_ns();
#else
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000000000ll + t.tv_nsec;
#endif
}

static const struct oo_bpf_func_proto oo_bpf_ktime_get_ns_proto = {
  .kern = {
    .func = CAST_KBPF_HELPER(bpfhelper_ktime_get_ns),
    .gpl_only = true,
    .ret_type = RET_INTEGER,
  },
};


OO_BPF_CALL_2(bpfhelper_map_lookup_elem, struct bpf_map*, map, void*, key)
{
  return (unsigned long) map->ops->map_lookup_elem(map, key);
}

static const struct oo_bpf_func_proto oo_bpf_map_lookup_elem_proto = {
  .kern = {
    .func = CAST_KBPF_HELPER(bpfhelper_map_lookup_elem),
    .gpl_only = false,
    .pkt_access = true,
    .ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
    .arg1_type = ARG_CONST_MAP_PTR,
    .arg2_type = ARG_PTR_TO_MAP_KEY,
  },
};

OO_BPF_CALL_4(bpfhelper_map_update_elem, struct bpf_map*, map, void*, key,
           void*, value, u64, flags)
{
  return map->ops->map_update_elem(map, key, value, flags);
}

static const struct oo_bpf_func_proto oo_bpf_map_update_elem_proto = {
  .kern = {
    .func = CAST_KBPF_HELPER(bpfhelper_map_update_elem),
    .gpl_only = false,
    .pkt_access = true,
    .ret_type = RET_INTEGER,
    .arg1_type = ARG_CONST_MAP_PTR,
    .arg2_type = ARG_PTR_TO_MAP_KEY,
    .arg3_type = ARG_PTR_TO_MAP_VALUE,
    .arg4_type = ARG_ANYTHING,
  },
};

OO_BPF_CALL_2(bpfhelper_map_delete_elem, struct bpf_map*, map, void*, key)
{
  return map->ops->map_delete_elem(map, key);
}

static const struct oo_bpf_func_proto oo_bpf_map_delete_elem_proto = {
  .kern = {
    .func = CAST_KBPF_HELPER(bpfhelper_map_delete_elem),
    .gpl_only = false,
    .pkt_access = true,
    .ret_type = RET_INTEGER,
    .arg1_type = ARG_CONST_MAP_PTR,
    .arg2_type = ARG_PTR_TO_MAP_KEY,
  },
};


OO_BPF_CALL_5(bpfhelper_xdp_event_output, struct oo_xdp_buff*, xdp,
              struct bpf_map*, map, u64, flags, void*, meta, u64, meta_size)
{
#ifdef __KERNEL__
  u64 xdp_size = (flags & BPF_F_CTXLEN_MASK) >> 32;

  if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
    return -EINVAL;
  if (unlikely(xdp_size > (unsigned long)(xdp->data_end - xdp->data)))
    return -EFAULT;

  return onload_bpf_event_output(map, flags, meta, meta_size, xdp->data,
                                 xdp_size);
#else
  return -EOPNOTSUPP;
#endif
}

static const struct oo_bpf_func_proto oo_bpf_xdp_event_output_proto = {
  .kern = {
    .func           = CAST_KBPF_HELPER(bpfhelper_xdp_event_output),
    .gpl_only       = true,
    .ret_type       = RET_INTEGER,
    .arg1_type      = ARG_PTR_TO_CTX,
    .arg2_type      = ARG_CONST_MAP_PTR,
    .arg3_type      = ARG_ANYTHING,
    .arg4_type      = ARG_PTR_TO_MEM,
    .arg5_type      = ARG_CONST_SIZE_OR_ZERO,
  },
  .kernel_only = 1,
};

static const struct oo_bpf_func_proto*
 oo_xdp_func_proto_impl(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
  switch( func_id ) {
  case BPF_FUNC_ktime_get_ns:
    return &oo_bpf_ktime_get_ns_proto;
  case BPF_FUNC_map_lookup_elem:
    return &oo_bpf_map_lookup_elem_proto;
  case BPF_FUNC_map_update_elem:
    return &oo_bpf_map_update_elem_proto;
  case BPF_FUNC_map_delete_elem:
    return &oo_bpf_map_delete_elem_proto;
  case BPF_FUNC_perf_event_output:
    if( oo_have_perf() )
      return &oo_bpf_xdp_event_output_proto;
    /* else fallthrough */
  default:
    return NULL;
  }
}


static const struct bpf_func_proto*
 oo_xdp_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
  /* gratuitous wrapper function, solely to force the return type of
   * oo_xdp_func_proto_impl to be oo_bpf_func_proto and thus prevent a
   * potential source of mistakes */
  const struct oo_bpf_func_proto* proto;
  proto = oo_xdp_func_proto_impl(func_id, prog);
  return proto ? &proto->kern : NULL;
}


static bool oo_xdp_is_valid_access(int off, int size,
                                   enum bpf_access_type type,
                                   const struct bpf_prog* prog,
                                   struct bpf_insn_access_aux* info)
{
  if( type == BPF_WRITE )
    return false;

  switch (off) {
  case offsetof(struct xdp_md, data):
    info->reg_type = PTR_TO_PACKET;
    return size == 4;
  case offsetof(struct xdp_md, data_meta):
    info->reg_type = PTR_TO_PACKET_META;
    return size == 4;
  case offsetof(struct xdp_md, data_end):
    info->reg_type = PTR_TO_PACKET_END;
    return size == 4;
  /* ingress_ifindex and rx_queue_index not currently implemented */
  }

  return false;
}

static u32 oo_xdp_convert_ctx_access(enum bpf_access_type type,
                                     const struct bpf_insn *si,
                                     struct bpf_insn *insn_buf,
                                     struct bpf_prog *prog, u32 *target_size)
{
  struct bpf_insn *insn = insn_buf;

  switch (si->off) {
  case offsetof(struct xdp_md, data):
    *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct oo_xdp_buff, data),
              si->dst_reg, si->src_reg,
              offsetof(struct oo_xdp_buff, data));
    break;
  case offsetof(struct xdp_md, data_meta):
    *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct oo_xdp_buff, data_meta),
              si->dst_reg, si->src_reg,
              offsetof(struct oo_xdp_buff, data_meta));
    break;
  case offsetof(struct xdp_md, data_end):
    *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct oo_xdp_buff, data_end),
              si->dst_reg, si->src_reg,
              offsetof(struct oo_xdp_buff, data_end));
    break;
  }

  return insn - insn_buf;
}

static int oo_bpf_noop_prologue(struct bpf_insn *insn_buf, bool direct_write,
                                const struct bpf_prog *prog)
{
  /* Nothing needed for XDP */
  return 0;
}

const struct bpf_verifier_ops xdp_verifier_ops = {
  .get_func_proto = oo_xdp_func_proto,
  .is_valid_access = oo_xdp_is_valid_access,
  .convert_ctx_access = oo_xdp_convert_ctx_access,
  .gen_prologue = oo_bpf_noop_prologue,
};

