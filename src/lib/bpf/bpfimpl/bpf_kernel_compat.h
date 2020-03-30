/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef BFPIMPL_BPF_KERNEL_COMPAT_H
#define BFPIMPL_BPF_KERNEL_COMPAT_H

#ifdef __KERNEL__
#include <driver/linux_affinity/autocompat.h>

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/overflow.h>
/* oom.h is a dodgy workaround, because signal_pending is defined in different
 * header files in different kernel versions, but oom.h always includes the
 * appropriate header.
 */
#include <linux/oom.h>
#include <linux/seqlock.h>

struct fd;

#ifndef READ_ONCE
#define READ_ONCE(x) ACCESS_ONCE((x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (ACCESS_ONCE((x)) = (v))
#endif

#ifndef EFRM_HAVE_READ_SEQCOUNT_LATCH
extern int raw_read_seqcount_latch(seqcount_t *s);
#endif

#ifndef EFRM_HAVE_WRITE_SEQCOUNT_LATCH
extern void raw_write_seqcount_latch(seqcount_t *s);
#endif

#ifndef EFRM_HAVE_RBTREE
struct rb_node;
extern void rb_link_node_rcu(struct rb_node *node, struct rb_node *parent,
                             struct rb_node **rb_link);
#endif

#ifndef EFRM_HAVE_SKB_METADATA
struct sk_buff;
extern unsigned char skb_metadata_len(const struct sk_buff *skb);
#endif

#ifndef EFRM_HAVE_BIN2HEX
extern char *bin2hex(char *dst, const void *src, size_t count);
#endif

#ifndef EFRM_HAVE_PRANDOM_U32_STATE
struct rnd_state;
extern u32 prandom_u32_state(struct rnd_state *state);
#endif

#ifndef EFRM_HAVE_NETDEV_NOTIFIER_INFO
# define netdev_notifier_info_to_dev(info) (info)
#endif

#ifndef EFRM_HAVE_ARRAY_SIZE
/* FIXME SCJ needs check for overflow */
# define array_size(a, b) ((a)*(b))
#endif

#ifndef EFRM_HAVE_WRITE_ONCE
# define WRITE_ONCE(x, v) (ACCESS_ONCE((x)) = (v))
#endif

#ifndef EFRM_HAVE_S_MIN_MAX
# define U8_MAX          ((u8)~0U)
# define S8_MAX          ((s8)(U8_MAX>>1))
# define S8_MIN          ((s8)(-S8_MAX - 1))
# define U16_MAX         ((u16)~0U)
# define S16_MAX         ((s16)(U16_MAX>>1))
# define S16_MIN         ((s16)(-S16_MAX - 1))
# define U32_MAX         ((u32)~0U)
# define S32_MAX         ((s32)(U32_MAX>>1))
# define S32_MIN         ((s32)(-S32_MAX - 1))
# define U64_MAX         ((u64)~0ULL)
# define S64_MAX         ((s64)(U64_MAX>>1))
# define S64_MIN         ((s64)(-S64_MAX - 1))
#endif

#ifndef EFRM_HAVE_INIT_LIST_HEAD_RCU
static inline void INIT_LIST_HEAD_RCU(struct list_head *list)
{
  WRITE_ONCE(list->next, list);
  WRITE_ONCE(list->prev, list);
}
#endif

/* This avoids bringing in the header file that include various defintions
 * required for qdisc functionality, which we don't need.  This causes
 * problems because there are build asserts on the size of the data structure
 * in the eBPF code that handles this, to ensure compatibility between the
 * kernel handling and the public data structure definitions.  We avoid
 * this by replacing it with our own def in all cases.
 */
#define __NET_SCHED_GENERIC_H
struct sk_buff;
struct qdisc_skb_cb {
#define QDISC_CB_PRIV_LEN 20
  unsigned char data[QDISC_CB_PRIV_LEN];
};
extern struct qdisc_skb_cb* qdisc_skb_cb(const struct sk_buff *skb);

/* We can't declare things as pure_initcall() in a module, so anything that
 * we depend on that would use this mechanism for initialisation needs to be
 * handled elsewhere.
 */
#define pure_initcall(fn)

#ifdef alloc_percpu_gfp
# define HAVE_ATOMIC_PERCPU 1
#else
/* kernel < 3.18 */
# define HAVE_ATOMIC_PERCPU 0
/* This implementation isn't sufficient, in general. See comment at the bottom
 * of onload_hashtab.c.
 */
static inline void __percpu* __alloc_percpu_gfp(size_t size, size_t align,
                                                gfp_t gfp)
{
#ifdef __GFP_ATOMIC
#ifndef NDEBUG
  /* __GFP_ATOMIC was added in 4.4. Don't worry about prior to that because
   * at least some of our testing will catch if this bug happens */
  BUG_ON(gfp & __GFP_ATOMIC);
#endif
#endif
  return __alloc_percpu(size, align);
}
#endif

#endif

extern int kallsyms_show_value(void);

/* This is used if the eBPF program calls the get_prandom_u32 function */
extern void prandom_init_once(void* arg);

extern int set_memory_ro(unsigned long addr, int numpages);
extern int set_memory_rw(unsigned long addr, int numpages);
extern int set_memory_x(unsigned long addr, int numpages);

extern void module_memfree(void *module_region);

struct btf;
struct seq_file;
extern void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
                              struct seq_file *m);

#ifndef lock_acquire_exclusive
#define lock_acquire_exclusive(l, s, t, n, i) lock_acquire(l, s, t, 0, 1, n, i)
#endif

#ifndef seqcount_acquire
#define seqcount_acquire(l, s, t, i) lock_acquire_exclusive(l, s, t, NULL, i)
#endif

#ifndef seqcount_release
#define seqcount_release(l, n, i) lock_release(l, n, i)
#endif

#ifndef hlist_nulls_entry_safe
#define hlist_nulls_entry_safe(ptr, type, member) \
        ({ typeof(ptr) ____ptr = (ptr); \
           !is_a_nulls(____ptr) ? hlist_nulls_entry(____ptr, type, member) : NULL; \
        })
#endif

#ifndef hlist_nulls_for_each_entry_safe
#define hlist_nulls_for_each_entry_safe(tpos, pos, head, member)                \
        for (({barrier();}),                                                    \
             pos = rcu_dereference_raw(hlist_nulls_first_rcu(head));            \
                (!is_a_nulls(pos)) &&                                           \
                ({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member);        \
                   pos = rcu_dereference_raw(hlist_nulls_next_rcu(pos)); 1; });)
#endif

#endif /* BFPIMPL_BPF_KERNEL_COMPAT_H */
