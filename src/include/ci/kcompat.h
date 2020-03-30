/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef TEST_KERNEL_COMPAT_H
#define TEST_KERNEL_COMPAT_H

/* This header file and the associated lib/tests/kernel_compat provide
 * shimmery to enable compilation, and to a certain extent running, of
 * kernel code in userspace.  The extent to which it is valid is driven
 * very much by the current uses of the code, and no reliance should be made
 * on correct behaviour.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <linux/random.h>
#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>
#include <ci/tools/byteorder.h>
#include <ci/tools.h>
#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <onload/atomics.h>


#ifndef __bool_true_false_are_defined
# define bool int
# define true 1
# define false 0
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint16_t __be16;
typedef uint32_t __be32;

typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#ifndef __aligned_u64
/* Not supplied by linux/types.h on old kernels */
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#endif

#define U8_MAX          ((u8)~0U)
#define S8_MAX          ((s8)(U8_MAX>>1))
#define S8_MIN          ((s8)(-S8_MAX - 1))
#define U16_MAX         ((u16)~0U)
#define S16_MAX         ((s16)(U16_MAX>>1))
#define S16_MIN         ((s16)(-S16_MAX - 1))
#define U32_MAX         ((u32)~0U)
#define S32_MAX         ((s32)(U32_MAX>>1))
#define S32_MIN         ((s32)(-S32_MAX - 1))
#define U64_MAX         ((u64)~0ULL)
#define S64_MAX         ((s64)(U64_MAX>>1))
#define S64_MIN         ((s64)(-S64_MAX - 1))

#ifdef __i386__
# define BITS_PER_LONG 32
#else
# define BITS_PER_LONG 64
#endif

#define min CI_MIN
#define max CI_MAX

#define min_t(type, x, y) min(x, y)
#define max_t(type, x, y) max(x, y)

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define PAGE_SHIFT              12
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

#define BIT(nr)                 (1UL << (nr))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define array_size(a, b) ((a)*(b))

#define fls(n) ci_log2_ge((n) + 1,0)

#define cpu_to_le16 CI_BSWAP_LE16
#define cpu_to_le32 CI_BSWAP_LE32
#define cpu_to_le64 CI_BSWAP_LE64
#define cpu_to_be16 CI_BSWAP_BE16
#define cpu_to_be32 CI_BSWAP_BE32
#define cpu_to_be64 CI_BSWAP_BE64

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

#define NUMA_NO_NODE    (-1)

#define __percpu
#define DECLARE_PER_CPU(type, name) extern __typeof__(type) name
#define DEFINE_PER_CPU(type, name) __typeof__(type) name
#define this_cpu_ptr(x) x
#define get_cpu_var(x) (*(this_cpu_ptr(&x)))
#define put_cpu_var(x) (void)&(x)

#define WRITE_ONCE(x, val) (x) = (val)
#define READ_ONCE(x) (x)

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define container_of(p_,t_,f_) CI_CONTAINER(t_,f_,p_)
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#define ____cacheline_aligned CI_ALIGN(CI_CACHE_LINE_SIZE)
#define __cacheline_aligned ____cacheline_aligned
#define __aligned CI_ALIGN
#define __user
#define __must_check
#define unlikely(x) x
#define __printf(a, b)
#define barrier()
#define __force
#define __read_mostly
#define __weak __attribute__((weak))
#define noinline
#define __init __attribute__ ((constructor))
#define pure_initcall(x)

#define EXPORT_SYMBOL_GPL(x)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(x)

#define IS_ENABLED(x) x
#define IS_BUILTIN(x) IS_ENABLED(x)


/***********************************************************
 * Basic kernel functionality
 ***********************************************************/

extern int in_atomic(void);
extern int in_interrupt(void);

struct task_struct;
extern int signal_pending(struct task_struct *p);

extern int cond_resched(void);
extern bool need_resched(void);

#define CAP_NET_RAW 13
#define CAP_SYS_ADMIN 21

extern bool capable(int cap);

#define EFRM_NET_HAS_USER_NS
struct user_namespace;
extern int ns_capable(struct user_namespace* user_ns, int c);

extern int ci_getgid(void);

#define KSYM_NAME_LEN 128
extern int kallsyms_show_value(void);

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
struct work_struct {
  work_func_t func;
};

#define INIT_WORK(w, f) (w)->func = (f);
extern bool schedule_work(struct work_struct *work);

/***********************************************************
 * Concurrency
 ***********************************************************/

typedef oo_atomic_t atomic_t;

typedef struct {
  int64_t counter;
} atomic_long_t;

typedef struct refcount_struct {
        atomic_t refs;
} refcount_t;

extern void atomic_add(int i, atomic_t *v);
extern void atomic_set(atomic_t *v, int i);
extern long atomic_long_add_return(long i, atomic_long_t *l);
extern void atomic_long_sub(long i, atomic_long_t *l);

struct mutex {
  pthread_mutex_t mutex;
};

extern void mutex_lock(struct mutex* m);
extern void mutex_unlock(struct mutex* m);
extern void mutex_init(struct mutex* m);
extern void mutex_destroy(struct mutex* m);
extern int mutex_is_locked(struct mutex* m);

#define DEFINE_MUTEX(mutexname) \
  struct mutex mutexname = { .mutex = PTHREAD_MUTEX_INITIALIZER };

typedef struct spinlock {
  pthread_mutex_t spin;
} spinlock_t;

extern void spin_lock_init(spinlock_t* s);
extern int spin_is_locked(spinlock_t* s);
extern void spin_lock_bh(spinlock_t* s);
extern void spin_unlock_bh(spinlock_t* s);

#define DEFINE_SPINLOCK(lockname) \
  struct spinlock lockname = { .spin = PTHREAD_MUTEX_INITIALIZER };

struct rcu_head {
  int dummy;
};

#define __rcu
#define rcu_dereference_check(p, c) (p)
#define rcu_dereference(p) (p)
#define rcu_read_lock()
#define rcu_read_unlock()
#define kfree_rcu(p, r) kfree(p)

#define INIT_LIST_HEAD_RCU(name) \
  { (name)->next = (name); (name)->prev = (name); }

#define list_add_tail_rcu(insert, after) \
  ci_dllist_insert_before((after), (insert))
#define list_del_rcu ci_dllist_remove
#define list_for_each_entry_rcu(a, b, c) for( 0; 0; )

/***********************************************************
 * Memory
 ***********************************************************/

#define GFP_USER 0
#define GFP_KERNEL 0
#define __GFP_ZERO 0
#define __GFP_NOWARN 0
#define PAGE_KERNEL 0

extern int copy_from_user(void* dst, const void* src, size_t n);
extern int copy_to_user(void* dst, const void* src, size_t n);

extern int set_memory_ro(unsigned long addr, int numpages);
extern int set_memory_rw(unsigned long addr, int numpages);
extern int set_memory_x(unsigned long addr, int numpages);

typedef int gfp_t;
typedef int pgprot_t;
extern void *kcalloc(size_t n, size_t size, gfp_t flags);
extern void *kzalloc(size_t size, gfp_t flags);
extern void *kmalloc_array(size_t n, size_t size, gfp_t flags);
extern void kfree(void *objp);

#define vmalloc vzalloc
#define vmalloc_user vzalloc
extern void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot);
extern void *vzalloc(unsigned long size);
extern void vfree(void *addr);

#define VMALLOC_END 0
#define VMALLOC_START 0

void* module_alloc(unsigned long size);
void module_memfree(void *module_region);


/***********************************************************
 * Utils
 ***********************************************************/

#define BUG_ON(cond) ci_assert((cond) == 0)
#define BUILD_BUG_ON(x) (void)(x)

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) \
  ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
  return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
  return IS_ERR_VALUE((unsigned long)ptr);
}

extern int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);

#define print_hex_dump(a, b, c, d, e, f, g, h)
#define pr_err(fmt, ...)
#define pr_warn(fmt, ...)
#define pr_info_once(fmt, ...)

#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)

extern void sort(void *base, size_t num, size_t size,
                 int (*cmp_func)(const void *, const void *),
                 void (*swap_func)(void *, void *, int size));

extern int fls64(u64 x);

/* Old kernels leak their internal rnd_state to userspace in linux/random.h,
 * so here's some preprocessor trickery to ensure we work in both cases */
struct onload_rnd_state {
  int dummy;
};
#define rnd_state onload_rnd_state
extern void prandom_init_once(void* arg);
extern u32 prandom_u32_state(struct rnd_state *state);
extern unsigned int get_random_int(void);

#define bin2hex(dst, src, count) (dst)

#define SHA_MESSAGE_BYTES (512 /*bits*/ / 8)
#define SHA_DIGEST_WORDS 5
#define SHA_WORKSPACE_WORDS 16

extern void sha_init(u32 *buf);
extern void sha_transform(u32 *digest, const u8 *data, u32 *array);

#define __WARN_printf(arg...)   do { ci_log(arg); } while (0)

#define WARN(condition, format...) ({           \
        int __ret_warn_on = !!(condition);      \
        if (unlikely(__ret_warn_on))            \
                __WARN_printf(format);          \
        unlikely(__ret_warn_on);                \
})

#define WARN_ON(condition) ({                                   \
        int __ret_warn_on = !!(condition);                      \
        if (unlikely(__ret_warn_on))                            \
                __WARN_printf("assertion failed at %s:%d\n",    \
                                __FILE__, __LINE__);            \
        unlikely(__ret_warn_on);                                \
})

#define WARN_ON_ONCE(condition) ({                      \
        static int __warned;                            \
        int __ret_warn_once = !!(condition);            \
                                                        \
        if (unlikely(__ret_warn_once && !__warned)) {   \
                __warned = true;                        \
                WARN_ON(1);                             \
        }                                               \
        unlikely(__ret_warn_once);                      \
})

#define WARN_ONCE(condition, format...) ({      \
        static int __warned;                    \
        int __ret_warn_once = !!(condition);    \
                                                \
        if (unlikely(__ret_warn_once))          \
                if (WARN(!__warned, format))    \
                        __warned = 1;           \
        unlikely(__ret_warn_once);              \
})

/***********************************************************
 * Data structures
 ***********************************************************/

#define POISON_POINTER_DELTA 0
#define LIST_POISON2 ((void *) 0x200 + POISON_POINTER_DELTA)
#define list_head ci_dllink_s
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)
#define list_empty ci_dllink_is_self_linked

struct latch_tree_node {
  int dummy;
};

struct latch_tree_root {
  int dummy;
};

struct latch_tree_ops {
  bool (*less)(struct latch_tree_node *a, struct latch_tree_node *b);
  int  (*comp)(void *key, struct latch_tree_node *b);
};

struct latch_tree_root;
struct latch_tree_ops;
extern void latch_tree_insert(struct latch_tree_node *node,
                              struct latch_tree_root *root,
                              const struct latch_tree_ops *ops);
extern void latch_tree_erase(struct latch_tree_node *node,
                             struct latch_tree_root *root,
                             const struct latch_tree_ops *ops);
#define latch_tree_find(a, b, c) NULL

/***********************************************************
 * Networking
 ***********************************************************/

#define VLAN_HLEN 4

struct net_device {
  unsigned int flags;
  unsigned int mtu;
  unsigned short hard_header_len;
};

struct qdisc_skb_cb {
#define QDISC_CB_PRIV_LEN 20
  unsigned char data[QDISC_CB_PRIV_LEN];
};

struct sk_buff {
  char cb[48];
  char* data;
  unsigned char* head;
};

extern void dev_put(struct net_device* dev);

extern u8 skb_metadata_len(const struct sk_buff *skb);
extern unsigned int skb_headlen(const struct sk_buff *skb);
extern void *skb_header_pointer(const struct sk_buff *skb, int offset,
                                int len, void *buffer);
extern u8 *skb_tail_pointer(const struct sk_buff *skb);
extern unsigned char *skb_network_header(const struct sk_buff *skb);
extern unsigned char *skb_mac_header(const struct sk_buff *skb);

extern struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb);

#define STACK_FRAME_NON_STANDARD(x)

/***********************************************************
 * Filesystems
 ***********************************************************/

struct file;
struct fd {
  struct file *file;
  unsigned int flags;
};

/* NB: implementations of these functions are not provided by the kcompat
 * library. Users are expected to bring their own fdtable with them */
extern struct fd fdget(unsigned int fd);
extern void fdput(struct fd fd);

#endif /* TEST_KERNEL_COMPAT_H */
