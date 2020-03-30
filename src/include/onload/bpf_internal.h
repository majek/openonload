/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This is the main include file for the kernel side of the Onload BPF
 * implementation. Unlike bpf_kernel.h, this file is used both for the normal
 * kernel build and when the implementation is being built in userspace under
 * the shim. */
#ifndef ONLOAD_BPF_INTERNAL_H_
#define ONLOAD_BPF_INTERNAL_H_

#include <ci/compat.h>
#include <ci/tools/sysdep.h>
#ifndef __KERNEL__
# include <errno.h>
#endif
#include "bpf_ioctl.h"

#ifdef __KERNEL__
#include <linux/unistd.h>
#include <cplane/mib.h>

#ifdef __NR_bpf
# include <uapi/linux/bpf.h>
/* There is some question about the best range of kernels on which to support
 * kernel map interop.  Initially this was based on BPF_ANY, which is present
 * in any kernel with usable eBPF.  However, in the interests of presenting a
 * more consistent set of functionality to users, and reducing the amount of
 * testing for initial GA, kernel interop is disabled. */
#  define CI_HAVE_KERNEL_BPF 0
#else
# define CI_HAVE_KERNEL_BPF 0
#endif

/* General-purpose code selection macro: expands to the first parameter if
 * running on a kernel with the bpf(2) syscall, otherwise the second. */
#if CI_HAVE_KERNEL_BPF
# define CI_IF_KBPF(k, o)     k
#else
# define CI_IF_KBPF(k, o)     o
#endif

#else  /* ndef __KERNEL__ */

# define __user
/* userspace build never has kernel BPF support, because it's all about
 * cunning interop stuff which references kernel innards */
# define CI_HAVE_KERNEL_BPF 0

#endif

enum bpf_map_type;
struct bpf_map;
struct bpf_map_ops;
struct bpf_insn;
struct oo_bpf_map;
struct seq_file;
struct file;
union bpf_attr;
struct oo_bpf_map_ops;
struct net_device;

/* Top-level in-kernel representation of a BPF program object.
 * Programmes are loaded in from userspace with ook_bpf_prog_load() (from the
 * OO_BPF_PROG_IOC_LOAD ioctl). At that point they are verified for safety
 * and semi-bound (also done by verifier code) to replace references to
 * transient entities such as map fds. The result of that semi-binding is
 * stored in 'insns'/'insn_cnt'. It is also immediately JITted for running in
 * kernelspace ('kernel_jitted'). JITting for userspace is done from 'insns'
 * when a userspace address space requests that it is needed. */
struct oo_bpf_prog {
  int refcount;    /* protected by stored_progs_mtx */
  short /*enum bpf_prog_type*/ type;
  /* This program uses some features such that it can only be executed in
   * kernelspace: automatically enable EF_POLL_IN_KERNEL when it's attached
   * to a stack */
  ci_uint8 kernel_only;

  /* Entry points to the JITted implementation of this program appropriate to
   * run in kernelspace. This is an array, because BPF supports function
   * calls. The 0th entry is the one you want (the others are kept around
   * solely so that we can free them when done). */
  struct oo_bpf_prog_func* kernel_progs;
  size_t progs_cnt;
  /* Needed solely for the ook_bpf_prog_get_info() ioctl */
  size_t prog0_jitted_bytes;

  /* Number of elements in the 'insns' array */
  size_t insn_cnt;
  /* Checked and semi-bound implementation of this BPF program. These
   * instructions will need to go through one more step of binding in order
   * to be JITted in to a particular address space, but that data is not
   * persisted */
  struct bpf_insn* insns;

  /* Name given to this program by userspace. Not necessarily 0-terminated.
   * Does not necessarily contain ASCII. Completely untrustworthy. */
  char name[BPF_OBJ_NAME_LEN];

  size_t used_maps_cnt;
  struct oo_bpf_map** used_maps;

#ifdef __KERNEL__
  /* Freeing programmes is deferred to the work queue, because it can happen
   * in atomic context */
  struct work_struct work;
#endif
};


#define OO_BPF_MAP_F_KERNEL_ONLY  1

struct oo_bpf_map_ops {
  /* lookup/update/delete/get_next_key have identical semantics to the
   * equivalently-named kernel functions, and must do so in order to
   * interoperate successfully in BPF-capable kernels. */
  void* (*lookup)(const struct oo_bpf_map*, const void* key);
  int (*update)(const struct oo_bpf_map*, const void* key, const void* value,
                 ci_uint64 flags);
  int (*delete)(const struct oo_bpf_map*, const void* key);
  int (*get_next_key)(const struct oo_bpf_map*, const void* key,
                      void *next_key);
  void (*release)(struct oo_bpf_map* map, struct file* map_file);

  /* Certain map types requires special handling on updates, rather than
   * calling through directly to the map's update op.  This op is used for
   * such maps.
   */
  int (*update_special)(int fd, struct oo_bpf_map*, const void* key,
                        const void* value, ci_uint64 flags);

  /* The following are only needed on slow paths (allocation, verify, etc.) */
  int /*enum bpf_map_type*/ type;
  unsigned flags;
  /* Total number of bytes (including struct oo_bpf_map) to allocate for the
   * main pointer */
  unsigned struct_bytes;
  /* Returns the number of bytes to allocate in oo_bpf_map::data. Called as
   * the first thing during map creation. May return <0 to fail creation (and
   * pass that errno back to the caller). May return zero if this map type is
   * going to deal with memory entirely by itself. */
  ssize_t (*shmbuf_bytes)(enum bpf_map_type type, unsigned key_size,
                          unsigned value_size, unsigned max_entries,
                          unsigned flags);
  /* Do any necessary initialization, typically of the fields after struct
   * oo_bpf_map. When this is called, all the oo_bpf_map members will have
   * been populated already (including 'data'). Returns <0 on error, and that
   * errno is passed to the caller. This pointer may be NULL, when the map
   * type needs no additional initialization. */
  int (*init)(struct oo_bpf_map*);
  /* Deallocate everything allocated by init(). This may be NULL if nothing
   * needs deallocation. */
  void (*free)(struct oo_bpf_map*);
  /* Identical semantics to the equivalently-named kernel function. */
  ci_uint32 (*gen_lookup)(const struct oo_bpf_map*, struct bpf_insn*);
  /* Duplicates of some of these pointers, needed to give to our verifier */
  const struct bpf_map_ops* kops;
};

/* Top-level in-kernel representation of a BPF map object */
struct oo_bpf_map {
  /* We stick a struct bpf_map here, however that's not as simple as you
   * think. There are two, incompatible bpf_map structs: one that is built in
   * to Onload and comes with our copy of the verifier, and one that comes
   * with the native kernel on which we're running (pedant's corner: the two
   * might be compatible by fluke. The latter does not exist on old kernels).
   * This all explains why we can't define this field as 'struct bpf_map',
   * but rather use this ugly casting: this header file is included both by
   * files talking to the real kernel and by files talking to Onload's copy.
   *
   * We need this field in order to give it to our verifier. Note that this
   * struct is only populated enough to make the verifier work - most of the
   * fields remain bogus.
   *
   * The other struct bpf_map points to this oo_bpf_map, via the logic
   * described by the oo_map_priv macro.
   *
   * This field must be at the beginning of oo_bpf_map, to avoid the need for
   * pointer-shifting thunks in bpf_map::ops. */
  char kern_bpf_map[CI_CACHE_LINE_SIZE * 4] CI_ALIGN(CI_CACHE_LINE_SIZE);

  const struct oo_bpf_map_ops* ops;
  /* Dimensions and type of the map, from creation time */
  int /*enum bpf_map_type*/ map_type;
  unsigned key_size;
  unsigned value_size;
  unsigned max_entries;
  unsigned map_flags;
  /* The bulk of the data for the map. It is currently required that maps use
   * this field to store their data location and it must have been vmalloced,
   * however it's easy to see that for future per-CPU map types this won't be
   * good enough. */
  char* data;
  size_t data_pages;
  /* Data that we overwrote in the kernel's struct bpf_map in order to use as
   * a pointer to this structure. See long comment above
   * adapt_kernel_bpf_map() */
  void* replaced_kernel_priv;
  /* Overwritten value of bpf_map::ops which we changed to our own ops */
  const struct bpf_map_ops* replaced_kernel_ops;
  /* Name given to this program by userspace. Not necessarily 0-terminated.
   * Does not necessarily contain ASCII. Completely untrustworthy. */
  char name[BPF_OBJ_NAME_LEN];
  ci_atomic_t refcount;
};


/* These two are called at driver load/unload times to initialize globals */
int ook_bpf_progs_ctor(void);
void ook_bpf_progs_dtor(void);

/* NB: this function can fail due to refcount overflow */
int/*bool*/ ook_bpf_map_incref(struct oo_bpf_map* map);
void ook_bpf_map_decref(struct oo_bpf_map* map);

struct oo_bpf_map* get_oo_map(struct file* f);
ci_uint64 ook_bpf_ktime_get_ns(void);
int oo_bpf_map_init(struct oo_bpf_map* map,
                     const struct oo_bpf_map_create_arg* attr,
                     const struct bpf_map_ops* kops);
/* Undo the effect of save_jitted_code, i.e. free multiple programmes and
 * the array itself. */
void oo_bpf_free_progs_array(struct oo_bpf_prog_func** progs, size_t* count);

#ifndef __KERNEL__
/* Call the JIT for userspace code. This is part of the implementation of
 * oo_bpf_jit(), so the input parameters are from the mmapping of one of our
 * bpf prog fds. */
int oou_bpf_prog_jit(struct bpf_insn* insns, size_t insn_cnt,
                     int prog_type, size_t* progs_cnt_out,
                     struct oo_bpf_prog_func** jitted_out);
#endif

#ifdef __KERNEL__
int ook_get_prog_for_onload(enum oo_bpf_attach_point attach_point,
                            const char* stack_name, ci_hwport_id_t hwport,
                            struct oo_bpf_prog** prog);

int ook_get_prog_fd_for_onload(enum oo_bpf_attach_point attach_point,
                               const char* stack_name, ci_hwport_id_t hwport);
#endif

/* For documentation of the below functions, see the prototypes of the
 * equivalent userspace function with the oo_bpf_ prefix. */

int ook_bpf_version_check(const char* user_version, const char* user_intf_ver,
                          int user_debug);

/* Allocates and JITs a new BPF programme, using the data provided in 'attr'.
 * The returned prog has a refcount of 1. Use ook_bpf_prog_decref() to free
 * it. */
int ook_bpf_prog_load(const struct oo_bpf_prog_load_arg* attr,
                      struct oo_bpf_prog** prog_out);

void ook_bpf_prog_decref(struct oo_bpf_prog* prog);
#ifdef __KERNEL__
/* Special-use internal functions. decref_only decrements the refcount and
 * returns the new value. free_only frees the prog right now without using the
 * refcount. These are needed for the stack polling path which can happen in
 * atomic context, therefore needs to be done in two steps with a work queue
 * in between them. This workqueue magic can't happen within prog.c because
 * that file lives in fake-kernel world. */
int ook_bpf_prog_decref_only(struct oo_bpf_prog* prog);
void ook_bpf_prog_free_only(struct oo_bpf_prog* prog);
#endif

int ook_bpf_prog_get_by_attachment(const struct oo_bpf_prog_attach_arg* attach,
                                   struct oo_bpf_prog** prog);

int ook_bpf_prog_attach(struct oo_bpf_prog* prog,
                        const struct oo_bpf_prog_attach_arg* arg);

int ook_bpf_prog_detach(struct oo_bpf_prog* prog,
                        const struct oo_bpf_prog_attach_arg* arg);

int ook_bpf_prog_test_run(struct oo_bpf_prog* prog,
                          void __user* uarg,
                          struct oo_bpf_prog_test_run_arg* arg);

int ook_bpf_prog_get_all(int attach_cnt,
                         struct oo_bpf_prog_attach_arg __user* attaches);

int ook_bpf_prog_get_info(struct oo_bpf_prog* prog,
                          struct oo_bpf_prog_info __user* info,
                          int is_sysadmin);

/* Allocates and initializes a new Onload BPF map. The returned 'out_map' has
 * a refcount of 1, so use ook_bpf_map_decref() to free it */
int ook_bpf_map_create(struct oo_bpf_map_create_arg* attr,
                       struct oo_bpf_map** out_map);


typedef long (*oo_map_manip_op_t)(int fd, struct oo_bpf_map*,
                                  const void __user*, void __user*, ci_uint64);

int ook_bpf_map_get_info(struct oo_bpf_map* map,
                         struct oo_bpf_map_info __user* info);

long ook_bpf_map_lookup_elem(int fd, struct oo_bpf_map* map,
                             const void __user* key,
                             void __user* value, ci_uint64 flags);

long ook_bpf_map_update_elem(int fd, struct oo_bpf_map* map,
                             const void __user* key, void __user* value,
                             ci_uint64 flags);

long ook_bpf_map_delete_elem(int fd, struct oo_bpf_map* map,
                             const void __user* key,
                             void __user* value, ci_uint64 flags);

long ook_bpf_map_get_next_key(int fd, struct oo_bpf_map* map,
                              const void __user* key,
                              void __user* value, ci_uint64 flags);

static inline int check_map_or_prog_flags(int flags, int all_flags)
{
  if( flags &~ all_flags )
    return -EINVAL;
  if( flags & OO_BPF_F_RDONLY && flags & OO_BPF_F_WRONLY )
    return -EINVAL;
  return 0;
}


/* Maps that are imported from the kernel expect to have various ops performed
 * within an rcu_read_lock().  We could restrict the locking only to maps that
 * actually use rcu, but it's probably not worth on the relatively slow syscall
 * path.  What we do know is that if a map is able to be used from userlevel it
 * cannot require rcu, so we don't (and can't) lock there.
 */
#ifdef __KERNEL__
static inline void oo_map_lock(void)
{
  rcu_read_lock();
}

static inline void oo_map_unlock(void)
{
  rcu_read_unlock();
}
#else
#define oo_map_lock()
#define oo_map_unlock()
#endif


#ifdef __KERNEL__
/* Given its name, you'd think this prototype belongs in tcp_helper_fns.h,
 * however that header file includes lots of kernel bits, so is incompatible
 * with our kcompat environment in bpfimpl */
void tcp_helper_xdp_prog_changed(const char* stack_name,
                                 ci_hwport_id_t hwport);
u64 onload_bpf_event_output(struct bpf_map *map, u64 flags, void *meta,
                            u64 meta_size, void *ctx, u64 ctx_size);
int oo_init_perf(void);
void oo_release_perf(void);
int oo_have_perf(void);
#else
static inline int oo_have_perf(void)
{
  return 0;
}
#endif

#endif
