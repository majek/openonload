/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifdef __KERNEL__
# include "bpfimpl_kernel_config.h"
# include "bpf_kernel_compat.h"
# include <cplane/cplane.h>
# include <onload/cplane_driver.h>
#else
# include <limits.h>
# include <net/if.h>
# include <ci/kcompat.h>
# include <cplane/mib.h>
struct net;
#endif /* __KERNEL__ */

#include <linux/bpf.h>
#include <linux/filter.h>

#include <onload/bpf_internal.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/dllist.h>
#include <ci/tools/utils.h>
#include <ci/internal/xdp_buff.h>
#include <onload/debug.h>
#include "uk_bpf_intf_ver.h"
#include <onload/version_check.h>
#include "bpfimpl.h"


/* Arbitrary limit to cap kernel resource consumption */
#define MAX_STORED_PROGS  4096

/* Entry in the list of programme attachments, i.e. the user's requests to
 * attach specific BPF programmes to stacks, ports or the whole machine. See
 * oo_bpf_prog_attach() docs. stored_progs is a doubly-linked list of these
 * things. */
struct oo_bpf_prog_attachment {
  ci_dllink link;
  struct oo_bpf_prog* prog;
  enum oo_bpf_attach_point attach_point;
  char stack[CI_CFG_STACK_NAME_LEN];
  ci_hwport_id_t hwport;
};

/* Protects stored_progs, stored_progs_count and oo_bpf_prog::refcount. A
 * mutex won't do because we need to be able to look up progs from a stack
 * poll (via ook_get_prog_for_onload), which can happen in atomic context */
static DEFINE_SPINLOCK(stored_progs_lock);
/* List of all things set by oo_bpf_prog_attach(). */
static CI_DLLIST_DECLARE(stored_progs);
/* Number of items currently in stored_progs */
static size_t stored_progs_count;


#ifdef __i386__
/* 32-bit Linux kernels are built with -mregparm=3, which changes the function
 * calling convention. The JIT knows this, and the calling convention of the
 * JITted programme (and all calls to helper functions from JITted code) is
 * that the first 3 parameters go in registers. Userspace Onload is not built
 * with this option, so we have to use the equivalent __attribute__ (see
 * OO_BPF_JIT_FUNC_ATTR) to make things work. gcc treats function pointers
 * with and without this attribute as incompatible (as it should), but the
 * imported kernel headers don't include the attribute (because they don't
 * need to because it was the default). We therefore need to cast the
 * attribute away, in the certain knowledge that the JITted code will
 * unconditionally treat it as if it were there. */
# define CAST_KBPF_FUNC(f)  ((bpf_prog_t*)(f))
#else
# define CAST_KBPF_FUNC(f)  (f)
#endif


#ifndef __KERNEL__
/* To make shim tests compile: */
static inline void tcp_helper_xdp_prog_changed(const char* stack_name,
                                               ci_hwport_id_t hwport)
{
  (void)stack_name;
  (void)hwport;
}
#endif


int ook_bpf_version_check(const char* user_version, const char* user_intf_ver,
                          int user_debug)
{
  return oo_version_check_impl(user_version, user_intf_ver, user_debug,
                               OO_UK_BPF_INTF_VER);
}


/* Release kernel resources allocated by bpf_prog_alloc() and bpf_check().
 * Also works to undo bpf_prog_alloc() alone. The implementation herein
 * requires some careful reading of the kernel code to see what it allocates,
 * and what is freed by bpf_prog_free() and what we're expected to free
 * ourselves. See also the call to bpf_prog_kallsyms_del_all() in
 * save_jitted_code(), which technically belongs here but actually we need to
 * do it early for the reasons described at the call site. The code here is
 * broadly thematically similar to __bpf_prog_put in the kernel code.
 *
 * Notably, kernel bpf_prog instances (as freed by this function) do not live
 * for very long in our implementation. They're constructed to be able to
 * verify and JIT code and then destructed before our ook_bpf_prog_load() or
 * oou_bpf_prog_jit() returns. They do not last for the lifetime of a
 * oo_bpf_prog. */
static void kprog_free(struct bpf_prog* kprog)
{
  unsigned i;

  /* This stuff is done by syscall.c in the kernel, so we genuinely need to
   * do it ourselves. */
  for( i = 0; i < kprog->aux->used_map_cnt; ++i )
    ook_bpf_map_decref((struct oo_bpf_map*)kprog->aux->used_maps[i]);
  kfree(kprog->aux->used_maps);

#ifdef __KERNEL__
  bpf_prog_free(kprog);
#else
  /* This is the wrong function to call, but user compat doesn't handle
   * deferred work and it's better to be slightly deficient than to have to
   * wade through definite false positives from a leak checker */
  __bpf_prog_free(kprog);
#endif
}


/* Load and initialize a kernel bpf_prog instance. */
static int ook_bpf_kprog_load(struct bpf_prog** kprog_out,
                              const struct bpf_insn* insns,
                              size_t insn_cnt, enum bpf_prog_type prog_type,
                              const char* name)
{
  struct bpf_prog* kprog;

  kprog = bpf_prog_alloc(bpf_prog_size(insn_cnt), GFP_USER);
  if( !kprog )
    return -ENOMEM;

  kprog->expected_attach_type = __MAX_BPF_ATTACH_TYPE;
  kprog->aux->offload_requested = 0;
  kprog->len = insn_cnt;
  memcpy(kprog->insns, insns, bpf_prog_insn_size(kprog));
  kprog->orig_prog = NULL;
  kprog->jited = 0;
  atomic_set(&kprog->aux->refcnt, 1);
  kprog->gpl_compatible = 1;
  kprog->type = prog_type;
  if( name )
    strncpy(kprog->aux->name, name, sizeof(kprog->aux->name));

  *kprog_out = kprog;
  return 0;
}

extern int bpf_check(struct bpf_prog **fp, union bpf_attr *attr);


/* Run through prog->insns looking for BPF_LD_MAP_FD opcodes, and replace
 * the fds therein (which will become meaningless as soon as the BPF load is
 * completed) with indexes into oo_bpf_prog::used_maps.
 *
 * The only thing which reads the resultant insn stream is the userspace
 * verifier, which statically knows that the fds aren't real fds, via a
 * distinct __bpf_map_get() implementation. */
static int make_map_fds_persistent(struct oo_bpf_prog* prog, size_t nmaps)
{
  size_t i, j;
  size_t maps_found = 0;
  struct fd f = { .file = NULL };

  if( nmaps == 0 )
    return 0;
  prog->used_maps_cnt = nmaps;
  prog->used_maps = ci_alloc(nmaps * sizeof(struct oo_bpf_map*));
  if( ! prog->used_maps ) {
    OO_DEBUG_ERR(ci_log("%s: out of memory allocating maps", __FUNCTION__));
    return -ENOMEM;
  }

  for( i = 0; i < prog->insn_cnt; ++i ) {
    struct bpf_insn* insn = &prog->insns[i];
    if( insn->code == (BPF_LD | BPF_DW | BPF_IMM) &&
        insn->src_reg == BPF_PSEUDO_MAP_FD ) {
      struct oo_bpf_map* map;
      f = fdget(insn->imm);
      if( ! f.file ) {
        OO_DEBUG_ERR(ci_log("%s: fd %d not found", __FUNCTION__, insn->imm));
        goto fail;
      }
      map = get_oo_map(f.file);
      if( ! map ) {
        OO_DEBUG_ERR(ci_log("%s: fd %d is not a map",
                            __FUNCTION__, insn->imm));
        goto fail;
      }
      /* O(n^2) algorithm here, but the verifier will reject anything with
       * more than 64 maps, so it doesn't really matter */
      for( j = 0; j < maps_found; ++j )
        if( prog->used_maps[j] == map )
          break;
      insn->imm = j;
      if( j == maps_found ) {
        ci_assert_lt(maps_found, nmaps);
        if( maps_found >= nmaps ) {
          /* should be impossible, but don't crash anyway */
          OO_DEBUG_ERR(ci_log("%s: miscounted distinct maps", __FUNCTION__));
          goto fail;
        }
        prog->used_maps[maps_found++] = map;
      }
      fdput(f);
      f.file = NULL;
    }
  }

  ci_assert_equal(maps_found, nmaps);
  prog->used_maps_cnt = maps_found;
  for( i = 0; i < maps_found; ++i ) {
    if( ! ook_bpf_map_incref(prog->used_maps[i]) ) {
      OO_DEBUG_ERR(ci_log("%s: map index %zd refcount overflow",
                          __FUNCTION__, i));
      goto fail_incref;
    }
  }
  return 0;

 fail_incref:
  while( i )
    ook_bpf_map_decref(prog->used_maps[--i]);
 fail:
  if( f.file )
    fdput(f);
  prog->used_maps_cnt = 0;
  ci_free(prog->used_maps);
  prog->used_maps = NULL;
  return -EBADF;
}


/* Get rid of the oo_bpf_prog::used_maps member, by freeing all its members
 * and the list itself */
static void free_used_maps(struct oo_bpf_prog* prog)
{
  size_t i;

  for( i = 0; i < prog->used_maps_cnt; ++i )
    ook_bpf_map_decref(prog->used_maps[i]);
  ci_free(prog->used_maps);
  prog->used_maps_cnt = 0;
  prog->used_maps = NULL;
}


void oo_bpf_free_progs_array(struct oo_bpf_prog_func** progs, size_t* count)
{
  size_t i;

  for( i = 0; i < *count; ++i ) {
    /* This code is adapted from bpf_jit_free() */
    void* hdr = (void*)((long)(*progs)[i].func & PAGE_MASK);
#ifdef __KERNEL__
    /* It's unnecessary to do unlock_ro in userspace because module_memfree
     * doesn't actually need to write to the memory */
    bpf_jit_binary_unlock_ro(hdr);
    bpf_jit_binary_free(hdr);
#else
    /* Prototype for bpf_jit_binary_free() is hard to get hold of in
     * userspace, because it's in filter.h */
    module_memfree(hdr);
#endif
  }
  ci_free(*progs);
  *progs = NULL;
  *count = 0;
}


/* Given a kprog which has just come out of bpf_check(), steal the JITted code
 * from it (which may involve actually calling the JIT) and stash the code in
 * the *_out parameters. 'Steal' in this context also means zeroing out fields
 * in the kprog so that the kprog can be immediately freed while leaving the
 * JITted code allocations alive. */
static int save_jitted_code(struct bpf_prog* kprog, size_t* progs_cnt_out,
                            struct oo_bpf_prog_func** jitted_out,
                            size_t* prog0_bytes_out)
{
  size_t progs_cnt;
  size_t prog0_bytes = 0;
  struct oo_bpf_prog_func* jitted;

  /* We're never going to need these (it didn't even manipulate the kernel's
   * kallsyms), and we're about to clear the 'jited' flag which makes this
   * (incorrectly) do nothing */
  bpf_prog_kallsyms_del_all(kprog);

  /* The kernel verifier behaviour is weird: if there are subprogs then
   * bpf_check will JIT them all, if there aren't then it won't JIT anything.
   * We normalize it all here. */
  if( kprog->aux->func_cnt ) {
    /* There were subprogs */
    size_t i;

    for( i = 0; i < kprog->aux->func_cnt; ++i ) {
      if( ! kprog->aux->func[i]->jited ) {
        OO_DEBUG_ERR(ci_log("%s: JITting subprog %zu failed",
                            __FUNCTION__, i));
        return -ENOEXEC;
      }
    }

    progs_cnt = kprog->aux->func_cnt;
    jitted = ci_alloc(progs_cnt * sizeof(struct oo_bpf_prog_func));
    if( ! jitted ) {
      OO_DEBUG_ERR(ci_log("%s: out of memory allocating %zu subprogs",
                          __FUNCTION__, progs_cnt));
      return -ENOMEM;
    }
    for( i = 0; i < progs_cnt; ++i ) {
      jitted[i].func = CAST_KBPF_FUNC(kprog->aux->func[i]->bpf_func);
      /* prevent kprog_free freeing bpf_func: */
      bpf_prog_unlock_ro(kprog->aux->func[i]);
      kprog->aux->func[i]->jited = 0;
      bpf_prog_lock_ro(kprog->aux->func[i]);
    }
    prog0_bytes = kprog->aux->func[0]->jited_len;
  }
  else {
    /* There weren't subprogs. We need to do our own JIT */
    kprog = bpf_int_jit_compile(kprog);
    if( ! kprog->jited ) {
      OO_DEBUG_ERR(ci_log("%s: JITting failed", __FUNCTION__));
      return -ENOEXEC;
    }

    progs_cnt = 1;
    jitted = ci_alloc(1 * sizeof(struct oo_bpf_prog_func));
    if( ! jitted ) {
      OO_DEBUG_ERR(ci_log("%s: out of memory allocating subprogs",
                          __FUNCTION__));
      return -ENOMEM;
    }

    jitted[0].func = CAST_KBPF_FUNC(kprog->bpf_func);
    kprog->jited = 0;  /* prevent kprog_free freeing bpf_func */
    prog0_bytes = kprog->jited_len;
  }

  *progs_cnt_out = progs_cnt;
  *jitted_out = jitted;
  if( prog0_bytes_out )
    *prog0_bytes_out = prog0_bytes;
  return 0;
}


static int is_prog_kernel_only(const struct oo_bpf_prog* prog,
                               struct bpf_prog* kprog)
{
  size_t i;

  if( CI_CFG_BPF_USERSPACE == 0 )
    return 1;

  for( i = 0; i < prog->used_maps_cnt; ++i )
    if( prog->used_maps[i]->ops->flags & OO_BPF_MAP_F_KERNEL_ONLY )
      return 1;

  for( i = 0; i < prog->insn_cnt; ++i ) {
    struct bpf_insn* insn = &prog->insns[i];
    /* Is this insn a call to a BPF helper function (as opposed to a call to
     * another bit of BPF code)? */
    if( insn->code == (BPF_JMP | BPF_CALL) &&
        insn->src_reg != BPF_PSEUDO_CALL ) {
      if( is_bpf_func_kernel_only(prog->type, insn->imm, kprog) )
        return 1;
    }
  }

  return 0;
}


int ook_bpf_prog_load(const struct oo_bpf_prog_load_arg* attr,
                      struct oo_bpf_prog** prog_out)
{
  int rc;
  struct oo_bpf_prog* prog = NULL;
  size_t insn_bytes;
  union bpf_attr kattr;
  struct bpf_prog* kprog;

  rc = check_map_or_prog_flags(attr->prog_flags, OO_BPF_F__PROG_ALL);
  if( rc < 0 )
    return rc;

  if( attr->prog_type != BPF_PROG_TYPE_XDP )
    return -EINVAL;

  prog = ci_alloc(sizeof(*prog));
  if( ! prog ) {
    OO_DEBUG_ERR(ci_log("%s: out of memory allocating prog", __FUNCTION__));
    return -ENOMEM;
  }
  memset(prog, 0, sizeof(*prog));
  prog->refcount = 1;
  strncpy(prog->name, attr->prog_name, sizeof(prog->name));
  prog->type = attr->prog_type;

  prog->insn_cnt = attr->insn_cnt;
  insn_bytes = sizeof(prog->insns[0]) * prog->insn_cnt;
  prog->insns = ci_alloc(insn_bytes);
  if( ! prog->insns ) {
    OO_DEBUG_ERR(ci_log("%s: out of memory allocating insns", __FUNCTION__));
    rc = -ENOMEM;
    goto fail_insns_alloc;
  }
  if( copy_from_user(prog->insns, (const void*)(uintptr_t)attr->insns,
                     insn_bytes) ) {
    rc = -EFAULT;
    goto fail_insns_copy;
  }

  rc = ook_bpf_kprog_load(&kprog, prog->insns, attr->insn_cnt,
                          attr->prog_type, attr->prog_name);
  if( rc ) {
    OO_DEBUG_ERR(ci_log("%s: eBPF program creation failed, rc %d",
                 __FUNCTION__, rc));
    goto fail_prog_load;
  }

  memset(&kattr, 0, sizeof(kattr));
  /* other fields of kattr are not used by bpf_check(). We do not populate
   * them 'just in case' because it's the safer option with regard to the
   * potential for leaking stuff in case of later upgrades to kernel code. */
  kattr.log_level = attr->log_level;
  kattr.log_size = attr->log_size;
  kattr.log_buf = attr->log_buf;
  kattr.prog_flags = attr->prog_flags;
  rc = bpf_check(&kprog, &kattr);
  if( rc ) {
    OO_DEBUG_ERR(ci_log("%s: eBPF program verification failed, rc %d",
                  __FUNCTION__, rc));
    goto fail_verify;
  }

  rc = save_jitted_code(kprog, &prog->progs_cnt, &prog->kernel_progs,
                        &prog->prog0_jitted_bytes);
  if( rc ) {
    /* function already logged something useful */
    goto fail_jit;
  }

  rc = make_map_fds_persistent(prog, kprog->aux->used_map_cnt);
  if( rc ) {
    /* function already logged something useful */
    goto fail_map_fds;
  }

  prog->kernel_only = is_prog_kernel_only(prog, kprog);
  kprog_free(kprog);
  *prog_out = prog;
  return 0;

 fail_map_fds:
  oo_bpf_free_progs_array(&prog->kernel_progs, &prog->progs_cnt);
 fail_jit:
 fail_verify:
  kprog_free(kprog);
 fail_prog_load:
 fail_insns_copy:
  ci_free(prog->insns);
 fail_insns_alloc:
  ci_free(prog);
  return rc;
}


#ifndef __KERNEL__

#define DEBUG_UL_VERIFIER(x)  /* x */

int oou_bpf_prog_jit(struct bpf_insn* insns, size_t insn_cnt,
                     int prog_type, size_t* progs_cnt_out,
                     struct oo_bpf_prog_func** jitted_out)
{
  int rc;
  struct bpf_prog* kprog;
  union bpf_attr kattr;
  DEBUG_UL_VERIFIER(char logbuf[65536];)

  rc = ook_bpf_kprog_load(&kprog, insns, insn_cnt,
                          (enum bpf_prog_type)prog_type, NULL);
  if( rc ) {
    OO_DEBUG_ERR(ci_log("%s: eBPF program creation failed, rc %d",
                 __FUNCTION__, rc));
    return rc;
  }

  memset(&kattr, 0, sizeof(kattr));   /* A completely default kattr is fine */
  DEBUG_UL_VERIFIER(kattr.log_buf = (intptr_t)logbuf;)
  DEBUG_UL_VERIFIER(kattr.log_level = 9;)
  DEBUG_UL_VERIFIER(kattr.log_size = sizeof(logbuf);)
  rc = bpf_check(&kprog, &kattr);
  if( rc ) {
    OO_DEBUG_ERR(ci_log("%s: eBPF program verification failed, rc %d",
                  __FUNCTION__, rc));
    DEBUG_UL_VERIFIER(puts(logbuf);)
    goto fail_verify;
  }

  rc = save_jitted_code(kprog, progs_cnt_out, jitted_out, NULL);
  if( rc ) {
    /* function already logged something useful */
    goto fail_jit;
  }

  kprog_free(kprog);
  return 0;

 fail_jit:
 fail_verify:
  kprog_free(kprog);
  return rc;
}
#endif


int ook_bpf_prog_decref_only(struct oo_bpf_prog* prog)
{
  int new_refcount;

  spin_lock_bh(&stored_progs_lock);
  ci_assert_gt(prog->refcount, 0);
  new_refcount = --prog->refcount;
  spin_unlock_bh(&stored_progs_lock);
  return new_refcount;
}


void ook_bpf_prog_free_only(struct oo_bpf_prog* prog)
{
  free_used_maps(prog);
  oo_bpf_free_progs_array(&prog->kernel_progs, &prog->progs_cnt);
  ci_free(prog->insns);
  ci_free(prog);
}


void ook_bpf_prog_decref(struct oo_bpf_prog* prog)
{
  if( ook_bpf_prog_decref_only(prog) == 0 )
    ook_bpf_prog_free_only(prog);
}


/* Removes an existing entry in the stored_progs list, but does not
 * destroy it. Returns the value of its parameter, for the convenience of
 * callers. stored_progs_lock must be held prior to calling this function. */
static struct oo_bpf_prog_attachment*
unlink_attachment(struct oo_bpf_prog_attachment* pa)
{
  ci_assert(spin_is_locked(&stored_progs_lock));
  ci_assert(pa->prog);
  ci_dllist_remove_safe(&pa->link);
  --stored_progs_count;
  return pa;
}


/* Destroys an oo_bpf_prog_attachment object, which must not currently be
 * linked in to the stored_progs list. stored_progs_lock must not be held
 * prior to calling this function. */
static void destroy_attachment(struct oo_bpf_prog_attachment* pa)
{
  ci_assert(pa->prog);
  ook_bpf_prog_decref(pa->prog);
  ci_free(pa);
}


/* Scans through stored_progs looking for the attachment with the given
 * properties. It is axiomatic for that list that there can be at most one.
 * stored_progs_lock must be held prior to calling this function. */
static struct oo_bpf_prog_attachment*
find_attachment(enum oo_bpf_attach_point attach_point,
                const char* stack, ci_hwport_id_t hwport)
{
  struct oo_bpf_prog_attachment* pa;
  ci_assert(spin_is_locked(&stored_progs_lock));
  CI_DLLIST_FOR_EACH2(struct oo_bpf_prog_attachment, pa, link, &stored_progs)
    if( pa->attach_point == attach_point &&
        pa->hwport == hwport &&
        ! strncmp(pa->stack, stack, sizeof(pa->stack)) )
      return pa;
  return NULL;
}


#ifdef __KERNEL__
static struct net* current_netns(void)
{
  /* During task exit there is a phase where nsproxy is NULL but processing
   * still happens. Deal with that case solely for paranoia reasons - none of
   * the callers of this function should be running during task exit */
  return current->nsproxy ? current->nsproxy->net_ns : &init_net;
}
#endif


#ifdef __KERNEL__
static int get_attachment_dev_cp(struct oo_cplane_handle* cp,
                                 int ifindex, ci_hwport_id_t* hwport_out)
{
  int rc;
  cicp_hwport_mask_t mask;
  cicp_encap_t encap;

  if( ! ifindex ) {
    *hwport_out = CI_HWPORT_ID_BAD;
    return 0;
  }
  rc = oo_cp_find_llap(cp, ifindex, NULL, &mask, NULL, NULL, &encap);
  if( rc ) {
    OO_DEBUG_ERR(ci_log("%s: ifindex %d not found (%d)",
                        __FUNCTION__, ifindex, rc));
    return -ENODEV;
  }
  if( encap.type &~ CICP_LLAP_TYPE_SLAVE ) {
    /* All types of encapsulation/bonding/etc. are banned because the kernel
     * (tested 4.18) ignores XDP on such devices and because we'd still give
     * the raw packet to the program rather than the deencapsulated packet */
    OO_DEBUG_ERR(ci_log("%s: ifindex %d is a derived device",
                        __FUNCTION__, ifindex));
    return -EOPNOTSUPP;
  }
  *hwport_out = cp_hwport_mask_first(mask);
  return 0;
}
#endif

/* Helper for ook_bpf_prog_attach/detach, doing the translation from userspace
 * ifindex to a hwport, with the appropriate hack to make the test shim
 * compilable. */
static int get_attachment_dev(int ifindex, ci_hwport_id_t* hwport_out)
{
  if( ! ifindex ) {
    *hwport_out = CI_HWPORT_ID_BAD;
    return 0;
  }
#ifdef __KERNEL__
  {
    int rc;
    struct oo_cplane_handle* cp;

    cp = cp_acquire_and_sync(current_netns(), CP_SYNC_LIGHT);
    if( ! cp )
      return -EIO;
    rc = get_attachment_dev_cp(cp, ifindex, hwport_out);
    cp_release(cp);
    return rc;
  }
#else
  /* for shim only, an arbitrary identifying value */
  *hwport_out = ifindex;
  return 0;
#endif
}


int ook_get_prog_for_onload(enum oo_bpf_attach_point attach_point,
                            const char* stack_name, ci_hwport_id_t hwport,
                            struct oo_bpf_prog** prog)
{
  struct oo_bpf_prog_attachment* pa;
  struct oo_bpf_prog_attachment* best_pa = NULL;
  int rc = -ENOENT;
  int best_level = -1;

  spin_lock_bh(&stored_progs_lock);
  /* The semantics of this are debatable. One option would be to return an
   * 'amalgam' programme which runs all the attachments associated with this
   * point, i.e. the global, per-intf and per-stack (and containing intf
   * programmes if it's a bond/vlan). For now we just return the single 'most
   * precise' match. */
  CI_DLLIST_FOR_EACH2(struct oo_bpf_prog_attachment, pa, link, &stored_progs) {
    if( pa->attach_point == attach_point &&
        (pa->hwport == CI_HWPORT_ID_BAD || pa->hwport == hwport) &&
        (pa->stack[0] == '\0' ||
         ! strncmp(pa->stack, stack_name, sizeof(pa->stack))) ) {
      int level = (pa->stack[0] ? 2 : 0) |
                  (pa->hwport != CI_HWPORT_ID_BAD ? 1 : 0);
      if( level > best_level ) {
        best_level = level;
        best_pa = pa;
      }
    }
  }
  if( best_pa ) {
    ++best_pa->prog->refcount;
    *prog = best_pa->prog;
    rc = 0;
  }
  spin_unlock_bh(&stored_progs_lock);
  return rc;
}


CI_BUILD_ASSERT(OO_BPF_STACK_NAME_LEN >= CI_CFG_STACK_NAME_LEN);

static int is_stack_name_valid(const char* stack)
{
  return strnlen(stack, OO_BPF_STACK_NAME_LEN) <= CI_CFG_STACK_NAME_LEN;
}


int ook_bpf_prog_get_by_attachment(const struct oo_bpf_prog_attach_arg* attach,
                                   struct oo_bpf_prog** prog)
{
  struct oo_bpf_prog_attachment* pa;
  ci_hwport_id_t hwport;
  int rc;

  if( ! is_stack_name_valid(attach->stack) )
    return -E2BIG;
  rc = get_attachment_dev(attach->ifindex, &hwport);
  if( rc )
    return rc;

  spin_lock_bh(&stored_progs_lock);
  pa = find_attachment((enum oo_bpf_attach_point)attach->attach_point,
                       attach->stack, hwport);
  if( pa )
    ++pa->prog->refcount;
  *prog = pa ? pa->prog : NULL;
  spin_unlock_bh(&stored_progs_lock);

  return pa ? 0 : -ENOENT;
}


int ook_bpf_prog_attach(struct oo_bpf_prog* prog,
                        const struct oo_bpf_prog_attach_arg* arg)
{
  int rc;
  ci_hwport_id_t hwport;
  struct oo_bpf_prog_attachment* pa;
  struct oo_bpf_prog_attachment* old_pa;
  struct oo_bpf_prog* replaced_prog;

  ci_assert_nequal(prog->refcount, 0);

  if( arg->attach_point >= (ci_uint32)OO_BPF_ATTACH_MAX )
    return -EINVAL;
  if( arg->flags &~ OO_BPF_PROG_ATTACH_F_REPLACE )
    return -EINVAL;
  if( ! is_stack_name_valid(arg->stack) )
    return -E2BIG;

#ifdef __KERNEL__
  {
    struct oo_cplane_handle* cp = NULL;
    cp_activation_flags flags;
    cp = cp_acquire_and_sync(current_netns(), CP_SYNC_LIGHT);
    if( ! cp )
      return -EIO;
    flags = *cp->mib->valid_activation_flags;
    rc = get_attachment_dev_cp(cp, arg->ifindex, &hwport);
    cp_release(cp);
    if( (~flags) & CP_ACTIVATION_FLAG_ONLOAD_XDP )
      return -ENOKEY;
  }
#else
  rc = get_attachment_dev(arg->ifindex, &hwport);
#endif

  if( rc )
    return rc;

  /* We might not need this allocation, if we're replacing an existing entry
   * in the list. We're not going to find that out until we enter the mutex,
   * however, so let's do it anyway. */
  pa = ci_alloc(sizeof(*pa));
  if( ! pa ) {
    OO_DEBUG_ERR(ci_log("%s: out of memory allocating attachment",
                        __FUNCTION__));
    return -ENOMEM;
  }

  memset(pa, 0, sizeof(*pa));
  pa->attach_point = (enum oo_bpf_attach_point)arg->attach_point;
  pa->hwport = hwport;
  pa->prog = prog;
  strncpy(pa->stack, arg->stack, sizeof(pa->stack));

  /* setup all done, now add it to the list */
  spin_lock_bh(&stored_progs_lock);
  if( prog->refcount == INT_MAX ) {
    rc = -E2BIG;
    goto fail_refcount_or_dup;
  }

  old_pa = find_attachment(pa->attach_point, pa->stack, pa->hwport);
  if( old_pa ) {
    if( ! (arg->flags & OO_BPF_PROG_ATTACH_F_REPLACE) ) {
      rc = -EEXIST;
      goto fail_refcount_or_dup;
    }
    replaced_prog = old_pa->prog;
    old_pa->prog = prog;
    ++prog->refcount;
  }
  else {
    if( stored_progs_count >= MAX_STORED_PROGS ) {
      rc = -E2BIG;
      goto fail_refcount_or_dup;
    }

    ++prog->refcount;
    ci_dllist_push_tail(&stored_progs, &pa->link);
    ++stored_progs_count;
  }
  spin_unlock_bh(&stored_progs_lock);

  if( old_pa ) {
    /* we must have replaced an existing entry */
    ci_free(pa);
    ook_bpf_prog_decref(replaced_prog);
  }

  tcp_helper_xdp_prog_changed(pa->stack, pa->hwport);
  return 0;

 fail_refcount_or_dup:
  spin_unlock_bh(&stored_progs_lock);
  ci_free(pa);
  return rc;
}


int ook_bpf_prog_detach(struct oo_bpf_prog* prog,
                        const struct oo_bpf_prog_attach_arg* arg)
{
  struct oo_bpf_prog_attachment* pa;
  ci_hwport_id_t hwport;
  int rc;

  if( ! is_stack_name_valid(arg->stack) )
    return -E2BIG;
  rc = get_attachment_dev(arg->ifindex, &hwport);
  if( rc )
    return rc;

  spin_lock_bh(&stored_progs_lock);
  pa = find_attachment((enum oo_bpf_attach_point)arg->attach_point,
                       arg->stack, hwport);
  if( pa && prog && pa->prog != prog )
    pa = NULL;
  if( pa )
    unlink_attachment(pa);
  spin_unlock_bh(&stored_progs_lock);

  if( pa ) {
    tcp_helper_xdp_prog_changed(pa->stack, pa->hwport);
    destroy_attachment(pa);
  }

  return pa ? 0 : -ENOENT;
}


int ook_bpf_prog_test_run(struct oo_bpf_prog* prog,
                          void __user* uarg,
                          struct oo_bpf_prog_test_run_arg* arg)
{
  unsigned i;
  int rc = 0;
  ci_uint64 start, end;
  char* pkt_in_orig;
  ci_uint32 data_start;
  ci_uint32 alloc_size;
  struct oo_xdp_buff ctx;
  struct oo_xdp_rxq_info rxq;

  if( arg->iterations > 10000 )    /* totally arbitrary number */
    return -EINVAL;
  if( arg->pkt_len > 65535 || arg->max_pkt_len > 65535 )
    return -E2BIG;
  if( prog->type != BPF_PROG_TYPE_XDP )
    return -ENOTSUPP;

  alloc_size = arg->pkt_len + CI_MAX(arg->max_pkt_len, arg->pkt_len);
  pkt_in_orig = ci_alloc(alloc_size);
  if( ! pkt_in_orig )
    return -ENOMEM;
  if( arg->pkt_len &&
      copy_from_user(pkt_in_orig, (const void*)(uintptr_t)arg->pkt,
                     arg->pkt_len) ) {
    ci_free(pkt_in_orig);
    return -EFAULT;
  }

  data_start = CI_MIN(arg->pkt_len + XDP_PACKET_HEADROOM,
                      alloc_size - arg->pkt_len);

  memset(&ctx, 0, sizeof(ctx));
  memset(&rxq, 0, sizeof(rxq));
  ctx.data_hard_start = pkt_in_orig + arg->pkt_len;
  ctx.rxq = &rxq;

  start = ci_frc64_get();
  for( i = 0; i < arg->iterations; ++i ) {
    ctx.data = ctx.data_meta = pkt_in_orig + data_start;
    ctx.data_end = (char*)ctx.data + arg->pkt_len;
    memcpy(ctx.data, pkt_in_orig, arg->pkt_len);
    arg->result = prog->kernel_progs[0].func(&ctx, prog->insns);
  }
  end = ci_frc64_get();
  arg->ticks = end - start;
  arg->pkt_len = (char*)ctx.data_end - (char*)ctx.data;

  if( copy_to_user(uarg, arg, sizeof(*arg)) ||
      (arg->pkt_len && arg->max_pkt_len &&
       copy_to_user((void*)(uintptr_t)arg->pkt, ctx.data,
                    CI_MIN(arg->max_pkt_len, arg->pkt_len))) ) {
    rc = -EFAULT;
  }
  ci_free(pkt_in_orig);
  return rc;
}


int ook_bpf_prog_get_all(int attach_cnt,
                         struct oo_bpf_prog_attach_arg __user* uattaches)
{
  int rc = 0;

  int buffer_size;
  int count;

  struct oo_bpf_prog_attach_arg* attaches = NULL;
  struct oo_bpf_prog_attachment* pa;
#ifdef __KERNEL__
  struct oo_cplane_handle* cp = NULL;
#endif

  buffer_size = CI_MIN(attach_cnt, MAX_STORED_PROGS);
  if( buffer_size > 0 ) {
    attaches = ci_alloc(buffer_size * sizeof(*attaches));
    if( ! attaches )
      return -ENOMEM;
    memset(attaches, 0, buffer_size * sizeof(*attaches));
  }

  /* This loop can only go round at most twice. We try the first time without
   * cp because it seems like a common use-case to call this just to confirm
   * that there aren't any attachments in this netns, so we don't want to spin
   * up an unnecessary onload_cp_server as a side-effect. */
  for( ; ; ) {
    bool need_cp = false;

    count = 0;
    spin_lock_bh(&stored_progs_lock);
    CI_DLLIST_FOR_EACH2(struct oo_bpf_prog_attachment, pa, link, &stored_progs) {
      int ifindex = 0;
      if( pa->hwport != CI_HWPORT_ID_BAD ) {
#ifdef __KERNEL__
        if( cp )
          ifindex = oo_cp_get_hwport_ifindex(cp, pa->hwport);
        else
          need_cp = true;
#endif
      }
      if( ifindex < 0 )  /* most likely this hwport has no representation in
                          * this netns */
        continue;
      if( count < buffer_size ) {
        attaches[count].attach_point = pa->attach_point;
        attaches[count].ifindex = ifindex;
        strncpy(attaches[count].stack, pa->stack, CI_CFG_STACK_NAME_LEN);
        /* If CI_CFG_STACK_NAME_LEN < sizeof(attaches[0].stack) then that's fine
        * because we memset above */
      }
      ++count;
    }
    spin_unlock_bh(&stored_progs_lock);

    if( ! need_cp )
      break;

#ifdef __KERNEL__
    cp = cp_acquire_and_sync(current_netns(), CP_SYNC_LIGHT);
    if( ! cp )
      return -EIO;
#endif
  }

#ifdef __KERNEL__
  if( cp )
    cp_release(cp);
#endif

  if( attaches ) {
    rc = copy_to_user(uattaches, attaches, buffer_size * sizeof(*attaches));
    if( rc != 0 )
      rc = -EFAULT;

    ci_free(attaches);
  }
  return rc == 0 ? count : rc;
}


int ook_bpf_prog_get_info(struct oo_bpf_prog* prog,
                          struct oo_bpf_prog_info __user* info,
                          int is_sysadmin)
{
  int rc;
  struct oo_bpf_prog_info prog_info;

  rc = copy_from_user(&prog_info, info, sizeof(struct oo_bpf_prog_info));
  if( rc != 0 )
    return -EFAULT;

  prog_info.type = prog->type;
  prog_info.nr_map_ids = prog->used_maps_cnt;
  strncpy(prog_info.name, prog->name, sizeof(prog_info.name));

  if( ! is_sysadmin ) {
    /* Give out only basic information to non-root users. It would probably
     * have been reasonable to give out the number of instructions, however
     * that would create an API where you needed to know whether you're
     * sysadmin in order to figure out whether you can read the results */
    prog_info.xlated_prog_len = 0;
    prog_info.jited_prog_len = 0;
  }
  else {
    size_t ebpf_buffer_size = prog_info.xlated_prog_len;
    size_t jit_buffer_size  = prog_info.jited_prog_len;

    /* Return the original size of the eBPF bytecode and jitted code */
    prog_info.xlated_prog_len = prog->insn_cnt * sizeof(struct bpf_insn);
    prog_info.jited_prog_len  = prog->prog0_jitted_bytes;

    /* Copy eBPF bytecode and jitted code to the userspace buffers */
    if( rc == 0 && prog_info.xlated_prog_insns )
      rc = copy_to_user((void*)(uintptr_t)prog_info.xlated_prog_insns,
                        prog->insns,
                        CI_MIN(ebpf_buffer_size,
                              prog->insn_cnt * sizeof(struct bpf_insn)));
    if( rc == 0 && prog_info.jited_prog_insns )
      rc = copy_to_user((void*)(uintptr_t)prog_info.jited_prog_insns,
                        prog->kernel_progs[0].func,
                        CI_MIN(jit_buffer_size, prog->prog0_jitted_bytes));
    if( rc != 0 )
      return -EFAULT;
  }

  rc = copy_to_user(info, &prog_info, sizeof(struct oo_bpf_prog_info));
  if( rc != 0 )
    rc = -EFAULT;
  return rc;
}


/* Remove from stored_progs all items unconditionally. */
static void remove_all_attachments(void)
{
  struct oo_bpf_prog_attachment* pa;
  struct oo_bpf_prog_attachment* next;
  CI_DLLIST_DECLARE(destroy_list);

  spin_lock_bh(&stored_progs_lock);
  CI_DLLIST_FOR_EACH3(struct oo_bpf_prog_attachment, pa, link,
                      &stored_progs, next) {
    unlink_attachment(pa);
    ci_dllist_push_tail(&destroy_list, &pa->link);
  }
  spin_unlock_bh(&stored_progs_lock);

  CI_DLLIST_FOR_EACH3(struct oo_bpf_prog_attachment, pa, link,
                      &destroy_list, next) {
    destroy_attachment(pa);
  }
}


int ook_bpf_progs_ctor(void)
{
  return 0;
}


void ook_bpf_progs_dtor(void)
{
  remove_all_attachments();
  ci_assert_equal(stored_progs_count, 0);
}
