/*
** Copyright 2005-2018  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/* In-kernel support for UL Control Plane */
#include <ci/compat.h>
#include <ci/tools.h>
#include <onload/mmap.h>
#include <onload/debug.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/moduleparam.h>
#include <linux/log2.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include "../linux_resource/kernel_compat.h"
#include "../linux_onload/onload_kernel_compat.h"
#include <cplane/mib.h>
#include <onload/fd_private.h>
#include <onload/tcp_driver.h>
#include <onload/cplane_driver.h>
#include <onload/cplane_module_params.h>
#include <cplane/server.h>

#include "onload_internal.h"


/* This is a module parameter.  It controls the timeout in seconds for which
 * stack-creation waits for the control plane to be ready. */
int cplane_init_timeout = 10;

/* Module parameter to control the grace period before the server is killed
 * when all users have gone. */
int cplane_server_grace_timeout = 30;

/* Module parameter limiting the depth of the route requests queue. */
int cplane_route_request_limit = 1000;
/* Module parameter limiting the route request timeout. */
#define CP_ROUTE_REQ_TIMEOUT_DEFAULT_MS 200
int cplane_route_request_timeout_ms = CP_ROUTE_REQ_TIMEOUT_DEFAULT_MS;
unsigned long cplane_route_request_timeout_jiffies;

/* Parsed cplane parameters */
int cplane_server_params_array_num = 0;
size_t cplane_server_params_array_len = 0;
char** cplane_server_params_array = NULL;

const char* cplane_server_const_params[] = {
#ifdef IFLA_BOND_SLAVE_MAX
    /* If the kernel publishes bonding state over netlink, tell the cplane
     * server so.  This means that the bonding timer will never have to run.
     *
     * There are a lot of "intermediate" kernel versions which publish
     * **some** info over netlink.  We may not disable the bonding timer
     * unless we have **all** the needed info, including
     * IFLA_BOND_SLAVE_MII_STATUS.  If IFLA_BOND_SLAVE_MAX is defined,
     * then IFLA_BOND_SLAVE_MII_STATUS is published as well.
     */
    "--"CPLANE_SERVER_FORCE_BONDING_NETLINK,
#endif
    "--"CPLANE_SERVER_DAEMONISE_CMDLINE_OPT,
    "--"CPLANE_SERVER_HWPORT_NUM_OPT, OO_STRINGIFY(CI_CFG_MAX_HWPORTS),
    "--"CPLANE_SERVER_IPADDR_NUM_OPT, OO_STRINGIFY(CI_CFG_MAX_LOCAL_IPADDRS),
};
#define CP_SERVER_CONST_PARAM_NUM \
  (sizeof(cplane_server_const_params) / sizeof(char*))

/* Protects the state that is not associated with a single cplane instance
 * -- for example, the hash table containing all the instances.  The "link"
 * member of each oo_cplane_handle is protected by that lock, though.
 */
static spinlock_t cp_lock;

/* When onload module is loaded with a parameter, a handler from
 * module_param_call() may be called before module_init() hook.
 * I.e. module-parsing function must ensure that cp_lock is initialized. */
static inline void cp_lock_init(void)
{
  /* The module loading is a single-threaded process which starts at
   * load_module() function.  At the end it calls the module_init() hook,
   * which calls oo_cp_driver_ctor(), and the cp_lock is definitely
   * initialized.  I.e. we do not need to protect cp_lock_inited variable
   * by another spinlock. */
  static bool cp_lock_inited = false;
  if( cp_lock_inited )
    return;
  spin_lock_init(&cp_lock);
  cp_lock_inited = true;
}


struct cp_vm_private_data {
  struct oo_cplane_handle* cp;
  /* This mapping defines the association of a UL server with the kernel
   * control plane instance.  There are in gerenal other mappings held by the
   * server that do not have this flag set. */
#define CP_VM_PRIV_FLAG_SERVERLINK   0x0001ull
  uint64_t cp_vm_flags;

  /* Reference count for the memory mapping. */
  atomic_t cp_vm_refcount;
};


/* All instances of the control plane are stored in a hash table that is
 * indexed by network namespace pointers.  Access to the table is protected by
 * cp_lock.
 *     The implementation of the hash table is modelled on that used for the
 * mm hash table by the trampoline.  Each entry in the table is a doubly-linked
 * list of oo_cplane_handle structures. */
#define CP_INSTANCE_HASH_SIZE  256
static ci_dllist cp_hash_table[CP_INSTANCE_HASH_SIZE];

/* Has the control plane subsystem been fully initialized? */
int cp_initialized = 0;

/* hash_mm() can make stronger assumptions about the alignment of the pointers
 * that it hashes than we can in hash_netns().  About the best we can do is to
 * expect that the kernel is likely to round the addresses up to a power of two
 * no smaller than the object, but not farther, and then to throw away the
 * corresponding number of bits. */
#define HASH_NETNS_SHIFT (ilog2(sizeof(struct oo_cplane_handle) - 1) + 1)
CI_BUILD_ASSERT(__builtin_constant_p(HASH_NETNS_SHIFT));

/* Function to hash a network namespace pointer. */
static inline unsigned hash_netns(const struct net* netns)
{
  ci_uintptr_t t = (ci_uintptr_t) netns;
  return (t >> HASH_NETNS_SHIFT) & (CP_INSTANCE_HASH_SIZE - 1);
}


/* Utility function to find control plane instance for a specified network
 * namespace.  Returns pointer to the control plane instance, or NULL if
 * not found.
 */
static struct oo_cplane_handle* cp_table_lookup(const struct net* netns)
{
  unsigned hash = hash_netns(netns);
  ci_dllink* link;

  ci_assert(spin_is_locked(&cp_lock));

  CI_DLLIST_FOR_EACH(link, &cp_hash_table[hash]) {
    struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                               link, link);
    if( cp->cp_netns == netns )
      return cp;
  }

  return NULL;
}


/* Add a new item to the control plane hash table. */
static void cp_table_insert(struct net* netns, struct oo_cplane_handle* cp)
{
  OO_DEBUG_CPLANE(ci_log("%s: netns=%p cp=%p", __FUNCTION__, netns, cp));

  ci_assert(spin_is_locked(&cp_lock));
  ci_assert(! cp_table_lookup(netns));

  ci_dllist_push(&cp_hash_table[hash_netns(netns)], &cp->link);
}


/* If this function returns true, then user may call all functions from
 * include/cplane/cplane.h without crash or other unexpected consequence. */
static int cp_is_usable(struct oo_cplane_handle* cp)
{
  return cp->usable;
}

/* Onload requires oof to be populated.  As oof instances
 * might come and go, cplane is asked each time new oof appears to
 * populate it with its state.  The oof_version tracks oof-populate
 * requests and wakes client (onload) once the request is fullfilled
 * or timeout happens (see oo_cp_wait_for_server and oo_cp_oof_ready).
 */
static int
cp_is_usable_for_oof(struct oo_cplane_handle* cp, cp_version_t version)
{
  return cp_is_usable(cp) && version != OO_ACCESS_ONCE(*cp->mib->oof_version);
}


static void cp_destroy(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib = &cp->mib[0];
  OO_DEBUG_CPLANE(ci_log("%s:", __FUNCTION__));

  ci_assert(! in_atomic());

  /* The memory mapping held by the server holds a reference to [cp], and when
   * that mapping is destroyed, [cp->server_pid] is released before the
   * reference to [cp] is dropped. */
  ci_assert_equal(cp->server_pid, NULL);

  vfree(mib->fwd_rw);
  mib->fwd_rw = NULL;
  vfree(cp->mem);
  cp->mem = NULL;
  kfree(mib->dim);
  mib->dim = NULL;

  cicpplos_dtor(&cp->cppl);

#ifdef EFRM_HAVE_NF_NET_HOOK
  oo_unregister_nfhook(cp->cp_netns);
#endif

  put_net(cp->cp_netns);
  kfree(cp);
}

static void cp_kill(struct oo_cplane_handle* cp)
{

  ci_dllist_remove_safe(&cp->link);

  /* Holding cp_handle_lock ensures that cp->server_pid is not going to be
   * released under our feet.  Calling kill_pid() is safe in atomic context. */
  if( cp->server_pid != NULL )
    kill_pid(cp->server_pid, SIGQUIT, 1);

}

static void cp_kill_work(struct work_struct *work)
{
  struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                             destroy_work.work, work);
  spin_lock(&cp_lock);
  spin_lock_bh(&cp->cp_handle_lock);
  cp_kill(cp);
  spin_unlock_bh(&cp->cp_handle_lock);
  spin_unlock(&cp_lock);

  cp_release(cp);
}

/* Should be called under cp_lock only */
static int/*bool*/ cp_cancel_kill(struct oo_cplane_handle* cp)
{
  ci_assert(cp->killed);
  if( cancel_delayed_work(&cp->destroy_work) ) {
    OO_DEBUG_CPLANE(ci_log("%s: Cancel killing work item: cp=%p netns=%p",
                           __FUNCTION__, cp, cp->cp_netns));
    cp->killed = 0;
    return 1;
  }

  OO_DEBUG_CPLANE(ci_log("%s: Failed to cancel killing work item: "
                         "cp=%p netns=%p", __FUNCTION__,
                         cp, cp->cp_netns));
  return 0;
}

static void cp_destroy_work(struct work_struct *work)
{
  struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                             destroy_work.work, work);
  cp_destroy(cp);
}

void cp_release(struct oo_cplane_handle* cp)
{
  int /*bool*/ last_ref_gone;

  spin_lock(&cp_lock);
  spin_lock_bh(&cp->cp_handle_lock);

  OO_DEBUG_CPLANE(ci_log("%s: cp=%p netns=%p refcount=%d", __FUNCTION__, cp,
                         cp->cp_netns, atomic_read(&cp->refcount)));

  last_ref_gone = atomic_dec_and_test(&cp->refcount);
  if( last_ref_gone ) {
    OO_DEBUG_CPLANE(ci_log("%s: last ref gone: cp=%p netns=%p", __FUNCTION__,
                           cp, cp->cp_netns));
    ci_dllist_remove_safe(&cp->link);
  }
  /* If we have a server and the reference count has dropped to one, there
   * are no clients left, and we should kill the server, but only if Onload is
   * configured to spawn servers automatically. */
  else if( cplane_spawn_server && atomic_read(&cp->refcount) == 1 ) {
    if( cp->killed ) {
      /* If the cp_kill_work is scheduled, then the only refcount belongs to it.
       * We should cancel the delayed work and destroy the cp object. */
      if( cp_cancel_kill(cp) ) {
        OO_DEBUG_CPLANE(ci_log("%s: last ref gone when kill was pending: "
                               "cp=%p netns=%p", __FUNCTION__,
                                cp, cp->cp_netns));
        last_ref_gone = 1;
        ci_dllist_remove_safe(&cp->link);
      }
      /* else the refcount owner will release it in time */
    }
    else if( cp->server_pid != NULL ) {
      cp->killed = 1;
      atomic_inc(&cp->refcount);
      queue_delayed_work(CI_GLOBAL_WORKQUEUE, &cp->destroy_work,
                         HZ * cplane_server_grace_timeout);
      OO_DEBUG_CPLANE(ci_log("%s: Schedule killing orphaned server: cp=%p "
                             "netns=%p server_pid=%p", __FUNCTION__,
                             cp, cp->cp_netns, cp->server_pid));
    }
    else {
      OO_DEBUG_CPLANE(ci_log("%s:  One reference with no server. --bootstrap? "
                             "cp=%p netns=%p", __FUNCTION__,
                             cp, cp->cp_netns));
    }
  }
  spin_unlock_bh(&cp->cp_handle_lock);
  spin_unlock(&cp_lock);

  if( last_ref_gone ) {
    /* cp_destroy() may not be called in atomic context, but
     * cp_acquire_from_netns/cp_release may be called by users from any
     * context.  So, we always use workqueue to call cp_destroy(). */
    INIT_DELAYED_WORK(&cp->destroy_work, cp_destroy_work);
    queue_delayed_work(CI_GLOBAL_WORKQUEUE, &cp->destroy_work, 0);
  }
}

static struct cp_vm_private_data*
cp_get_vm_data(const struct vm_area_struct* vma)
{
  return (struct cp_vm_private_data*) vma->vm_private_data;
}

static void vm_op_open(struct vm_area_struct* vma)
{
  struct cp_vm_private_data* cp_vm_data = cp_get_vm_data(vma);
  OO_DEBUG_CPLANE(ci_log("%s: cp=%p", __FUNCTION__, cp_vm_data->cp));
  atomic_inc(&cp_vm_data->cp_vm_refcount);

  /* The mappings do not need to hold their own reference to [cp] as they hold
   * a reference to the [struct file] for /dev/onload, which holds a reference
   * to [cp]. */
}

static void vm_op_close(struct vm_area_struct* vma)
{
  struct cp_vm_private_data* cp_vm_data = cp_get_vm_data(vma);

  ci_assert(cp_vm_data);
  ci_assert(cp_vm_data->cp);

  if( atomic_dec_and_test(&cp_vm_data->cp_vm_refcount) ) {
    /* If this mapping is the one that held the association between UL server
     * and kernel, tear that association down. */
    if( cp_vm_data->cp_vm_flags & CP_VM_PRIV_FLAG_SERVERLINK ) {
      struct oo_cplane_handle* cp = cp_vm_data->cp;
      struct pid* server_pid = cp->server_pid;

      ci_assert(server_pid);

      /* Interlock with cp_kill_work(). */
      spin_lock_bh(&cp->cp_handle_lock);
      cp->server_pid = NULL;
      spin_unlock_bh(&cp->cp_handle_lock);

      put_pid(server_pid);
    }

    kfree(cp_vm_data);
  }
}

static int cp_fault_mib(struct vm_area_struct *vma, struct vm_fault *vmf)
{
  unsigned long offset = VM_FAULT_ADDRESS(vmf) - vma->vm_start;
  struct oo_cplane_handle* cp = cp_get_vm_data(vma)->cp;

  ci_assert(cp->bytes);
  ci_assert(cp->mem);
  ci_assert_lt(offset, cp->bytes);
  vmf->page = vmalloc_to_page(cp->mem + offset);
  get_page(vmf->page);

  return 0;
}

static int cp_fault_fwd_rw(struct vm_area_struct *vma, struct vm_fault *vmf)
{
  unsigned long offset = VM_FAULT_ADDRESS(vmf) - vma->vm_start;
  struct oo_cplane_handle* cp = cp_get_vm_data(vma)->cp;

  vmf->page = vmalloc_to_page((void*)((uintptr_t)cp->mib[0].fwd_rw + offset));
  get_page(vmf->page);

  return 0;
}

static int vm_op_fault(
#ifndef EFRM_HAVE_NEW_FAULT
                       struct vm_area_struct *vma,
#endif
                       struct vm_fault *vmf) {
#ifdef EFRM_HAVE_NEW_FAULT
  struct vm_area_struct *vma = vmf->vma;
#endif
  struct oo_cplane_handle* cp = cp_get_vm_data(vma)->cp;

  /* Is the server running?  It is silly to use cplane when server has
   * already gone. */
  if( cp->server_pid == NULL )
    return VM_FAULT_SIGBUS;

  switch( vma->vm_pgoff >> OO_MMAP_TYPE_WIDTH ) {
    case OO_MMAP_CPLANE_ID_MIB:
      return cp_fault_mib(vma, vmf);
    case OO_MMAP_CPLANE_ID_FWD_RW:
      return cp_fault_fwd_rw(vma, vmf);
    default:
      return VM_FAULT_SIGBUS;
  }
}

static struct vm_operations_struct vm_ops = {
  .open  = vm_op_open,
  .close = vm_op_close,
  .fault = vm_op_fault,
  /* linux/Documentation/filesystems/Locking: ->access is needed only for
   * VM_IO | VM_PFNMAP VMAs. */
};

static int
cp_mmap_mib(struct oo_cplane_handle* cp, struct vm_area_struct* vma)
{
  unsigned long bytes = vma->vm_end - vma->vm_start;

  if( vma->vm_flags & VM_WRITE ) {
    int rc;

    /* If server is started manually, the user must have CAP_NET_ADMIN
     * to avoid collisions. */
#ifdef EFRM_NET_HAS_USER_NS
    if( ! ns_capable(current->nsproxy->net_ns->user_ns, CAP_NET_ADMIN) )
#else
    if( ! capable(CAP_NET_ADMIN) )
#endif
      return -EPERM;

#ifdef CONFIG_COMPAT
    /* Do not allow cplane server under compat: __copy_siginfo_to_user32()
     * is completely wrong for us and does not copy cp_fwd_key to UL. */
    if( is_compat_task() ) {
      ci_log("The Onload Control Plane server is 32-bit, "
             "while the kernel is 64-bit.  This is not supported.  "
             "Please ensure that "
             "/sys/module/onload/parameters/cplane_server_path points to "
             "the 64-bit onload_cp_server binary.");
      return -EFAULT;
    }
#endif

    /* Cplane process starts.  Let's allocate new cplane instance. */
    rc = 0;
    spin_lock_bh(&cp->cp_handle_lock);
    /* Check that there isn't already a server running for this control plane.
     */
    if( cp->server_pid != NULL ) {
      OO_DEBUG_CPLANE(ci_log("%s: Already have a server: cp=%p "
                             "pid(server)=%d pid(current)=%d", __FUNCTION__,
                             cp, pid_nr(cp->server_pid),
                             task_tgid_nr(current)));
      rc = -EBUSY;
    }
    /* Fixme: If a previous server exited while there will still clients
     * active, and some of those clients are still around, we will hit this
     * branch.  For now, we bail out; bug70351 tracks improvements. */
    else if( cp->mem != NULL ) {
      OO_DEBUG_CPLANE(ci_log("%s: cp->mem not NULL: cp=%p", __FUNCTION__, cp));
      rc = -ENOTEMPTY;
    }
    /* Don't allow a server to run if there are no other references to the
     * control plane instance for this namespace.  We ourselves hold two
     * references: one for the fd and one for the mmap() call.  This is
     * required to prevent control plane servers becoming orphaned in the case
     * where Onload ceases to care about a namespace while a server is starting
     * up, and so the test is only necessary when Onload is configured to spawn
     * the servers itself.
     *     There is a race in the case where two servers are spawned in
     * parallel, but since only one will survive, it will be reaped in short
     * order. */
    else if( cplane_spawn_server && atomic_read(&cp->refcount) <= 2 ) {
      OO_DEBUG_CPLANE(ci_log("%s: No other references: cp=%p", __FUNCTION__,
                             cp));
      rc = -ENONET;
    }
    if( rc < 0 ) {
      spin_unlock_bh(&cp->cp_handle_lock);
      return rc;
    }
    /* get_pid() needn't be done inside the spinlock, so we drop the lock
     * first. */
    cp->server_pid = task_pid(current);
    spin_unlock_bh(&cp->cp_handle_lock);
    get_pid(cp->server_pid);


    /* Since the association of the kernel state with the UL server has
     * happened here in the mmap() handler, we wish to break that association
     * when the mapping is destroyed.  This means that we need to recognise
     * this mapping as being the one defining the association.  So, set a flag.
     */
    cp_get_vm_data(vma)->cp_vm_flags |= CP_VM_PRIV_FLAG_SERVERLINK;

    /* We need a chunk of memory, continuious in both kernel and UL address
     * spaces.
     * We probably need kvmalloc() https://lwn.net/Articles/711653/ */
    ci_assert_equal(cp->mem, NULL);
    cp->mem = vmalloc(bytes);
    cp->bytes = bytes;
    memset(cp->mem, 0, bytes);
  }
  else {
    /* Client wants to use MIBs. */
    if( cp->mem == NULL )
      return -ENOENT;
    if( ! cp_is_usable(cp) )
      return -ENOENT;
    if( bytes != cp->bytes )
      return -EPERM;
  }
  return 0;
}

static int
cp_mmap_fwd_rw(struct oo_cplane_handle* cp, struct vm_area_struct* vma)
{
  struct cp_mibs* mib = &cp->mib[0];
  unsigned long bytes = vma->vm_end - vma->vm_start;

  if( ! (vma->vm_flags & VM_WRITE) )
    return -EACCES;

  /* If it is the server, then finish all the allocations and setup */
  if( task_pid(current) == cp->server_pid ) {
    /* Server have filled in the mib->dim structure before calling this, so
     * we can set up the mib structure.  We also copy the dimension structure
     * to UL-unaccessible memory, so that cplane server can't crash kernel. */
    mib->dim = kmalloc(sizeof(struct cp_tables_dim), GFP_KERNEL);
    if( mib->dim == NULL )
      return -ENOMEM;
    memcpy(mib->dim, cp->mem, sizeof(struct cp_tables_dim));
    if( cp_init_mibs(cp->mem, mib) > cp->bytes ) {
      ci_log("Cplane MIB dimensions do not match with mmaped area size");
        kfree(mib->dim);
      return -EFAULT;
    }
    
    /* mib->dim->fwd_mask may be ~128K, cp_fwd_rw_row is 16 bytes - i.e.
     * kmalloc does not fit here. */
    mib->fwd_rw = vmalloc(CI_ROUND_UP(
                    (mib->dim->fwd_mask + 1) * sizeof(struct cp_fwd_rw_row),
                      PAGE_SIZE));
    if( mib->fwd_rw == NULL ) {
      kfree(mib->dim);
      return -ENOMEM;
    }
    /* mark server ready to accept notifications from the main netns cp_server */
    ci_wmb();
    cp->server_initialized = 1;
  }
  else if( mib->fwd_rw == NULL )
    return -ENOENT;

  if( bytes != CI_ROUND_UP(
                (mib->dim->fwd_mask + 1) * sizeof(struct cp_fwd_rw_row),
                PAGE_SIZE) ) {
    ci_log("Unexpected size %ld instead of %ld for mapping fwd_rw "
           "control plane memory", bytes,
           CI_ROUND_UP((mib->dim->fwd_mask + 1) *
                       sizeof(struct cp_fwd_rw_row),
                       PAGE_SIZE));
    return -EFAULT;
  }

  return 0;
}


static struct net* netns_from_cp(struct oo_cplane_handle* cp)
{
  return cp->cp_netns;
}


static struct oo_cplane_handle*
__cp_acquire_from_netns_if_exists(const struct net* netns, int revive_killed)
{
  struct oo_cplane_handle* existing_cplane_inst;

  OO_DEBUG_CPLANE(ci_log("%s: netns=%p", __FUNCTION__, netns));

  spin_lock(&cp_lock);
  existing_cplane_inst = cp_table_lookup(netns);
  if( existing_cplane_inst != NULL && cplane_spawn_server &&
      existing_cplane_inst->killed ) {
    if( ! revive_killed || ! cp_cancel_kill(existing_cplane_inst) ) {
      /* There is a cplane server running, but we are going to kill it,
       * and we were not asked to revive. */
      existing_cplane_inst = NULL;
    }
    /* else we have cancelled the kill delayed work and
     * we are inheriting its refcount */
  }
  else if( existing_cplane_inst != NULL )
    atomic_inc(&existing_cplane_inst->refcount);
  spin_unlock(&cp_lock);
  return existing_cplane_inst;
}

static struct oo_cplane_handle* __cp_acquire_from_netns(struct net* netns)
{
  struct oo_cplane_handle* new_cplane_inst;
  struct oo_cplane_handle* existing_cplane_inst;
  int rc;
  const struct cred *orig_creds = NULL;

  existing_cplane_inst = __cp_acquire_from_netns_if_exists(netns, CI_TRUE);
  if( existing_cplane_inst != NULL )
    return existing_cplane_inst;

  /* We need to create a new cplane instance, which may block, so better
   * not be in_atomic() here.
   */
  ci_assert(!in_atomic());

  OO_DEBUG_CPLANE(ci_log("%s: allocating new cplane for netns %p",
                         __FUNCTION__, netns));

  new_cplane_inst = kzalloc(sizeof(struct oo_cplane_handle), GFP_KERNEL);
  if( new_cplane_inst == NULL )
    return NULL;

#ifdef EFRM_HAVE_NF_NET_HOOK
  if( oo_register_nfhook(netns) != 0 ) {
    ci_log("Failed to register netfilter hook for namespace");
    return NULL;
  }
#endif

  /* Initialise the new instance and take a reference to it. */
  spin_lock_init(&new_cplane_inst->cp_handle_lock);
  init_waitqueue_head(&new_cplane_inst->cp_waitq);
  new_cplane_inst->cp_netns = get_net(netns);
  INIT_DELAYED_WORK(&new_cplane_inst->destroy_work, cp_kill_work);
  atomic_inc(&new_cplane_inst->refcount);
  INIT_LIST_HEAD(&new_cplane_inst->fwd_req);

  /* cicpplos_ctor() must be called with CAP_NET_RAW. */
  new_cplane_inst->cppl.cp = new_cplane_inst;
  orig_creds = oo_cplane_empower_cap_net_raw(netns);
  rc = cicpplos_ctor(&new_cplane_inst->cppl);
  oo_cplane_drop_cap_net_raw(orig_creds);

  if( rc != 0 ) {
    cp_destroy(new_cplane_inst);
    ci_log("ERROR: failed to create control plane protocol instance: "
           "rc=%d", rc);
    return NULL;
  }

  spin_lock(&cp_lock);
  existing_cplane_inst = cp_table_lookup(netns);
  if( existing_cplane_inst == NULL ) {
    /* Insert the new instance into the global state.  We already hold a
     * reference to it, so nobody can come along and destroy it under our feet,
     * even once we drop the lock. */
    cp_table_insert(netns, new_cplane_inst);
  }
  else {
    /* We raced against someone else creating a new instance.  Free our new
     * instance, and take a reference to theirs instead.  Since we hold the
     * lock, it will not go away before we get a chance to take a reference. */
    OO_DEBUG_CPLANE(ci_log("%s: raced", __FUNCTION__));
    atomic_inc(&existing_cplane_inst->refcount);
    spin_unlock(&cp_lock);
    cp_destroy(new_cplane_inst);
    return existing_cplane_inst;
  }
  spin_unlock(&cp_lock);

  return new_cplane_inst;
}

struct oo_cplane_handle* cp_acquire_from_netns(struct net* netns)
{
  struct oo_cplane_handle* cp = __cp_acquire_from_netns(netns);
  if( cp == NULL )
    return NULL;

  if( ! cp_is_usable(cp) ) {
    cp_release(cp);
    return NULL;
  }
  return cp;
}

struct oo_cplane_handle* cp_acquire_from_netns_if_exists(const struct net* netns)
{
  struct oo_cplane_handle* cp =
                      __cp_acquire_from_netns_if_exists(netns, CI_FALSE);
  if( cp == NULL )
    return NULL;

  if( ! cp_is_usable(cp) ) {
    cp_release(cp);
    return NULL;
  }
  return cp;
}

/* Takes out a reference to the control plane handle corresponding to a file
 * descriptor.  The caller should call cp_release() when it's finished with it.
 */
static struct oo_cplane_handle* cp_acquire_from_priv(ci_private_t* priv)
{
  OO_DEBUG_CPLANE(ci_log("%s: priv=%p", __FUNCTION__, priv));

  /* If we have a stack, just take a reference to its control plane. */
  if( priv->thr ) {
    ci_assert(priv->thr->netif.cplane);
    atomic_inc(&priv->thr->netif.cplane->refcount);
    return priv->thr->netif.cplane;
  }
  /* If we've used this fd before, it will have a handle already. */
  else if( priv->priv_cp != NULL ) {
    atomic_inc(&priv->priv_cp->refcount);
    return priv->priv_cp;
  }
  else {
    struct oo_cplane_handle* priv_cp;

    /* If we don't have a stack and we don't already have a handle, we find (or
     * create) a control plane for the current namespace. */
    OO_DEBUG_CPLANE(ci_log("%s: No handle. priv=%p", __FUNCTION__, priv));
    priv_cp = __cp_acquire_from_netns(current->nsproxy->net_ns);
    if( priv_cp == NULL )
      return NULL;

    /* Interlock against other people trying to get a cplane handle for this
     * fd. */
    spin_lock(&cp_lock);
    if( priv->priv_cp == NULL ) {
      /* Remember the handle and take an extra reference to it, so that in
       * total we will have one reference for the caller and one for the priv
       * itself. */
      atomic_inc(&priv_cp->refcount);
      priv->priv_cp = priv_cp;
      spin_unlock(&cp_lock);
    }
    else {
      /* Somebody else came along first and stashed a cplane handle inside this
       * fd, so use that instead of the one that we just obtained. */
      OO_DEBUG_CPLANE(ci_log("%s: Raced. priv=%p", __FUNCTION__, priv));
      atomic_inc(&priv->priv_cp->refcount);
      spin_unlock(&cp_lock);
      cp_release(priv_cp);
    }

    return priv->priv_cp;
  }

  /* Unreachable. */
  ci_assert(0);
}


/* Verifies that the calling process is a cplane server. If so,
 * returns a reference to the CP handle via 'out'. If not, returns a
 * suitable error code.
 */
extern int
cp_acquire_from_priv_if_server(ci_private_t* priv,
                               struct oo_cplane_handle** out)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);

  if( cp == NULL )
    return -ENOENT;

  if( cp->server_pid != task_pid(current) ) {
    cp_release(cp);
    return -EACCES;
  }

  if( out ) {
    *out = cp;
  }
  else {
    cp_release(cp);
  }

  return 0;
}


int
oo_cplane_mmap(ci_private_t* priv, struct vm_area_struct* vma)
{
  struct oo_cplane_handle* cp;
  struct cp_vm_private_data* cp_vm_data;
  int rc;

  ci_assert_equal(OO_MMAP_TYPE(VMA_OFFSET(vma)), OO_MMAP_TYPE_CPLANE);
  cp = cp_acquire_from_priv(priv);
  if( cp == NULL )
    return -ENOMEM;

  cp_vm_data = kzalloc(sizeof(*cp_vm_data), GFP_KERNEL);
  if( cp_vm_data == NULL ) {
    rc = -ENOMEM;
    goto fail;
  }
  cp_vm_data->cp = cp;

  vma->vm_ops = &vm_ops;
  vma->vm_private_data = (void*) cp_vm_data;

  switch( OO_MMAP_ID(VMA_OFFSET(vma)) ) {
    case OO_MMAP_CPLANE_ID_MIB:
      rc = cp_mmap_mib(cp, vma);
      break;
    case OO_MMAP_CPLANE_ID_FWD_RW:
      rc = cp_mmap_fwd_rw(cp, vma);
      break;
    default:
      rc = -EINVAL;
  }

  if( rc != 0 )
    goto fail;

  /* Increment refcount: */
  vm_op_open(vma);

 out:
  cp_release(cp);
  return rc;

 fail:
  kfree(cp_vm_data);
  goto out;
}

int oo_cp_get_mib_size(ci_private_t *priv, void *arg)
{
  ci_uint32* arg_p = arg;
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  /* Fixme: get correct cplane instance. */

  *arg_p = cp->bytes;
  rc = cp->bytes == 0 ? -ENOENT : 0;
  cp_release(cp);
  return rc;
}

struct cp_fwd_req {
  struct list_head link;
  struct completion compl;
  int completed;
  int id; /* The id used to identify completion of the request */
};

/* True if the forward request id "large" is larger than "small", and the
 * distance is within limit "cplane_route_request_limit". */
static int/*bool*/ cp_fwd_req_id_ge(int large, int small)
{
  return ((large - small) & CP_FWD_FLAG_REQ_MASK) <
                                            cplane_route_request_limit;
}

/* This is similar to kill_pid_info() in the kernel, but the key difference is
 * that we call send_sig_info() directly, meaning that we bypass the
 * permissions check. */
static int cp_send_sig_info(int sig, struct siginfo* info, struct pid* pid)
{
  int rc = -ESRCH;
  struct task_struct* task;

  rcu_read_lock();
 retry:
  task = pid_task(pid, PIDTYPE_PID);
  if( task != NULL ) {
    rc = send_sig_info(sig, info, task);
    if( rc == -ESRCH )
      goto retry;
  }
  rcu_read_unlock();

  return rc;
}

int oo_op_route_resolve(struct oo_cplane_handle* cp,
                        struct cp_fwd_key* key)
{
  struct cp_mibs* mib = &cp->mib[0];
  struct siginfo info = {};
  int rc;
  struct cp_fwd_req* req;

  if( cp == NULL )
    return -ENOMEM;

  info.si_signo = mib->dim->fwd_req_sig;
  /* si_code MUST be negative to force copy_siginfo copy the key properly */
  { CI_BUILD_ASSERT(CP_FWD_FLAG_REQ == 0x80000000); }
  info.si_code = CP_FWD_FLAG_REQ;
  memcpy(cp_siginfo2key(&info), key, sizeof(*key));
  if( ! (key->flag & CP_FWD_KEY_REQ_WAIT) ) {
    atomic_inc(&cp->stats.fwd_req_nonblock);
    spin_lock_bh(&cp->cp_handle_lock);
    if( cp->server_pid != NULL )
      rc = cp_send_sig_info(info.si_signo, &info, cp->server_pid);
    else
      rc = -ESRCH;
    spin_unlock_bh(&cp->cp_handle_lock);
    return rc;
  }

  if( ! cp_fwd_req_id_ge(cp->fwd_req_id, cp->stats.fwd_req_complete) )
    return -ENOSPC;
  req = kzalloc(sizeof(*req), GFP_ATOMIC);
  if( req == NULL )
    return -ENOMEM;
  init_completion(&req->compl);
  spin_lock_bh(&cp->cp_handle_lock);
  req->id = cp->fwd_req_id++ & CP_FWD_FLAG_REQ_MASK;
  info.si_code |= req->id;
  if( cp->server_pid != NULL )
    rc = cp_send_sig_info(info.si_signo, &info, cp->server_pid);
  else
    rc = -ESRCH;
  if( rc != 0 ) {
    spin_unlock_bh(&cp->cp_handle_lock);
    kfree(req);
    return rc;
  }
  list_add_tail(&req->link, &cp->fwd_req);
  spin_unlock_bh(&cp->cp_handle_lock);

  wait_for_completion_interruptible_timeout(
                                &req->compl,
                                cplane_route_request_timeout_jiffies);

  spin_lock_bh(&cp->cp_handle_lock);
  if( ! req->completed ) {
    list_del(&req->link);
    cp->stats.fwd_req_complete++;
    if( current && signal_pending(current) ) {
      rc = -EINTR; /* interrupted */
    }
    else {
      rc = -EAGAIN; /* timeout */
      ci_log("WARNING: no response to route request 0x%x.  "
             "Is the Control Plane server running?  Consider increasing "
             "cplane_route_request_timeout_ms parameter.", req->id);
    }
  }
  kfree(req);
  spin_unlock_bh(&cp->cp_handle_lock);

  return rc;
}


typedef int(* cp_wait_check_fn)(struct oo_cplane_handle* cp, cp_version_t arg);

static int
cp_wait_interruptible(struct oo_cplane_handle* cp, cp_wait_check_fn check,
                      cp_version_t arg)
{
  /* Wait for a server.  The wait_event...() functions return immediately if we
   * already have one. */
  if( cplane_init_timeout == 0 ) {
    return check(cp, arg) ? 0 : (cp_is_usable(cp) ? -EAGAIN: -ESRCH);
  }
  else if( cplane_init_timeout < 0 ) {
    return wait_event_interruptible(cp->cp_waitq, check(cp, arg));
    /* wait_event_interruptible() returns zero on success and negative on
     * error. */
  }
  else {
    int rc = wait_event_interruptible_timeout(cp->cp_waitq, check(cp, arg),
                                              cplane_init_timeout * HZ);
    /* wait_event_interruptible_timeout() returns zero on timeout, positive on
     * wake, and negative on error. */
    if( rc == 0 )
      return -ETIMEDOUT;
    else if( rc > 0 )
      return 0;
    return rc;
  }
  /* unreachable */
  ci_assert(0);
  return 0;
}


int oo_cp_oof_sync(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib = &cp->mib[0];
  int rc;
  cp_version_t ver;

  if( cp == NULL )
    return -ENOMEM;

  atomic_inc(&cp->stats.oof_req_nonblock);
  ver = *cp->mib->oof_version;

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    rc = kill_pid(cp->server_pid, mib->dim->oof_req_sig, 1);
  else
    rc = -ESRCH;
  spin_unlock_bh(&cp->cp_handle_lock);

  return cp_wait_interruptible(cp, cp_is_usable_for_oof, ver);
}


int oo_cp_fwd_resolve_rsop(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  struct cp_fwd_key* key = arg;
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = oo_op_route_resolve(cp, key);

  cp_release(cp);
  return rc;
}

int oo_cp_fwd_resolve_complete(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp;
  struct cp_fwd_req* req;
  ci_uint32 req_id = *(ci_uint32*)arg;
  int rc = 0;

  rc = cp_acquire_from_priv_if_server(priv, &cp);
  if( rc < 0 )
    return rc;

  ci_assert_nflags(req_id, ~CP_FWD_FLAG_REQ_MASK);
  if( req_id & ~CP_FWD_FLAG_REQ_MASK ) {
    rc = -EFAULT;
    goto out;
  }

  spin_lock_bh(&cp->cp_handle_lock);
  list_for_each_entry(req, &cp->fwd_req, link) {
    if( req->id == req_id ) {
      list_del(&req->link);
      cp->stats.fwd_req_complete++;
      break;
    }
  }
  if( &req->link == &cp->fwd_req ) {
    rc = -ENOENT;
    ci_log("WARNING: %s: no route requests when asked to complete 0x%x; "
           "next is 0x%x", __func__, req_id, cp->fwd_req_id);
    goto out_unlock;
  }
  ci_assert_equal(req->id, req_id);

  complete(&req->compl);
  req->completed = 1;

 out_unlock:
  spin_unlock_bh(&cp->cp_handle_lock);

 out:
  cp_release(cp);
  return rc;
}

static int verinfo2arp_req(struct oo_cplane_handle* cp,
                           cicp_verinfo_t* verinfo,
                           struct net_device** dev_out,
                           ci_ip_addr_t* nexthop_out)
{
  struct cp_mibs* mib = &cp->mib[0];
  struct cp_fwd_row* fwd;
  struct cp_fwd_data* data;
  ci_ifid_t ifindex;

  if( ! CICP_ROWID_IS_VALID(verinfo->id) ||
      verinfo->id > mib->dim->fwd_mask ) {
    return -ENOENT;
  }

  fwd = cp_get_fwd(mib, verinfo);
  if( ~fwd->flags & CICP_FWD_FLAG_DATA_VALID )
    return -EBUSY;

  data = cp_get_fwd_data(mib, verinfo);

  ifindex = data->ifindex;
  *nexthop_out = data->next_hop;
  ci_rmb();
  if( ! cp_fwd_version_matches(mib, verinfo) )
    return -ENOENT;

  /* Someone is definitely using this route: */
  cp_get_fwd_rw(mib, verinfo)->frc_used = ci_frc64_get();

  *dev_out = dev_get_by_index(netns_from_cp(cp), ifindex);
  if( *dev_out == NULL )
    return -ENOENT;
  return 0;
}

int __oo_cp_arp_resolve(struct oo_cplane_handle* cp,
                        cicp_verinfo_t* op)
{
  struct net_device *dev;
  struct neighbour *neigh;
  int rc;
  ci_ip_addr_t next_hop;

  rc = verinfo2arp_req(cp, op, &dev, &next_hop);
  if( rc != 0 )
    return rc;
  rc = -ENOMEM;

  neigh = neigh_lookup(&arp_tbl, &next_hop, dev);
  if( neigh == NULL ) {
    neigh = neigh_create(&arp_tbl, &next_hop, dev);
    if(CI_UNLIKELY( neigh == NULL ))
      goto fail;
  }

  /* We should not ask to re-resolve ARP if it is REACHABLE or in the
   * process of resolving.  Just-created entry has 0 state. */
  if( neigh->nud_state == 0 || neigh->nud_state & (~NUD_VALID | NUD_STALE) )
    neigh_event_send(neigh, NULL);

  neigh_release(neigh);
 fail:
  dev_put(dev);
  return rc;
}

int oo_cp_arp_resolve_rsop(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = __oo_cp_arp_resolve(cp, arg);

  cp_release(cp);
  return rc;
}

static int oo_cp_neigh_update(struct neighbour *neigh, int state)
{
  return neigh_update(neigh, NULL, state, NEIGH_UPDATE_F_ADMIN
#ifndef EFRM_OLD_NEIGH_UPDATE
                      /* linux>=4.12 needs nlmsg_pid parameter */
                      , 0
#endif
                      );

}

int __oo_cp_arp_confirm(struct oo_cplane_handle* cp,
                        cicp_verinfo_t* op)
{
  struct net_device *dev;
  struct neighbour *neigh;
  int rc;
  ci_ip_addr_t next_hop;
  struct cp_mibs* mib = &cp->mib[0];

  atomic_inc(&cp->stats.arp_confirm_try);

  rc = verinfo2arp_req(cp, op, &dev, &next_hop);
  if( rc != 0 )
    return rc;
  rc = -ENOENT;

  neigh = neigh_lookup(&arp_tbl, &next_hop, dev);
  if( neigh == NULL )
    goto fail1;

  /* We've found a neigh entry based on fwd data.  Have it changed? */
  if( ! cp_fwd_version_matches(mib, op) )
    goto fail2;

  /* In theory, we should update in NUD_REACHABLE state only, but
   * we may be a bit slow in confirming ARP.
   * It is not sufficient to set neigh->confirmed, because we need
   * a netlink update to get the new "confirmed" value in the Cplane
   * server. */
  if( neigh->nud_state & (NUD_STALE | NUD_REACHABLE) ) {
    /* We need the neigh timer to be restarted, so we must *change*
     * the state value.  So we change to NUD_DELAY and then back to
     * NUD_REACHABLE. */
    oo_cp_neigh_update(neigh, NUD_DELAY);
    oo_cp_neigh_update(neigh, NUD_REACHABLE);
    atomic_inc(&cp->stats.arp_confirm_do);
  }
  rc = 0;

 fail2:
  neigh_release(neigh);
 fail1:
  dev_put(dev);
  return rc;
}

int oo_cp_arp_confirm_rsop(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = __oo_cp_arp_confirm(cp, arg);

  cp_release(cp);
  return rc;
}


int
oo_cp_get_active_hwport_mask(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                             cicp_hwport_mask_t *hwport_mask)
{
  struct cp_mibs* mib;
  cp_version_t version;
  cicp_rowid_t id;
  int rc;

  if( cp == NULL )
    return -ENODEV;

  CP_VERLOCK_START(version, mib, cp)

  rc = 0;
  id = cp_llap_find_row(mib, ifindex);

  if( id == CICP_ROWID_BAD ) {
    rc = -ENODEV;
    goto out;
  }
  else {
    *hwport_mask = mib->llap[id].tx_hwports;
  }

 out:
  CP_VERLOCK_STOP(version, mib)

  return rc;
}


static void cplane_route_request_timeout_proceed(void)
{
  cplane_route_request_timeout_jiffies =
                msecs_to_jiffies(cplane_route_request_timeout_ms);
}

/* Returns the path to the onload_cp_server binary as configured by the module
 * parameter. */
static char* cp_get_server_path(void)
{
  return cplane_server_path != NULL && *cplane_server_path != '\0' ?
           cplane_server_path :
           DEFAULT_CPLANE_SERVER_PATH;
}


/* Control whether to switch into namespace of current process. */
#define CP_SPAWN_SERVER_SWITCH_NS 0x00000001u
/* Used at start-of-day to spawn a server that will run without a client. */
#define CP_SPAWN_SERVER_BOOTSTRAP 0x00000002u

/* Spawns a control plane server for the network namespace of the current
 * process. */
static int cp_spawn_server(ci_uint32 flags)
{
  /* The maximum number of parameters that we'll stick on the end of the
   * command line, after building up the invariable and user-specified
   * arguments.  This includes the terminating NULL. */
  const int DIRECT_PARAM_MAX = 5;

  char* ns_file_path = NULL;
  char* path = cp_get_server_path();
#define LOCAL_ARGV_N 20
  char* local_argv[LOCAL_ARGV_N];
#define LOCAL_STRLEN 200
  char local_str[LOCAL_STRLEN];
  char* str = NULL;
  char** argv;
  char* envp[] = { NULL };
  int rc = 0;
  int num; /* a copy of cplane_server_params_array_num */
  int direct_param;
  int direct_param_base;

  OO_DEBUG_CPLANE(ci_log("%s: pid=%d path=%s", __FUNCTION__,
                         task_tgid_nr(current), path));

  ci_assert(current);

  ci_assert(flags & (CP_SPAWN_SERVER_SWITCH_NS | CP_SPAWN_SERVER_BOOTSTRAP));
  if( cplane_spawn_server && ! (flags & CP_SPAWN_SERVER_BOOTSTRAP) &&
      current->nsproxy->net_ns == &init_net &&
      cplane_server_grace_timeout != 0 ) {
    flags = CP_SPAWN_SERVER_BOOTSTRAP;
  }

  if( flags & CP_SPAWN_SERVER_SWITCH_NS ){
    ns_file_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if( ns_file_path == NULL )
      return -ENOMEM;
    snprintf(ns_file_path, PATH_MAX, "/proc/%d/ns/net", task_tgid_nr(current));
  }

  spin_lock(&cp_lock);
  num = cplane_server_params_array_num;
  /* The extra 1 is to account for argv[0]. */
  if( 1 + num + CP_SERVER_CONST_PARAM_NUM + DIRECT_PARAM_MAX <= LOCAL_ARGV_N ) {
    argv = local_argv;
  }
  else {
    argv = kmalloc(sizeof(cplane_server_const_params) +
                   (1 + num + DIRECT_PARAM_MAX) * sizeof(char*),
                   GFP_ATOMIC);
    if( argv == NULL )
      rc = -ENOMEM;
  }
  if( argv != NULL && num > 0 ) {
    ci_assert(cplane_server_params_array);
    if( cplane_server_params_array_len < LOCAL_STRLEN )
      str = local_str;
    else
      str = kmalloc(cplane_server_params_array_len + 1, GFP_ATOMIC);
    if( str != NULL ) {
      int n;

      memcpy(str, cplane_server_params_array[0],
             cplane_server_params_array_len + 1);
      for( n = 0; n < num; n++ ) {
        argv[n + 1] = str +
          (cplane_server_params_array[n] - cplane_server_params_array[0]);
      }
    }
    else {
      rc = -ENOMEM;
    }
  }
  spin_unlock(&cp_lock);
#undef LOCAL_ARGV_N
#undef LOCAL_STRLEN

  if( rc < 0 )
    goto out;
  argv[0] = path;
  memcpy(argv + 1 + num, cplane_server_const_params,
         sizeof(cplane_server_const_params));
  direct_param_base = 1 + num + CP_SERVER_CONST_PARAM_NUM;
  direct_param = 0;
  if( flags & CP_SPAWN_SERVER_SWITCH_NS ) {
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_NS_CMDLINE_OPT;
    argv[direct_param_base + direct_param++] = ns_file_path;
  }
  if( flags & CP_SPAWN_SERVER_BOOTSTRAP )
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_BOOTSTRAP;
#if !CI_CFG_IPV6
  argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_NO_IPV6;
#endif
  argv[direct_param_base + direct_param++] = NULL;
  ci_assert_le(direct_param, DIRECT_PARAM_MAX);

  rc = ci_call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC
#ifdef UMH_KILLABLE
                                                | UMH_KILLABLE
#endif
                              );

 out:
  kfree(ns_file_path);
  if( argv != local_argv )
    kfree(argv);
  if( str != local_str )
    kfree(str);
  return rc;
}


/* Initialises driver state for the control plane. */
int
oo_cp_driver_ctor(void)
{
  int i;

  for( i = 0; i < CP_INSTANCE_HASH_SIZE; ++i )
    ci_dllist_init(&cp_hash_table[i]);

  cp_lock_init();
  cplane_route_request_timeout_proceed();
  if( cplane_spawn_server && cplane_server_grace_timeout != 0 )
    cp_spawn_server(CP_SPAWN_SERVER_BOOTSTRAP);
  cp_initialized = 1;

  return 0;
}


/* Tears down driver state for the control plane. */
int
oo_cp_driver_dtor(void)
{
  return 0;
}

static int cp_is_usable_hook(struct oo_cplane_handle* cp, cp_version_t ver)
{
  return cp_is_usable(cp);
}

static int
cp_sync_tables_start(struct oo_cplane_handle* cp, enum cp_sync_mode mode,
                     cp_version_t* ver_out)
{
  cp_version_t old_ver = 0;
  int rc = 0;
  struct siginfo info = {};

  info.si_signo = cp->mib->dim->os_sync_sig;
  info.si_code = mode;

  switch( mode ) {
    case CP_SYNC_NONE:
      ci_assert(0);
      break;
    case CP_SYNC_LIGHT:
      old_ver = *cp->mib->idle_version;
      break;
    case CP_SYNC_DUMP:
      old_ver = *cp->mib->dump_version;
      /* Odd version means "dump in progress" - so we should wait for next-next
       * even version. */
      if( old_ver & 1 )
        old_ver++;
      break;

  }

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    cp_send_sig_info(cp->mib->dim->os_sync_sig, &info, cp->server_pid);
  else
    rc = -ESRCH;
  spin_unlock_bh(&cp->cp_handle_lock);

  *ver_out = old_ver;
  return rc;
}
static int cp_dump_synced(struct oo_cplane_handle* cp, cp_version_t old_ver)
{
  return cp_is_usable(cp) &&
         (old_ver ^ OO_ACCESS_ONCE(*cp->mib->dump_version)) & ~1;
}
static int cp_light_synced(struct oo_cplane_handle* cp, cp_version_t old_ver)
{
  return cp_is_usable(cp) &&
         (old_ver ^ OO_ACCESS_ONCE(*cp->mib->idle_version)) & ~1;
}


/* Spawns a control plane server if one is not running, and waits for it to
 * initialise up to a module-parameter-configurable timeout. */
static int
oo_cp_wait_for_server(struct oo_cplane_handle* cp, enum cp_sync_mode mode)
{
  int rc;
  cp_version_t ver = 0;
  cp_wait_check_fn fn;

  switch( mode ) {
    case CP_SYNC_NONE:
      fn = cp_is_usable_hook;
      break;
    case CP_SYNC_LIGHT:
      fn = cp_light_synced;
      break;
    case CP_SYNC_DUMP:
      fn = cp_dump_synced;
      break;
    default:
      ci_assert(0);
      return -EINVAL;
  }


  if( cp->server_pid != NULL ) {
    /* Cplane server has been started, but it may be unusable yet.
     * First of all, wait for full setup: */
    if( ! cp_is_usable(cp) ) {
      rc = cp_wait_interruptible(cp, cp_is_usable_hook, 0);
      if( rc < 0 )
        return rc;
      if( mode == CP_SYNC_NONE )
        return 0;
    }

    /* We probably need to re-sync it with OS depending on the mode.
     *
     * The server may disappear under our feet.  We'll misbehave but do not
     * crash in this case. */
    switch( mode ) {
      case CP_SYNC_NONE:
        return cp_wait_interruptible(cp, fn, ver);
      case CP_SYNC_LIGHT:
      case CP_SYNC_DUMP:
        rc = cp_sync_tables_start(cp, mode, &ver);
        if( rc != 0 )
          return rc;
    }
  }
  else if( cplane_spawn_server ) {
    /* We have no server.  Try to spawn one. */
    rc = cp_spawn_server(CP_SPAWN_SERVER_SWITCH_NS);
    if( rc < 0 ) {
      ci_log("%s: Failed to spawn server: rc=%d", __FUNCTION__, rc);
      return rc;
    }

    /* Ploughing on is almost certain to block, so schedule to give ourselves a
     * chance of being lucky. */
    schedule();

    /* We've just spawned server.  It is fresh.  No need to sync with OS. */
    fn = cp_is_usable_hook;
  }
  else {
    return -ENOENT;
  }

  return cp_wait_interruptible(cp, fn, ver);
}


/* Entered via an ioctl in order to wait for the presence of a UL server for
 * the control plane for the current namespace.  If a server already exists, we
 * will return without blocking. */
int oo_cp_wait_for_server_rsop(ci_private_t *priv, void* arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = oo_cp_wait_for_server(cp, *(ci_uint32*)arg);

  cp_release(cp);
  return rc;
}

/* Associate this fd with a control plane handle if it is not yet associated
 * with one.  This association will last until the fd is closed.  Calling this
 * function is not normally necessary as the association is set up just-in-time
 * at other entry points, but doing so explicitly allows a control plane server
 * to start even if there are no clients. */
int oo_cp_link_rsop(ci_private_t *priv, void* arg __attribute__((unused)))
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);

  if( cp == NULL )
    return -ENOMEM;

  /* This releases the function's reference, but not the priv's reference. */
  cp_release(cp);
  return 0;
}

int oo_cp_ready(ci_private_t *priv, void* arg)
{
  struct oo_cplane_handle* cp;
  int rc = cp_acquire_from_priv_if_server(priv, &cp);

  if( rc < 0 )
    return rc;

  if( ! cp->usable )
    cp->usable = 1;

  /* We've now initialised enough state to allow clients to start trying to
   * talk to us.  Wake up any clients who are waiting for a server. */
  wake_up_interruptible(&cp->cp_waitq);
  cp_release(cp);
  return 0;
}


/* Restart the control plane server in the init_net namepace after the
 * desired configuration has changed. */
static void cp_respawn_init_server(void)
{
  struct oo_cplane_handle* cp;
  if( ! cp_initialized || ! cplane_spawn_server )
    return;

  cp = __cp_acquire_from_netns_if_exists(&init_net, 0);
  if( cp != NULL ) {
    int killed = 0;

    spin_lock(&cp_lock);
    spin_lock_bh(&cp->cp_handle_lock);
    /* For unused cplane server, we expect 3 refcounts:
     * - from the server itself;
     * - from cp_acquire above;
     * - from the server itself because of --bootstrap option.
     */
    if( atomic_read(&cp->refcount) <= 3 ) {
      ci_log("Respawn the control plane server for the main (default) "
             "network namespace to apply new settings...");
      cp_kill(cp);
      killed = 1;
    }
    spin_unlock_bh(&cp->cp_handle_lock);
    spin_unlock(&cp_lock);
    cp_release(cp);

    if( ! killed ) {
      ci_log("New control plane server parameters will be applied after "
             "onload_cp_server restart");
      return;
    }
  }
  if( cplane_server_grace_timeout != 0 )
    cp_spawn_server(CP_SPAWN_SERVER_BOOTSTRAP);
}

int cplane_server_path_set(const char* val,
                           ONLOAD_MPC_CONST struct kernel_param* kp)
{
  char* old_path;
  char* new_path = kstrdup(skip_spaces(val), GFP_KERNEL);

  if( new_path == NULL )
    return -ENOMEM;

  strim(new_path);

  cp_lock_init();
  spin_lock(&cp_lock);
  old_path = cplane_server_path;
  cplane_server_path = new_path;
  spin_unlock(&cp_lock);

  if( old_path == NULL || strcmp(old_path, new_path) != 0 )
    cp_respawn_init_server();

  kfree(old_path);

  return 0;
}


int cplane_server_path_get(char* buffer,
                           ONLOAD_MPC_CONST struct kernel_param* kp)
{
  char* path;
  int len;

  spin_lock(&cp_lock);
  path = cp_get_server_path();
  /* The magic 4096 is documented in linux/moduleparam.h. */
  strncpy(buffer, path, 4096);
  len = strnlen(buffer, 4096);
  spin_unlock(&cp_lock);

  return len;
}

static int cp_proc_stats_show(struct seq_file *m,
                              void *private __attribute__((unused)))
{
  struct oo_cplane_handle* cp =
            cp_acquire_from_netns_if_exists(current->nsproxy->net_ns);
  if( cp == NULL ) {
    seq_printf(m, "No control plane instance in this net namespace.\n");
    return 0;
  }

  seq_printf(m, "Route requests (non-waiting):\t%d\n",
             atomic_read(&cp->stats.fwd_req_nonblock));
  seq_printf(m, "Route requests (waiting):\t%d\n", cp->fwd_req_id);
  seq_printf(m, "Route requests queue depth:\t%d\n",
             cp->fwd_req_id - cp->stats.fwd_req_complete);
  seq_printf(m, "Filter engine requests (non-waiting):\t%d\n",
             atomic_read(&cp->stats.oof_req_nonblock));
  seq_printf(m, "ARP confirmations (tried):\t%d\n",
             atomic_read(&cp->stats.arp_confirm_try));
  seq_printf(m, "ARP confirmations (successful):\t%d\n",
             atomic_read(&cp->stats.arp_confirm_do));
  seq_printf(m, "Dropped IP packets routed via OS:\t%d\n",
             cp->cppl.stat.dropped_ip);

  cp_release(cp);
  return 0;
}

int cp_proc_stats_open(struct inode *inode, struct file *file)
{
  return single_open(file, cp_proc_stats_show, NULL);
}


struct cp_pid_seq_state {
  ci_dllink* cp;
  loff_t offset;
  unsigned bucket;
};


static void* cp_server_pids_next(struct seq_file* s, void* state_,
                                 loff_t* pos)
{
  struct cp_pid_seq_state* state = state_;

  state->offset++;

  state->cp = state->cp->next;

  while( ci_dllist_is_anchor(&cp_hash_table[state->bucket], state->cp) &&
         (state->bucket < CP_INSTANCE_HASH_SIZE) ) {
    state->bucket++;
    state->cp = ci_dllist_head(&cp_hash_table[state->bucket]);
  }

  if( state->bucket == CP_INSTANCE_HASH_SIZE ) {
    /* End of file. */
    kfree(state);
    return NULL;
  }

  *pos = state->offset;
  return state;
}


static void* cp_server_pids_start(struct seq_file* s, loff_t* pos)
{
  struct cp_pid_seq_state* state;
  loff_t i;

  spin_lock(&cp_lock);

  state = kmalloc(sizeof(struct cp_pid_seq_state), GFP_ATOMIC);
  if ( !state ) {
    return NULL;
  }

  state->offset = 0;

  for( state->bucket = 0;
       state->bucket < CP_INSTANCE_HASH_SIZE;
       state->bucket++ ) {
    if( ci_dllist_not_empty(&cp_hash_table[state->bucket]) )
      break;
  }

  if( state->bucket == CP_INSTANCE_HASH_SIZE ) {
    /* File is empty. */
    kfree(state);
    return NULL;
  }

  state->cp = ci_dllist_head(&cp_hash_table[state->bucket]);

  for( i = 0; i < *pos; )
    if( cp_server_pids_next(s, state, &i) == NULL )
      return NULL;

  return state;
}


static void cp_server_pids_stop(struct seq_file* s, void* state_)
{
  struct cp_pid_seq_state* state = state_;

  if( state != NULL ) {
    kfree(state);
  }

  spin_unlock(&cp_lock);
}


static int cp_server_pids_show(struct seq_file* s, void* state_)
{
  struct cp_pid_seq_state* state = state_;
  struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                             link, state->cp);
  pid_t pid = 0;

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    pid = pid_vnr(cp->server_pid);
  spin_unlock_bh(&cp->cp_handle_lock);

  if( pid != 0 )
    seq_printf(s, "%d\n", pid);

  return 0;
}


static struct seq_operations cp_server_pids_ops = {
  .start = cp_server_pids_start,
  .next = cp_server_pids_next,
  .stop = cp_server_pids_stop,
  .show = cp_server_pids_show
};

extern int cp_server_pids_open(struct inode *inode, struct file *file) {
  return seq_open(file, &cp_server_pids_ops);
}


static char* get_next_word(char* str)
{
  for( ; *str != '\0'; str++ ) {
    if( isspace(*str) ) {
      *str = '\0';
      return skip_spaces(str + 1);
    }
  }
  return NULL;
}

int cplane_server_params_set(const char* val,
                             ONLOAD_MPC_CONST struct kernel_param* kp)
{
  char** old;
  char** new = NULL;
  int n = 0;
  size_t old_len;
  size_t len = 0;
  char* new_string = kstrdup(skip_spaces(val), GFP_KERNEL);

  if( new_string == NULL )
    return -ENOMEM;

  strim(new_string);
  if( new_string[0] == '\0' ) {
    kfree(new_string);
  }
  else {
    /* We need to allocate an array of the size of the word number in the
     * new_string.  strlen(new_string) is an over-estimation for the
     * number of words. */
    len = strlen(new_string);
    new = kmalloc(len * sizeof(void*), GFP_KERNEL);
    if( new == NULL ) {
      kfree(new_string);
      return -ENOMEM;
    }
    for( n = 0; new_string != NULL; n++) {
      new[n] = new_string;
      new_string = get_next_word(new_string);
    }
  }

  cp_lock_init();
  spin_lock(&cp_lock);
  old = cplane_server_params_array;
  old_len = cplane_server_params_array_len;
  cplane_server_params_array = new;
  cplane_server_params_array_num = n;
  cplane_server_params_array_len = len;
  spin_unlock(&cp_lock);

  if( (old == NULL) != (new == NULL) || old_len != len ||
      (old != NULL && new != NULL && memcmp(*old, *new, len) != 0) )
    cp_respawn_init_server();

  if( old != NULL ) {
    kfree(*old);
    kfree(old);
  }

  return 0;
}

int cplane_server_params_get(char* buffer,
                             ONLOAD_MPC_CONST struct kernel_param* kp)
{
  char* s;
  size_t add, len;
  int n;
  /* The magic 4096 is documented in linux/moduleparam.h. */
  const int BUFFER_LEN = 4096;

  spin_lock(&cp_lock);
  s = buffer;
  len = 0;
  for( n = 0; n < cplane_server_params_array_num; n++ ) {
    add = strlen(cplane_server_params_array[n]);
    if( add + len > BUFFER_LEN )
      break;
    memcpy(s, cplane_server_params_array[n], add);
    s += add;
    len += add;
    if( add == BUFFER_LEN )
      break;
    *s = ' ';
    s++;
    len++;
  }
  spin_unlock(&cp_lock);

  /* The return value is the length of the string, excluding the terminating
   * \0.  If we've written any parameters, that \0 will overwrite the last
   * character, so fix up the accounting. */
  if( len > 0 ) {
    --s;
    --len;
  }

  *s = '\0';

  return len;
}


int oo_cp_get_server_pid(struct oo_cplane_handle* cp)
{
  int pid = 0;

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    pid = pid_nr(cp->server_pid);
  spin_unlock_bh(&cp->cp_handle_lock);

  return pid;
}

int cplane_server_grace_timeout_set(const char* val,
                                    ONLOAD_MPC_CONST struct kernel_param* kp)
{
  int old_val = cplane_server_grace_timeout;
  int rc = param_set_int(val, kp);
  if( rc != 0 )
    return rc;
  if( (cplane_server_grace_timeout == 0) != (old_val == 0) )
    cp_respawn_init_server();
  return 0;
}

int cplane_route_request_timeout_set(const char* val,
                                     ONLOAD_MPC_CONST struct kernel_param* kp)
{
  int rc = param_set_int(val, kp);
  if( rc != 0 )
    return rc;
  cplane_route_request_timeout_proceed();
  return 0;
}


int oo_cp_llap_change_notify_all(struct oo_cplane_handle* main_cp)
{
  int rc = 0;
  int hash;
  spin_lock(&cp_lock);
  for( hash = 0; hash < CP_INSTANCE_HASH_SIZE; ++hash ) {
    ci_dllink* link;
    CI_DLLIST_FOR_EACH(link, &cp_hash_table[hash]) {
      struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                                 link, link);
      if( cp == main_cp || ! cp->server_initialized )
          continue;
      spin_lock_bh(&cp->cp_handle_lock);
      if( cp->server_pid != NULL ) {
        int rc1 = kill_pid(cp->server_pid, cp->mib[0].dim->llap_update_sig, 1);
        if( rc == 0 )
          rc = rc1;
      }
      spin_unlock_bh(&cp->cp_handle_lock);
    }
  }
  spin_unlock(&cp_lock);
  return rc;
}

