/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_platform  */

#ifndef __CI_DRIVER_PLATFORM_LINUX_KERNEL_H__
#define __CI_DRIVER_PLATFORM_LINUX_KERNEL_H__


/**********************************************************************
 * Kernel headers.
 */

#ifndef __ci_driver_shell__	/* required to get ksym versions working */
#define __NO_VERSION__
#endif

#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/vmalloc.h>	
#include <linux/ioport.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/lp.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/utsname.h>
#include <linux/wait.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>   
#include <asm/io.h>
#include <asm/irq.h>
/* XXX: PPC_HACK: This file doesn't seem to exist on PPC.  What are
   the implications of not including it */
#if ! defined (__PPC__)
#include <asm/segment.h>
#endif
#include <asm/bitops.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/dma.h>
#include <asm/uaccess.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/mtrr.h>
#endif
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>

#ifndef LINUX_VERSION_CODE
# error No LINUX_VERSION_CODE.
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#  include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
# error "Linux 2.6+ required"
#endif

#include <linux/init.h>     /* module_init/module_exit */

#include <driver/linux_net/kernel_compat.h>

typedef int socklen_t;

/*--------------------------------------------------------------------
 *
 * Scyld ... seem to have unredhatted their redhat kernel ... go figure
 *
 *--------------------------------------------------------------------*/
#if defined(SCYLD_KERNEL) && defined(RED_HAT_LINUX_KERNEL)
#undef RED_HAT_LINUX_KERNEL
#endif


/*--------------------------------------------------------------------
 * Address space
 *--------------------------------------------------------------------*/

/*! A [ci_addr_spc_t] is a context in which to interpret pointers.
**
** - CI_ADDR_SPC_INVALID means do not attempt to interpret the pointers
**
** - CI_ADDR_SPC_KERNEL means the pointers can be dereferenced directly
**
** - CI_ADDR_SPC_CURRENT means we're in a context in which we can access
**   userlevel pointers via some optimised mechanism (copy_to/from_user()
**   on Linux).
**
** - Any other value is effectively a pointer to page tables in which the
**   pointers may be resolved.  When in such a context there is no
**   guarantee that we can access the memory, as we may not be able to
**   page-in non-resident pages.
*/
typedef struct mm_struct* ci_addr_spc_t;

#define CI_ADDR_SPC_INVALID     ((ci_addr_spc_t)(ci_uintptr_t) 1)
#define CI_ADDR_SPC_KERNEL      ((ci_addr_spc_t)(ci_uintptr_t) 2)
#define CI_ADDR_SPC_CURRENT     ((ci_addr_spc_t)(ci_uintptr_t) 3)

#define ci_addr_spc_is_user(as) (((ci_uintptr_t) (as) & 0x3) == 0u)


/*--------------------------------------------------------------------
 *
 * Misc version fixups.
 *
 *--------------------------------------------------------------------*/

/* These have disappeared */
#define copy_to_user_ret(to,from,n,retval) \
    do{ if (copy_to_user(to,from,n)) return retval; }while(0)
#define copy_from_user_ret(to,from,n,retval) \
    do{ if (copy_from_user(to,from,n)) return retval; }while(0)


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
# define ci_io_remap_pfn_range(vma, vaddr, pfn, size, prot)          \
   io_remap_page_range((vma), (vaddr), (pfn) << PAGE_SHIFT, (size), (prot))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
# define ci_io_remap_pfn_range(vma, vaddr, pfn, size, prot)          \
   io_remap_pfn_range((vma), (vaddr), (pfn), (size), (prot))
#else
# define ci_io_remap_pfn_range(vma, vaddr, pfn, size, prot)          \
   io_remap_pfn_range((vma), (vaddr), (pfn), (size), (prot))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
typedef struct files_struct ci_fdtable;
#else
typedef struct fdtable ci_fdtable;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
# define fop_has_readv
#else
# undef fop_has_readv
#endif

/* splice_write was introduces before 2.6.18, but we really need sendfile()
 * only. In 2.6.18, sendfile() works even without splice_write fop, but it
 * is not true for later kernels. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
# define fop_has_splice
#else
# undef fop_has_splice
#endif

/* If the IP driver is not known to be built on the same host as the CHAR 
 * driver we insulate it against data structure changes through these 
 * accessors. These are currently out of line. If it turns out to be a
 * problem performance-wise we can get cleverer. */
extern struct page* ci_follow_page(ci_addr_spc_t addr_spc, caddr_t address);

#include <linux/capability.h>
/* Do allow system administration via ioctl? */
ci_inline int ci_is_sysadmin(void)
{
  return capable(CAP_SYS_ADMIN);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
ci_inline ci_fdtable *ci_files_fdtable(struct files_struct *f)
{ return f; }
ci_inline void ci_fdtable_set_fd(ci_fdtable *fdt, int fd, void *p)
{ fdt->fd[fd] = p; }
#else
ci_inline ci_fdtable *ci_files_fdtable(struct files_struct *f)
{ return files_fdtable(f); }
ci_inline void ci_fdtable_set_fd(ci_fdtable *fdt, int fd, void *p)
{ rcu_assign_pointer(fdt->fd[fd], p); }
#endif


ci_inline void ci_unlock_task(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
  read_unlock(&tasklist_lock);
#else
  rcu_read_unlock();
#endif
}

ci_inline struct task_struct* ci_lock_task_by_pid(pid_t p) {
  struct task_struct* t;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
  read_lock(&tasklist_lock);
#else
  rcu_read_lock();
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,24)
  t = find_task_by_pid(p);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
  t = find_task_by_pid_type(p, PIDTYPE_PID);
#else
  {
    struct pid* pid = find_vpid(p);
    t = pid_task(pid, PIDTYPE_PID);
  }
#endif
  if( !t )
    ci_unlock_task();
  return t;
}

#ifndef DEFINE_RWLOCK
#define DEFINE_RWLOCK(name) rwlock_t name = RW_LOCK_UNLOCKED
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(name) spinlock_t name = SPIN_LOCK_UNLOCKED
#endif

/*--------------------------------------------------------------------
 *
 * VMALLOC and helpers
 *
 *--------------------------------------------------------------------*/

#define VMALLOC_VMADDR(x) ((unsigned long)(x))    /* depreciated */


ci_inline void
ci_sleep_ms(ulong ms)
{
  set_current_state(TASK_INTERRUPTIBLE);
  schedule_timeout((HZ*ms)/1000);
}

/*--------------------------------------------------------------------
 *
 * Kernel definitions for SHUT_RD and friends
 *
 *--------------------------------------------------------------------*/

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2


/*--------------------------------------------------------------------
 *
 * ci_waitable_t
 *
 *--------------------------------------------------------------------*/

#define CI_BLOCKING_CTX_ARG(x)

typedef struct {
  wait_queue_head_t  wq;
} ci_waitable_t;

typedef struct {
  wait_queue_t	w;
} ci_waiter_t;

typedef long  ci_waitable_timeout_t;  /* jiffies */
typedef int (*ci_waiter_on_wakeup_fn)(ci_waiter_t*, void*, void*, int rc,
                                      ci_waitable_timeout_t);


#define ci_waitable_ctor(w)	init_waitqueue_head(&(w)->wq)
#define ci_waitable_dtor(w)	do{}while(0)

#define ci_waitable_active(w)	waitqueue_active(&(w)->wq)
#define ci_waitable_wakeup_one(w)			\
  do{ wake_up_interruptible(&(w)->wq); }while(0)
#define ci_waitable_wakeup_all(w)			\
  do{ wake_up_interruptible_all(&(w)->wq); }while(0)

#if HZ > 2000
# error HZ is too big for ci_waitq_init_timeout
#endif

#define ci_waitable_init_timeout(t, timeval)  \
  do {                                        \
    if( ci_waitq_wait_forever(timeval) )      \
      *(t) = -1;                \
    else                                      \
    {                                         \
      *(t) = (timeval)->tv_sec * HZ + (timeval)->tv_usec * HZ / 1000000u; \
      *(t) = CI_MAX(*(t), 1);                 \
    }                                         \
  } while(0)

#define ci_waitable_init_timeout_from_ms(t, ms)  \
  do {                                        \
    if( ms == 0 )                             \
      *(t) = -1;                \
    else                                      \
      *(t) = msecs_to_jiffies(ms);            \
  } while(0)

ci_inline int __ci_waiter_pre(ci_waiter_t* waiter, ci_waitable_t* waitable) {
  init_waitqueue_entry(&waiter->w, current);
  set_current_state(TASK_INTERRUPTIBLE);
  add_wait_queue(&waitable->wq, &waiter->w);
  return 0;
}
#define ci_waiter_pre(wr, wb)  __ci_waiter_pre(wr, wb)

ci_inline int __ci_waiter_exclusive_pre(ci_waiter_t* waiter,
					ci_waitable_t* waitable) {
  init_waitqueue_entry(&waiter->w, current);
  set_current_state(TASK_INTERRUPTIBLE);
  add_wait_queue_exclusive(&waitable->wq, &waiter->w);
  return 0;
}
#define ci_waiter_exclusive_pre  __ci_waiter_exclusive_pre

#define ci_waiter_post(waiter, waitable)		\
  remove_wait_queue(&(waitable)->wq, &(waiter)->w);	\

ci_inline void ci_waiter_dont_wait(ci_waiter_t* waiter,
				   ci_waitable_t* waitable) {
  ci_waiter_post(waiter, waitable);
  set_current_state(TASK_RUNNING);
}

#define ci_waiter_prepare_continue_to_wait(a, b)  \
  set_current_state(TASK_INTERRUPTIBLE)

#define ci_waiter_dont_continue_to_wait(a, b)  \
    set_current_state(TASK_RUNNING);

#define CI_WAITER_CONTINUE_TO_WAIT	1
#define CI_WAITER_CONTINUE_TO_WAIT_REENTRANT  2
#define CI_WAITER_CONVERT_REENTRANT(x)    (x)

/* If timeout is negative, the function will wait forever and return
 * -ERESTARTSYS in case of signal arrival.
 * If timeout is positive, the funtion will wait for the given timeout and
 * return -EINTR in case of signal.
 * Such a behaviour is implemented to match Linux one, and also because
 * there is no way to properly restart a system call with timeout.
 */
ci_inline int ci_waiter_wait(ci_waiter_t* waiter, ci_waitable_t* w,
			     ci_waitable_timeout_t *timeout,
			     void* opaque1, void* opaque2,
			     ci_waiter_on_wakeup_fn on_wakeup) {
  int rc;
  ci_waitable_timeout_t t = -1;
  if( timeout )
    t = *timeout;
 again:
  rc = 0;
  if( t >= 0 ) {
    t = schedule_timeout(t);
    if( t == 0 )                        rc = -ETIMEDOUT;
    else if( signal_pending(current) )  rc = -EINTR;
  }
  else {
    schedule();
    if( signal_pending(current) )  rc = -ERESTARTSYS;
  }
  rc = on_wakeup(waiter, opaque1, opaque2, rc, t);
  if( rc == CI_WAITER_CONTINUE_TO_WAIT )  goto again;
  if( timeout )
    *timeout = t;
  return rc;
}


/*--------------------------------------------------------------------
 *
 * wait_queue 
 *
 *--------------------------------------------------------------------*/

typedef wait_queue_head_t	ci_waitq_t;
typedef wait_queue_t		ci_waitq_waiter_t;
typedef long			ci_waitq_timeout_t;  /* jiffies */

#define ci_waitq_ctor(wq)	init_waitqueue_head(wq)
#define ci_waitq_dtor(wq)	do{}while(0)

#define ci_waitq_active(wq)	waitqueue_active(wq)
#define ci_waitq_wakeup(wq)	do{ wake_up_interruptible(wq); }while(0)
#define ci_waitq_wakeup_all(wq)	do{ wake_up_interruptible_all(wq); }while(0)

#if HZ > 2000
# error HZ is too big for ci_waitq_init_timeout
#endif

ci_inline void ci_waitq_init_timeout(ci_waitq_timeout_t* t,
                                     ci_timeval_t* timeval) {
  if( ci_waitq_wait_forever(timeval) )
    *t = -1;
  else {
    *t = timeval->tv_sec * HZ + timeval->tv_usec * HZ / 1000000u;
    *t = CI_MAX(*t, 1);
  }
}

#define ci_waitq_waiter_pre(waiter, wq)		\
  do {						\
    init_waitqueue_entry(waiter, current);	\
    set_current_state(TASK_INTERRUPTIBLE);	\
    add_wait_queue((wq), (waiter));		\
  } while(0)

#define ci_waitq_waiter_exclusive_pre(waiter, wq)	\
  do {							\
    init_waitqueue_entry(waiter, current);		\
    set_current_state(TASK_INTERRUPTIBLE);		\
    add_wait_queue_exclusive((wq), (waiter));		\
  } while(0)

#define ci_waitq_waiter_wait(waiter, wq, cond)	\
  do { if( !(cond) )  schedule(); } while(0)

#define ci_waitq_waiter_timedwait(waiter, wq, cond, timeout)		\
  do {									\
    if( !(cond) ) {							\
      if( *(timeout) >= 0 ) *(timeout) = schedule_timeout(*(timeout));	\
      else                  schedule();					\
    }									\
  } while(0)

#define ci_waitq_waiter_again(waiter, wq)       \
  do {                                          \
    set_current_state(TASK_INTERRUPTIBLE);      \
  } while(0)

#define ci_waitq_waiter_post(waiter, wq)	\
  do {						\
    set_current_state(TASK_RUNNING);		\
    remove_wait_queue((wq), (waiter));		\
  } while(0)

#define ci_waitq_waiter_signalled(waiter, wq)  (signal_pending(current))

#define ci_waitq_waiter_timedout(timeout)      (*(timeout) == 0)






#if defined(pte_pfn) && defined(pfn_valid)
# define ci_pte_valid(pte)	pfn_valid(pte_pfn(pte))
#else
# define ci_pte_valid(pte)	1
#endif

extern unsigned ci_va_to_pfn(void* addr);


/*--------------------------------------------------------------------
 *
 * ci_contig_shmbuf_t: A (potentially) large buffer that is contiguous in
 * the driver address space, and may be mapped to userlevel.
 *
 *--------------------------------------------------------------------*/

typedef struct {
  char*		p;
  unsigned	bytes;
} ci_contig_shmbuf_t;


ci_inline int ci_contig_shmbuf_alloc(ci_contig_shmbuf_t* kus, unsigned bytes) {
  ci_assert(bytes > 0);
  kus->bytes = CI_ROUND_UP(bytes, CI_PAGE_SIZE);
  ci_assert(! ci_in_atomic());
  kus->p = vmalloc(kus->bytes);
  return kus->p ? 0 : -ENOMEM;
}

ci_inline void ci_contig_shmbuf_free(ci_contig_shmbuf_t* kus) {
  ci_assert(! ci_in_atomic());
  ci_assert(kus);  ci_assert(kus->p);
  vfree(kus->p);
  CI_DEBUG_ZERO(kus);
}

ci_inline caddr_t ci_contig_shmbuf_ptr(ci_contig_shmbuf_t* kus)
{ return kus->p; }

ci_inline size_t ci_contig_shmbuf_size(ci_contig_shmbuf_t* kus)
{ return kus->bytes; }

ci_inline int ci_contig_shmbuf_mmap(ci_contig_shmbuf_t* kus, unsigned offset,
				unsigned long* bytes, void* opaque,
				int* map_num, unsigned long* p_offset) {
  unsigned n = ci_contig_shmbuf_size(kus) - offset;
  n = CI_MIN(n, *bytes);
  *bytes -= n;
  ++*map_num;
  *p_offset += n;
  return 0;
}

/*! map offset in contiguous shmbuf to physical page frame number */
ci_inline unsigned ci_contig_shmbuf_nopage(ci_contig_shmbuf_t* kus,
					   unsigned offset)
{
  ci_assert(CI_OFFSET(offset, CI_PAGE_SIZE) == 0);
  ci_assert(offset < kus->bytes);
  return ci_va_to_pfn(kus->p + offset);
}


/*--------------------------------------------------------------------
 *
 * PCI support layer
 *
 *--------------------------------------------------------------------*/

#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ > 91)
#  define CI_KERNEL_PCI(_f, ...) \
  (driver_is_master ? pci_##_f(__VA_ARGS__) : ci_kernel_pci_##_f(__VA_ARGS__))
#else
#  define CI_KERNEL_PCI(_f, _a...) \
  (driver_is_master ? pci_##_f(##_a) : ci_kernel_pci_##_f(##_a))
#endif




#define CI_KERNEL_PCI_MODULE_INIT(x)       CI_KERNEL_PCI(module_init, x)
#define CI_KERNEL_PCI_SET_DRVDATA(x, y)    CI_KERNEL_PCI(set_drvdata, x, y)
#define CI_KERNEL_PCI_GET_DRVDATA(x)       CI_KERNEL_PCI(get_drvdata, x)
#define CI_KERNEL_PCI_UNREGISTER_DRIVER(x) CI_KERNEL_PCI(unregister_driver, x)



/*--------------------------------------------------------------------
 *
 * Support for NetDevice Features
 *
 *--------------------------------------------------------------------*/

#  include <linux/ethtool.h>
#  include <linux/if_vlan.h>


/*--------------------------------------------------------------------
 *
 * udelay
 *
 *--------------------------------------------------------------------*/

#define ci_udelay(us) udelay((us))


/*--------------------------------------------------------------------
 *
 * Process priority.
 *
 *--------------------------------------------------------------------*/

/* These functions are exported, but declared in "private" pci.h */
extern unsigned char pci_max_busnr(void);
struct pci_bus * pci_add_new_bus(struct pci_bus *parent, struct pci_dev *dev, int busnr);

/*--------------------------------------------------------------------
 *
 * GPL ONLY symbols
 *
 *--------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7))
#define LINUX_DEVICE_REGISTER_EXPORTED
#endif


/*--------------------------------------------------------------------
 *
 * oo_clone_fd()
 *
 *--------------------------------------------------------------------*/

/* Clone filp to a new fd.  As long as filp is one of ours, this is like
** doing open ("/dev/efab0"), except you don't need access to /dev/efab0
** (i.e. works independently of NIC, and works if you've been chroot-ed to
** a place where you can't see /dev/).
**
** Returns a new fd that references the same kind of file object as filp
** (though a distinct 'instance'), or negative error code on failure.  If
** [new_filp_out] is not NULL, then it is filled.  The caller then owns a
** reference to the new filp, and must ensure it is released.
*/
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif
ci_inline int oo_clone_fd(struct file* filp, struct file** new_filp_out,
                          int flags) {
  /* dentry_open() will construct a new struct file given an appropriate
  ** struct dentry and struct vfsmount: all we need to do is grab a
  ** reference to the entries that the original filp points to.
  */
  int new_fd = get_unused_fd();

  if( new_fd >= 0 ) {
    struct file *new_filp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    new_filp = dentry_open(&filp->f_path, filp->f_flags, current_cred());
#else
    dget(filp->f_dentry);
    mntget(filp->f_vfsmnt);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29))
    new_filp = dentry_open(filp->f_dentry, filp->f_vfsmnt, filp->f_flags);
#else
    new_filp = dentry_open(filp->f_dentry, filp->f_vfsmnt, filp->f_flags,
                           current_cred());
#endif /* linux-2.6.9 */
    /* NB. If dentry_open() fails it drops the refs to f_dentry and
    ** f_vfsmnt for us, so there's no leak here.  Move along.
    */
#endif /* linux-3.6 */
    if( ! IS_ERR(new_filp) ) {
      if( new_filp_out ) {
	*new_filp_out = new_filp;
	get_file(new_filp);
      }
      if( flags & O_CLOEXEC ) {
        struct files_struct *files = current->files;
        ci_fdtable *fdt;
        spin_lock(&files->file_lock);
        fdt = ci_files_fdtable(files);
        rcu_assign_pointer(fdt->fd[new_fd], new_filp);
        efx_set_close_on_exec(new_fd, fdt);
        spin_unlock(&files->file_lock);

      } else
        fd_install(new_fd, new_filp);
    }
    else {
      put_unused_fd(new_fd);
      new_fd = -ENOMEM;
    }
  }

  return new_fd;
}

#define ci_get_file get_file
#define ci_fget     fget
#define ci_fput     fput

extern struct ci_private_s *ci_fpriv(struct file *);
extern struct file *ci_privf(struct ci_private_s *);


/* 2.6.14 have RTMGRP_* for user mode only */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
  #if defined(RTMGRP_LINK) || \
      defined(RTMGRP_IPV4_IFADDR) || \
      defined(RTMGRP_IPV4_ROUTE)
    #error "oops"
  #endif
#define RTMGRP_LINK        RTNLGRP_LINK
#define RTMGRP_IPV4_IFADDR RTNLGRP_IPV4_IFADDR
#define RTMGRP_IPV4_ROUTE  RTNLGRP_IPV4_ROUTE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define dev_get_by_index(net, ifindex) dev_get_by_index(ifindex)
#endif


#endif  /* __CI_DRIVER_PLATFORM_LINUX_KERNEL_H__ */
/*! \cidoxg_end */
