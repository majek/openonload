/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

/*
** Copyright 2012     Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
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
*//*! \file linux_trampoline_ppc64.c System call trampolines for Linux/PPC64
** <L5_PRIVATE L5_SOURCE>
** \author  <rrw@kynesim.co.uk>
**  \brief  Package - driver/linux	Linux driver support
**   \date  2012/11/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_linux */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <linux/unistd.h>
#include "ppc64_linux_trampoline_internal.h"

/* Debugging for internal use only */
#  define TRAMP_DEBUG(x...) (void)0
//#define TRAMP_DEBUG(x...) printk(KERN_ERR x)


#define TRAMPOLINE_BITS_64  0
#define TRAMPOLINE_BITS_32  1

typedef struct state_struct
{
    syscall_entry_t *replace_close;
    syscall_entry_t *replace_exit_group;
    syscall_entry_t *replace_rt_sigaction;
    
    /* We don't actually replace these syscalls, but we do thunk them so
     * that we can call them ourselves.
     */
    syscall_entry_t *no_replace_epoll_create1;
    syscall_entry_t *no_replace_epoll_create;

    syscall_entry_t *no_replace_epoll_ctl;
    syscall_entry_t *no_replace_epoll_wait;

    syscall_entry_t *no_replace_accept4;
    syscall_entry_t *no_replace_accept;
    syscall_entry_t *no_replace_socketcall;
    syscall_entry_t *no_replace_sendmsg;

    syscall_entry_t *no_replace_ipc;
} state_t;

state_t state;
atomic_t efab_syscall_used;

static int setup_trampoline(struct pt_regs *regs, 
                            int opcode, int arg, 
                            int bits);

/* We (somewhat arbitrarily) regard calls from onload as calls to the 64-bit
 *  syscall entry points.
 */

asmlinkage int efab_linux_sys_close(int fd)
{
    int rc;

    if (state.replace_close)
    {
        TRAMP_DEBUG ("close %d via saved_sys_close=%p...", fd, state.replace_close->original_entry64);
        rc = ((int (*)(int))(state.replace_close->original_entry64))(fd);
        TRAMP_DEBUG (".. = %d", rc);
    }
    else
    {
        ci_log("Unexpected close() request before full init");
        return -EFAULT;
    }
    return rc;
}

asmlinkage int efab_linux_sys_exit_group(int status)
{
    if (state.replace_exit_group)
    {
        return ((int (*)(int))(state.replace_exit_group->original_entry64))(status);
    }
    else
    {
        ci_log("Unexpected exit_group() request before full init");
        return -EFAULT;
    }
}

#if CI_CFG_USERSPACE_EPOLL
asmlinkage int efab_linux_sys_epoll_create1(int flags)
{
    asmlinkage int (*sys_epoll_create_fn)(int);
    int rc;

#ifdef __NR_epoll_create1
    if (state.no_replace_epoll_create1)
    {
        sys_epoll_create_fn = (int (*)(int))(state.no_replace_epoll_create1->original_entry64);
        TRAMP_DEBUG("epoll_create1 via %p .. ", sys_epoll_create_fn);
        rc = sys_epoll_create_fn(flags);
        if (rc != -ENOSYS)
            goto out;
    }
#endif
    if (!state.no_replace_epoll_create)
    {
        ci_log("Unexpected epoll_ctl() request before full init");
        return -EFAULT;
    }
    sys_epoll_create_fn = (int (*)(int))(state.no_replace_epoll_create->original_entry64);
    TRAMP_DEBUG("epoll_create via %p .. ", sys_epoll_create_fn);
    rc = sys_epoll_create_fn(1);
    ci_assert_equal(flags & ~EPOLL_CLOEXEC, 0);
    if (rc >= 0 && (flags & EPOLL_CLOEXEC))
    {
        struct files_struct *files = current->files;
        struct fdtable *fdt;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        efx_set_close_on_exec(rc, fdt);
        spin_unlock(&files->file_lock);
    }
    
    goto out;
out:
    TRAMP_DEBUG(" ... = %d ", rc);
    return rc;
}

asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                        struct epoll_event *event)
{
    asmlinkage int (*sys_epoll_ctl_fn)(int, int, int, struct epoll_event *);
    int rc;

    if (!state.no_replace_epoll_ctl)
    {
        ci_log("Unexpected epoll_ctl() request before full init");
        return -EFAULT;
    }

    sys_epoll_ctl_fn = (int (*)(int, int , int, struct epoll_event *))
        (state.no_replace_epoll_ctl->original_entry64);
  TRAMP_DEBUG ("epoll_ctl(%d,%d,%d,%p) via %p...", epfd, op, fd, event,
               sys_epoll_ctl_fn);
  rc = sys_epoll_ctl_fn(epfd, op, fd, event);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

asmlinkage int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                                         int maxevents, int timeout)
{
  asmlinkage int (*sys_epoll_wait_fn)(int, struct epoll_event *, int, int);
  int rc;

  if( !state.no_replace_epoll_wait ) {
    ci_log("Unexpected epoll_wait() request before full init");
    return -EFAULT;
  }

  sys_epoll_wait_fn = (int (*)(int, struct epoll_event *, int, int))
                       (state.no_replace_epoll_wait->original_entry64);
  TRAMP_DEBUG ("epoll_wait(%d,%p,%d,%d) via %p...", epfd, events, maxevents,
               timeout, sys_epoll_wait_fn);
  rc = sys_epoll_wait_fn(epfd, events, maxevents, timeout);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif /* CI_CFG_USERSPACE_EPOLL */


asmlinkage int efab_linux_sys_accept4(int fd, struct sockaddr __user* addr,
                                      int __user* addrlen,
                                      unsigned long __user*socketcall_args,
                                      int flags)
{
  int rc;


#ifdef __NR_accept4
  {
    asmlinkage int (*sys_accept4_fn)(int, struct sockaddr*, socklen_t *, int);

    if( state.no_replace_accept4 == NULL ) {
        ci_log("Unexpected accept4() request before full init");
        return -EFAULT;
    }

    
    sys_accept4_fn = (int (*)(int, struct sockaddr *, socklen_t *, int))
    (state.no_replace_accept4->original_entry64);

    TRAMP_DEBUG ("accept4(%d,%p,%d,%d) via %p...", fd, addr, *addrlen,
                 flags, sys_accept4_fn);
    rc = sys_accept4_fn(fd, addr, addrlen, flags);
    if( rc != -ENOSYS )
      goto out;
  }
  /* Drop through if rc == ENOSYS to try accept() */
#endif
#if defined(__NR_accept)
  {
    asmlinkage int (*sys_accept_fn)(int, struct sockaddr *, socklen_t *);

    if (state.no_replace_accept == NULL) {
        ci_log("Unexpected accept() request before full init");
        return -EFAULT;
    }
        
    sys_accept_fn = (int (*)(int, struct sockaddr *, socklen_t *))
       (state.no_replace_accept->original_entry64);
    TRAMP_DEBUG ("accept(%d,%p,%d) via %p...", fd, addr, *addrlen,
                 sys_accept_fn);
    rc = sys_accept_fn(fd, addr, addrlen);

    /* If we ever need non-zero flags here, we should implement it
     * For now, we use non-zero flags iff the system has accept4. */
    ci_assert_equal(flags, 0);
    if( rc != -ENOSYS )
      goto out;
  }
  /* Drop through if rc == ENOSYS to try socketcall() */
#endif
#if defined(__NR_socketcall)
  {
    asmlinkage int (*sys_socketcall_fn)(int, unsigned long *);
    unsigned long args[4];

    if (state.no_replace_socketcall == NULL) {
        ci_log("Unexpected socketcall() request before full init");
        return -EFAULT;
    }

    sys_socketcall_fn = (int (*)(int, unsigned long *))(state.no_replace_socketcall->original_entry64);
    TRAMP_DEBUG ("accept4(%d,%p,%p(%d),%d) via %p...", fd, addr, addrlen,
                 addrlen ? *addrlen : 0,
                 flags, sys_socketcall_fn);
    memset(args, 0, sizeof(args));
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)addr;
    args[2] = (unsigned long)addrlen;
    args[3] = (unsigned long)flags;
    rc = -EFAULT;
    if (copy_to_user(socketcall_args, args, sizeof(args)))
      goto out;

# ifdef SYS_ACCEPT4
    rc = (sys_socketcall_fn) (SYS_ACCEPT4, socketcall_args);
    if( rc == -EINVAL )
# endif
    {
      rc = (sys_socketcall_fn) (SYS_ACCEPT, socketcall_args);
      /* If we ever need non-zero flags here, we should implement it */
      ci_assert_equal(flags, 0);
    }
    goto out;
  }
#endif

#if !defined(__NR_accept) && !defined(__NR_accept) && !defined(__NR_socketcall)
#error "Can't find accept syscall number"
#endif

out:
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}


asmlinkage int efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                                      unsigned long __user* socketcall_args,
                                      unsigned flags)
{
  int rc;


  {
#ifdef __NR_sendmsg
    asmlinkage int (*sys_sendmsg_fn)(int, struct msghdr *, unsigned);

    if( state.no_replace_sendmsg == NULL ) {
        ci_log("Unexpected sendmsg() request before full init");
        return -EFAULT;
    }
    sys_sendmsg_fn = (int (*)(int, struct msghdr *, unsigned ))
        (state.no_replace_sendmsg->original_entry64);
    TRAMP_DEBUG ("sendmsg(%d,%p,%d) via %p...", fd, msg, flags, sys_sendmsg_fn);
    rc = sys_sendmsg_fn(fd, msg, flags);
#elif defined(__NR_socketcall)
    asmlinkage int (*sys_socketcall_fn)(int, unsigned long *);
    unsigned long args[3];

    if( state.no_replace_socketcall == NULL ) {
        ci_log("Unexpected sendmsg->socketcall() request before full init");
        return -EFAULT;
    }

    sys_socketcall_fn = (int (*)(int, unsigned long *))
        (state.no_replace_socketcall->original_entry64);
    TRAMP_DEBUG ("sendmsg(%d,%p,%d) via %p...", fd, msg,
                 flags, sys_socketcall_fn);
    memset(args, 0, sizeof(args));
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)msg;
    args[2] = (unsigned long)flags;
    rc = -EFAULT;
    if (copy_to_user(socketcall_args, args, sizeof(args)) == 0)
      rc = (sys_socketcall_fn) (SYS_SENDMSG, socketcall_args);
#else
#error "Can't find sendmsg syscall number"
#endif
  }

  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

asmlinkage int efab_linux_sys_sigaction(int signum,
                                        const struct sigaction *act,
                                        struct sigaction *oact)
{
  int rc;

  if (state.replace_rt_sigaction == NULL) {
    ci_log("Unexpected rt_sigaction() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("sigaction(%d,%p,%p,%d) via %p...", signum, act, oact,
               (int)sizeof(sigset_t), state.replace_rt_sigaction->original_entry64);
  rc = ((int (*)(int, const struct sigaction *, struct sigaction *, size_t))
        (state.replace_rt_sigaction->original_entry64))(signum, act, oact, sizeof(sigset_t));
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

asmlinkage int efab_linux_sys_sigaction32(int signum,
                                          const struct sigaction32 *act,
                                          struct sigaction32 *oact)
{
  int rc;

  if (state.replace_rt_sigaction == NULL) {
    ci_log("Unexpected rt_sigaction() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("sigaction(%d,%p,%p,%d) via %p...", signum, act, oact,
               (int)sizeof(sigset_t), state.replace_rt_sigaction->original_entry32);
  rc = ((int (*)(int, const struct sigaction32 *, struct sigaction32 *, size_t))
        (state.replace_rt_sigaction->original_entry32))(signum, act, oact, sizeof(sigset_t));
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

/* Our close handler, 64-bit */
static int efab_linux_trampoline_close64(int fd)
{
  /* Firstly, is this one our sockets?  If not, do the usual thing */
  struct file *f;
  int rc;

  efab_syscall_enter();
  
  f = fget (fd);
  if (f) {
      if (FILE_IS_ENDPOINT(f)) {
        /* Yep -- it's one of ours.  This means current process must be using the
         * module (otherwise how did one of our sockets get in this proc's fd
         * table?).  It seems it didn't get intercepted -- trampoline back up.
         * However, only set up trampoline if this has been called via the
         * correct sys-call entry point
         */
        if (setup_trampoline (PT_REGS_FROM_SYSCALL(), 
                              CI_TRAMP_OPCODE_CLOSE, fd, TRAMPOLINE_BITS_64) == 0)
        {
            /* The trampoline will get run.  Let it handle the rest. */
            fput(f);
            efab_syscall_exit();
            return 0;
        }
    }
    /* Undo the fget above */
    fput(f);
  }
  
  /* Not one of our FDs -- usual close */
  rc = ((int (*)(int))(state.replace_close->original_entry64))(fd);
  TRAMP_DEBUG("Close64: Chain returns %d \n", rc);
  efab_syscall_exit();
  return rc;
}

int efab_linux_trampoline_close32(int fd)
{
  /* Firstly, is this one our sockets?  If not, do the usual thing */
  struct file *f;
  int rc;

  efab_syscall_enter();

  f = fget (fd);
  if (f) {
      if (FILE_IS_ENDPOINT(f)) {
      /* Yep -- it's one of ours.  This means current process must be using the
       * module (otherwise how did one of our sockets get in this proc's fd
       * table?).  It seems it didn't get intercepted -- trampoline back up.
       * However, only set up trampoline if this has been called via the
       * correct sys-call entry point
       */
        if (setup_trampoline (PT_REGS_FROM_SYSCALL(), 
                              CI_TRAMP_OPCODE_CLOSE, fd, TRAMPOLINE_BITS_32) == 0)
        {
            /* The trampoline will get run.  Let it handle the rest. */
            fput(f);
            efab_syscall_exit();
            return 0;
        }
    }
    /* Undo the fget above */
    fput(f);
  }
  
  /* Not one of our FDs -- usual close */
  rc = ((int (*)(int))(state.replace_close->original_entry32))(fd);
  TRAMP_DEBUG("Close32: Chain returns %d \n", rc);
  efab_syscall_exit();
  return rc;
}

static int setup_trampoline(struct pt_regs *regs, 
                            int opcode, int arg, 
                            int bits)
{
    struct mm_hash *p;
    ci_uintptr_t trampoline_entry = 0, trampoline_exclude = 0,
        trampoline_toc = 0, trampoline_fixup = 0;
    int rc = -EBADF;
    
    read_lock(&oo_mm_tbl_lock);
    p = oo_mm_tbl_lookup(current->mm);
    if (p)
    {
        trampoline_entry = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_entry);
        trampoline_exclude = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_exclude);
        trampoline_toc = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_toc);
        trampoline_fixup = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_user_fixup);
    }
    read_unlock(&oo_mm_tbl_lock);
    
    TRAMP_DEBUG("%s: trampoline_entry = %p \n", __func__, (void *)trampoline_entry);

    /* OK. We have the entry - set up a trampoline to user space */
    if (trampoline_entry)
    {
        if (!access_ok(VERIFY_READ, trampoline_entry, 1))
        {
            /* Can't read this address. Fail! */
            ci_log("Pid %d (mm=%p) has bad trampoline entry: %p",
                   current->tgid, current->mm, (void *)trampoline_entry);
            return -EBADF;
        }

        /* Check for the excluded address */
        if (regs->nip == trampoline_exclude)
        {
            TRAMP_DEBUG("Ignoring call from excluded address 0x%08lx",
                        (unsigned long)trampoline_exclude);
            return -EBUSY;
        }

        TRAMP_DEBUG("%s: bits = %d; set up trampoline. \n", __func__, bits);
        if (bits == TRAMPOLINE_BITS_64)
        {
            setup_trampoline64(regs, opcode, arg, 
                               (void *)trampoline_entry, (void *)trampoline_toc,
                               (void *)trampoline_fixup);
        }
        else
        {
            setup_trampoline32(regs, opcode, arg,
                               (void *)trampoline_entry, (void *)trampoline_toc,
                               (void *)trampoline_fixup);
        }
        rc = 0;
    }
    else
    {
        OO_DEBUG_VERB(ci_log("Error -- attempt to trampoline for unknown process"));
        rc = -ENOENT;
    }
    return rc;
}


#ifdef OO_DO_HUGE_PAGES


#include <linux/unistd.h>
asmlinkage int efab_linux_sys_shmget(key_t key, size_t size, int shmflg)
{
    int rc;
    sys_ipc_fn_t fn = get_ipc_fn();

    TRAMP_DEBUG ("shmget(%d,%d,%d) via %p...", key, size, shmflg,
                 fn);
    rc = sys_shmget(key, size, shmflg);
    TRAMP_DEBUG ("... = %d", rc);
    return rc;
}

asmlinkage long efab_linux_sys_shmat(int shmid, char __user *addr, int shmflg)
{
    long rc;
    int r;

    /* We need to do this directly, for lack of a user-space address to
     * put the result address in 
     */
    TRAMP_DEBUG ("shmat(%d,%p,%d) via %p...", shmid, addr, shmflg,
                 do_shmat);
    r = do_shmat(shmid, addr, shmflg, &rc);
    if (r < 0) { rc = (long)-1; }
    TRAMP_DEBUG ("... = %p", rc);
    return rc;
}
asmlinkage int efab_linux_sys_shmdt(char __user *addr)
{
    int rc;
    
    TRAMP_DEBUG ("shmdt(%p) via %p...", addr, sys_shmdt);
    rc = sys_shmdt(addr);
    TRAMP_DEBUG ("... = %d", rc);
    return rc;
}
asmlinkage int efab_linux_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  int rc;

  TRAMP_DEBUG ("shmdt(%p) via %p...", shmid, cmd, buf, sys_shmctl);
  rc = 
      sys_shmctl(shmid, cmd, buf);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif

int efab_linux_trampoline_ctor(int no_sct)
{
    int rc;

    atomic_set(&efab_syscall_used, 0);

    memset(&state, '\0', sizeof(struct state_struct));

    rc = linux_trampoline_ppc64_internal_ctor();
    if (!rc) 
    {
        if (no_sct)
        {
            TRAMP_DEBUG("syscalls NOT hooked - no_sct requested");
        }
        else
        {
            state.replace_close = 
                linux_trampoline_ppc64_intercept_syscall(__NR_close,
                                                         efab_linux_trampoline_close64,
                                                         efab_linux_trampoline_close32);
#ifdef OO_CAN_HANDLE_TERMINATION
            state.replace_exit_group =
                linux_trampoline_ppc64_intercept_syscall(__NR_exit_group,
                                                         efab_linux_trampoline_exit_group,
                                                         efab_linux_trampoline_exit_group);
#endif
            state.replace_rt_sigaction =
                linux_trampoline_ppc64_intercept_syscall(__NR_rt_sigaction,
                                                         efab_linux_trampoline_sigaction,
                                                         efab_linux_trampoline_sigaction32);
        }

#ifdef __NR_epoll_create1
        state.no_replace_epoll_create1 = 
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_create1,
                                                     NULL, NULL);
#endif
        state.no_replace_epoll_create =
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_create, NULL, NULL);
        state.no_replace_epoll_ctl =
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_ctl, NULL, NULL);
        state.no_replace_epoll_wait = 
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_wait, NULL, NULL);

#ifdef __NR_accept4
        state.no_replace_accept4 = 
            linux_trampoline_ppc64_intercept_syscall(__NR_accept4, NULL, NULL);
#endif
#ifdef __NR_accept
        state.no_replace_accept = 
            linux_trampoline_ppc64_intercept_syscall(__NR_accept, NULL, NULL);
#endif
#ifdef __NR_socketcall
        state.no_replace_socketcall =
            linux_trampoline_ppc64_intercept_syscall(__NR_socketcall, NULL, NULL);
#endif
        /* On PPC, there is only one SysV IPC syscall .. */

        state.no_replace_ipc = 
            linux_trampoline_ppc64_intercept_syscall(__NR_ipc, NULL, NULL);
    }
    else
    {
        TRAMP_DEBUG("Warning: syscall table not found - can't read sys_close");
        return 0;
    }
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
#define synchronize_sched synchronize_kernel
#endif

int efab_linux_trampoline_dtor(int no_sct)
{
    int waiting = 0;

    /* Restore syscalls */
    linux_trampoline_ppc64_restore_syscalls();

    /* Give any just-entered syscalls a chance to increment their
     *  atomic
     */
    synchronize_sched();
#ifdef CONFIG_PREEMPT
    schedule_timeout(msecs_to_jiffies(50));
#endif
    while (atomic_read(&efab_syscall_used))
    {
        if (!waiting)
        {
            ci_log("Waiting for intercepted syscalls to finish .. ");
            waiting = 1;
        }
        schedule_timeout(msecs_to_jiffies(50));
    }
    if (waiting)
    {
        ci_log("\t .. OK");
        synchronize_sched();
#ifdef CONFIG_PREEMPT
        /* Try to wait .. */
        schedule_timeout(msecs_to_jiffies(50));
        ci_log("Unload is dangerous on RT kernels: prepare to crash.");
        #endif
    }
 
    linux_trampoline_ppc64_dispose();
   
    return 0;
}

int efab_linux_trampoline_debug (ci_uintptr_t *param)
{
  unsigned long op = *param;
  void *p;

  TRAMP_DEBUG("Trampoline debug op=%lx", op);
  (void)op;

  *param = (unsigned long)find_syscall_table(&p);

  return 0;
}


#ifndef NDEBUG

/* Trampoline into userland failure - this function is never called, and
 *  would need to know whether userspace was 64 or 32 bit in order to
 *  work out how to buld the trampoline, so it does nothing for now - rrw
 *  2012-12-14
 */
void efab_linux_trampoline_ul_fail(void)
{
  struct pt_regs *regs = 0;  /* don't know how to do this on this platform */
  struct mm_hash *p;
  ci_uintptr_t trampoline_ul_fail = 0;

  ci_assert(regs);

  if (current->mm) {
    read_lock (&oo_mm_tbl_lock);
    p = oo_mm_tbl_lookup(current->mm);
    read_unlock (&oo_mm_tbl_lock);
    if (p) {
      trampoline_ul_fail = (ci_uintptr_t) CI_USER_PTR_GET (p->trampoline_ul_fail);
    }
    else {
      ci_log("%s: no entry for pid %u", __FUNCTION__, current->tgid);
      return;
    }
  }
  else {
    ci_log("%s: pid %u is dying - no mm", __FUNCTION__, current->tgid);
    return;
  }

  ci_log("%s: syscall backtrace (pid %d)", __FUNCTION__, current->tgid);
  ci_backtrace();
  ci_log("%s: provoking user-level fail on syscall exit for pid %d",
         __FUNCTION__, current->tgid);


  ci_log("(not really, don't know how on this platform)");

  return;
}

#endif /* !NDEBUG */

/* End file */

