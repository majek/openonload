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
** Copyright 2005-2012  Solarflare Communications Inc.
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
*//*! \file linux_trampoline.c System call trampolines for Linux
** <L5_PRIVATE L5_SOURCE>
** \author  gel,mjs
**  \brief  Package - driver/linux	Linux driver support
**   \date  2005/03/01
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

/*--------------------------------------------------------------------
 *
 * Platform-specific stuff
 *
 *--------------------------------------------------------------------*/

#ifdef __x86_64__
#  include <asm/msr.h>
/* No asm/pda.h in >= 2.6.30.
 * Its content is partially in asm/percpu.h, but approach is different. */
#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#    define OLD_RSP_PROVIDED 1
#    include <asm/pda.h>
#  else
#    define OLD_RSP_PROVIDED 0
#    include <asm/percpu.h>
     DECLARE_PER_CPU(unsigned long, kernel_stack);

      /* Copy'n'paste percpu_read() and percpu_write() definitions.
       * We can't use percpu_read/percpu_write directly, since they access
       * the variable per_cpu__old_rsp, which we can't emulate (we just
       * know its address).
       * percpu_* macros are different in 2.6.30&2.6.31 vs >=2.6.32.
       */
#    if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#      define percpu_read_from_p(pointer) percpu_from_op("mov", *pointer)
#      define percpu_write_to_p(pointer, val) \
         percpu_to_op("mov", *pointer, val)
#    else
#      define percpu_read_from_p(pointer) ({ \
         typeof(*pointer) __tmp_var__;                              \
         preempt_disable();                                         \
         __tmp_var__ = (*SHIFT_PERCPU_PTR(pointer, my_cpu_offset)); \
         preempt_enable();                                          \
         __tmp_var__;                                               \
       })
#      define percpu_write_to_p(pointer, val) ({ \
         preempt_disable();                                   \
         (*SHIFT_PERCPU_PTR(pointer, my_cpu_offset)) = val;  \
         preempt_enable();                                    \
       })
#    endif
#    if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#      define percpu_p(name) (&(per_cpu__ ## name))
#    else
#      define percpu_p(name) (&name)
#    endif
#  endif


#ifdef CONFIG_COMPAT
#  include <asm/ia32_unistd.h>

/* Kernels >=2.6.18 do not define __NR_ia32_close after some muppet decided to
 * do some "tidying up" (quite why an enumerated list with random holes in it
 * is more tidy than a complete list I know not).  Anyway, define it here
 * (there's no way it can change).
 */
#  define __NR_ia32_close 6
#  define __NR_ia32_exit_group 252
#  define __NR_ia32_rt_sigaction 174
#endif /*CONFIG_COMPAT*/


#  define cs(r) (r)->cs
#  define ds(r) (r)->ds
#  define es(r) (r)->es
#  define ss(r) (r)->ss
#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#    define ip(r) (r)->rip
#    define di(r) (r)->rdi
#    define si(r) (r)->rsi
#    define sp(r) (r)->rsp
#    define bp(r) (r)->rbp
#    define ax(r) (r)->rax
#    define bx(r) (r)->rbx
#    define cx(r) (r)->rcx
#    define dx(r) (r)->rdx
#    define orig_ax(r) (r)->orig_rax
#    define flags(r) (r)->eflags
#    define sp0(t) (t)->rsp0
#  else
#    define ip(r) (r)->ip
#    define di(r) (r)->di
#    define si(r) (r)->si
#    define sp(r) (r)->sp
#    define bp(r) (r)->bp
#    define ax(r) (r)->ax
#    define bx(r) (r)->bx
#    define cx(r) (r)->cx
#    define dx(r) (r)->dx
#    define orig_ax(r) (r)->orig_ax
#    define flags(r) (r)->flags
#    define sp0(t) (t)->sp0
#  endif
#endif

#if defined(__i386__)
#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#    define bx(r) (r)->ebx
#    define cx(r) (r)->ecx
#    define dx(r) (r)->edx
#    define si(r) (r)->esi
#    define di(r) (r)->edi
#    define bp(r) (r)->ebp
#    define ax(r) (r)->eax
#    define ds(r) (r)->xds
#    define es(r) (r)->xes
#    define orig_ax(r) (r)->orig_eax
#    define ip(r) (r)->eip
#    define cs(r) (r)->xcs
#    define flags(r) (r)->eflags
#    define sp(r) (r)->esp
#    define ss(r) (r)->xss
#    define sp0(t) (t)->esp0
#  else
#    define bx(r) (r)->bx
#    define cx(r) (r)->cx
#    define dx(r) (r)->dx
#    define si(r) (r)->si
#    define di(r) (r)->di
#    define bp(r) (r)->bp
#    define ax(r) (r)->ax
#    define ds(r) (r)->ds
#    define es(r) (r)->es
#    define orig_ax(r) (r)->orig_ax
#    define ip(r) (r)->ip
#    define cs(r) (r)->cs
#    define flags(r) (r)->flags
#    define sp(r) (r)->sp
#    define ss(r) (r)->ss
#    define sp0(t) (t)->sp0
#  endif
#endif


/* On RHEL5 kernels (2.6.18, x86_64 only) the sys-call
 * table is part of a special memory mapping used for the kernel text
 * section.  This mapping has been observed to start at 2MB above the
 * base of phyiscal memory.
 *
 * No other kernel uses such a hack. (Really?)
 * Possibly, the reason is in linux-2.6-x86-relocatable.patch
 * Tested: a lot of Debian kernels, RHEL<=4 kernels.
 */
#ifdef __x86_64__
# if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)
#  define NEED_SYSCALL_MAPPING_HACK()  ((__pa(loc) >> PAGE_SHIFT) >= end_pfn)
# else
#  define NEED_SYSCALL_MAPPING_HACK()  0
# endif
#endif


/*--------------------------------------------------------------------
 *
 * Tracing / debugging
 *
 *--------------------------------------------------------------------*/

/* Debugging for internal use only */
#  define TRAMP_DEBUG(x...) (void)0


/**************************************************************************** 
 * System-call trampoline stuff.
 *
 * The trampoline mechanism will bodge the return address on the stack, then
 * return from syscall.  The bodged return address points at a handler stub in
 * the user-library, which does the appropriate thing.
 *
 * This is very useful when we detect a system call that we would have normally
 * expected to intercept in the user-library.  Currently we do this only for
 * close.  The trampoline will call the close in the user-library, before
 * returning to immediately after where the original system call was issued.
 *
 * Can also be useful when an error is detected in the system call -- rather
 * than kernel panic, trampoline back to the user-lib wich assert-fails there.
 */


/* The address of the system call table.
 */
static void **syscall_table = 0;

#ifdef CONFIG_COMPAT

/* The address of the 32-bit compatibility system call table.
 */
static void **ia32_syscall_table = 0;

#endif


/* We must save the original addresses of the routines we intercept.
 */
static asmlinkage int (*saved_sys_close)(int);
static asmlinkage int (*saved_sys_exit_group)(int);
static asmlinkage int (*saved_sys_rt_sigaction)(int, const struct sigaction *,
                                                struct sigaction *, size_t);
#ifdef CONFIG_COMPAT
static asmlinkage int (*saved_sys_rt_sigaction32)(int,
                                                  const struct sigaction32 *,
                                                  struct sigaction32 *,
                                                  unsigned int);
#endif


atomic_t efab_syscall_used;


/* Find the syscall table...
 */
#if defined(CONFIG_X86_XEN)
/* Note this needs to be before i386 'cos most XEN builds are i386 */
static void **find_syscall_table(void)
{
  /* We don't currently have any non-appalling way of doing this. */
  return NULL;
}
#elif defined(__i386__)

/* For x86, we can ask for the address of the IDT and look up the entry for
 * int 0x80 to find the syscall entry point, then search for the distinctive
 * opcode for "call *table(,%eax,4)", which is 0xff,0x14,0x85,<table>.
 */
static void **find_syscall_table(void)
{
  unsigned long *idtbase;
  unsigned char *p, *end, idt[6];
  void **result = NULL;

  __asm__("sidt %0" : "=m"(idt));
  idtbase = (unsigned long *)(idt[2] | (idt[3] << 8) | (idt[4] << 16)
                              | (idt[5] << 24));
  TRAMP_DEBUG("idt base=%p, entry 0x80=%08lx,%08lx", idtbase,
              idtbase[0x80*2], idtbase[0x80*2+1]);
  p = (unsigned char *)((idtbase[0x80*2] & 0xffff)
                        | (idtbase[0x80*2+1] & 0xffff0000));
  TRAMP_DEBUG("int 0x80 entry point at %p", p);
  end = p + 1024 - 7;
  while (p < end) {
    if ((p[0] == 0xff) && (p[1] == 0x14) && (p[2] == 0x85)) {
      result = *(void***)(p + 3);
      TRAMP_DEBUG("syscall table at %p", result);
      return result;
    }
    p++;
  }

  TRAMP_DEBUG("didn't find syscall table address");
  return result;
}

#elif defined(__x86_64__)

/* For x86_64, we can find the syscall entry point directly from the LSTAR
 * MSR.  The opcode we need to locate is "call *table(,%rax,8)" which is
 * 0xff,0x14,0xc5,<table> (but note that <table> here is only 4 bytes, not 8).
 */
static void **find_syscall_table(void)
{
  unsigned long result = 0;
  unsigned char *p, *pend;

  rdmsrl(MSR_LSTAR, result);
  TRAMP_DEBUG("msr_lstar=%lx", result);
  p = (unsigned char *)result;
  pend = p + 1024 - 7;
  while (p < pend) {
    if ((p[0] == 0xff) && (p[1] == 0x14) && (p[2] == 0xc5)) {
      result &= ~ 0xffffffffUL;
      result |= (p[3] | (p[4] << 8) | (p[5] << 16) | (p[6] << 24));
      TRAMP_DEBUG("syscall table at %lx", result);
      return (void **)result;
    }
    p++;
  }
  TRAMP_DEBUG("didn't find syscall table address");
  return NULL;
}

#ifdef CONFIG_COMPAT
/* We also need to find the ia32_syscall_table used by 32-bit apps in 64-bit
 * mode.  This can be found via int 0x80 in a similar way to x86 -- but the
 * IDTR and entries in it are larger here, and the instruction we're looking
 * for is "call *table(,%rax,8)" (as for the 64-bit syscall table).
 */
static void **find_ia32_syscall_table(void)
{
  unsigned long result = 0;
  unsigned char *p, *pend;
  unsigned int *idtbase;
  unsigned char idt[10];

  __asm__("sidt %0" : "=m"(idt));
  idtbase = *(unsigned int **)(&idt[2]);
  TRAMP_DEBUG("idt base=%p, entry 0x80=%08x,%08x,%08x", idtbase,
              idtbase[0x80*4], idtbase[0x80*4+1], idtbase[0x80*4+2]);
  result = (idtbase[0x80*4] & 0xffff) | (idtbase[0x80*4+1] & 0xffff0000)
           | ((unsigned long)idtbase[0x80*4+2] << 32);
  p = (unsigned char *)result;
  TRAMP_DEBUG("int 0x80 entry point at %p", p);
  pend = p + 1024 - 7;
  while (p < pend) {
    if ((p[0] == 0xff) && (p[1] == 0x14) && (p[2] == 0xc5)) {
      result &= ~ 0xffffffffUL;
      result |= (p[3] | (p[4] << 8) | (p[5] << 16) | (p[6] << 24));
      TRAMP_DEBUG("ia32_syscall table at %lx", result);
      return (void **)result;
    }
    p++;
  }
  TRAMP_DEBUG("didn't find ia32_syscall table address");
  return NULL;
}
#endif

#elif defined(__ia64__)

/* tramplines not used on ia64 */

asmlinkage int efab_linux_trampoline_close(__attribute__((unused)) int unused)
{
  TRAMP_DEBUG ("ia64 efab_linux_trampoline_close() called");
  return 0;
}

static void **find_syscall_table(void)
{
  return NULL;
}

#else
#error "Don't know how to find syscall table on this platform"
#endif


/* A way to call the original sys_close, exported to other parts of the code.
 */
asmlinkage int efab_linux_sys_close(int fd)
{
  int rc;

  if( saved_sys_close == NULL ) {
    ci_log("Unexpected close() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("close %d via saved_sys_close=%p...", fd, saved_sys_close);
  rc = (saved_sys_close) (fd);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}


asmlinkage int efab_linux_sys_exit_group(int status)
{
  if( saved_sys_exit_group == NULL ) {
    ci_log("Unexpected exit_group() request before full init");
    return -EFAULT;
  }
  return saved_sys_exit_group(status);
}

#if CI_CFG_USERSPACE_EPOLL
asmlinkage int efab_linux_sys_epoll_create1(int flags)
{
  asmlinkage int (*sys_epoll_create_fn)(int);
  int rc;

  if( syscall_table == NULL ) {
    ci_log("Unexpected epoll_ctl() request before full init");
    return -EFAULT;
  }

#ifdef __NR_epoll_create1
  sys_epoll_create_fn = syscall_table[__NR_epoll_create1];
  TRAMP_DEBUG ("epoll_create1(%d) via %p...", flags, sys_epoll_create);
  rc = sys_epoll_create_fn(flags);
  if( rc != -ENOSYS )
    goto out;
  /* fallthrough to epoll_create */
#endif
  sys_epoll_create_fn = syscall_table[__NR_epoll_create];
  TRAMP_DEBUG ("epoll_create via %p...", sys_epoll_create);
  rc = sys_epoll_create_fn(1);
  ci_assert_equal(flags & ~EPOLL_CLOEXEC, 0);
  if( rc >= 0 && flags & EPOLL_CLOEXEC ) {
    struct files_struct *files = current->files;
    struct fdtable *fdt;
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    efx_set_close_on_exec(rc, fdt);
    spin_unlock(&files->file_lock);
  }

#ifdef __NR_epoll_create1
out:
#endif
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                        struct epoll_event *event)
{
  asmlinkage int (*sys_epoll_ctl_fn)(int, int, int, struct epoll_event *);
  int rc;

  if( syscall_table == NULL ) {
    ci_log("Unexpected epoll_ctl() request before full init");
    return -EFAULT;
  }

  sys_epoll_ctl_fn = syscall_table[__NR_epoll_ctl];
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

  if( syscall_table == NULL ) {
    ci_log("Unexpected epoll_wait() request before full init");
    return -EFAULT;
  }

  sys_epoll_wait_fn = syscall_table[__NR_epoll_wait];
  TRAMP_DEBUG ("epoll_wait(%d,%p,%d,%d) via %p...", epfd, events, maxevents,
               timeout, sys_epoll_wait_fn);
  rc = sys_epoll_wait_fn(epfd, events, maxevents, timeout);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif /* CI_CFG_USERSPACE_EPOLL */


asmlinkage int efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                                      unsigned long __user* socketcall_args,
                                      unsigned flags)
{
  int rc;

  if( syscall_table == NULL ) {
    ci_log("Unexpected sendmsg() request before full init");
    return -EFAULT;
  }

  {
#ifdef __NR_sendmsg
    asmlinkage int (*sys_sendmsg_fn)(int, struct msghdr *, unsigned);

    sys_sendmsg_fn = syscall_table[__NR_sendmsg];
    TRAMP_DEBUG ("sendmsg(%d,%p,%d) via %p...", fd, msg, flags, sys_sendmsg_fn);
    rc = sys_sendmsg_fn(fd, msg, flags);
#elif defined(__NR_socketcall)
    asmlinkage int (*sys_socketcall_fn)(int, unsigned long *);
    unsigned long args[3];

    sys_socketcall_fn = syscall_table[__NR_socketcall];
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

  if( saved_sys_rt_sigaction == NULL ) {
    ci_log("Unexpected rt_sigaction() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("sigaction(%d,%p,%p,%d) via %p...", signum, act, oact,
               sizeof(sigset_t), saved_sys_rt_sigaction);
  rc = saved_sys_rt_sigaction(signum, act, oact, sizeof(sigset_t));
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#ifdef CONFIG_COMPAT
asmlinkage int efab_linux_sys_sigaction32(int signum,
                                          const struct sigaction32 *act,
                                          struct sigaction32 *oact)
{
  int rc;

  if( saved_sys_rt_sigaction32 == NULL ) {
    ci_log("Unexpected rt_sigaction32() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("sigaction32(%d,%p,%p,%d) via %p...", signum, act, oact,
               sizeof(sigset_t), saved_sys_rt_sigaction);
  rc = saved_sys_rt_sigaction32(signum, act, oact, sizeof(sigset_t));
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

#endif

#if defined(__x86_64__) && !OLD_RSP_PROVIDED
/* For old kernels, oldrsp per-cpu variable is exported and accessible by
 * module.  For newer kernel, we have to calculate it. */
ci_inline unsigned long *get_oldrsp_addr(void)
{
  static unsigned long *oldrsp_addr = NULL;
  if (oldrsp_addr)
    return oldrsp_addr;

  /* 
   * Dirty hack to find location of old_rsp, which is not exported.
   * 1. get system_call from MSR_LSTAR (again).
   * It looks following:
   *   swapgs
   *        0f 01 f8
   *   <some CFI stuff (?)>
   *   movq   %rsp,PER_CPU_VAR(old_rsp)
   *        65 48 89 24 25 XX XX
   *   <some zeroes>
   *   movq   PER_CPU_VAR(kernel_stack),%rsp
   *        65 48 8b 24 25 YY YY
   * where kernel_stack is exported, so it can be checked.
   * 2. look through the code and find/check we have what we expect.
   */
  {
    unsigned long result;
#ifndef NDEBUG
    unsigned char *ptr;
#endif
    unsigned char *p;
    unsigned long kernel_stack_p = (unsigned long)percpu_p(kernel_stack);
    unsigned char *p_end;

    rdmsrl(MSR_LSTAR, result);
    p = (unsigned char *)result;
#ifndef NDEBUG
    ptr = p;
#define OOPS(msg) { \
    int i;                                                                \
    ci_log(msg);                                                          \
    for (i = 0; i < 10; i++) {                                             \
      ci_log("system_call + %d*4: %02x %02x %02x %02x", i,                \
             ptr[i * 4], ptr[i * 4 + 1], ptr[i * 4 + 2], ptr[i * 4 + 3]); \
    }                                                                     \
    ci_assert(0);                                                         \
  }
#else
#define OOPS(msg) { ci_log(msg); return NULL;}
#endif
    if (p[0] != 0x0f || p[1] != 0x01 || p[2] != 0xf8) {
      OOPS("Unexpected code at the beginning of system_call(), "
           "can't trampoline.");
    }
    p += 3;
    p_end = p + 32;
    while (p[0] != 0x65 || p[1] != 0x48 || p[2] != 0x89 ||
           p[3] != 0x24 || p[4] != 0x25) {
      p++;
      if (p >= p_end) {
        OOPS("Unexpected code in system_call(), can't trampoline.\n"
             "Can't find movq %%rsp,PER_CPU_VAR(old_rsp)");
      }
    }
    p += 5;
    result = p[0] + (p[1] << 8);
    p +=2;
    while (*p == 0)
      p++;
    if (p[0] != 0x65 || p[1] != 0x48 || p[2] != 0x8b ||
        p[3] != 0x24 || p[4] != 0x25 ||
        p[5] != (kernel_stack_p & 0xff) || p[6] != (kernel_stack_p >> 8)) {
      OOPS("Unexpected code in system_call(), can't trampoline.\n"
           "Expecting movq PER_CPU_VAR(kernel_stack),%%rsp");
    }
    TRAMP_DEBUG("&per_cpu__old_rsp=%08lx", result);

#undef OOPS

    oldrsp_addr = (unsigned long *)result;
  }
  return oldrsp_addr;
}
#endif

/* Avoid returning to UL via short-path sysret.  The problem exists at
 * least on RHEL4 2.6.9 64-bit kernel + 32-bit UL.  Previously, we've done
 * it with TIF_IRET flag.  The problem is, TIF_IRET is not supposed to be
 * set for x86_64 kernel, so nobody clear it.   As a result, we have
 * performance degradation at best (all syscalls go via long path iret),
 * and various bugs in some cases (bug 19262).  So, we set TIF_NEED_RESCHED
 * flag, which is guaranteed to be handled in any kernel.  We do not really
 * need to be rescheduled, but we need to avoid the fast sysret path. */
ci_inline void
avoid_sysret(void)
{
  set_thread_flag (TIF_NEED_RESCHED);
}

/* This function will munge the stack ready for trampoline into the calling
 * process.  Note that it doesn't actually perform the trampoline immediately
 * -- this won't happen until the system-call returns.
 * regs must point to the stack-frame pushed at sys-call entry (this can be
 * found on x86 by taking the address of a system-call's first parameter).
 * The value of the "data" param will be passed to the trampoline handler in a
 * register (edx on x86).
 * The trampoline handler will be entered with the original system-call's
 * return address in another g/p reg (ecx on x86)
 */
static int
setup_trampoline (struct pt_regs *regs, int opcode, int data) {
  struct mm_hash *p;
  ci_uintptr_t trampoline_entry = 0;
  ci_uintptr_t trampoline_exclude = 0;
  int rc;

  read_lock (&oo_mm_tbl_lock);
  p = oo_mm_tbl_lookup(current->mm);
  if (p) {
    trampoline_entry = (ci_uintptr_t) CI_USER_PTR_GET (p->trampoline_entry);
    trampoline_exclude = (ci_uintptr_t) CI_USER_PTR_GET (p->trampoline_exclude);
  }
  read_unlock (&oo_mm_tbl_lock);

  if (trampoline_entry) {
    unsigned long *user_sp =0;

    /* Found the relevant mm -- trampoline to user-space.  To do so we
     * hack the return address on the stack.
     */
    if (!access_ok (VERIFY_READ, trampoline_entry, 1)) {
      /* We can't trampoline to this address.  The user may have changed his
       * address space, or supplied a bad trampoline-entry at registration time
       * -- so fail gracefully
       */
      ci_log ("Pid %d (mm=%p) has bad trampoline entry: 0x%08lX",
              current->tgid, current->mm, (unsigned long)trampoline_entry);
      return -EBADF;
    }

    /* It's one of our's.  We would normally have expected to intercept
     * this call from the user-library; trampoling by hacking stack.
     * We verify the stack is as we expect first.
     */

#if defined(__x86__)
    ci_assert (sizeof *user_sp == 4);

    if (cs(regs) != __USER_CS) {
      ci_log ("Warning: trampoline-handler called not from kernel code!");
# ifndef NDEBUG
      ci_log ("This is a debug-build driver, so I'm going to fail here!");
      ci_assert (0);
# endif
      return -EINVAL;
    }
        
    /* Can't verify ip with access_ok() -- it often points at 0xffffe002
     * (i.e. the vsyscall-page)
     */
    TRAMP_DEBUG("setup_trampoline:");
    TRAMP_DEBUG("  bx %08lx", bx(regs));
    TRAMP_DEBUG("  cx %08lx", cx(regs));
    TRAMP_DEBUG("  dx %08lx", dx(regs));
    TRAMP_DEBUG("  si %08lx", si(regs));
    TRAMP_DEBUG("  di %08lx", di(regs));
    TRAMP_DEBUG("  bp %08lx", bp(regs));
    TRAMP_DEBUG("  ax %08lx", ax(regs));
    TRAMP_DEBUG("  ds %08x", ds(regs));
    TRAMP_DEBUG("  es %08x", es(regs));
    TRAMP_DEBUG("  orig_ax %08lx", orig_ax(regs));
    TRAMP_DEBUG("  ip %08lx", ip(regs));
    TRAMP_DEBUG("  cs %08x", cs(regs));
    TRAMP_DEBUG("  flags %08lx", flags(regs));
    TRAMP_DEBUG("  sp %08lx", sp(regs));
    TRAMP_DEBUG("  ss %08x", ss(regs));

    if (ip(regs) == trampoline_exclude) {
      TRAMP_DEBUG("Ignoring call from excluded address 0x%08lx",
                  (unsigned long)trampoline_exclude);
      return -EBUSY;
    }

    /* The little stub in user-mode needs the opcode and data on the user-mode
     * stack (originally we passed these in registers, ecx and edx, but this
     * doesn't work in the case of a 32-bit app on a 64-bit machine calling a
     * system call via the SYSCALL instruction, as used in 2.6 kernels).  The
     * trampoline handler function may trash ecx and edx (which are scratch
     * registers for x86 functions, but NOT for system calls), so we also push
     * the original contents of these registers after we push the return
     * address onto the user-mode stack.
     *
     * First we ensure there is sufficient user-space stack
     */
    if (!access_ok (VERIFY_WRITE, sp(reg) - 20, 20)) {
      ci_log ("Bogus user-mode stack; cannot trampoline!");
      return -EFAULT;
    }
    user_sp = (unsigned long*)sp(reg);
    user_sp--;
    if (copy_to_user (user_sp, &ip(regs), 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &cx(regs), 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &dx(regs), 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &data, 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &opcode, 4) != 0)  return -EFAULT;

    /* Hack registers so they're restored to state expected by tramp handler */
    sp(regs) = (ci_uintptr_t) user_sp;

    /* Hack the return address on the stack to do the trampoline */
    ip(regs) = trampoline_entry;

    avoid_sysret();
    TRAMP_DEBUG("set tramp entry 0x%08lx", (unsigned long)trampoline_entry);


#elif defined(__i386__)

    ci_assert (sizeof *user_sp == 4);

    if (cs(regs) != __USER_CS) {

      ci_log ("Warning: trampoline-handler called not from kernel code!");
# ifndef NDEBUG
      ci_log ("This is a debug-build driver, so I'm going to fail here!");
      ci_assert (0);
# endif
      return -EINVAL;
    }
        
    /* Can't verify ip with access_ok() -- it often points at 0xffffe002
     * (i.e. the vsyscall-page)
     * XXX casts to unsigned long were added to avoid warnings -- 2.6.18
     * and 2.6.30 has different types for these values.
     */
    TRAMP_DEBUG("setup_trampoline:");
    TRAMP_DEBUG("  bx %08lx", bx(regs));
    TRAMP_DEBUG("  cx %08lx", cx(regs));
    TRAMP_DEBUG("  dx %08lx", dx(regs));
    TRAMP_DEBUG("  si %08lx", si(regs));
    TRAMP_DEBUG("  di %08lx", di(regs));
    TRAMP_DEBUG("  bp %08lx", bp(regs));
    TRAMP_DEBUG("  ax %08lx", ax(regs));
    TRAMP_DEBUG("  ds %08lx", (unsigned long)ds(regs));
    TRAMP_DEBUG("  es %08lx", (unsigned long)es(regs));
    TRAMP_DEBUG("  orig_ax %08lx", orig_ax(regs));
    TRAMP_DEBUG("  ip %08lx", ip(regs));
    TRAMP_DEBUG("  cs %08lx", (unsigned long)cs(regs));
    TRAMP_DEBUG("  flags %08lx", flags(regs));
    TRAMP_DEBUG("  sp %08lx", sp(regs));
    TRAMP_DEBUG("  ss %08lx", (unsigned long)ss(regs));

    if (ip(regs) == trampoline_exclude) {
      TRAMP_DEBUG("Ignoring call from excluded address 0x%08lx",
                  (unsigned long)trampoline_exclude);
      return -EBUSY;
    }

    /* The little stub in user-mode needs the opcode and data on the user-mode
     * stack (originally we passed these in registers, ecx and edx, but this
     * doesn't work in the case of a 32-bit app on a 64-bit machine calling a
     * system call via the SYSCALL instruction, as used in 2.6 kernels).  The
     * trampoline handler function may trash ecx and edx (which are scratch
     * registers for x86 functions, but NOT for system calls), so we also push
     * the original contents of these registers after we push the return
     * address onto the user-mode stack.
     *
     * First we ensure there is sufficient user-space stack
     */
    if (!access_ok (VERIFY_WRITE, sp(regs) - 20, 20)) {
      ci_log ("Bogus user-mode stack; cannot trampoline!");
      return -EFAULT;
    }
    user_sp = (unsigned long*)sp(regs);
    user_sp--;
    if (copy_to_user (user_sp, &ip(regs), 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &cx(regs), 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &dx(regs), 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &data, 4) != 0)  return -EFAULT;
    user_sp--;
    if (copy_to_user (user_sp, &opcode, 4) != 0)  return -EFAULT;

    /* Hack registers so they're restored to state expected by tramp handler */
    sp(regs) = (ci_uintptr_t) user_sp;

    /* Hack the return address on the stack to do the trampoline */
    ip(regs) = trampoline_entry;

    avoid_sysret();
    TRAMP_DEBUG("set tramp entry 0x%08lx", (unsigned long)trampoline_entry);

#elif defined(__x86_64__)

    /* There probably isn't any useful verification we can do here...
     * The good news is that on x86_64 it is impossible to issue a system-call
     * from supervisor mode (unlike IA32), and so calls to 'close' from the
     * kernel don't go via the system-call table.  The bad news is that it is
     * still theoretically possible to call via the system-call table, in which
     * case all kinds of badness is liable to happen -- TODO: Is there any way
     * to verify we're called from user-mode on x86_64?
     */

    TRAMP_DEBUG("setup_trampoline:");
    /* Only a partial pt_regs stack frame is set up -- these are missing: */
    TRAMP_DEBUG("  r15 %016lx XX",regs->r15); /* not saved by syscall entry */
    TRAMP_DEBUG("  r14 %016lx XX",regs->r14); /* not saved by syscall entry */
    TRAMP_DEBUG("  r13 %016lx XX",regs->r13); /* not saved by syscall entry */
    TRAMP_DEBUG("  r12 %016lx XX",regs->r12); /* not saved by syscall entry */
    TRAMP_DEBUG("  bp %016lx XX", bp(regs)); /* not saved by syscall entry */
    TRAMP_DEBUG("  bx %016lx XX", bx(regs)); /* not saved by syscall entry */
    /* These are always present: */
    TRAMP_DEBUG("  r11 %016lx",regs->r11);
    TRAMP_DEBUG("  r10 %016lx",regs->r10);
    TRAMP_DEBUG("  r9  %016lx",regs->r9);
    TRAMP_DEBUG("  r8  %016lx",regs->r8);
    TRAMP_DEBUG("  ax %016lx", ax(regs));
    TRAMP_DEBUG("  cx %016lx", cx(regs));
    TRAMP_DEBUG("  dx %016lx", dx(regs));
    TRAMP_DEBUG("  si %016lx", si(regs));
    TRAMP_DEBUG("  di %016lx", di(regs));
    TRAMP_DEBUG("  orig_ax %016lx", orig_ax(regs));
    TRAMP_DEBUG("  ip %016lx", ip(regs));
    /* Not always present but may be fixed up on syscall handler slow paths: */
    TRAMP_DEBUG("  cs  %016lx XX",regs->cs);
    TRAMP_DEBUG("  flags %016lx XX", flags(regs));
    TRAMP_DEBUG("  rsp %016lx XX", sp(regs));
    TRAMP_DEBUG("  ss  %016lx XX",regs->ss);

    if (ip(regs) == trampoline_exclude) {
      TRAMP_DEBUG("Ignoring call from excluded address");
      return -EBUSY;
    }

    /* We need to get data back to the user-mode stub handler.  Specifically
     * -- the real return address, the op-code, and the "data" field (eg.
     * file-descriptor for close).  We do this by corrupting the registers that
     * are saved on the stack, so when we trampoline back the trampoline has
     * these values in its regs as expected.  However, note that the trampoline
     * handler must not trash ANY registers, since Linux system-calls don't.
     * Therefore, we save the original values of the registers on the user-mode
     * stack, to allow the trampoline stub to restore register state before
     * returning to whoever called the syscall in the first place.
     *
     * On Linux x86_64 the old user-sp is stored in the per-cpu variable
     * oldrsp.
     */
    {
      unsigned long *orig_user_sp;
#if OLD_RSP_PROVIDED
      orig_user_sp = (unsigned long *)read_pda(oldrsp);
#else
      orig_user_sp = (unsigned long *)percpu_read_from_p(get_oldrsp_addr());
#endif

      user_sp = orig_user_sp;
      TRAMP_DEBUG("read user_sp=%p", user_sp);

      /* Make sure there is sufficient user-space stack */
      if (!access_ok (VERIFY_WRITE, user_sp - 24, 24)) {
        ci_log ("Invalid user-space stack-pointer; cannot trampoline!");
        return -EFAULT;
      }

      ci_assert (sizeof *user_sp == 8);

      user_sp--;
      /* Return address */
      if (copy_to_user (user_sp, &ip(regs), 8) != 0)  return -EFAULT;
      user_sp--;
      /* %rdi will be trashed by opcode */
      if (copy_to_user (user_sp, &di(regs), 8) != 0)  return -EFAULT;
      user_sp--;
      /* %rsi will be trashed by data */
      if (copy_to_user (user_sp, &si(regs), 8) != 0)  return -EFAULT;

      /* Write the updated rsp */
#if OLD_RSP_PROVIDED
      write_pda(oldrsp, (unsigned long)user_sp);
#else
      percpu_write_to_p(get_oldrsp_addr(), (unsigned long)user_sp);
#endif
      TRAMP_DEBUG("wrote user_sp=%p", user_sp);

      /* On some slow paths through the syscall code (e.g. when ptracing) the
       * top of the stack frame gets fixed up, and the rsp there may get copied
       * back to the pda oldrsp field on exit from the syscall.  So, if we find
       * the original rsp in the rsp field on the stack, we need to update that
       * too.
       */
      if (sp(regs) == (unsigned long)orig_user_sp) {
        sp(regs) = (unsigned long)user_sp;
        TRAMP_DEBUG("wrote sp=%p as well", user_sp);
      }
    }

    /* The little stub in user-mode expects the fd to close in rsi, and
     * the original return address (so that it can get back) in rdx.  We've
     * saved away the original values of these regs on the user stack so that
     * the trampoline stub may restore the state before returning to whoever
     * made the system-call.
     */
    di(regs) = opcode;
    si(regs) = data;

    /* Hack the return address on the stack to do the trampoline */
    ip(regs) = trampoline_entry;

    TRAMP_DEBUG("set tramp entry %016lx", (unsigned long) trampoline_entry);


#elif defined(__ia64__)
  /* trampoline not support in ia64 */
  if (trampoline_entry)
   {
     user_sp = 0;
     TRAMP_DEBUG("set tramp entry %016lx", trampoline_entry);
   }

#else
#error "Don't know how to support trampolines on this architecture"
#endif

    rc = 0;
  }
  else {
    /* Attempt to trampoline for a process not using our stack */
    OO_DEBUG_VERB(ci_log("Error -- attempt to trampoline for unknown process"));
    rc = -ENOENT;
  }
  
  return rc;
}

 
/* This is the main body of our hacked version of the close system call (but we
 * are actually called by a wrapper which sets up the "regs" argument).  Since
 * we've hacked the system call table, then all close system calls will come
 * via this wrapper.  If appropriate, the call will be trampolined back to user
 * space, to our library's close which _should_ have intercepted.
 */
asmlinkage long
efab_linux_trampoline_handler_close (int fd, struct pt_regs *regs, void *ret) {
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
      if (setup_trampoline (regs, CI_TRAMP_OPCODE_CLOSE, fd) == 0) {
        /* The trampoline will get run.  Let it handle the rest. */
        fput (f);
        efab_syscall_exit();
        return 0;
      }
    }
    /* Undo the fget above */
    fput (f);
  }

  /* Not one of our FDs -- usual close */
  rc = (saved_sys_close) (fd);
  efab_syscall_exit();
  return rc;
}


#ifdef CONFIG_COMPAT

/* In order to support 32-bit apps running in compatibility mode, we need a
 * hybrid of the i386 and x86_64 trampoline setup code.  The struct pt_regs on
 * the stack appear as for the x86_64 code (with a few extra registers at the
 * end, as we are called from an interrupt rather than a SYSCALL instruction);
 * but the userland side looks like i386, so the stack contains 32-bit words
 * and the parameters must be passed on the stack, not in registers.
 */
static int
setup_trampoline32 (struct pt_regs *regs, int opcode, int data) {

  struct mm_hash *p;
  ci_uintptr_t trampoline_entry = 0;
  ci_uintptr_t trampoline_exclude = 0;
  int rc;

  read_lock (&oo_mm_tbl_lock);
  p = oo_mm_tbl_lookup(current->mm);
  if (p) {
    trampoline_entry = (ci_uintptr_t) CI_USER_PTR_GET (p->trampoline_entry);
    trampoline_exclude =  (ci_uintptr_t) CI_USER_PTR_GET (p->trampoline_exclude);
  }
  read_unlock (&oo_mm_tbl_lock);

  if (trampoline_entry) {
    unsigned int *user32_sp;

    /* Found the relevant mm -- trampoline to user-space.  To do do we
     * hack the return address on the stack.
     */
    if (!access_ok (VERIFY_READ, trampoline_entry, 1)) {
      /* We can't trampoline to this address.  The user may have changed his
       * address space, or supplied a bad trampoline-entry at registration time
       * -- so fail gracefully
       */
      ci_log ("Warning: pid %d has bad trampoline entry: 0x%08lx",
              current->tgid, (unsigned long)trampoline_entry);
      return -EBADF;
    }

    /* It's one of our's.  We would normally have expected to intercept
     * this call from the user-library; trampoling by hacking stack.
     * We verify the stack is as we expect first.
     */

    ci_assert (sizeof *user32_sp == 4);

    if (cs(regs) != __USER32_CS) {

      /* We couldn't check this for the 64-bit syscall, but we *can* do this
       * check here, because we get extra stuff on the stack due to coming from
       * an interrupt.
       */
      ci_log ("Warning: 32-bit trampoline-handler called unexpectedly (%016lx)",
              cs(regs));
#ifndef NDEBUG
      ci_log ("This is a debug-build driver, so I'm going to fail here!");
      ci_assert (0);
#endif
      return -EINVAL;
    }
        
    TRAMP_DEBUG("setup_trampoline32:");
    TRAMP_DEBUG("  r15 %016lx XX",regs->r15);
    TRAMP_DEBUG("  r14 %016lx XX",regs->r14);
    TRAMP_DEBUG("  r13 %016lx XX",regs->r13);
    TRAMP_DEBUG("  r12 %016lx XX",regs->r12);
    TRAMP_DEBUG("  bp %016lx XX", bp(regs));
    TRAMP_DEBUG("  bx %016lx XX", bx(regs));
    TRAMP_DEBUG("  r11 %016lx",regs->r11);
    TRAMP_DEBUG("  r10 %016lx",regs->r10);
    TRAMP_DEBUG("  r9  %016lx",regs->r9);
    TRAMP_DEBUG("  r8  %016lx",regs->r8);
    TRAMP_DEBUG("  ax %016lx", ax(regs));
    TRAMP_DEBUG("  cx %016lx", cx(regs));
    TRAMP_DEBUG("  dx %016lx", dx(regs));
    TRAMP_DEBUG("  si %016lx", si(regs));
    TRAMP_DEBUG("  di %016lx", di(regs));
    TRAMP_DEBUG("  orig_ax %016lx", orig_ax(regs));
    TRAMP_DEBUG("  ip %016lx", ip(regs));
    /* Extra context from entry via interrupt: */
    TRAMP_DEBUG("  cs  %016lx",regs->cs);
    TRAMP_DEBUG("  flags %016lx", flags(regs)); 
    TRAMP_DEBUG("  sp %016lx", sp(regs));
    TRAMP_DEBUG("  ss  %016lx",regs->ss);

    if (ip(regs) == trampoline_exclude) {
      TRAMP_DEBUG("Ignoring call from excluded address");
      return -EBUSY;
    }
    /* The little stub in user-mode needs the opcode and data on the user-mode
     * stack (originally we passed these in registers, ecx and edx, but this
     * doesn't work in the case of a 32-bit app on a 64-bit machine calling a
     * system call via the SYSCALL instruction, as used in 2.6 kernels).  The
     * trampoline handler function may trash ecx and edx (which are scratch
     * registers for x86 functions, but NOT for system calls), so we also push
     * the original contents of these registers after we push the return
     * address onto the user-mode stack.
     *
     * First we ensure there is sufficient user-space stack
     */
    if (!access_ok (VERIFY_WRITE, sp(regs) - 20, 20)) {
      ci_log ("Bogus 32-bit user-mode stack; cannot trampoline!");
      return -EFAULT;
    }
    user32_sp = (unsigned int*)sp(regs);
    user32_sp--;
    if (copy_to_user (user32_sp, &ip(regs), 4) != 0)  return -EFAULT;
    user32_sp--;
    if (copy_to_user (user32_sp, &cx(regs), 4) != 0)  return -EFAULT;
    user32_sp--;
    if (copy_to_user (user32_sp, &dx(regs), 4) != 0)  return -EFAULT;
    user32_sp--;
    if (copy_to_user (user32_sp, &data, 4) != 0)  return -EFAULT;
    user32_sp--;
    if (copy_to_user (user32_sp, &opcode, 4) != 0)  return -EFAULT;

    /* Hack registers so they're restored to state expected by tramp handler */
    sp(regs) = (ci_uintptr_t) user32_sp;

    /* Hack the return address on the stack to do the trampoline */
    ip(regs) = trampoline_entry;

    TRAMP_DEBUG("set tramp entry 0x%08lx", (unsigned long)trampoline_entry);
    avoid_sysret();
    rc = 0;
  }
  else {
    /* Attempt to trampoline for a process not using our stack */
    OO_DEBUG_VERB(ci_log("Error -- attempt to trampoline for unknown process"));
    rc = -ENOENT;
  }
  
  return rc;
}


asmlinkage int
efab_linux_trampoline_handler_close32(int fd, struct pt_regs *regs, void *ret) {
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
      if (setup_trampoline32 (regs, CI_TRAMP_OPCODE_CLOSE, fd) == 0) {
        fput (f);
        efab_syscall_exit();
        return 0;
      }
    }
    /* Undo the fget above */
    fput (f);
  }

  /* Not one of our FDs -- usual close */
  rc = (saved_sys_close) (fd);
  efab_syscall_exit();
  return rc;
}

#endif

#ifdef OO_DO_HUGE_PAGES
#include <linux/unistd.h>
asmlinkage int efab_linux_sys_shmget(key_t key, size_t size, int shmflg)
{
  asmlinkage int (*sys_shmget_fn)(key_t, size_t, int);
  int rc;

  ci_assert(syscall_table);

  sys_shmget_fn = syscall_table[__NR_shmget];
  TRAMP_DEBUG ("shmget(%d,%d,%d) via %p...", key, size, shmflg,
               sys_shmget_fn);
  rc = sys_shmget_fn(key, size, shmflg);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage long efab_linux_sys_shmat(int shmid, char __user *addr, int shmflg)
{
  asmlinkage long (*sys_shmat_fn)(int, char __user *, int);
  long rc;

  ci_assert(syscall_table);

  sys_shmat_fn = syscall_table[__NR_shmat];
  TRAMP_DEBUG ("shmat(%d,%p,%d) via %p...", shmid, addr, shmflg,
               sys_shmat_fn);
  rc = sys_shmat_fn(shmid, addr, shmflg);
  TRAMP_DEBUG ("... = %p", rc);
  return rc;
}
asmlinkage int efab_linux_sys_shmdt(char __user *addr)
{
  asmlinkage int (*sys_shmdt_fn)(char __user *);
  int rc;

  ci_assert(syscall_table);

  sys_shmdt_fn = syscall_table[__NR_shmdt];
  TRAMP_DEBUG ("shmdt(%p) via %p...", addr, sys_shmdt_fn);
  rc = sys_shmdt_fn(addr);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage int efab_linux_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  asmlinkage int (*sys_shmctl_fn)(int, int, struct shmid_ds __user *);
  int rc;

  ci_assert(syscall_table);

  sys_shmctl_fn = syscall_table[__NR_shmctl];
  TRAMP_DEBUG ("shmdt(%p) via %p...", shmid, cmd, buf, sys_shmctl_fn);
  rc = sys_shmctl_fn(shmid, cmd, buf);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif


/* This function abstracts writing to the syscall.  Sadly some later kernels
 * map the syscall tables read-only.  Fidling with permissions is tricky, so we
 * just kmap ourselves a new mapping onto the table.
 */
static void
patch_syscall_table (void **table, unsigned entry, void *func,
                     void* prev_func)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
  void *mapped;
  void **loc = table + entry;
  ci_uintptr_t offs = ((ci_uintptr_t)loc) & (PAGE_SIZE-1);
  struct page *pg;

#ifdef __x86_64__
  if( NEED_SYSCALL_MAPPING_HACK() ) {
    unsigned pfn = ((unsigned long) loc - __START_KERNEL_map) >> PAGE_SHIFT;
    pfn += 0x200;  /* magic! adjust by 2MB */
    TRAMP_DEBUG ("%s: pfn is %u", __FUNCTION__, pfn);
    pg = pfn_to_page(pfn);
    TRAMP_DEBUG ("%s: pg for pfn %u is %p", __FUNCTION__, pfn, pg);
  }
  else
#endif
    pg = virt_to_page (loc);

  TRAMP_DEBUG ("calling vmap (%p, 1, VM_MAP, PAGE_KERNEL)", pg);
  mapped = vmap (&pg, 1, VM_MAP, PAGE_KERNEL);
  TRAMP_DEBUG ("%s: mapped to %p", __FUNCTION__, mapped);
  if (mapped == NULL) {
    ci_log ("ERROR: could not map syscall table -- there will be no trampolining");
    return;
  }

  loc = (void**) ((ci_uintptr_t) mapped + offs);
  if( *loc == prev_func ) {
    TRAMP_DEBUG ("%s: writing to %p", __FUNCTION__, loc);
    *loc = func;
  }
  else
    ci_log("ERROR: Did not patch syscall table (*loc=%p prev_func=%p)",
           *loc, prev_func);

  TRAMP_DEBUG ("%s: unmapping", __FUNCTION__);
  vunmap (mapped);
  TRAMP_DEBUG ("%s: all done", __FUNCTION__);

#else
  /* vmap not available on earlier kernels, but they don't protect the syscall
   * table against writing, so "just do it" (tm)
   */
  table [entry] = func;
#endif
}


/* This function initializes the mm hash-table, and hacks the sys call table
 * so that we intercept close.
 */
int efab_linux_trampoline_ctor(int no_sct)
{
  syscall_table = find_syscall_table();

  atomic_set(&efab_syscall_used, 0);
  if (syscall_table) {
    /* We really have to hope that syscall_table was found correctly.  There
     * is no reliable way to check it (e.g. by looking at the contents) which
     * will work on all platforms...
     */
    TRAMP_DEBUG("syscall_table=%p: close=%p exit_group=%p, rt_sigaction=%p",
                syscall_table, syscall_table[__NR_close],
                syscall_table[__NR_exit_group],
                syscall_table[__NR_rt_sigaction]);

#ifdef OO_CAN_HANDLE_TERMINATION
    efab_linux_termination_ctor();
#endif

    saved_sys_close = syscall_table [__NR_close];
    ci_assert(saved_sys_close == (void *)sys_close);
    saved_sys_exit_group = syscall_table [__NR_exit_group];
    saved_sys_rt_sigaction = syscall_table [__NR_rt_sigaction];

    ci_mb();
    if (no_sct) {
      TRAMP_DEBUG("syscalls NOT hooked - no_sct requested");
    } else {
      patch_syscall_table (syscall_table, __NR_close,
                           efab_linux_trampoline_close, saved_sys_close);
      if( safe_signals_and_exit ) {
#ifdef OO_CAN_HANDLE_TERMINATION
        patch_syscall_table (syscall_table, __NR_exit_group,
                             efab_linux_trampoline_exit_group,
                             saved_sys_exit_group);
#endif
        patch_syscall_table (syscall_table, __NR_rt_sigaction,
                             efab_linux_trampoline_sigaction,
                             saved_sys_rt_sigaction);
      }
      TRAMP_DEBUG("syscalls hooked: close=%p exit_group=%p, rt_sigaction=%p",
                  syscall_table[__NR_close], syscall_table[__NR_exit_group],
                  syscall_table[__NR_rt_sigaction]);
    }
  } else {
    /* syscall_table wasn't found, so we may have no way to sys_close()... */
    TRAMP_DEBUG("warning: syscall table not found - can't read sys_close");
    return 0;
  }

#ifdef CONFIG_COMPAT

  ia32_syscall_table = find_ia32_syscall_table();

  if (ia32_syscall_table && !no_sct) {
    /* We can do a sanity check on the ia32_syscall_table value: sys_close is
     * the same for both 64-bit and 32-bit, so the current entry for sys_close
     * in the 32-bit table should match the original value from the 64-bit
     * table, which we've saved in saved_sys_close in the code above.
     */
    TRAMP_DEBUG("ia32_syscall_table=%p: close=%p, exit_group=%p, "
                "rt_sigaction=%p", ia32_syscall_table,
                ia32_syscall_table[__NR_ia32_close],
                ia32_syscall_table[__NR_ia32_exit_group],
                ia32_syscall_table[__NR_ia32_rt_sigaction]);
    saved_sys_rt_sigaction32 = ia32_syscall_table[__NR_ia32_rt_sigaction];
    ci_mb();

    if (ia32_syscall_table[__NR_ia32_close] == saved_sys_close) {
      patch_syscall_table (ia32_syscall_table, __NR_ia32_close,
                           efab_linux_trampoline_close32, saved_sys_close);
    } else {
      TRAMP_DEBUG("expected ia32 sys_close=%p, but got %p", saved_sys_close,
                  ia32_syscall_table[__NR_ia32_close]);
      ci_log("ia32 close syscall NOT hooked");
    }
    if( safe_signals_and_exit &&
        ia32_syscall_table[__NR_ia32_exit_group] == saved_sys_exit_group) {
      ci_assert_equal(ia32_syscall_table[__NR_ia32_exit_group],
                      saved_sys_exit_group);
#ifdef OO_CAN_HANDLE_TERMINATION
      patch_syscall_table (ia32_syscall_table, __NR_ia32_exit_group,
                           efab_linux_trampoline_exit_group,
                           saved_sys_exit_group);
#endif
      patch_syscall_table (ia32_syscall_table, __NR_ia32_rt_sigaction,
                           efab_linux_trampoline_sigaction32,
                           saved_sys_rt_sigaction32);
    } else {
      TRAMP_DEBUG("expected ia32 sys_exit_group=%p, but got %p",
                  saved_sys_exit_group,
                  ia32_syscall_table[__NR_ia32_exit_group]);
      ci_log("ia32 exit_group syscall NOT hooked");
    }
    TRAMP_DEBUG("ia32 syscalls hooked: close=%p, exit_group=%p, "
                "rt_sigaction=%p",
                ia32_syscall_table[__NR_ia32_close],
                ia32_syscall_table[__NR_ia32_exit_group],
                ia32_syscall_table[__NR_ia32_rt_sigaction]);
  } else {
    /* ia32_syscall_table wasn't found - can't trampoline for 32-bit apps */
    TRAMP_DEBUG("warning: ia32 syscall table not found");
  }
#endif

  return 0;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
#define synchronize_sched synchronize_kernel
#endif
int
efab_linux_trampoline_dtor (int no_sct) {
  if (syscall_table != NULL && !no_sct) {
    int waiting = 0;

    /* Restore the system-call table to its proper state */
    patch_syscall_table (syscall_table, __NR_close, saved_sys_close,
                         efab_linux_trampoline_close);
    if( safe_signals_and_exit ) {
#ifdef OO_CAN_HANDLE_TERMINATION
      patch_syscall_table (syscall_table, __NR_exit_group, saved_sys_exit_group,
                           efab_linux_trampoline_exit_group);
#endif
      patch_syscall_table (syscall_table, __NR_rt_sigaction,
                           saved_sys_rt_sigaction,
                           efab_linux_trampoline_sigaction);
    }
    TRAMP_DEBUG("syscalls restored: close=%p, exit_group=%p, rt_sigaction=%p",
                syscall_table[__NR_close], syscall_table[__NR_exit_group],
                syscall_table[__NR_rt_sigaction]);

    /* If anybody have already entered our syscall handlers, he should get
     * to efab_syscall_used++ now: let's wait a bit. */
    synchronize_sched();
#ifdef CONFIG_PREEMPT
    /* No guarantee, but let's try to wait */
    schedule_timeout(msecs_to_jiffies(50));
#endif
    while( atomic_read(&efab_syscall_used) ) {
      if( !waiting ) {
        ci_log("%s: Waiting for intercepted syscalls to finish...",
               __FUNCTION__);
        waiting = 1;
      }
      schedule_timeout(msecs_to_jiffies(50));
    }
    if( waiting )
      ci_log("%s: All syscalls have finished", __FUNCTION__);
    /* And now wait for exiting from syscall after efab_syscall_used-- */
    synchronize_sched();
#ifdef CONFIG_PREEMPT
    /* No guarantee, but let's try to wait */
    schedule_timeout(msecs_to_jiffies(50));
#endif
  }

#ifdef CONFIG_COMPAT
  if (ia32_syscall_table != NULL && !no_sct) {
    /* Restore the ia32 system-call table to its proper state */
    patch_syscall_table (ia32_syscall_table,  __NR_ia32_close,
                         saved_sys_close, efab_linux_trampoline_close32);
    if( safe_signals_and_exit ) {
#ifdef OO_CAN_HANDLE_TERMINATION
      patch_syscall_table (ia32_syscall_table, __NR_ia32_exit_group,
                           saved_sys_exit_group,
                           efab_linux_trampoline_exit_group);
#endif
      patch_syscall_table (ia32_syscall_table, __NR_ia32_rt_sigaction,
                           saved_sys_rt_sigaction32,
                           efab_linux_trampoline_sigaction32);
    }
    TRAMP_DEBUG("ia32 syscalls restored: close=%p, exit_group=%p, "
                "rt_sigaction=%p",
                ia32_syscall_table[__NR_ia32_close],
                ia32_syscall_table[__NR_ia32_exit_group],
                ia32_syscall_table[__NR_ia32_rt_sigaction]);
  }
#endif

  return 0;
}


int efab_linux_trampoline_debug (ci_uintptr_t *param)
{
  unsigned long op = *param;

  TRAMP_DEBUG("Trampoline debug op=%lx", op);
  (void)op;

  *param = (unsigned long)find_syscall_table();

  return 0;
}


#ifndef NDEBUG

/* Use the trampoline mechanism to cause userland to fail with a backtrace on
 * exit from this syscall.  We have to find the right place to mess around with
 * the stack, but that's easy: as long as we're executing within a system call,
 * the top of the stack page contains the struct pt_regs that we need.  (Bad
 * things will almost certainly happen if you call this function from any other
 * context!)
 */
void efab_linux_trampoline_ul_fail(void)
{
#if defined(__x86__) || defined(__i386__) || defined(__x86_64__)
  struct pt_regs *regs = ((struct pt_regs *)(sp0(&current->thread))) - 1;
#else
  struct pt_regs *regs = 0;  /* don't know how to do this on this platform */
#endif
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

#if defined(__x86__) || defined(__i386__) || defined(__x86_64__)
  ip(regs) = trampoline_ul_fail;
#else
  ci_log("(not really, don't know how on this platform)");
#endif

  return;
}

#endif /* !NDEBUG */

