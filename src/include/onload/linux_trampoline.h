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
*//*! \file linux_trampoline.h
** <L5_PRIVATE L5_HEADER >
** \author  gel,mjs
**  \brief  System call trampolines for Linux
**   \date  2005/03/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_LINUX_TRAMPOLINE_H__
#define __CI_DRIVER_EFAB_LINUX_TRAMPOLINE_H__

#include <ci/internal/transport_config_opt.h>
#include <ci/internal/trampoline.h>
#include <onload/common.h>
#include <onload/fd_private.h>



#ifndef __ci_driver__
#error "This is a driver module."
#endif

/* Count users of our syscall interceprion.  Prevent crash when close()
 * with SO_LINGER runs if Onload module is unloaded simultaneously.
 */
extern atomic_t efab_syscall_used;
static inline void efab_syscall_enter(void)
{
  atomic_inc(&efab_syscall_used);
  ci_wmb();
}
static inline void efab_syscall_exit(void)
{
  /* For non-PREEMPT kernel, we'll exit our code just after this,
   * so synchronize_sched() in unload code is safe enough. 
   * For CONFIG_PREEMPT, we'd like to preempt_disable() for the next few
   * instructions.  Unluckily, we have no way to do this. */
#ifdef CONFIG_PREEMPT
  preempt_check_resched(); /* try to be more safe: better resched now */
#endif
  atomic_dec(&efab_syscall_used);
}

extern int efab_linux_trampoline_ctor(int no_sct);
extern int efab_linux_trampoline_dtor(int no_sct);
extern int efab_linux_trampoline_register(ci_private_t *priv, void *arg);

extern asmlinkage int efab_linux_trampoline_close(int fd);
#ifdef CONFIG_COMPAT
extern asmlinkage int efab_linux_trampoline_close32(int fd);
#endif
extern asmlinkage int efab_linux_trampoline_ioctl (unsigned int fd,
                                                   unsigned int cmd,
                                                   unsigned long arg);

extern asmlinkage long efab_linux_trampoline_handler_close(int fd,
                                                           struct pt_regs *regs,
                                                           void *ret);
extern asmlinkage int efab_linux_trampoline_handler_close32(int fd,
                                                          struct pt_regs *regs,
                                                          void *ret);

extern int efab_linux_trampoline_debug(ci_uintptr_t *param);

#ifndef NDEBUG
extern void efab_linux_trampoline_ul_fail(void);
#else
#define efab_linux_trampoline_ul_fail() ((void)0)
#endif

extern int safe_signals_and_exit;
/* NB onload/ioctl.h and lib/transport/ip/signal.c copies this test */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
#define OO_CAN_HANDLE_TERMINATION
extern asmlinkage long efab_linux_trampoline_exit_group(int status);
extern void efab_linux_termination_ctor(void);
#endif

extern asmlinkage long
efab_linux_trampoline_sigaction(int sig, const struct sigaction *act,
                                struct sigaction *oact, size_t sigsetsize);
#ifdef CONFIG_COMPAT
#include <asm/ia32.h>
extern asmlinkage int
efab_linux_trampoline_sigaction32(int sig, const struct sigaction32 *act32,
                                  struct sigaction32 *oact32,
                                  unsigned int sigsetsize);
#endif


struct mm_hash;
struct mm_signal_data;
extern int efab_signal_mm_init(const ci_tramp_reg_args_t *args,
                               struct mm_hash *p);
extern void efab_signal_process_init(const struct mm_signal_data *tramp_data);
extern void efab_signal_process_fini(const struct mm_signal_data *tramp_data);
extern int efab_signal_die(ci_private_t *priv_unused, void *arg);

#endif
/*! \cidoxg_end */
