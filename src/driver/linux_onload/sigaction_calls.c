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
*//*! \file sigaction_calls.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  siggaction calls via ioctl
**   \date  2011/09/05
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>

static int
efab_signal_handler_type(int sig, __sighandler_t user_handler)
{
  if( user_handler == SIG_IGN )
    return OO_SIGHANGLER_IGN_BIT;
  else if( user_handler != SIG_DFL )
    return OO_SIGHANGLER_USER;
  else if( sig_kernel_stop(sig) )
    return OO_SIGHANGLER_STOP;
  else if( sig_kernel_coredump(sig) )
    return OO_SIGHANGLER_CORE;
  else if( sig_kernel_ignore(sig) )
    return OO_SIGHANGLER_IGN_BIT;
  else
    return OO_SIGHANGLER_TERM;
}

/* Substitute signal handler by our variant. */
static int
efab_signal_substitute(int sig, struct sigaction *new_act,
                       const struct mm_signal_data *tramp_data)
{
  int rc;
  __sighandler_t handler;
  struct k_sigaction *k;
  int type;
  __user struct oo_sigaction *user_data;
  struct oo_sigaction signal_data;
  ci_int32 old_type;
  ci_int32 seq;

  user_data = &(((struct oo_sigaction *)
                 (CI_USER_PTR_GET(tramp_data->user_data)))[sig - 1]);
  if( !access_ok(VERIFY_WRITE, user_data, sizeof(struct oo_sigaction) ) )
    return -EFAULT;
  rc = __get_user(old_type, &user_data->type);
  if( rc != 0 )
    return rc;
  seq = (old_type & OO_SIGHANGLER_SEQ_MASK) + (1 << OO_SIGHANGLER_SEQ_SHIFT);

  /* We are going to change signal handler: UL should wait until we've
   * finished */
  signal_data.type = OO_SIGHANGLER_BUSY | seq;
  rc = __put_user(signal_data.type, &user_data->type);
  if( rc != 0 )
    return -EFAULT;

  spin_lock_irq(&current->sighand->siglock);
  k = &current->sighand->action[sig - 1];
  if( new_act )
    k->sa = *new_act;
  type = efab_signal_handler_type(sig, k->sa.sa_handler);
  handler = type <= OO_SIGHANGLER_DFL_MAX ? tramp_data->handlers[type] : NULL;
  BUILD_BUG_ON(SIG_DFL != NULL);

  /* We do not handle this signal: */
  if( type != OO_SIGHANGLER_USER && handler == NULL ) {
    spin_unlock_irq(&current->sighand->siglock);
    ci_verify(__put_user(old_type | OO_SIGHANGLER_IGN_BIT | seq,
                         &user_data->type) == 0);

    return 0;
  }

  OO_DEBUG_SIGNAL(ci_log("%s: change sig=%d handler %p flags %lx restorer %p",
                         __func__, sig, k->sa.sa_handler,
                         k->sa.sa_flags, k->sa.sa_restorer));
  signal_data.flags = k->sa.sa_flags;
  if( type == OO_SIGHANGLER_USER )
    CI_USER_PTR_SET(signal_data.handler, k->sa.sa_handler);
  else {
    CI_USER_PTR_SET(signal_data.handler, handler);
    k->sa.sa_flags |= SA_SIGINFO;
    if( tramp_data->sarestorer ) {
      k->sa.sa_flags |= SA_RESTORER;
      k->sa.sa_restorer = tramp_data->sarestorer;
    }
  }
  if( k->sa.sa_flags & SA_SIGINFO )
    k->sa.sa_handler = tramp_data->handler_postpone3;
  else
    k->sa.sa_handler = tramp_data->handler_postpone1;
  spin_unlock_irq(&current->sighand->siglock);

  OO_DEBUG_SIGNAL(ci_log("%s: set sig=%d handler %p flags %lx restorer %p",
                         __func__, sig, k->sa.sa_handler,
                         k->sa.sa_flags, k->sa.sa_restorer));

  /* Copy signal_data to UL; type BUSY */
  rc = __copy_to_user(user_data, &signal_data, sizeof(signal_data));
  if( rc != 0 )
    return -EFAULT;
  /* Fill in the real type */
  ci_verify(__put_user(type | seq, &user_data->type) == 0);

  return 0;
}

int efab_signal_mm_init(const ci_tramp_reg_args_t *args, struct mm_hash *p)
{
  int i;

  if( args->max_signum < _NSIG )
    return -E2BIG;

  p->signal_data.handler_postpone1 =
                    CI_USER_PTR_GET(args->signal_handler_postpone1);
  p->signal_data.handler_postpone3 =
                    CI_USER_PTR_GET(args->signal_handler_postpone3);
  p->signal_data.sarestorer = CI_USER_PTR_GET(args->signal_sarestorer);

  for( i = 0; i <= OO_SIGHANGLER_DFL_MAX; i++ )
    p->signal_data.handlers[i] = CI_USER_PTR_GET(args->signal_handlers[i]);

  p->signal_data.user_data = args->signal_data;
  p->signal_data.sa_onstack_intercept = args->sa_onstack_intercept;

  return 0;
}

void efab_signal_process_init(const struct mm_signal_data *tramp_data)
{
  int sig;

  OO_DEBUG_SIGNAL(ci_log("%s(%p) pid %d",
                         __func__, tramp_data, current->pid));

  /* At start-of-day, we intercept all already-installed handlers
   * and deadly SIG_DFL */
  for( sig = 1; sig <= _NSIG; sig++ ) {
    struct k_sigaction *k;

    /* Never, never intercept SIGKILL. You'll get deadlock since exit_group
     * sends SIGKILL to all other threads. */
    if( sig_kernel_only(sig) )
      continue;

    /* If this is our handler, do nothing.  This is second init from the
     * same process.  It happens in fork hooks, when second netif is
     * created, etc. */
    spin_lock_irq(&current->sighand->siglock);
    k = &current->sighand->action[sig - 1];
    if( k->sa.sa_handler == tramp_data->handler_postpone3 ||
        k->sa.sa_handler == tramp_data->handler_postpone1 ) {
      spin_unlock_irq(&current->sighand->siglock);
      OO_DEBUG_SIGNAL(ci_log("%s: double init pid=%d",
                             __func__, current->pid));
      break;
    }
    spin_unlock_irq(&current->sighand->siglock);

    /* Ignore any errors */
    (void) efab_signal_substitute(sig, NULL, tramp_data);
  }
}

/* Change substituted sigaction to the structure really meant by user.
 * If sa is provided, copy user sigaction data here to pass to user.
 * If sa==NULL, substitute in-place. */
static int
efab_signal_report_sigaction(int sig, struct sigaction *sa,
                             const struct mm_signal_data *tramp_data)
{
  struct oo_sigaction signal_data;
  ci_int32 type;
  __user struct oo_sigaction *user_data = &(((struct oo_sigaction *)
                   (CI_USER_PTR_GET(tramp_data->user_data)))[sig - 1]);
  int rc;
#define MAX_TRIES_BUSY 1000
  int tried_busy = 0;
  int tried_changed = 0;
  int sa_provided = (sa != NULL);

  if( !access_ok(VERIFY_WRITE, user_data, sizeof(struct oo_sigaction) ) )
    return -EFAULT;

re_read_data:
  do {
    rc = __copy_from_user(&signal_data, user_data, sizeof(signal_data));
    if( rc != 0 )
      return -EFAULT;
    tried_busy++;
  } while( (signal_data.type & OO_SIGHANGLER_TYPE_MASK) ==
           OO_SIGHANGLER_BUSY && tried_busy <= MAX_TRIES_BUSY );
  if( tried_busy > MAX_TRIES_BUSY ) {
    ci_log("%s: signal() or sigaction() runs for too long", __func__);
    return -EBUSY;
  }

report:
  spin_lock_irq(&current->sighand->siglock);
  if( sa_provided )
    *sa = current->sighand->action[sig - 1].sa;
  else
    sa = &current->sighand->action[sig-1].sa;

  if( sa->sa_handler != tramp_data->handler_postpone3 &&
      sa->sa_handler != tramp_data->handler_postpone1 ) {
    spin_unlock_irq(&current->sighand->siglock);
    return 0;
  }

  OO_DEBUG_SIGNAL(ci_log("%s: process sig=%d handler %p flags %lx restorer %p",
                         __func__, sig, sa->sa_handler,
                         sa->sa_flags, sa->sa_restorer));
  if( (signal_data.type & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_USER)
    sa->sa_handler = CI_USER_PTR_GET(signal_data.handler);
  else if( ! (signal_data.type & OO_SIGHANGLER_IGN_BIT) ) {
    sa->sa_handler = SIG_DFL;
    sa->sa_flags &= ~SA_RESTORER;
    if( ! (signal_data.flags & SA_SIGINFO) )
      sa->sa_flags &= ~SA_SIGINFO;
    sa->sa_restorer = NULL;
  }
  OO_DEBUG_SIGNAL(ci_log("%s: to user sig=%d handler %p flags %lx restorer %p",
                         __func__, sig, sa->sa_handler,
                         sa->sa_flags, sa->sa_restorer));

  spin_unlock_irq(&current->sighand->siglock);

  /* Re-check that UL have not changed signal_data. */
  type = signal_data.type;
  rc = __copy_from_user(&signal_data, user_data, sizeof(signal_data));
  if( rc != 0 )
    return rc;
  if( type != signal_data.type ) {
    tried_changed++;
    if( tried_changed > MAX_TRIES_BUSY ) {
      ci_log("%s: signal() or sigaction() called too fast", __func__);
      return -EBUSY;
    }
    if( (signal_data.type & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_BUSY ) {
      tried_busy = 0;
      goto re_read_data;
    }
    else
      goto report;
  }

  return 0;
}

void efab_signal_process_fini(const struct mm_signal_data *tramp_data)
{
  int sig;

  OO_DEBUG_SIGNAL(ci_log("%s(%p) pid %d: current->flags=%x, "
                         "tramp_data->user_data=%p", __func__,
                         tramp_data, current->pid, (int)current->flags,
                         CI_USER_PTR_GET(tramp_data->user_data)));
  /* Check if we should really do anything */
  if( current->flags & PF_EXITING )
    return; /* the process is exiting */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
  if( current->in_execve )
    return; /* in execve() */
#endif
  if( CI_USER_PTR_GET(tramp_data->user_data) == NULL )
    return; /* nothing was inited */

  OO_DEBUG_SIGNAL(ci_log("%s(%p) pid %d: uninstall interception",
                         __func__, tramp_data, current->pid));
  for( sig = 1; sig <= _NSIG; sig++ ) {
    if( sig_kernel_only(sig) )
      continue;
    if( efab_signal_report_sigaction(sig, NULL, tramp_data) != 0 )
      break;
  }
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
#define valid_signal(s) ((s) <= _NSIG)
#endif
static int
efab_signal_do_sigaction(int sig, struct sigaction *act,
                         struct sigaction *oact,
                         const struct mm_signal_data *tramp_data,
                         int *out_pass_to_kernel)
{
  int rc = 0;

  if( !valid_signal(sig) || sig < 1 || (act != NULL && sig_kernel_only(sig)) )
    return -EINVAL;


  if( oact != NULL ) {
    rc = efab_signal_report_sigaction(sig, oact, tramp_data);
    if( rc != 0 )
      return rc;
  }

  if( act != NULL ) {
    sigdelsetmask(&act->sa_mask, sigmask(SIGKILL) | sigmask(SIGSTOP));

  /* If the signal is ignored now, we should ignore all already-pending
   * signals.  Instead of doing it, pass this to OS. */
    if( act->sa_handler == SIG_IGN ||
        (act->sa_handler == SIG_DFL && sig_kernel_ignore(sig)) )
      *out_pass_to_kernel = 1;
    else if( act->sa_flags & SA_ONSTACK && !tramp_data->sa_onstack_intercept )
      *out_pass_to_kernel = 1;
    else
      rc = efab_signal_substitute(sig, act, tramp_data);
  }

  return rc;
}

static int
efab_signal_get_tramp_data(struct mm_signal_data *tramp_data)
{
  const struct mm_hash *p;

  read_lock (&oo_mm_tbl_lock);
  p = oo_mm_tbl_lookup(current->mm);
  if( p == NULL ) {
    read_unlock (&oo_mm_tbl_lock);
    return -ENOSYS;
  }
  *tramp_data = p->signal_data;
  read_unlock (&oo_mm_tbl_lock);

  if( CI_USER_PTR_GET(tramp_data->user_data) == NULL )
    return -ENOSYS;
  return 0;
}

asmlinkage long
efab_linux_trampoline_sigaction(int sig, const struct sigaction *act,
                                struct sigaction *oact, size_t sigsetsize)
{
  int rc = 0;
  struct sigaction old, new;
  struct mm_signal_data tramp_data;
  int pass_to_kernel = 0;

  efab_syscall_enter();

  if( sigsetsize != sizeof(sigset_t) ) {
    efab_syscall_exit();
    return -EINVAL;
  }

  /* Is it our process? */
  if( efab_signal_get_tramp_data(&tramp_data) ) {
    rc = efab_linux_sys_sigaction(sig, act, oact);
    efab_syscall_exit();
    return rc;
  }

  if( act != NULL ) {
    rc = copy_from_user(&new, act, sizeof(new));
    if( rc != 0 ) {
      efab_syscall_exit();
      return -EFAULT;
    }
  }

  rc = efab_signal_do_sigaction(sig, act ? &new : NULL,
                                oact ? &old : NULL, &tramp_data,
                                &pass_to_kernel);

  if( pass_to_kernel )
    efab_linux_sys_sigaction(sig, act, NULL);

  if( rc == 0 && oact != NULL ) {
    rc = copy_to_user(oact, &old, sizeof(old));
    if( rc != 0 ) {
      efab_syscall_exit();
      return -EFAULT;
    }
  }
  efab_syscall_exit();
  return rc;
}

#ifdef CONFIG_COMPAT
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{ return (u32)(unsigned long)uptr; }
#endif

asmlinkage int
efab_linux_trampoline_sigaction32(int sig, const struct sigaction32 *act32,
                                  struct sigaction32 *oact32,
                                  unsigned int sigsetsize)
{
  struct sigaction act, oact;
  compat_sigset_t set32;
  int rc;
  struct mm_signal_data tramp_data;
  int pass_to_kernel = 0;

  efab_syscall_enter();

  if( sigsetsize != sizeof(compat_sigset_t) ) {
    efab_syscall_exit();
    return -EINVAL;
  }

  /* Is it our process? */
  if( efab_signal_get_tramp_data(&tramp_data) ) {
    rc = efab_linux_sys_sigaction32(sig, act32, oact32);
    efab_syscall_exit();
    return rc;
  }

  if( act32 != NULL ) {
    compat_uptr_t handler, restorer;

    if( !access_ok(VERIFY_READ, act32, sizeof(*act32)) ||
        __get_user(handler, &act32->sa_handler) ||
        __get_user(act.sa_flags, &act32->sa_flags) ||
        __get_user(restorer, &act32->sa_restorer) ||
        __copy_from_user(&set32, &act32->sa_mask, sizeof(compat_sigset_t)) ) {
      efab_syscall_exit();
      return -EFAULT;
    }
    act.sa_handler = compat_ptr(handler);
    act.sa_restorer = compat_ptr(restorer);

    ci_assert_ge(_COMPAT_NSIG_WORDS, _NSIG_WORDS << 1);
    switch (_NSIG_WORDS) { /* Note: no break */
    case 4: act.sa_mask.sig[3] = set32.sig[6] | (((long)set32.sig[7]) << 32);
    case 3: act.sa_mask.sig[2] = set32.sig[4] | (((long)set32.sig[5]) << 32);
    case 2: act.sa_mask.sig[1] = set32.sig[2] | (((long)set32.sig[3]) << 32);
    case 1: act.sa_mask.sig[0] = set32.sig[0] | (((long)set32.sig[1]) << 32);
    }
  }

  rc = efab_signal_do_sigaction(sig, act32 ? &act : NULL,
                                oact32 ? &oact : NULL, &tramp_data,
                                &pass_to_kernel);
  if( pass_to_kernel )
    efab_linux_sys_sigaction32(sig, act32, NULL);

  if( rc == 0 && oact32 != NULL ) {
    switch (_NSIG_WORDS) { /* Note: no break */
    case 4:
      set32.sig[7] = (oact.sa_mask.sig[3] >> 32);
      set32.sig[6] = oact.sa_mask.sig[3];
    case 3:
      set32.sig[5] = (oact.sa_mask.sig[2] >> 32);
      set32.sig[4] = oact.sa_mask.sig[2];
    case 2:
      set32.sig[3] = (oact.sa_mask.sig[1] >> 32);
      set32.sig[2] = oact.sa_mask.sig[1];
    case 1:
      set32.sig[1] = (oact.sa_mask.sig[0] >> 32);
      set32.sig[0] = oact.sa_mask.sig[0];
    }

    if( !access_ok(VERIFY_WRITE, oact32, sizeof(*oact32)) ||
        __put_user(ptr_to_compat(oact.sa_handler), &oact32->sa_handler) ||
        __put_user(ptr_to_compat(oact.sa_restorer), &oact32->sa_restorer) ||
        __put_user(oact.sa_flags, &oact32->sa_flags) ||
        __copy_to_user(&oact32->sa_mask, &set32, sizeof(compat_sigset_t))) {
      efab_syscall_exit();
      return -EFAULT;
    }
  }

  efab_syscall_exit();
  return rc;
}
#endif

