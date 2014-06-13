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
*//*! \file terminate.c exit_group() syscall substitution.
** <L5_PRIVATE L5_SOURCE>
** \author  kostik,sasha
**  \brief  Package - driver/linux_onload   Linux driver support
**   \date  2011/08/22
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 
#include <ci/internal/transport_config_opt.h>

#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_fns.h>
#include <onload/linux_onload.h>
#include <onload/linux_trampoline.h>

#ifdef OO_CAN_HANDLE_TERMINATION

/* Max number of stacks we can handle in process termination code.
 * Should not exceed 64, because we use uint64 to keep bitmap. */
#define TERMINATE_STACKS_NUM     64

#  define TERM_DEBUG(x...) (void)0

/* This is equivalent of the kernel signal_wake_up(t, 1)
 * function which is not an export symbol. Let's hope
 * it works in the same manner in all the kernels */
static inline void efab_signal_wake_up(struct task_struct* t)
{
  DECLARE_WAITQUEUE(wq, NULL);

  set_tsk_thread_flag(t, TIF_SIGPENDING);

  /* default_wake_function  is equivalent to
   * wake_up_state(t, TASK_INTERRUPTIBLE | TASK_WAKEKILL)
   * kick_process is not exported prior to 2.6.31, and there is almost
   * no way to copy it. */
  wq.private = t;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
  if( !default_wake_function(&wq, TASK_WAKEKILL | TASK_INTERRUPTIBLE, 0, NULL) )
      kick_process(t);
#else
#ifndef TASK_WAKEKILL
#define TASK_WAKEKILL (TASK_STOPPED | TASK_TRACED)
#endif
  default_wake_function(&wq, TASK_WAKEKILL | TASK_INTERRUPTIBLE, 0, NULL);
#endif
}


/* Function should act the same as zap_other_threads() kernel
 * function does. For reasons I don't understand zap_other_threads
 * is not an exported symbol.
 */
static void efab_zap_other_threads(struct task_struct *p)
{
  struct task_struct *t;

  p->signal->group_stop_count = 0;
# if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
  p->signal->flags = SIGNAL_GROUP_EXIT;
# endif
# endif

# if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
  if( thread_group_empty(p) )
    return;
# endif

  for (t = next_thread(p); t != p; t = next_thread(t)) {
    /*
     * Don't bother with already dead threads
     */
    if (t->exit_state)
      continue;

# if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,20)
    if (t != p->group_leader)
      t->exit_signal = -1;
#   endif

    sigaddset(&t->pending.signal, SIGKILL);
#   if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,14)
    rm_from_queue(SIG_KERNEL_STOP_MASK, &t->pending);
#   endif
    efab_signal_wake_up(t);
  }
}

static void (*efab_my_zap_other_threads)(struct task_struct *p);


/* Find all stacks in multithreaded application.
 * Should be used together with efab_terminate_(un)lock_all_stacks() */
static int
efab_terminate_find_all_stacks(tcp_helper_resource_t *stacks[],
                               int max_stacks_num)
{
  struct files_struct* files;
  struct fdtable* fdt;
  ci_uint32 stacks_num = 0;
  int i, j = 0;

  /* if we're single-threaded - all is fine, no need to lock stacks */
  if (thread_group_empty(current))
    return 0;

  ci_assert(max_stacks_num);
  TERM_DEBUG ("%s: pid %d", __func__, current->pid);

  files = current->files;
  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);

  for (;;) {
    unsigned long set;

    i = j * __NFDBITS;
    if( i >= fdt->max_fds )
      goto unlock;

    set = efx_get_open_fds(j++, fdt);

    while( set ) {
      if( set & 1 ) {
        struct file * file = fdt->fd[i];

        if( file && file->f_op == &oo_fops ) {
          /* it's a netif FD */
          tcp_helper_resource_t *thr;

          ci_assert(file->private_data);
          thr = ((ci_private_t* )file->private_data)->thr;
          /* skip unspecialized fds */
          if( thr != NULL ) {
            if( stacks_num == max_stacks_num ) {
              OO_DEBUG_ERR(ci_log("%s: stack count overflow", __FUNCTION__));
              goto unlock;
            }
    
            /* We already keep a ref for this thr via file, but we need
             * one more ref because other threads may close this file
             * before we'll kill them. */
            efab_thr_ref(thr);
            stacks[stacks_num++] = thr;
          }
        }
      }
      i++;
      set >>= 1;
    }
  }

unlock:
  spin_unlock(&files->file_lock);

  TERM_DEBUG ("%s: pid %d onload stacks %d", __func__, current->pid,
              stacks_num);
  return stacks_num;
}

/* Try to lock all stacks.  If can't, remove them from the stack list. */
static void
efab_terminate_lock_all_stacks(tcp_helper_resource_t *stacks[],
                               int stacks_num)
{
  int i, tries = 0, found_locked;
  ci_uint64 get_lock = 0;
  static DEFINE_MUTEX(exit_netifs_lock);

  TERM_DEBUG("%s: pid=%d, stacks_num=%d, stacks[0]=%d", __func__,
             current->pid, stacks_num, stacks[0]->id);

  /* In case of one stack, just try to get the lock for 0.5sec */
  if( stacks_num == 1 ) {
    tcp_helper_resource_t* thr = stacks[0];
    if( efab_eplock_lock_timeout(&thr->netif, msecs_to_jiffies(500))
        != 0 ) {
      OO_DEBUG_ERR(ci_log("Pid %d failed to terminate stack %d properly",
                          current->pid, thr->id));
      efab_thr_release(thr);
      stacks[0] = NULL;
    }
    ci_assert(ci_netif_is_locked(&thr->netif));
    return;
  }

  /* Maximum number of tries for all stacks is (MAX_ADD_TRIES + stacks_num).
   * I.e. we try to get lock for each stack, and after that we have 10
   * additional tries to get locks which were unavailable at the first
   * pass. */
#define MAX_ADD_TRIES 10

  ci_assert_ge(sizeof(get_lock) * 8, stacks_num);

  /* Take all netif locks.  We should not do this simultaneously
   * with other processes 
   */
  TERM_DEBUG("%s: %d get exit_netifs_lock", __FUNCTION__, current->pid);
  mutex_lock(&exit_netifs_lock);
  TERM_DEBUG("%s: %d got exit_netifs_lock", __FUNCTION__, current->pid);
  do {
    found_locked = 0;

    TERM_DEBUG("%s: %d get_lock=%llx", __FUNCTION__, current->pid, get_lock);
    for( i = 0; i < stacks_num; i++ ) {
      /* We try to get lock for 50 ms, <=64 stacks, <=74 tries: <=3.7s. */
      tcp_helper_resource_t* thr = stacks[i];
      int rc;

      if( get_lock & ((ci_uint64)1 << i) )
        continue;

      ++tries;
      TERM_DEBUG("%s: %d try to lock stack %d, tries=%d", __FUNCTION__,
                 current->pid, thr->id, tries);
      rc = efab_eplock_lock_timeout(&thr->netif, msecs_to_jiffies(50));
      if( rc != 0 ) {
        OO_DEBUG_ERR(ci_log("%s: pid %d failed to get netif lock "
                            "for stack %d (try %d/%d)", __FUNCTION__,
                            current->pid, thr->id, tries,
                            MAX_ADD_TRIES + stacks_num));
        found_locked = 1;
        if( tries >= MAX_ADD_TRIES + stacks_num ) {
          OO_DEBUG_ERR(ci_log("Pid %d failed to terminate stack %d properly",
                              current->pid, thr->id));
          efab_thr_release(thr);
          stacks[i] = NULL;
        }
      }
      else {
        ci_assert(ci_netif_is_locked(&thr->netif));
        get_lock |= (ci_uint64)1 << i;
        TERM_DEBUG("%s: %d lock stack %d", __FUNCTION__, current->pid, thr->id);
      }
    }
  } while( found_locked && tries < MAX_ADD_TRIES + stacks_num );
  TERM_DEBUG("%s: %d all stacks locked", __FUNCTION__, current->pid);
  mutex_unlock(&exit_netifs_lock);
  TERM_DEBUG("%s: %d exit_netifs_lock released", __FUNCTION__, current->pid);
}

/* Unlock all stacks */
void
efab_terminate_unlock_all_stacks(tcp_helper_resource_t *stacks[],
                                 int stacks_num)
{
  int i;

  for( i = 0; i < stacks_num; i++ ) {
    if( stacks[i] == NULL )
      continue;
    ci_netif_unlock(&stacks[i]->netif);
    TERM_DEBUG("%s: %d unlock stack %d", __func__, current->pid, stacks[i]->id);
    efab_thr_release(stacks[i]);
  }
}

/* This function should act exactly the same as the normal
 * do_group_exit() kernel function before it calls do_exit(). */
static void efab_exit_group(int *status_p)
{
  struct sighand_struct *const sighand = current->sighand;
  struct signal_struct *sig = current->signal;
  struct task_struct *tsk;
  int tries, found;

  if( (sig->flags & SIGNAL_GROUP_EXIT) || (sig->group_exit_task != NULL) )
    *status_p = sig->group_exit_code;
  else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#define TASKLIST_IS_NON_RCU
#endif
#ifdef TASKLIST_IS_NON_RCU
    read_lock(&tasklist_lock);
#endif
    spin_lock_irq(&sighand->siglock);

    if( (sig->flags & SIGNAL_GROUP_EXIT) || (sig->group_exit_task != NULL) ) {
      /* Another thread got here before we took the lock.  */
      *status_p = sig->group_exit_code;
    }
    else {
      sig->group_exit_code = *status_p;
      sig->flags = SIGNAL_GROUP_EXIT;
      efab_my_zap_other_threads(current);
    }

    spin_unlock_irq(&sighand->siglock);
#ifdef TASKLIST_IS_NON_RCU
    read_unlock(&tasklist_lock);
#endif

    /* Now we should wait for threads to receive SIGKILL and exit.
     * TODO: ideally, do something like wait_consider_task(). */
    tries = 0;
    do {
      found = 0;

      tsk = current;
#ifdef TASKLIST_IS_NON_RCU
      read_lock(&tasklist_lock);
#endif
      while_each_thread(current, tsk) {
        if( tsk->exit_code == 0 ) {
          found = 1;
          break;
        }
      }
#ifdef TASKLIST_IS_NON_RCU
      read_unlock(&tasklist_lock);
#endif

      /* timeout=1 shows much better results than just shedule()
       * since we free CPU for some time and the thread is able to
       * process SIGKILL. */
      if( found )
        schedule_timeout_uninterruptible(1);

      tries++;
    } while (found && tries < HZ/2);
    TERM_DEBUG("found=%d tries=%d", found, tries);
  }
}


asmlinkage long
efab_linux_trampoline_exit_group(int status)
{
  tcp_helper_resource_t *stacks[TERMINATE_STACKS_NUM];
  ci_uint32 stacks_num = 0;

  efab_syscall_enter();

  BUILD_BUG_ON(sizeof(ci_uint64) * 8 < TERMINATE_STACKS_NUM);
  stacks_num = efab_terminate_find_all_stacks(stacks, TERMINATE_STACKS_NUM);

  /* die in the most appropriate way */
  if( stacks_num ) {
    /* lock all the stacks */
    efab_terminate_lock_all_stacks(stacks, stacks_num);
    /* Kill all threads while they do not have netif locks (we have them!).
     * Change status: see exit_group() for details. */
    status = (status & 0xff) << 8;
    efab_exit_group(&status);
    /* now when everybody is dead we can release netifs */
    efab_terminate_unlock_all_stacks(stacks, stacks_num);

    /* really exit */
    efab_syscall_exit();
    do_exit(status);

    /*UNREACHABLE*/
    return 0;
  }
  else {
    efab_syscall_exit();
    /* XXX: PPC_HACK: doesn't handle trampoline */
    return efab_linux_sys_exit_group(status);
  }
}

/* Properly die because of signal sig */
int
efab_signal_die(ci_private_t *priv_unused, void *arg)
{
  ci_int32 sig = *(ci_int32 *)arg;
  tcp_helper_resource_t *stacks[TERMINATE_STACKS_NUM];
  ci_uint32 stacks_num = 0;

  if( sig_kernel_only(sig) || sig_kernel_ignore(sig) ||
      sig_kernel_stop(sig) || sig_kernel_coredump(sig) )
    return -EINVAL;

  BUILD_BUG_ON(sizeof(ci_uint64) * 8 < TERMINATE_STACKS_NUM);
  stacks_num = efab_terminate_find_all_stacks(stacks, TERMINATE_STACKS_NUM);

  if( stacks_num ) {
    int status = sig; /* unused */

    /* lock all the stacks */
    efab_terminate_lock_all_stacks(stacks, stacks_num);
    /* kill all threads while they do not have netif locks (we have them!) */
    efab_exit_group(&status);
    /* now when everybody is dead we can release netifs */
    efab_terminate_unlock_all_stacks(stacks, stacks_num);
  }

  /* Simulate "normal" behaviour: remove sighandler and send the signal
   * again. */
  spin_lock_irq(&current->sighand->siglock);
  current->sighand->action[sig-1].sa.sa_handler = SIG_DFL;
  spin_unlock_irq(&current->sighand->siglock);

  send_sig(sig, current, 0);
  /*UNREACHABLE*/
  return 0;
}


void efab_linux_termination_ctor(void)
{
#ifdef EFRM_HAS_FIND_KSYM
  efab_my_zap_other_threads = efrm_find_ksym("zap_other_threads");
  TERM_DEBUG("Find zap_other_threads via kallsyms at %p", t.addr);

  if( efab_my_zap_other_threads == NULL )
#endif
  {
    efab_my_zap_other_threads = efab_zap_other_threads;
    TERM_DEBUG("Using our zap_other_threads implementation");
  }

}

#else  /* OO_CAN_HANDLE_TERMINATION */

int
efab_signal_die(ci_private_t *priv_unused, void *arg)
{
  return 0;
}

#endif /* OO_CAN_HANDLE_TERMINATION */
