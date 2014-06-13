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
*//*! \file epoll_device.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  /dev/onload_epoll char device implementation
**   \date  2011/03/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>

#if CI_CFG_USERSPACE_EPOLL

#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/tcp_helper_fns.h>
#include <onload/epoll.h>
#include <linux/eventpoll.h>
#include <linux/unistd.h> /* for __NR_epoll_pwait */
#include "onload_internal.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
/* Normal Linux epoll depth check does not work for us.
 * We should check that we do not poll ourself inside epoll_wait call. */
#define OO_EPOLL_NEED_NEST_PROTECTION
#endif


/*************************************************************
 * EPOLL2 private file data
 *************************************************************/
struct oo_epoll2_private {
  struct file  *kepo;
  spinlock_t    lock;
  int           do_spin;
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
  struct list_head busy_tasks;
#endif
  tcp_helper_resource_t* stacks[CI_CFG_EPOLL_MAX_STACKS];
};
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
struct oo_epoll_busy_task {
  struct list_head  link;
  struct task_struct *task;
};
#endif


/*************************************************************
 * EPOLL1 private file data
 *************************************************************/
struct oo_epoll1_private {
  /* Shared memory */
  struct oo_epoll1_shared *sh;
  struct page *page; /*!< shared page used for shared memory */

  /* Poll table and workqueue, used in callback */
  poll_table pt;
  wait_queue_t wait;
  wait_queue_head_t *whead;
};

/*************************************************************
 * EPOLL common private file data
 *************************************************************/
struct oo_epoll_file_private {
  int type;
#define OO_EPOLL_TYPE_UNKNOWN   0
#define OO_EPOLL_TYPE_1         1
#define OO_EPOLL_TYPE_2         2
  union {
    struct oo_epoll1_private p1;
    struct oo_epoll2_private p2;
  } p;
};


static inline int oo_epoll_ctl_copy_to_kernel(struct oo_epoll_item *item_u,
                                              ci_uint32 epoll_ctl_n,
                                              struct oo_epoll_item *dest)
{
  if( epoll_ctl_n > CI_CFG_EPOLL_MAX_POSTPONED )
    return -EFAULT;
  if( copy_from_user(dest, item_u,
                     sizeof(struct oo_epoll_item) * epoll_ctl_n) )
    return -EFAULT;
  return 0;
}


static inline void oo_epoll_warn_postpone_error(ci_uint32 ctl_n,
                                                int fd, int i, int rc,
                                                ci_int32 maxevents)
{
  if( rc && (i != ctl_n - 1 || maxevents != 0) ) {
    ci_log("postponed epoll_ctl(fd=%d) returned error %d; ignoring",
           fd, rc);
    ci_log("consider disabling EF_EPOLL_CTL_FAST to get "
           "the correct behaviour");
  }
}


/*************************************************************
 * EPOLL2-specific code
 *************************************************************/
static void oo_epoll2_ctor(struct oo_epoll2_private *priv, struct file  *kepo)
{
  spin_lock_init(&priv->lock);
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
  INIT_LIST_HEAD(&priv->busy_tasks);
#endif
  priv->kepo = kepo;
}

static int oo_epoll2_init(struct oo_epoll_file_private *priv,
                         ci_fixed_descriptor_t kepfd)
{
  struct file *file = fget((int)kepfd);

  if(unlikely( file == NULL ))
    return -EBADF;
  priv->type = OO_EPOLL_TYPE_2;
  oo_epoll2_ctor(&priv->p.p2, file);
  return 0;
}

static int oo_epoll2_add_stack(struct oo_epoll2_private* priv,
                              tcp_helper_resource_t* fd_thr)
{
  int i;

  /* Common case is that we already know about this stack, so make that
   * fast.
   */
  for( i = 0; i < CI_CFG_EPOLL_MAX_STACKS; ++i )
    if( priv->stacks[i] == fd_thr )
      return 1;
    else if(unlikely( priv->stacks[i] == NULL ))
      break;

  /* Try to add stack.  NB. May already be added by concurrent thread. */
  spin_lock(&priv->lock);
  for( i = 0; i < CI_CFG_EPOLL_MAX_STACKS; ++i ) {
    if( priv->stacks[i] == fd_thr )
      break;
    if( priv->stacks[i] != NULL )
      continue;
    priv->stacks[i] = fd_thr;
    /* We already keep ref for this thr via file,
     * so efab_tcp_helper_k_ref_count_inc() can't fail. */
    efab_tcp_helper_k_ref_count_inc(fd_thr);
    break;
  }
  spin_unlock(&priv->lock);
  return i < CI_CFG_EPOLL_MAX_STACKS;
}


static int oo_epoll2_ctl(struct oo_epoll2_private *priv, int op_kepfd,
                         int op_op, int op_fd, struct epoll_event *op_event)
{
  tcp_helper_resource_t *fd_thr;
  struct file *file;
  int rc;
  ci_uint32 fd_sock_id;
  citp_waitable *fd_w;

  /* We are interested in ADD only */
  if( op_op != EPOLL_CTL_ADD )
    return efab_linux_sys_epoll_ctl(op_kepfd, op_op, op_fd, op_event);

  /* system poll() and friends use fget_light(), which is cheap.
   * But they do not export fget_light to us, so we have to use fget(). */
  file = fget(op_fd);
  if(unlikely( file == NULL ))
    return -EBADF;

  /* Check for the dead circle.
   * We should check that we are not adding ourself. */
  {
    struct oo_epoll_file_private *p = file->private_data;
    if(unlikely( p->type == OO_EPOLL_TYPE_2 && &p->p.p2 == priv )) {
      fput(file);
      return -EINVAL;
    }
  }

  /* Is op->fd ours and if yes, which netif it has? */
  /* Fixme: epoll fd - do we want to accelerate something? */
  if( file->f_op != &linux_tcp_helper_fops_udp &&
      file->f_op != &linux_tcp_helper_fops_tcp ) {
    int rc;
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
    struct oo_epoll_busy_task t;
    t.task = current;
    spin_lock(&priv->lock);
    list_add(&t.link, &priv->busy_tasks);
    spin_unlock(&priv->lock);
#endif

#if CI_CFG_USERSPACE_PIPE
    if( ( file->f_op == &linux_tcp_helper_fops_pipe_reader ||
          file->f_op == &linux_tcp_helper_fops_pipe_writer ) )
      priv->do_spin = 1;
#endif
    fput(file);
    rc = efab_linux_sys_epoll_ctl(op_kepfd, op_op, op_fd, op_event);
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
      spin_lock(&priv->lock);
      list_del(&t.link);
      spin_unlock(&priv->lock);
#endif
    return rc;
  }

  /* Onload socket here! */
  fd_thr = ((ci_private_t *)file->private_data)->thr;
  fd_sock_id = ((ci_private_t *)file->private_data)->sock_id;
  priv->do_spin = 1;

  if(unlikely( ! oo_epoll2_add_stack(priv, fd_thr) )) {
    static int printed;
    if( !printed )
      ci_log("Can't add stack %d to epoll set: consider "
             "increasing CI_CFG_EPOLL_MAX_STACKS", fd_thr->id);
    /* fall through to sys_epoll_ctl() without interrupt */
  }

  /* Let kernel add fd to the epoll set, but ask endpoint to avoid enabling
   * interrupts.
   * And we keep file ref while using fd_w to avoid nasty things. */
  fd_w = SP_TO_WAITABLE(&fd_thr->netif, fd_sock_id);
  ci_bit_set(&fd_w->sb_aflags, CI_SB_AFLAG_AVOID_INTERRUPTS_BIT);
  rc = efab_linux_sys_epoll_ctl(op_kepfd, op_op, op_fd, op_event);
  ci_bit_clear(&fd_w->sb_aflags, CI_SB_AFLAG_AVOID_INTERRUPTS_BIT);
  fput(file);

  return rc;
}

/* Apply all postponed epoll_ctl and ignore the results (just print
 * a message), since there is nothing to do now. */
static int oo_epoll2_apply_ctl(struct oo_epoll2_private *priv,
                               struct oo_epoll2_action_arg *op)
{
  struct oo_epoll_item postponed_k[CI_CFG_EPOLL_MAX_POSTPONED];
  struct oo_epoll_item *postponed_u = CI_USER_PTR_GET(op->epoll_ctl);
  int i;
  int rc = 0;

  rc = oo_epoll_ctl_copy_to_kernel(postponed_u, op->epoll_ctl_n, postponed_k);
  if( rc != 0 )
    return rc;

  for( i = 0; i < op->epoll_ctl_n; i++ ) {
    if(  postponed_k[i].fd != -1 ) {
      rc = oo_epoll2_ctl(priv, op->kepfd, postponed_k[i].op,
                         postponed_k[i].fd, &postponed_u[i].event);
      oo_epoll_warn_postpone_error(op->epoll_ctl_n, postponed_k[i].fd, i, rc,
                                   op->maxevents);
    }
  }

  /* Return the last rc */
  return rc;
}


#define OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni)                       \
  for( i = 0; i < CI_CFG_EPOLL_MAX_STACKS; ++i )                        \
    if( (thr = (priv)->stacks[i]) == NULL )                             \
      break;                                                            \
    else if(unlikely( thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND )) \
      continue;                                                         \
    else if( (ni = &thr->netif) || 1 )


static void oo_epoll2_wait(struct oo_epoll2_private *priv,
                           struct oo_epoll2_action_arg *op)
{
  ci_uint64 start_frc = 0, now_frc = 0; /* =0 to make gcc happy */
  tcp_helper_resource_t* thr;
  ci_netif* ni;
  int i;
  ci_int32 timeout = op->timeout;

  /* Get the start of time. */
  if( timeout > 0 || ( timeout < 0 && op->spin_cycles ) )
    ci_frc64(&start_frc);

  /* Declare that we are spinning - even if we are just polling */
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni)
    if( ! ni->state->is_spinner )
      ni->state->is_spinner = 1;

  /* Poll each stack for events */
  op->rc = -ENOEXEC; /* impossible value */
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    if( ci_netif_may_poll(ni) && ci_netif_has_event(ni) &&
        ci_netif_trylock(ni) ) {
      int did_wake;
      ni->state->poll_did_wake = 0;
      ci_netif_poll(ni);
      did_wake = ni->state->poll_did_wake;
      ci_netif_unlock(ni);

      /* Possibly, we've got necessary event.  If true, exit */
      if( did_wake ) {
        op->rc = efab_linux_sys_epoll_wait(op->kepfd,
                                           CI_USER_PTR_GET(op->events),
                                           op->maxevents, 0);
        if( op->rc != 0 )
          goto do_exit;
      }
    }
  }

  /* Do we have anything to do? */
  if( op->rc == -ENOEXEC ) {
    /* never called sys_epoll_wait() - do it! */
    op->rc = efab_linux_sys_epoll_wait(op->kepfd, CI_USER_PTR_GET(op->events),
                                       op->maxevents, 0);
  }
  if( op->rc != 0 || timeout == 0 )
    goto do_exit;

  /* Fixme: eventually, remove NO_USERLAND stacks from this list.
   * Here is a good moment: we are going to spin or block, so there are
   * a lot of time.  But avoid locking! */

  /* Spin for a while. */
  if( op->spin_cycles ) {
    ci_uint64 schedule_frc;
    ci_uint64 max_spin = op->spin_cycles;
    int spin_limited_by_timeout = 0;
    ci_assert(start_frc);

    if( timeout > 0) {
      ci_uint64 max_timeout_spin = (ci_uint64)timeout * cpu_khz;
      if( max_timeout_spin <= max_spin ) {
        max_spin = max_timeout_spin;
        spin_limited_by_timeout = 1;
      }
    }

    /* spin */
    now_frc = schedule_frc = start_frc;
    do {
      if(unlikely( signal_pending(current) )) {
        op->rc = -EINTR; /* epoll_wait returns EINTR, not ERESTARTSYS! */
        goto do_exit;
      }

      OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
        if( ci_netif_may_poll(ni) &&
            ci_netif_need_poll_spinning(ni, now_frc) &&
            ci_netif_trylock(ni) ) {
          ci_netif_poll(ni);
          ci_netif_unlock(ni);
        }
        else if( ! ni->state->is_spinner )
          ni->state->is_spinner = 1;
      }

      op->rc = efab_linux_sys_epoll_wait(op->kepfd, CI_USER_PTR_GET(op->events),
                                         op->maxevents, 0);
      if( op->rc != 0 )
        goto do_exit;

      ci_frc64(&now_frc);
      if(unlikely( now_frc - schedule_frc > cpu_khz / 1000 )) {
        schedule(); /* schedule() every 1ms */
        schedule_frc = now_frc;
      }
      else
        ci_spinloop_pause();
    } while( now_frc - start_frc < max_spin );

    if( spin_limited_by_timeout )
      goto do_exit;
  }

  /* Even without spinning, netif_poll for 4 netifs takes some time.
   * Count it. */
  if( timeout > 0 ) {
    ci_uint64 spend_ms;
    if( ! op->spin_cycles )
      ci_frc64(&now_frc); /* In spin case, re-use now_frc value */
    spend_ms = now_frc - start_frc;
    do_div(spend_ms, cpu_khz);
    ci_assert_ge((int)spend_ms, 0);
    if( timeout > (int)spend_ms ) {
      timeout -= spend_ms;
    }
    else
      goto do_exit;
  }

  /* Going to block: enable interrupts; reset spinner flag */
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    if( ni->state->is_spinner )
      ni->state->is_spinner = 0;
    tcp_helper_request_wakeup(thr);
  }

  /* Block */
  op->rc = efab_linux_sys_epoll_wait(op->kepfd, CI_USER_PTR_GET(op->events),
                                     op->maxevents, timeout);
  return;

do_exit:
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    if( ni->state->is_spinner )
      ni->state->is_spinner = 0;
  }
  return;
}


static int oo_epoll2_action(struct oo_epoll2_private *priv,
                            struct oo_epoll2_action_arg *op)
{
#ifdef __NR_epoll_pwait
  sigset_t ksigmask, sigsaved;
#endif
  int return_zero = false;

  op->rc = 0;

  /* Restore kepfd if necessary */
  if(unlikely( op->kepfd == -1 )) {
    op->kepfd = oo_install_file_to_fd_cloexec(priv->kepo);
    if( op->kepfd < 0 )
      return op->kepfd;
    /* We've restored kepfd.  Now we should return 0! */
    return_zero = true;
  }

  /* Call all postponed epoll_ctl calls; ignore rc. */
  if( op->epoll_ctl_n )
    op->rc = oo_epoll2_apply_ctl(priv, op);

  if( op->maxevents ) {
    if( CI_USER_PTR_GET(op->sigmask) ) {
#ifdef __NR_epoll_pwait
      if (copy_from_user(&ksigmask, CI_USER_PTR_GET(op->sigmask),
                         sizeof(ksigmask))) {
        if( return_zero ) {
          op->rc = -EFAULT;
          return 0;
        }
        else
          return -EFAULT;
      }
      sigdelsetmask(&ksigmask, sigmask(SIGKILL) | sigmask(SIGSTOP));
      sigprocmask(SIG_SETMASK, &ksigmask, &sigsaved);
#else
      /* Fixme: we can work around it, but reimplemening sigprocmask() is
       * a complicated job... */
      ci_log("Your kernel does not support epoll_pwait(), but you are "
             "trying to use it.  Ignoring sigmask...");
#endif
    }

#ifdef OO_EPOLL_NEED_NEST_PROTECTION
    {
      struct oo_epoll_busy_task t;
      t.task = current;
      spin_lock(&priv->lock);
      list_add(&t.link, &priv->busy_tasks);
      spin_unlock(&priv->lock);
#endif
    if( priv->do_spin )
      oo_epoll2_wait(priv, op);
    else {
      op->rc = efab_linux_sys_epoll_wait(op->kepfd,
                                         CI_USER_PTR_GET(op->events),
                                         op->maxevents, op->timeout);
    }
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
      spin_lock(&priv->lock);
      list_del(&t.link);
      spin_unlock(&priv->lock);
    }
#endif

    if( CI_USER_PTR_GET(op->sigmask) ) {
#ifdef __NR_epoll_pwait
      if (op->rc == -EINTR) {
        memcpy(&current->saved_sigmask, &sigsaved, sizeof(sigsaved));
#ifdef HAVE_SET_RESTORE_SIGMASK
        set_restore_sigmask();
#else
        set_thread_flag(TIF_RESTORE_SIGMASK);
#endif
      }
      else {
        sigprocmask(SIG_SETMASK, &sigsaved, NULL);
      }
#endif
    }
  }

  if( return_zero || op->rc >= 0 )
    return 0;
  else
    return op->rc;
}

static void oo_epoll2_release(struct oo_epoll2_private *priv)
{
  int i;
  ci_assert(priv);

  /* Release KEPO */
  if( priv->kepo )
    fput(priv->kepo);

  /* Release references to all stacks */
  for( i = 0; i < CI_CFG_EPOLL_MAX_STACKS; i++ ) {
    if( priv->stacks[i] == NULL )
      break;
    efab_tcp_helper_k_ref_count_dec(priv->stacks[i], 1);
    priv->stacks[i] = NULL;
  }

#ifdef OO_EPOLL_NEED_NEST_PROTECTION
  ci_assert(list_empty(&priv->busy_tasks));
#endif
}

static unsigned oo_epoll2_poll(struct oo_epoll2_private* priv,
                               poll_table* wait)
{
#ifdef OO_EPOLL_NEED_NEST_PROTECTION
  if( current ) {
    struct oo_epoll_busy_task *t;
    spin_lock(&priv->lock);
    list_for_each_entry(t, &priv->busy_tasks, link) {
      if( t->task == current) {
        spin_unlock(&priv->lock);
        return POLLNVAL;
      }
    }
    spin_unlock(&priv->lock);
  }
#endif

  /* Fixme: poll all netifs? */

  return priv->kepo->f_op->poll(priv->kepo, wait);
}


/*************************************************************
 * EPOLL1-specific code
 *************************************************************/
static int oo_epoll1_callback(wait_queue_t *wait, unsigned mode, int sync,
                              void *key)
{
  struct oo_epoll1_private* priv = container_of(wait,
                                                struct oo_epoll1_private,
                                                wait);
  ci_uint32 tmp;
  do {
    tmp = priv->sh->flag;
  } while( ci_cas32u_fail(&priv->sh->flag, tmp,
                          (tmp + (1 << OO_EPOLL1_FLAG_SEQ_SHIFT)) |
                          OO_EPOLL1_FLAG_EVENT) );
  return 0;
}
static void oo_epoll1_queue_proc(struct file *file,
                                 wait_queue_head_t *whead,
                                 poll_table *pt)
{
  struct oo_epoll1_private* priv = container_of(pt,
                                                struct oo_epoll1_private,
                                                pt);
  init_waitqueue_func_entry(&priv->wait, oo_epoll1_callback);
  priv->whead = whead;
  add_wait_queue(whead, &priv->wait);
}
static int oo_epoll1_mmap(struct oo_epoll1_private* priv,
                          struct vm_area_struct* vma)
{
  struct file *file;
  int rc;

  if (vma->vm_end - vma->vm_start != PAGE_SIZE)
    return -EINVAL;
  if (vma->vm_flags & VM_WRITE)
    return -EPERM;

  /* Allocate shared memory */
#ifdef __GFP_ZERO
  priv->page = alloc_page(GFP_KERNEL|__GFP_ZERO);
#else
  priv->page = alloc_page(GFP_KERNEL);
#endif
  if( priv->page == NULL )
    return -ENOMEM;
  priv->sh = page_address(priv->page);
#ifndef __GFP_ZERO
  memset(priv->sh, 0, PAGE_SIZE);
#endif

  /* Create epoll fd */
  priv->sh->epfd = efab_linux_sys_epoll_create1(EPOLL_CLOEXEC);
  if( (int)priv->sh->epfd < 0 ) {
    rc = priv->sh->epfd;
    goto fail1;
  }

  /* Map memory to user */
  if( remap_pfn_range(vma, vma->vm_start, page_to_pfn(priv->page),
                      PAGE_SIZE, vma->vm_page_prot) < 0) {
    rc = -EIO;
    goto fail2;
  }

  /* Install callback */
  init_poll_funcptr(&priv->pt, oo_epoll1_queue_proc);
  file = fget(priv->sh->epfd);
  file->f_op->poll(file, &priv->pt);
  fput(file);

  return 0;

fail2:
  efab_linux_sys_close(priv->sh->epfd);
fail1:
  priv->sh = NULL;
  __free_page(priv->page);
  return rc;
}

static int oo_epoll1_release(struct oo_epoll1_private* priv)
{
  ci_assert(priv->whead);
  remove_wait_queue(priv->whead, &priv->wait);

  /* We can get here in 2 ways: via sys_close and via
   * (sys|efab)_exit_group -> put_files_struct.
   * In the second case, we cant't call sys_close(priv->sh->epfd), because
   * current->files is already set to NULL.
   */
  if( current->files )
    efab_linux_sys_close(priv->sh->epfd);

  __free_page(priv->page);
  return 0;
}

static int oo_epoll1_action(struct oo_epoll1_private *priv,
                           struct oo_epoll1_action_arg *op)
{
  struct oo_epoll_item item[CI_CFG_EPOLL_MAX_POSTPONED];
  struct oo_epoll_item *item_u = CI_USER_PTR_GET(op->epoll_ctl);
  int i;
  int rc = 0;

  if( op->epoll_ctl_n ) {
    rc = oo_epoll_ctl_copy_to_kernel(item_u, op->epoll_ctl_n, item);
    if( rc )
      return rc;

    for( i = 0; i < op->epoll_ctl_n; i++ ) {
      rc = efab_linux_sys_epoll_ctl(op->epfd, item[i].op,
                                    item[i].fd, &item_u[i].event);
      if( rc == 0 )
        rc = efab_linux_sys_epoll_ctl(priv->sh->epfd, item[i].op,
                                      item[i].fd, &item_u[i].event);

      oo_epoll_warn_postpone_error(op->epoll_ctl_n, item[i].fd, i, rc,
                                   op->maxevents);
    }
  }

  if( op->maxevents ) {
    ci_uint32 tmp;
    struct file *file = NULL;
    op->rc = efab_linux_sys_epoll_wait(priv->sh->epfd,
                                       CI_USER_PTR_GET(op->events),
                                       op->maxevents, 0/*timeout*/);
    if( op->rc < 0 )
      rc = op->rc;
    do {
      tmp = priv->sh->flag;
      if( (tmp & 1) == 0 )
        break;
      if( file == NULL )
        file = fget(priv->sh->epfd);
      if( file == NULL || file->f_op->poll(file, NULL) )
        break;
    } while( ci_cas32u_fail(&priv->sh->flag, tmp,
                            tmp & ~OO_EPOLL1_FLAG_EVENT) );
    if( file != NULL )
      fput(file);
  }
  else
    op->rc = rc;

  return rc;
}

/*************************************************************
 * Common /dev/onload_epoll code
 *************************************************************/
static long oo_epoll_fop_unlocked_ioctl(struct file* filp,
                                        unsigned cmd, unsigned long arg)
{
  struct oo_epoll_file_private *priv = filp->private_data;
  void __user* argp = (void __user*) arg;
  int rc;

  switch( cmd ) {
  case OO_EPOLL2_IOC_ACTION: {
    struct oo_epoll2_action_arg local_arg;

    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_2 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll2_action(&priv->p.p2, &local_arg);

    if( rc == 0 && copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
    break;
  }

  case OO_EPOLL2_IOC_INIT: {
    ci_fixed_descriptor_t local_arg;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_UNKNOWN )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll2_init(priv, local_arg);
    break;
  }

  case OO_EPOLL1_IOC_ACTION: {
    struct oo_epoll1_action_arg local_arg;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll1_action(&priv->p.p1, &local_arg);

    if( rc == 0 && copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
    break;
  }

  default:
    ci_log("unknown epoll device ioctl: 0x%x", cmd);
    rc = -EINVAL;
  }
  return rc;
}

#if !HAVE_UNLOCKED_IOCTL
int oo_epoll_fop_ioctl(struct inode* inode, struct file *filp,
                       unsigned cmd, unsigned long arg) 
{
  return oo_epoll_fop_unlocked_ioctl(filp, cmd, arg);
}
#endif

static int oo_epoll_fop_open(struct inode* inode, struct file* filp)
{
  struct oo_epoll_file_private *priv = kmalloc(sizeof(*priv), GFP_KERNEL);

  if(unlikely( priv == NULL ))
    return -ENOMEM;
  memset(priv, 0, sizeof(*priv));

  filp->private_data = (void*) priv;
  filp->f_op = &oo_epoll_fops;

  return 0;
}

static int oo_epoll_fop_release(struct inode* inode, struct file* filp)
{
  struct oo_epoll_file_private *priv = filp->private_data;

  ci_assert(priv);

  /* Type-specific cleanup */
  switch( priv->type ) {
    case OO_EPOLL_TYPE_1: oo_epoll1_release(&priv->p.p1); break;
    case OO_EPOLL_TYPE_2: oo_epoll2_release(&priv->p.p2); break;
    default: ci_assert_equal(priv->type, OO_EPOLL_TYPE_UNKNOWN);
  }

  /* Free priv data */
  kfree(priv);

  return 0;
}

static unsigned oo_epoll_fop_poll(struct file* filp, poll_table* wait)
{
  struct oo_epoll_file_private *priv = filp->private_data;

  ci_assert(priv);
  if( priv->type != OO_EPOLL_TYPE_2 )
    return POLLNVAL;
  return oo_epoll2_poll(&priv->p.p2, wait);
}

static int oo_epoll_fop_mmap(struct file* filp, struct vm_area_struct* vma)
{
  struct oo_epoll_file_private *priv = filp->private_data;
  int rc;

  ci_assert(priv);
  if( priv->type != OO_EPOLL_TYPE_UNKNOWN)
    return -EINVAL;
  rc = oo_epoll1_mmap(&priv->p.p1, vma);
  if( rc == 0 )
    priv->type = OO_EPOLL_TYPE_1;
  return rc;
}

struct file_operations oo_epoll_fops =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(poll, oo_epoll_fop_poll),
#if HAVE_UNLOCKED_IOCTL
  CI_STRUCT_MBR(unlocked_ioctl, oo_epoll_fop_unlocked_ioctl),
#else
  CI_STRUCT_MBR(ioctl, oo_epoll_fop_ioctl),
#endif
#if HAVE_COMPAT_IOCTL
  CI_STRUCT_MBR(compat_ioctl, oo_epoll_fop_unlocked_ioctl),
#endif
  CI_STRUCT_MBR(open, oo_epoll_fop_open),
  CI_STRUCT_MBR(release,  oo_epoll_fop_release),
  CI_STRUCT_MBR(mmap,  oo_epoll_fop_mmap),
};

static int oo_epoll_major;

/* the only external symbol here: init /dev/onload_epoll */
int __init oo_epoll_chrdev_ctor(void)
{
  int rc, major = 0; /* specify default major number here */

  rc = register_chrdev(major, OO_EPOLL_DEV_NAME, &oo_epoll_fops);
  if( rc < 0 ) {
    ci_log("%s: can't register char device %d", OO_EPOLL_DEV_NAME, rc);
    return rc;
  }
  if( major == 0 )
    major = rc;
  oo_epoll_major = major;

#ifdef NEED_IOCTL32
  {
    /* Register 64 bit handler for 32 bit ioctls.  In 2.6.11 onwards, this
     * uses the .compat_ioctl file op instead.
     */
    int ioc;
    for( ioc = 0; ioc < OO_OP_END; ++ioc )
      register_ioctl32_conversion(oo_epoll_operations[ioc].ioc_cmd, NULL);
  }
#endif

  return 0;
}

void oo_epoll_chrdev_dtor(void)
{
  if( oo_epoll_major )
    unregister_chrdev(oo_epoll_major, OO_EPOLL_DEV_NAME);

#ifdef NEED_IOCTL32
  {
    /* unregister 64 bit handler for 32 bit ioctls */
    int ioc;
    for( ioc = 0; ioc < OO_OP_END; ++ioc )
      unregister_ioctl32_conversion(oo_epoll_operations[ioc].ioc_cmd);
  }
#endif
}

#endif

