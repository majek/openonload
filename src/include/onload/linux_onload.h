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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Exported functions from linux onload driver.
**   \date  2005/04/25
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __CI_DRIVER_EFAB_LINUX_ONLOAD__
#define __CI_DRIVER_EFAB_LINUX_ONLOAD__

#ifndef __KERNEL__
# error Silly
#endif

#include <linux/linkage.h>
#include <ci/internal/transport_config_opt.h>
#include <linux/socket.h>
#include <linux/signal.h>
#include <linux/version.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#include <net/compat.h>
#endif
#include <linux/poll.h>
#include <driver/linux_net/kernel_compat.h>
#include <driver/linux_affinity/autocompat.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define CI_LINUX_NO_MOVE_ADDR
extern int efab_move_addr_to_kernel(void __user *uaddr, int ulen,
                                    struct sockaddr *kaddr);
#define move_addr_to_kernel efab_move_addr_to_kernel
#endif

#ifndef EFRM_HAVE_POLL_REQUESTED_EVENTS
static inline bool poll_does_not_wait(const poll_table *p)
{
  return p == NULL;
}
#endif

#if ! defined(EFRM_HAVE_F_DENTRY) && ! defined f_dentry
#define f_dentry f_path.dentry
#endif

#ifndef EFRM_HAVE_MSG_ITER
static inline void __msg_iov_init(struct msghdr *msg, struct iovec *iov,
                                  unsigned long iovlen)
{
  msg->msg_iov = iov;
  msg->msg_iovlen = iovlen;
}
#define oo_msg_iov_init(msg, dir, iov, iovlen, bytes) \
  __msg_iov_init(msg, iov, iovlen)
#else
#define oo_msg_iov_init(msg, dir, iov, iovlen, bytes) \
  iov_iter_init(&(msg)->msg_iter, dir, iov, iovlen, bytes)
#endif


#ifdef EFRM_SOCK_SENDMSG_NEEDS_LEN
static inline int oo_sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
  size_t bytes = 0;

#ifdef EFRM_HAVE_MSG_ITER
  bytes = msg->msg_iter.count;
#else
  int i;
  for( i = 0; i < msg->msg_iovlen; ++i )
    bytes += msg->msg_iov[i].iov_len;
#endif
  return sock_sendmsg(sock, msg, bytes);
}
#define sock_sendmsg oo_sock_sendmsg
#endif


#ifdef EFRM_SOCK_RECVMSG_NEEDS_BYTES
static inline int oo_sock_recvmsg(struct socket *sock, struct msghdr *msg,
                                  int flags)
{
  size_t bytes = 0;

#ifdef EFRM_HAVE_MSG_ITER
  bytes = msg->msg_iter.count;
#else
  int i;
  for( i = 0; i < msg->msg_iovlen; ++i )
    bytes += msg->msg_iov[i].iov_len;
#endif
  return sock_recvmsg(sock, msg, bytes, flags);

}
#define sock_recvmsg oo_sock_recvmsg
#endif

/*--------------------------------------------------------------------
 *
 * System calls
 *
 *--------------------------------------------------------------------*/

extern asmlinkage int
efab_linux_sys_close(int fd);

extern asmlinkage int
efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                       unsigned long __user* socketcall_args, unsigned flags);
#ifdef CONFIG_COMPAT
extern asmlinkage int
efab_linux_sys_sendmsg32(int fd, struct compat_msghdr __user* msg,
                         unsigned long __user* socketcall_args,
                         unsigned flags);
#endif


#if CI_CFG_USERSPACE_EPOLL
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/eventpoll.h>
#ifndef EPOLL_CLOEXEC
#include <linux/fcntl.h>
#ifdef O_CLOEXEC
#define EPOLL_CLOEXEC O_CLOEXEC
#else
#define EPOLL_CLOEXEC 02000000
#endif
#endif
extern asmlinkage int efab_linux_sys_epoll_create1(int flags);
extern asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                               struct epoll_event *event);
extern asmlinkage int efab_linux_sys_epoll_wait(int epfd,
                                                struct epoll_event *events,
                                                int maxevents, int timeout);
#endif

asmlinkage int efab_linux_sys_exit_group(int status);
asmlinkage int efab_linux_sys_sigaction(int signum,
                                        const struct sigaction *act,
                                        struct sigaction *oact);
#ifdef CONFIG_COMPAT

/* XXX: PPC_HACK: asm/ia32 is intel specific and not present on ppc.
   The function also seems to be intel specific. */
#if ! defined (__PPC__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
# include <linux/compat.h>
# define sigaction32 compat_sigaction
#else
# include <asm/ia32.h>
#endif
#else
# include <linux/compat.h>
struct sigaction32;
#endif
asmlinkage int efab_linux_sys_sigaction32(int signum,
                                          const struct sigaction32 *act,
                                          struct sigaction32 *oact);
#endif

#if defined(CONFIG_HUGETLB_PAGE) && CI_CFG_PKTS_AS_HUGE_PAGES && \
    defined(__x86_64__)
#define OO_DO_HUGE_PAGES
#include <linux/mm.h>
#include <linux/hugetlb.h>
struct shmid_ds;
asmlinkage int efab_linux_sys_shmget(key_t key, size_t size, int shmflg);
asmlinkage long efab_linux_sys_shmat(int shmid, char __user *addr, int shmflg);
asmlinkage int efab_linux_sys_shmdt(char __user *addr);
asmlinkage int efab_linux_sys_shmctl(int shmid, int cmd,
                                     struct shmid_ds __user *buf);
#endif

#ifdef CONFIG_NAMESPACES
#include <linux/nsproxy.h>
#ifdef EFRM_HAVE_TASK_NSPROXY
static inline struct nsproxy *
task_nsproxy_start(struct task_struct *tsk)
{
  rcu_read_lock();
  return task_nsproxy(tsk);
}
static inline void
task_nsproxy_done(struct task_struct *tsk)
{
  rcu_read_unlock();
}
#else
#ifdef EFRM_HAVE_SCHED_TASK_H
#include <linux/sched/task.h>
#endif
static inline struct nsproxy *
task_nsproxy_start(struct task_struct *tsk)
{
  task_lock(tsk);
  return tsk->nsproxy;
}
static inline void
task_nsproxy_done(struct task_struct *tsk)
{
  task_unlock(tsk);
}
#endif
#endif


/* Correct sequence for per-cpu variable access is: disable preemption to
 * guarantee that the CPU is not changed under your feet - read/write the
 * variable - enable preemption.  In linux >=3.17, we have this_cpu_read()
 * which checks for preemption and get_cpu_var()/put_cpu_var() which
 * disable/enable preemption.
 *
 * We do not care about preemption at all, for 2 reasons:
 * 1. We do not really care if we sometimes get variable from wrong CPU.
 * 2. The checks below are called from driverlink, and NAPI thread can not
 *    change CPU.
 *
 * So, we use fast-and-unreliable raw_cpu_read().
 * For older kernels, we implement raw_cpu_read() and raw_cpu_write().
 */
#ifndef raw_cpu_read
/* linux < 3.17 */

#ifndef raw_cpu_ptr
/* linux < 3.15 */

#if defined(per_cpu_var) || LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
/* per_cpu_var is defined from 2.6.30 to 2.6.33 */
#ifndef per_cpu_var
#define per_cpu_var(var) var
#endif

#define raw_cpu_ptr(var) \
      per_cpu_ptr(&per_cpu_var(var), raw_smp_processor_id())
#else
/* linux < 2.6.30 has per_cpu_ptr(), but it provides access to variables
 * allocated by alloc_percpu().  DEFINE_PER_CPU() defines another type of
 * variables, with per_cpu() and __raw_get_cpu_var() accessors. */
#define raw_cpu_ptr(var) (&__raw_get_cpu_var(var))
#endif

#endif /* raw_cpu_ptr */

#define raw_cpu_read(var) (*raw_cpu_ptr(var))
#define raw_cpu_write(var,val) \
  do {                          \
    *raw_cpu_ptr(var) = (val);  \
  } while(0)

#endif /* raw_cpu_read */

DECLARE_PER_CPU(unsigned long, oo_budget_limit_last_ts);
extern unsigned long oo_avoid_wakeup_under_pressure;
static inline int/*bool*/ oo_avoid_wakeup_from_dl(void)
{
  if( oo_avoid_wakeup_under_pressure == 0 )
    return 0;
  return raw_cpu_read(oo_budget_limit_last_ts) +
    oo_avoid_wakeup_under_pressure >= jiffies;
}

#endif  /* __CI_DRIVER_EFAB_LINUX_ONLOAD__ */
