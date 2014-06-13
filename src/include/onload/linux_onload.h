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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define CI_LINUX_NO_MOVE_ADDR
extern int efab_move_addr_to_kernel(void __user *uaddr, int ulen,
                                    struct sockaddr *kaddr);
#define move_addr_to_kernel efab_move_addr_to_kernel
#endif

/*--------------------------------------------------------------------
 *
 * System calls
 *
 *--------------------------------------------------------------------*/

extern asmlinkage int
efab_linux_sys_close(int fd);

extern asmlinkage int
efab_linux_sys_accept4(int fd, struct sockaddr __user* addr,
                       int __user* addrlen,
                       unsigned long __user* socketcall_args, int flags);

extern asmlinkage int
efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                       unsigned long __user* socketcall_args, unsigned flags);


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
#include <asm/ia32.h>
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



/* set cpu speed - needed only for kernel-created netifs */
extern int ci_set_cpu_khz(unsigned cpu_khz);


#endif  /* __CI_DRIVER_EFAB_LINUX_ONLOAD__ */
