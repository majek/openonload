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

#ifndef __ONLOAD_KERNEL_COMPAT_H__
#define __ONLOAD_KERNEL_COMPAT_H__

#include <driver/linux_net/kernel_compat.h>
#include <driver/linux_net/autocompat.h>
#include <driver/linux_affinity/autocompat.h>
#include <linux/file.h>
#include <linux/signal.h>

#ifndef current_fsuid
#define current_fsuid() current->fsuid
#endif
#ifndef current_fsgid
#define current_fsgid() current->fsgid
#endif

#ifdef EFRM_HAVE_KMEM_CACHE_S
#define kmem_cache kmem_cache_s
#endif


#ifndef __NFDBITS
# define __NFDBITS BITS_PER_LONG
#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
# define f_vfsmnt f_path.mnt
#endif


#ifndef EFRM_HAVE_NETDEV_NOTIFIER_INFO
#define netdev_notifier_info_to_dev(info) (info)
#endif

#ifndef EFRM_HAVE_REINIT_COMPLETION
#define reinit_completion(c) INIT_COMPLETION(*c)
#endif

#ifndef EFRM_HAVE_GET_UNUSED_FD_FLAGS
#ifdef O_CLOEXEC
static inline int
efrm_get_unused_fd_flags(unsigned flags)
{
  int fd = get_unused_fd();
  struct files_struct *files = current->files;
  struct fdtable *fdt;

  if( fd < 0 )
    return fd;

  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);
  if( flags & O_CLOEXEC)
    efx_set_close_on_exec(fd, fdt);
  else
    efx_clear_close_on_exec(fd, fdt);
  spin_unlock(&files->file_lock);

  return fd;
}
#undef get_unused_fd_flags
#define get_unused_fd_flags(flags) efrm_get_unused_fd_flags(flags)
#else /* ! O_CLOEXEC */
#define get_unused_fd_flags(flags) get_unused_fd()
#endif
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
#define ci_call_usermodehelper call_usermodehelper
#else
extern int
ci_call_usermodehelper(char *path, char **argv, char **envp, int wait);
#endif


#ifndef get_file_rcu
/* Linux <= 4.0 */
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#endif

/* A change to module_param_call() in Linux 4.15 highlighted that our
 * callbacks should have had a const argument.  The change to use a
 * const argument is much older than that (2.6.36)
 */
#ifdef EFRM_HAVE_CONST_KERNEL_PARAM
#define ONLOAD_MPC_CONST const
#else
#define ONLOAD_MPC_CONST
#endif

/* init_timer() was removed in Linux 4.15, with timer_setup()
 * replacing it */
#ifndef EFRM_HAVE_TIMER_SETUP
#define timer_setup(timer, callback, flags)     \
  init_timer(timer);                            \
  (timer)->data = 0;                            \
  (timer)->function = &callback;
#endif

#endif /* __ONLOAD_KERNEL_COMPAT_H__ */
