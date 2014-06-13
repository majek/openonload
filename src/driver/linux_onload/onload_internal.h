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

#ifndef __ONLOAD_INTERNAL_H__
#define __ONLOAD_INTERNAL_H__

#include <linux/init.h>


extern int oo_driverlink_register(void);
extern void oo_driverlink_unregister_nf(void);
extern void oo_driverlink_unregister_dl(void);


extern int  ci_install_proc_entries(void);
extern void ci_uninstall_proc_entries(void);

struct proc_dir_entry;
extern struct proc_dir_entry* oo_proc_root;

extern int ci_bonding_init(void);
extern void ci_bonding_fini(void);

extern void ci_bonding_set_timer_period(int period, int occurences);

extern void ci_bonding_get_xmit_policy_flags(void *net_dev, unsigned char *flags);

extern int __init oo_epoll_chrdev_ctor(void);
extern void oo_epoll_chrdev_dtor(void);

struct file;
extern int oo_install_file_to_fd(struct file *file, int flags);

extern int __init onloadfs_init(void);
extern void onloadfs_fini(void);

#include <onload/fd_private.h>
void onload_priv_free(ci_private_t *priv);

#endif  /* __ONLOAD_INTERNAL_H__ */
