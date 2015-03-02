/*
** Copyright 2005-2015  Solarflare Communications Inc.
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


#ifndef SFC_AFFINITY_KERNEL_COMPAT_H
#define SFC_AFFINITY_KERNEL_COMPAT_H

#include "driver/linux_affinity/autocompat.h"
#include <linux/proc_fs.h>

#if !defined(EFRM_HAVE_PROC_CREATE_DATA) && \
    !defined(EFRM_HAVE_PROC_CREATE_DATA_UMODE)
#ifdef EFRM_HAVE_PROC_CREATE
static inline struct proc_dir_entry *
proc_create_data(const char *name, umode_t mode,
         struct proc_dir_entry *parent,
         const struct file_operations *proc_fops,
         void *data)
{
    struct proc_dir_entry *pde;
    pde = proc_create(name, mode, parent, proc_fops);
    if (pde != NULL)
        pde->data = data;
    return pde;
}
#else
static inline struct proc_dir_entry *
proc_create_data(const char *name, umode_t mode,
		 struct proc_dir_entry *parent,
		 const struct file_operations *proc_fops,
		 void *data)
{
	struct proc_dir_entry *pde;
	pde = create_proc_entry(name, mode, parent);
	if (pde != NULL) {
		pde->proc_fops = (struct file_operations *)proc_fops;
		pde->data = data;
	}
	return pde;
}
static inline struct proc_dir_entry *
proc_create(const char *name, umode_t mode,
		 struct proc_dir_entry *parent,
		 const struct file_operations *proc_fops)
{
	return proc_create_data(name, mode, parent, proc_fops, NULL);
}
#endif
#endif

#ifndef EFRM_HAVE_PDE_DATA
static inline void *PDE_DATA(const struct inode *inode)
{
	return PROC_I(inode)->pde->data;
}
#endif


#endif
