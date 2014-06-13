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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides version-independent Linux kernel API for efrm library.
 * Only kernels >=2.6.9 are supported.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef __CI_EFRM_SYSDEP_LINUX_H__
#define __CI_EFRM_SYSDEP_LINUX_H__

#include <linux/version.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
#include <linux/hardirq.h>
#else
#include <asm/hardirq.h>
#endif
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/completion.h>
#include <linux/in.h>
#include <driver/linux_net/kernel_compat.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/* get roundup_pow_of_two(), which was in kernel.h in early kernel versions */
#include <linux/log2.h>
#endif


/********************************************************************
 *
 * List API
 *
 ********************************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
static inline void
list_replace_init(struct list_head *old, struct list_head *new)
{
	new->next = old->next;
	new->next->prev = new;
	new->prev = old->prev;
	new->prev->next = new;
	INIT_LIST_HEAD(old);
}
#endif

static inline struct list_head *list_pop(struct list_head *list)
{
	struct list_head *link = list->next;
	list_del(link);
	return link;
}

static inline struct list_head *list_pop_tail(struct list_head *list)
{
	struct list_head *link = list->prev;
	list_del(link);
	return link;
}


/********************************************************************
 *
 * Kfifo API
 *
 ********************************************************************/

/* The original kfifo API was introduced in 2.6.10 but the API was
 * re-written for 2.6.33.  Only use the kernel provided API if it is
 * the new one. */
#ifdef EFX_HAVE_NEW_KFIFO
# include <linux/kfifo.h>
# define EFRM_HAVE_KFIFO
#endif

/********************************************************************
 *
 * Threaded IRQ support
 *
 ********************************************************************/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#define EXF_HAVE_THREADED_IRQ
#endif

#ifdef EXF_HAVE_THREADED_IRQ
struct efrm_threaded_irq {};
#else
struct efrm_threaded_irq {
	struct workqueue_struct *irq_wq;
	struct work_struct irq_work;
};
#endif

#endif /* __CI_EFRM_SYSDEP_LINUX_H__ */
