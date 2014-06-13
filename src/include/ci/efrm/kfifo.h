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
 * This file provides Linux-like kfifo API for efrm library.
 *
 * Copyright 2010: Solarflare Communications Inc,
 *                 9501 Jeronimo Road, Suite 250,
 *                 Irvine, CA 92618, USA
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
 * Kfifo API taken from linux-2.6.33/include/linux/kfifo.h
 *   Copyright (C) 2009 Stefani Seibold <stefani@seibold.net>
 *   Copyright (C) 2004 Stelian Pop <stelian@popies.net>
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

#ifndef __CI_EFRM_KFIFO_H__
#define __CI_EFRM_KFIFO_H__

#ifndef __CI_EFRM_SYSDEP_H__
#error "Should only be included from ci/efrm/sysdep.h"
#endif

/*
 * This implementation of the kfifo API is based on the version in
 * Linux 2.6.33.  It is used by all versions of Linux before 2.6.33 as
 * well as non-Linux systems.
 */

struct efrm_kfifo {
	unsigned char *buffer;	/* the buffer holding the data */
	unsigned int size;	/* the size of the allocated buffer */
	unsigned int in;	/* data is added at offset (in % size) */
	unsigned int out;	/* data is extracted from off. (out % size) */
};
#define kfifo efrm_kfifo


extern void efrm_kfifo_init(struct kfifo *fifo, void *buffer,
			    unsigned int size);
#define kfifo_init efrm_kfifo_init


/**
 * kfifo_len - returns the number of used bytes in the FIFO
 * @fifo: the fifo to be used.
 */
static inline unsigned int efrm_kfifo_len(struct kfifo *fifo)
{
	register unsigned int	out;

	out = fifo->out;
	smp_rmb();
	return fifo->in - out;
}
#define kfifo_len efrm_kfifo_len


extern unsigned int
efrm_kfifo_in(struct kfifo *fifo, const void *from, unsigned int len);
#define kfifo_in efrm_kfifo_in


extern unsigned int
efrm_kfifo_out(struct kfifo *fifo, void *to, unsigned int len);
#define kfifo_out efrm_kfifo_out


/**
 * kfifo_in_locked - puts some data into the FIFO using a spinlock for locking
 * @fifo: the fifo to be used.
 * @from: the data to be added.
 * @n: the length of the data to be added.
 * @lock: pointer to the spinlock to use for locking.
 *
 * This function copies at most @len bytes from the @from buffer into
 * the FIFO depending on the free space, and returns the number of
 * bytes copied.
 */
static inline unsigned int
efrm_kfifo_in_locked(struct kfifo *fifo, const void *from, unsigned int n,
		     spinlock_t *lock)
{
	irq_flags_t flags;
	unsigned int ret;
	
	spin_lock_irqsave(lock, flags);
	
	ret = kfifo_in(fifo, from, n);
	
	spin_unlock_irqrestore(lock, flags);
	
	return ret;
}
#define kfifo_in_locked efrm_kfifo_in_locked


/**
 * kfifo_out_locked - gets some data from the FIFO using a spinlock for locking
 * @fifo: the fifo to be used.
 * @to: where the data must be copied.
 * @n: the size of the destination buffer.
 * @lock: pointer to the spinlock to use for locking.
 *
 * This function copies at most @len bytes from the FIFO into the
 * @to buffer and returns the number of copied bytes.
 */
static inline unsigned int
efrm_kfifo_out_locked(struct kfifo *fifo, void *to, unsigned int n,
		      spinlock_t *lock)
{
	irq_flags_t flags;
	unsigned int ret;
	
	spin_lock_irqsave(lock, flags);

	ret = kfifo_out(fifo, to, n);

	spin_unlock_irqrestore(lock, flags);

	return ret;
}
#define kfifo_out_locked efrm_kfifo_out_locked


#endif
