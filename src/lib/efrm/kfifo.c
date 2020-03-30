/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains implementation of the Linux kfifo API.
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

#include <ci/efrm/sysdep.h>
#include <ci/efhw/debug.h>

#ifndef EFRM_HAVE_KFIFO


/**
 * efrm_kfifo_size - returns the size of the fifo in bytes
 * @fifo: the fifo to be used.
 */
static inline unsigned int efrm_kfifo_size(struct kfifo *fifo)
{
	return fifo->size;
}


/**
 * efrm_kfifo_avail - returns the number of bytes available in the FIFO
 * @fifo: the fifo to be used.
 */
static inline unsigned int efrm_kfifo_avail(struct kfifo *fifo)
{
	return efrm_kfifo_size(fifo) - efrm_kfifo_len(fifo);
}


/*
 * efrm_kfifo_off internal helper function for calculating the index of a
 * given offeset
 */
static inline unsigned int efrm_kfifo_off(struct kfifo *fifo,
                                          unsigned int off)
{
	return off & (fifo->size - 1);
}


/*
 * efrm_kfifo_add_in internal helper function for updating the in offset
 */
static inline void efrm_kfifo_add_in(struct kfifo *fifo,
                                     unsigned int off)
{
	smp_wmb();
	fifo->in += off;
}


/*
 * efrm_kfifo_add_out internal helper function for updating the out offset
 */
static inline void efrm_kfifo_add_out(struct kfifo *fifo,
                                      unsigned int off)
{
	smp_mb();
	fifo->out += off;
}


static inline void efrm_kfifo_reset(struct kfifo *fifo)
{
	fifo->in = fifo->out = 0;
}


static void _efrm_kfifo_init(struct kfifo *fifo, void *buffer,
                             unsigned int size)
{
	fifo->buffer = buffer;
	fifo->size = size;

	efrm_kfifo_reset(fifo);
}


/**
 * efrm_kfifo_init - initialize a FIFO using a preallocated buffer
 * @fifo: the fifo to assign the buffer
 * @buffer: the preallocated buffer to be used.
 * @size: the size of the internal buffer, this has to be a power of 2.
 *
 */
void efrm_kfifo_init(struct kfifo *fifo, void *buffer,
                     unsigned int size)
{
        _efrm_kfifo_init(fifo, buffer, size);
}


static inline void efrm_kfifo_in_data(struct kfifo *fifo, const void *from,
                                      unsigned int len, unsigned int off)
{
	unsigned int l;

	/*
	 * Ensure that we sample the fifo->out index -before- we
	 * start putting bytes into the kfifo.
	 */

	smp_mb();

	off = efrm_kfifo_off(fifo, fifo->in + off);

	/* first put the data starting from fifo->in to buffer end */
	l = min(len, fifo->size - off);
	memcpy(fifo->buffer + off, from, l);

	/* then put the rest (if any) at the beginning of the buffer */
	memcpy(fifo->buffer, (char*)from + l, len - l);
}


/**
 * efrm_kfifo_in - puts some data into the FIFO
 * @fifo: the fifo to be used.
 * @from: the data to be added.
 * @len: the length of the data to be added.
 *
 * This function copies at most @len bytes from the @from buffer into
 * the FIFO depending on the free space, and returns the number of
 * bytes copied.
 *
 * Note that with only one concurrent reader and one concurrent
 * writer, you don't need extra locking to use these functions.
 */
unsigned int efrm_kfifo_in(struct kfifo *fifo,
                           const void *from, unsigned int len)
{
	len = min(efrm_kfifo_avail(fifo), len);

	efrm_kfifo_in_data(fifo, from, len, 0);
	efrm_kfifo_add_in(fifo, len);
	return len;
}


static inline void efrm_kfifo_out_data(struct kfifo *fifo, void *to,
                                       unsigned int len, unsigned int off)
{
	unsigned int l;

	/*
	 * Ensure that we sample the fifo->in index -before- we
	 * start removing bytes from the kfifo.
	 */

	smp_rmb();

	off = efrm_kfifo_off(fifo, fifo->out + off);

	/* first get the data from fifo->out until the end of the buffer */
	l = min(len, fifo->size - off);
	memcpy(to, fifo->buffer + off, l);

	/* then get the rest (if any) from the beginning of the buffer */
	memcpy((char*)to + l, fifo->buffer, len - l);
}


/**
 * efrm_kfifo_out - gets some data from the FIFO
 * @fifo: the fifo to be used.
 * @to: where the data must be copied.
 * @len: the size of the destination buffer.
 *
 * This function copies at most @len bytes from the FIFO into the
 * @to buffer and returns the number of copied bytes.
 *
 * Note that with only one concurrent reader and one concurrent
 * writer, you don't need extra locking to use these functions.
 */
unsigned int efrm_kfifo_out(struct kfifo *fifo,
                            void *to, unsigned int len)
{
	len = min(kfifo_len(fifo), len);

	efrm_kfifo_out_data(fifo, to, len, 0);
	efrm_kfifo_add_out(fifo, len);

	return len;
}


#endif
