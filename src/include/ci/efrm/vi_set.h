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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides public API for vi_set resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#ifndef __CI_EFRM_VI_SET_H__
#define __CI_EFRM_VI_SET_H__

#include <ci/efrm/resource.h>
#include <ci/efhw/common.h>
#include <ci/efrm/debug.h>


struct efrm_vi_set;
struct efrm_vi;
struct efrm_pd;


extern int
efrm_vi_set_alloc(struct efrm_pd *, int n_vis, unsigned vi_props,
		  struct efrm_vi_set **vi_set_out);

extern void
efrm_vi_set_release(struct efrm_vi_set *);

extern int
efrm_vi_set_num_vis(struct efrm_vi_set *);

extern int
efrm_vi_set_get_base(struct efrm_vi_set *);

extern int
efrm_vi_set_get_rss_context(struct efrm_vi_set *);

extern struct efrm_resource *
efrm_vi_set_to_resource(struct efrm_vi_set *);

extern struct efrm_vi_set *
efrm_vi_set_from_resource(struct efrm_resource *);

extern struct efrm_pd *
efrm_vi_set_get_pd(struct efrm_vi_set *);


#endif /* __CI_EFRM_VI_SET_H__ */
