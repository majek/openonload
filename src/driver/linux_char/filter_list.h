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

#ifndef __FILTER_LIST_H__
#define __FILTER_LIST_H__


extern void efch_filter_list_init(struct efch_filter_list *);

extern void efch_filter_list_free(struct efrm_resource *,
                                  struct efch_filter_list *);

extern int efch_filter_list_del(struct efrm_resource *,
                                struct efch_filter_list *, int filter_id);

extern int efch_filter_list_op(struct efrm_resource *,
                               struct efch_filter_list *,
                               ci_resource_op_t *, int *copy_out,
                               unsigned efx_filter_flags);


#endif  /* __FILTER_LIST_H__ */
