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

#ifndef __ONLOAD_SOCK_P_H__
#define __ONLOAD_SOCK_P_H__


#if CI_CFG_SOCKP_IS_PTR

typedef union citp_waitable_obj_u* oo_sp;

# define OO_SP_FROM_INT(ni, id)   ((oo_sp) (oo_sockid_to_ptr((ni), (id))))
# define OO_SP_TO_INT(p)          ((p)->waitable.bufid)
# define OO_SP_IS_NULL(p)         ((p) == NULL)
# define OO_SP_NOT_NULL(p)        ((p) != NULL)
# define OO_SP_EQ(pa, pb)         ((pa) == (pb))
# define OO_SP_FMT(p)             ((p) ? (int) (p)->waitable.bufid : -1)

# define OO_SP_NULL               NULL
# define OO_SP_INVALID            ((oo_sp)(ci_uintptr_t) -1)

#else

typedef ci_int32 oo_sp;

# define OO_SP_FROM_INT(ni, id)   (id)
# define OO_SP_TO_INT(p)          (p)

# define OO_SP_IS_NULL(p)         ((p) < 0)
# define OO_SP_NOT_NULL(p)        ((p) >= 0)
# define OO_SP_EQ(pa, pb)         ((pa) == (pb))
# define OO_SP_FMT(p)             ((int) (p))

# define OO_SP_NULL               -1
# define OO_SP_INVALID            -2

#endif


#endif  /* __ONLOAD_SOCK_P_H__ */
