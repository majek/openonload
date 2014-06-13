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

#ifndef __ONLOAD_STATE_P_H__
#define __ONLOAD_STATE_P_H__


#if CI_CFG_OOP_IS_PTR

typedef char* oo_p;

# define OO_P_IS_NULL(p)         ((p) == NULL)
# define OO_P_NOT_NULL(p)        ((p) != NULL)
# define OO_P_EQ(pa, pb)         ((pa) == (pb))
# define OO_P_FMT(p)             ((int)(ci_uintptr_t) (p))
# define OO_P_ADD(p, off)        do{ (p) += (off); }while(0)

# define OO_P_NULL               NULL
# define OO_P_INVALID            ((oo_p)(ci_uintptr_t) -1)

#else

typedef ci_int32 oo_p;

# define OO_P_INIT(p, ni, off)   ((p) = (off))
# define OO_P_OFF(p)             (p)

# define OO_P_IS_NULL(p)         ((p) < 0)
# define OO_P_NOT_NULL(p)        ((p) >= 0)
# define OO_P_EQ(pa, pb)         ((pa) == (pb))
# define OO_P_FMT(p)             ((int) (p))
# define OO_P_ADD(p, off)        do{ (p) += (off); }while(0)

# define OO_P_NULL               -1
# define OO_P_INVALID            -2

#endif


#endif  /* __ONLOAD_STATE_P_H__ */
