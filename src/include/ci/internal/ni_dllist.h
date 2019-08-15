/*
** Copyright 2005-2019  Solarflare Communications Inc.
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


#ifndef __CI_INTERNAL_NI_DLLIST_H__
#define __CI_INTERNAL_NI_DLLIST_H__

/*********************************************************************
*********************** Indirected linked lists **********************
*********************************************************************/


/* Get the code for the linked lists. */
#define CI_MK_ID(x)             ci_ni_dllist##x
#define CI_ILL_PTR(ctx, a)      ((ci_ni_dllist_link*) CI_NETIF_PTR((ctx), (a)))
#define CI_ILL_ADDR_EQ(a, b)    OO_P_EQ((a), (b))
#define CI_ILL_ADDR_T           oo_p
#define CI_ILL_ADDR_NULL        OO_P_NULL
#define CI_ILL_CTX_T            ci_netif*
#if CI_CFG_OOP_IS_PTR
# define CI_ILL_ADDR(ctx,lnk)	((oo_p) (lnk))
# define CI_ILL_CAS(p,old,new)  ci_cas_uintptr_succeed( \
                                            (volatile ci_uintptr_t*) (p), \
                                            (ci_uintptr_t) (old), \
                                            (ci_uintptr_t) (new))
# define CI_ILL_XCHG(p,new)     ((oo_p) ci_xchg_uintptr( \
                                            (volatile ci_uintptr_t*) (p), \
                                            (ci_uintptr_t) (new)))
#else
# define CI_ILL_CAS(p,old,new)  ci_cas32u_succeed((volatile ci_uint32*) (p), \
                                                  (ci_uint32) (old), \
                                                  (ci_uint32) (new))
# define CI_ILL_XCHG(p,new)     ((oo_p) ci_xchg32((volatile ci_uint32*) (p), \
                                                  (ci_uint32) (new)))
#endif
#define CI_ILL_NO_TYPES
#include <ci/tools/idllist.h.tmpl>


/* Get pointer from an address in the ci_netif_state address space. */
# define ci_ni_dllist_iter(ni, l)           \
            ((l) = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, (l)->next))
# define ci_ni_dllist_backiter(ni, l)       \
            ((l) = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, (l)->prev))


/*! \TODO Move these into their own header. */

#define CI_ILL_UNUSED           -2
#define CI_ILL_END              -1

#define _ci_ill_assert_valid(i, file, line) \
        _ci_assert_ge((int)(i), CI_ILL_END, (file), (line))

/* A singly linked list. */
#define ci_ill_assert_valid(i)  _ci_ill_assert_valid((i), __FILE__, __LINE__)
#define ci_ill_is_empty(i)      ((i) == CI_ILL_END)
#define ci_ill_not_empty(i)     ((i) != CI_ILL_END)

/* A singly linked list with tail pointer. */
#define ci_ill2_assert_valid(h,t)  do{                  \
  ci_assert((h) >= CI_ILL_END);                         \
  ci_assert((h) == CI_ILL_END || (t) >= CI_ILL_END);    \
  }while(0)

/* A double linked list. */
#define ci_idll_assert_valid(h,t)  do{                  \
  ci_assert((h) >= CI_ILL_END);                         \
  ci_assert((t) >= CI_ILL_END);                         \
  ci_assert((h) != CI_ILL_END || (t) == CI_ILL_END);    \
  ci_assert((h) == CI_ILL_END || (t) != CI_ILL_END);    \
  }while(0)

#endif /* __CI_INTERNAL_NI_DLLIST_H__ */
