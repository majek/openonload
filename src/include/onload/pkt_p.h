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

#ifndef __ONLOAD_PKT_P_H__
#define __ONLOAD_PKT_P_H__


/**********************************************************************
 * Pointers to packets.
 */

#if CI_CFG_PP_IS_PTR

typedef ci_ip_pkt_fmt* oo_pkt_p;

/* Convert to and from integer id.  Users of this are probably depending on
 * the implementation.
 */
#define OO_PP_ID(pp)             ((pp) ? (int) (pp)->pkt_id : -1)
#define OO_PP_ID_NULL            (-1)
#define OO_PKT_ID(pkt)           ((int) (pkt)->pkt_id)
#define OO_PKT_PP_INIT(pkt, iid) ((pkt)->pkt_id = (ci_int32) (iid))
#define OO_PP_INIT(ni, pp, iid)                                         \
  do {                                                                  \
    int __id = (iid);                                                   \
    (pp) = __id >= 0 ? (ci_ip_pkt_fmt*) __PKT_BUF((ni), __id) : NULL;   \
  } while(0)

/* Public interface. */
#define OO_PP_IS_NULL(pp)     ((pp) == NULL)
#define OO_PP_NOT_NULL(pp)    ((pp) != NULL)
#define OO_PP_EQ(ppa, ppb)    ((ppa) == (ppb))
#define OO_PP_FMT(pp)         ((pp) ? (int) (pp)->pkt_id : -1)
#define OO_PKT_FMT(pkt)       ((int) (pkt)->pkt_id)
#define OO_PKT_P(pkt)         (pkt)

#define OO_PP_NULL            NULL
#define OO_PP_INVALID         ((ci_ip_pkt_fmt*)(ci_uintptr_t) -1)

#else

typedef ci_int32 oo_pkt_p;

/* Convert to and from integer id.  Users of this are probably depending on
 * the implementation.
 */
#define OO_PP_ID(pp)             ((int) (pp))
#define OO_PP_INIT(ni, pp, iid)  ((pp) = (ci_int32) (iid))
#define OO_PP_ID_NULL            ((ci_int32) -1)
#define OO_PKT_ID(pkt)           ((int) (pkt)->pp)
#define OO_PKT_PP_INIT(pkt, iid) ((pkt)->pp = (ci_int32) (iid))

/* Public interface. */
#define OO_PP_IS_NULL(pp)     ((pp) < 0)
#define OO_PP_NOT_NULL(pp)    ((pp) >= 0)
#define OO_PP_EQ(ppa, ppb)    ((ppa) == (ppb))
#define OO_PP_FMT(pp)         OO_PP_ID(pp)
#define OO_PKT_FMT(pkt)       OO_PP_FMT((pkt)->pp)
#define OO_PKT_P(pkt)         ((pkt)->pp)

#define OO_PP_NULL            -1
#define OO_PP_INVALID         -2

#endif


#endif  /* __ONLOAD_PKT_P_H__ */
