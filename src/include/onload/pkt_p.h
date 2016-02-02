/*
** Copyright 2005-2016  Solarflare Communications Inc.
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



#endif  /* __ONLOAD_PKT_P_H__ */
