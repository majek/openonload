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

/* Logging macros for cplane code */
#ifndef __CPLANE_DEBUG_H__
#define __CPLANE_DEBUG_H__


extern unsigned cplane_debug_bits;

#define __CP_DEBUG_ERR__      0x00000001
#define __CP_DEBUG_ARP__      0x00000002
#define __CP_DEBUG_FWD__      0x00000004
#define __CP_DEBUG_MAC__      0x00000008
#define __CP_DEBUG_BOND__     0x00000010
#define __CP_DEBUG_SHM__      0x00000020
#define __CP_DEBUG_VERB__     0x00000040
#define __CP_DEBUG_IPP__      0x00000080

#define __CP_DEBUG_DEFAULT__ (__CP_DEBUG_ERR__)


#define CPLANE_LOG(bits, foo) \
  do{ if( cplane_debug_bits & (bits) ) { foo; } }while(0)

#ifdef NDEBUG
#define CPLANE_DBG(bits, foo)
#else
#define CPLANE_DBG(bits, foo) CPLANE_LOG(bits, foo)
#endif

#define CP_DBG_ERR(foo)     CPLANE_LOG(__CP_DEBUG_ERR__, foo)
#define CP_DBG_ARP(foo)     CPLANE_DBG(__CP_DEBUG_ARP__, foo)
#define CP_DBG_FWD(foo)     CPLANE_DBG(__CP_DEBUG_FWD__, foo)
#define CP_DBG_MAC(foo)     CPLANE_DBG(__CP_DEBUG_MAC__, foo)
#define CP_DBG_BOND(foo)    CPLANE_DBG(__CP_DEBUG_BOND__, foo)
#define CP_DBG_SHM(foo)     CPLANE_DBG(__CP_DEBUG_SHM__, foo)
#define CP_DBG_VERB(foo)    CPLANE_DBG(__CP_DEBUG_VERB__, foo)
#define CP_DBG_IPP(foo)     CPLANE_DBG(__CP_DEBUG_IPP__, foo)


#endif /* __CPLANE_DEBUG_H__ */
