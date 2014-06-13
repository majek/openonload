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


#ifndef __CI_EFHW_COMMON_CI2LINUX_H__
#define __CI_EFHW_COMMON_CI2LINUX_H__

#include <ci/compat.h>


# if defined(__KERNEL__)
#  error ci/efhw/common_ci2linux.h should not be included for Linux modules
# endif
#include <stdbool.h>
typedef unsigned long dma_addr_t;
#define DMA_ADDR_T_FMT "%lx"


#ifdef __KERNEL__ 
#define PRIx32 "x"
#define PRIx64 "llx"
#endif

#ifndef bool
#undef false
#undef true
typedef enum {
  false = 0,
  true = 1
} bool;
#endif

#ifndef uint64_t
#define uint64_t ci_uint64
#endif
#ifndef uint32_t
#define uint32_t ci_uint32
#endif
#ifndef uint16_t
#define uint16_t ci_uint16
#endif
#ifndef uint8_t
#define uint8_t  ci_uint8 
#endif

#ifndef int64_t
#define int64_t ci_int64 
#endif
#ifndef int32_t
#define int32_t ci_int32 
#endif
#ifndef int16_t
#define int16_t ci_int16 
#endif
#ifndef int8_t 
#define int8_t  ci_int8 
#endif

#endif /* __CI_EFHW_COMMON_CI2LINUX_H__ */
