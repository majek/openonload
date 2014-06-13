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


#ifndef __CI_EFHW_HARDWARE_UL_H__
#define __CI_EFHW_HARDWARE_UL_H__

#include <ci/compat.h>

ci_inline void
__raw_writeb(ci_uint8 data, volatile char *addr)
{
  *(volatile ci_uint8*) addr = data;
}
#define writeb __raw_writeb

ci_inline ci_uint8
__raw_readb(volatile char *addr)
{
  return *(volatile ci_uint8*) addr;
}
#define readb __raw_readb

ci_inline void
__raw_writew(ci_uint16 data, volatile char *addr)
{
  *(volatile ci_uint16*) addr = data;
}
#define writew __raw_writew

ci_inline ci_uint16
__raw_readw(volatile char *addr)
{
  return *(volatile ci_uint16*) addr;
}
#define readw __raw_readw

ci_inline void
__raw_writel(ci_uint32 data, volatile char *addr)
{
  *(volatile ci_uint32*) addr = data;
}
#define writel __raw_writel

ci_inline ci_uint32
__raw_readl(volatile char *addr)
{
  return *(volatile ci_uint32*) addr;
}
#define readl __raw_readl

ci_inline void
__raw_writeq(ci_uint64 data, volatile char *addr)
{
  *(volatile ci_uint64*) addr = data;
}
#define writeq __raw_writeq

ci_inline ci_uint64
__raw_readq(volatile char *addr)
{
  return *(volatile ci_uint64*) addr;
}
#define readq __raw_readq


#endif /* __CI_EFHW_HARDWARE_UL_H__ */
