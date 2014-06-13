/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_CRC32C_H__
#define __CI_TOOLS_CRC32C_H__

extern ci_uint32 ci_crc32c_partial(const ci_uint8 *buf, ci_uint32 buflen,
                                   ci_uint32 crc);

extern ci_uint32 ci_crc32c_partial_copy(ci_uint8 *dest, const ci_uint8 *buf,
                                        ci_uint32 buflen, ci_uint32 crc);

ci_inline ci_uint32 ci_crc32c(const ci_uint8 *buf, ci_uint32 buflen)
{
  return ~ci_crc32c_partial(buf, buflen, 0xffffffff);
}

#endif  /* __CI_TOOLS_CRC32C_H__ */
/*! \cidoxg_end */
