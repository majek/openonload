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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Byte-swapping etc.
**   \date  2008/05/19
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_BYTEORDER_H__
#define __CI_TOOLS_BYTEORDER_H__


/* CI_BSWAP_xx()  -- Byte-swap at runtime.  Argument must be in appropriate
 *                   domain.
 *
 * CI_BSWAPM_xx() -- Byte-swap at runtime.  Argument need not be in
 *                   appropriate domain -- high bits are truncated.
 *
 * See also CI_BSWAPC_xx() in <ci/compat> for swapping constants.
 */

/* Swap runtime values. */
#define CI_BSWAP_16(v)    ci_bswap16((ci_uint16) (v))
#define CI_BSWAP_32(v)    ci_bswap32((ci_uint32) (v))
#define CI_BSWAP_64(v)    ci_bswap64(v)


#if (CI_MY_BYTE_ORDER == CI_LITTLE_ENDIAN)
# define CI_BSWAP_LE16(v)    (v)
# define CI_BSWAP_LE32(v)    (v)
# define CI_BSWAP_LE64(v)    (v)
# define CI_BSWAP_BE16(v)    CI_BSWAP_16(v)
# define CI_BSWAP_BE32(v)    CI_BSWAP_32(v)
# define CI_BSWAP_BE64(v)    CI_BSWAP_64(v)
# define CI_BSWAPM_LE16(v)   ((ci_uint16) (v))
# define CI_BSWAPM_LE32(v)   ((ci_uint32) (v))
# define CI_BSWAPM_BE16(v)   CI_BSWAP_16(v)
# define CI_BSWAPM_BE32(v)   CI_BSWAP_32(v)
#elif (CI_MY_BYTE_ORDER == CI_BIG_ENDIAN)
# define CI_BSWAP_BE16(v)    (v)
# define CI_BSWAP_BE32(v)    (v)
# define CI_BSWAP_BE64(v)    (v)
# define CI_BSWAP_LE16(v)    CI_BSWAP_16(v)
# define CI_BSWAP_LE32(v)    CI_BSWAP_32(v)
# define CI_BSWAP_LE64(v)    CI_BSWAP_64(v)
# define CI_BSWAPM_BE16(v)   ((ci_uint16) (v))
# define CI_BSWAPM_BE32(v)   ((ci_uint32) (v))
# define CI_BSWAPM_LE16(v)   CI_BSWAP_16(v)
# define CI_BSWAPM_LE32(v)   CI_BSWAP_32(v)
#else
# error Bad endian.
#endif


#endif  /* __CI_TOOLS_BYTEORDER_H__ */
/*! \cidoxg_end */
