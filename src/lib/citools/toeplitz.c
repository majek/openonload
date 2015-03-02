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
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Toeplitz hash calculation
**   \date  2007/04/02
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */


#include "citools_internal.h"


ci_uint32 ci_toeplitz_hash(const ci_uint8 *key, const ci_uint8 *input, int n)
{
  ci_uint32 key_bits;
  ci_uint32 result = 0;

  key_bits = (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
  key += 4;

  while( --n >= 0 ) {
    ci_uint8 input_byte = *input++;
    ci_uint8 next_key_byte = *key++;
    ci_uint8 bit = 0x80;
    while (bit != 0) {
      if (input_byte & bit)  result ^= key_bits;
      key_bits <<= 1;
      if (next_key_byte & bit)  key_bits |= 1;
      bit >>= 1;
    }
  }

  return result;
}


/*! \cidoxg_end */
