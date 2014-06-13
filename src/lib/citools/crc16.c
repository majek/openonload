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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include "citools_internal.h"


/*
** 16-bit CRCs:
**
**  http://www.monitor-computing.pwp.blueyonder.co.uk/projects/crc16/
**  http://www.repairfaq.org/filipg/LINK/F_crc_v35.html
**  http://www.geocities.com/SiliconValley/Pines/6639/docs/crc.html
**  http://www.microconsultants.com/tips/crc/crc.txt
**  http://www.ross.net/crc/
*/


unsigned ci_crc16_add8(unsigned old_crc, unsigned poly, unsigned data)
{
  int i = 8;

  old_crc ^= (data << 8u);

  while( i-- ) {
    if( old_crc & 0x8000 )  old_crc = (old_crc << 1u) ^ poly;
    else                    old_crc <<= 1u;
  }

  return old_crc;
}

/*! \cidoxg_end */
