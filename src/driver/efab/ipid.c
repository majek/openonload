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
** <L5_PRIVATE L5_SOURCE >
** \author  stg
**  \brief  Char driver Efab IP ID allocation mechanism
**   \date  2004/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_efab */

#include <onload/ipid.h>

extern int efab_ipid_alloc(efab_ipid_cb_t* ipid)
{
  int i;
  int rv;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );
  ci_irqlock_lock( &ipid->lock, &lock_flags );

  /* go find an unused block */
  for( i = 0; i <= CI_IPID_BLOCK_COUNT; i++ ) {
    if( !ipid->range[i] ) {
      ipid->range[i]++;
      rv = CI_IPID_MIN + (i << CI_IPID_BLOCK_SHIFT);
      ci_assert((rv >= CI_IPID_MIN) &&
                (rv <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));
      goto alloc_exit;
    } else {
      ci_assert( ipid->range[i] == 1 );
    }
  }
  /* !!Out of blocks!! */
  rv = -ENOMEM;

 alloc_exit:
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return rv;
}


int
efab_ipid_free(efab_ipid_cb_t* ipid, int base )
{
  int i;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );

  if(  (base & CI_IPID_BLOCK_MASK) != 0 )
    return -EINVAL;  /* not actually on a block boundary */

  ci_assert((base >= CI_IPID_MIN) && 
            (base <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));

  ci_irqlock_lock( &ipid->lock, &lock_flags );
  i = (base - CI_IPID_MIN) >> CI_IPID_BLOCK_SHIFT;
  ci_assert( ipid->range[i] == 1 );
  ipid->range[i] = 0;
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return 0;
}

/*! \cidoxg_end */
