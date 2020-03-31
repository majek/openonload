/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  UL/driver IP ID allocation. 
**   \date  2004/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#ifdef __ci_driver__
# include <onload/ipid.h>
#else
# include <ci/internal/ipid.h>
# include <onload/ul.h>
#endif


#define LPF "ci_ipid_"


ci_inline int ci_ipid_range_get( ci_netif* ni, ci_fd_t fd )
{
# ifdef __ci_driver__
  int rc = efab_ipid_alloc(&efab_tcp_driver.ipid);
  LOG_IP(ci_log( LPF "range_get: %d", rc ));
  return rc;
# else
  ci_int32 v;

  int rc = oo_ipid_range_alloc(fd, &v);
  LOG_IP(ci_log( LPF "range_get: %d", rc ));
  return rc ? rc : v;

# endif
}

ci_inline int ci_ipid_range_release( ci_netif* ni, ci_fd_t fd, ci_int32 r )
{
# ifdef __ci_driver__
  return efab_ipid_free(&efab_tcp_driver.ipid, r);
# else

  return oo_ipid_range_free( fd, &r );
# endif
}

ci_inline void ci_ipid_init_next( ci_netif_ipid_cb_t* ipid, int idx )
{
  /* initialise the next ID to use */
  ipid->range[ idx ].next =
    ipid->range[ idx ].base + CI_IPID_BLOCK_MASK;
}

/* add a range to the end of the array of ranges for this netif
 * and initialise the record 
 * returns 0 for success else failed */
ci_inline int ci_ipid_range_add( ci_netif_ipid_cb_t* ipid, int range )
{
  ci_assert(ipid);

  if( CI_LIKELY( range >= 0 )) {
    ci_assert( (range+CI_IPID_BLOCK_MASK) <0x10000);
    ci_assert(ipid->max_index < (CI_IPID_BLOCK_COUNT - 1));
    ci_assert(ipid->max_index < CI_TP_IPID_RANGES);
	      
    ipid->range[ipid->max_index].base = (ci_uint16)range;
    ci_ipid_init_next( ipid, ipid->max_index );
    ++ipid->max_index;
    LOG_IP(ci_log( LPF "range_add: block %x at slot %d", 
		 range, ipid->max_index - 1));
    return 0;
  }
  return -1;
}

#if CI_CFG_FULL_IP_ID_HANDLING
/* Function to handle the re-cycling of IP ID blocks.  This is 
 * only invoked when the inline allocator function determines
 * that it is required - should not be called directly.
 */
void ci_ipid_recycle( ci_netif* ni, ci_fd_t fd )
{
  ci_netif_ipid_cb_t* ipid;

  ci_assert(ni);
  ipid = NI_IPID(ni);

  LOG_IP(ci_log( LPF "recycle: curr %d max %d",
		 ipid->current_index, ipid->max_index )); 
  ci_assert( ipid->current_index >= 0 );
  ci_assert( ipid->current_index < ipid->max_index );
  /* re-initialise the current block */
  ci_ipid_init_next( ipid, ipid->current_index );
  
  /* Are we restarting the range loop? */
  if( ++ipid->current_index == ipid->max_index ) {
    long now = ci_ip_time_now(ni);
    long diff = now - ipid->loop_start_time;

    /* If we got back here too quickly we have to (try) to get
     * some more IDs */
    if(diff < CI_IPID_MIN_CYCLE_TIME ) {
      /* Try to get a new range and add it to the list
       * If we get another block - use it right now & do not set the
       * start time (to see if this additional block does the trick)
       */
      LOG_IP(ci_log(LPF "recycle: we're busy - need another block"));
      if( (ipid->max_index == (CI_TP_IPID_RANGES - 1)) ||
	  ci_ipid_range_add( ipid, ci_ipid_range_get(ni, fd) ) ) {
	/* tough luck - no more to be had, just have to go around
	 * again & hope it doesn't cause a fragment re-assembly prob.  */
	ipid->low_use_start_time = now;
	ipid->current_index = 0;
      } 
    } else {
      /* always go back to the start of the ranges we have */
      ipid->current_index = 0;
      ipid->loop_start_time = now;  /* note when we did this */

      if( ( diff >= CI_IPID_MAX_CYCLE_TIME ) &&
	  ( ipid->max_index > 1 ) ) {
	/* we may be able to give a range back, if not we leave the 
	 * the low-use start time alone for next time we come here */
	if( (now - ipid->low_use_start_time) >=
		 CI_IPID_LOW_USE_TIME) {
	  /* release one block */
	  LOG_IP(ci_log(LPF "recycle: not so busy, release one block"));
	  ci_ipid_range_release( ni, fd, 
		 (ci_int32)ipid->range[ --ipid->max_index ].base);
	ipid->low_use_start_time = now;
	}
      } else {
	ipid->low_use_start_time = now;
      }	
    }
  }
}
#endif /* CI_CFG_FULL_IP_ID_HANDLING */

/* Set-up the IPIDs for netif [ni].  
 * Called from ci_netif_ctor() in netif_init.c.
 * \return 0 - success, else -ENOMEM if no addresses available.
 *
 * READ ME - IT'S IMPORTANT
 *
 * In the beta this function WILL FAIL cleanly if the IDs in the
 * char driver have been exhausted.  In that instance we MUST fail
 * the netif construction as well as, for efficiency, the IP ID 
 * allocator does NOT check that we have at least one block of 
 * addresses.
 */
int ci_ipid_ctor( ci_netif* ni, ci_fd_t fd )
{
  ci_netif_ipid_cb_t* ipid;
  int rc;

  ci_assert(ni);

  ipid = NI_IPID(ni);
  memset( ipid, 0, sizeof(*ipid));

#if CI_CFG_NO_IP_ID_FAILURE
  if( 0 > (rc = ci_ipid_range_get(ni, fd)) ) {
    ipid->no_free = 1; /* skip block 0 in dtor */
    rc = CI_IPID_MIN;  /* just use range 0 anyway */
  }
#else
  CI_TRY_RET( rc = ci_ipid_range_get(ni, fd) );
#endif

  ci_ipid_range_add( ipid, rc );

#if CI_CFG_FULL_IP_ID_HANDLING==0
  ipid->base = ipid->range[0].base;
  ipid->next = 0;
#endif

  ipid->loop_start_time =
    ipid->low_use_start_time = ci_ip_time_now(ni);
  return 0;
}


void ci_ipid_dtor( ci_netif* ni, ci_fd_t fd )
{
  ci_netif_ipid_cb_t* ipid;
  ci_assert(ni);
  ipid = NI_IPID(ni);
  ci_assert( ipid->max_index >= 0 && 
	     ipid->max_index < CI_TP_IPID_RANGES );

#if CI_CFG_NO_IP_ID_FAILURE
  /* frees (max_index - 1), may omit record 0 if
   * we had a problem with the initial allocation */
  while( ipid->max_index-- > ipid->no_free ) {
#else
  /* frees (max_index - 1) */
  while( ipid->max_index-- ) {
#endif
    ci_assert( ipid->range[ipid->max_index].base <= 
	       (ci_uint16)(0x10000 - CI_IPID_BLOCK_LENGTH) );
    ci_assert( !(ipid->range[ipid->max_index].base & 
		CI_IPID_BLOCK_MASK));
    LOG_IP(ci_log(LPF "dtor: release range %#x (%d)", 
		  ipid->range[ipid->max_index ].base,
		  ipid->max_index));
    ci_ipid_range_release( ni, fd, 
              (ci_int32)ipid->range[ipid->max_index ].base );
  }
    
}


#if CI_CFG_FULL_IP_ID_HANDLING && !defined(NDEBUG)

/* called from ci_netif_state_assert_valid() in netif.c */
void ci_ipid_assert_valid(ci_netif* ni, const char* file, int line)
{
  int ctr;
  ci_netif_ipid_cb_t* ipid;

  verify(ni);
  ipid = NI_IPID(ni);

  verify( ipid->max_index >= 0 && 
	     ipid->max_index < CI_TP_IPID_RANGES );

  verify( ipid->current_index >=0 &&
	     ipid->current_index < ipid->max_index );

  verify( ipid->low_use_start_time <= 
	     ipid->loop_start_time );

  for( ctr = 0; ctr < ipid->max_index; ctr++ ) {
    verify( ipid->range[ctr].base <= 
	       (ci_uint16)(0x10000 - CI_IPID_BLOCK_LENGTH) );
    verify( !(ipid->range[ctr].base & CI_IPID_BLOCK_MASK) );
    verify( ipid->range[ctr].next >= ipid->range[ctr].base );
    if( ctr != ipid->current_index )
      verify( ipid->range[ctr].next == 
	      ipid->range[ctr].base + CI_IPID_BLOCK_MASK );
    else
      verify( ipid->range[ctr].next <= 
	      ipid->range[ctr].base + CI_IPID_BLOCK_MASK );
  }
}

#endif


/*! \cidoxg_end */
