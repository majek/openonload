/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane O/S protocol support definitions
**   \date  2005/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_cplane_prot */

#ifndef __CI_DRIVER_EFAB_CPLANE_PROT_H__
#define __CI_DRIVER_EFAB_CPLANE_PROT_H__

#ifndef __ci_driver__
#error "this header is driver-only"
#endif

#include <onload/cplane_prot_types.h>
#include <ci/compat.h>
#include <ci/net/arp.h>


#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility push(default)
#endif

/* Number of deferred MAC-requiring packets */
#define CPLANE_PROT_PKTBUF_COUNT 128


/*----------------------------------------------------------------------------
 * O/S-specific Operations
 *---------------------------------------------------------------------------*/

/*! Request IP resolution and queue the ip packet that triggered it
 *  See the definition of cicppl_pktbuf_pend_send 
 */
extern int /*rc*/
cicpplos_pktbuf_defer_send(struct oo_cplane_handle* cp,
			   ci_addr_t addr, int buf_pktid,
                           ci_ifid_t ifindex, int in_atomic_context);

/*----------------------------------------------------------------------------
 * Pooled packet buffer support Operations
 *---------------------------------------------------------------------------*/

/*! Check that a packet buffer ID is valid */
ci_inline int /* bool */
cicppl_pktbuf_is_valid_id(cicp_bufpool_t *pool, int id)
{   return (id >= 0 && id < CPLANE_PROT_PKTBUF_COUNT);
}

/*! Return address of the packet referred to by a packet buffer ID  */
extern struct cicp_bufpool_pkt *
cicppl_pktbuf_pkt(cicp_bufpool_t *pool, int id);

/*! Return ID of a new packet buffer */
extern int
cicppl_pktbuf_alloc(cicp_bufpool_t *pool);

/*! Free a packet buffer referred to by its ID */
extern void
cicppl_pktbuf_free(cicp_bufpool_t *pool, int id);




#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility pop
#endif

#endif /* __CI_DRIVER_EFAB_CPLANE_PROT_H__ */

/*! \cidoxg_end */

