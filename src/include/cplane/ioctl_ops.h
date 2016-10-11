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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane operation definitions
**   \date  2005/07/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_cplane_ops */

#ifndef __CI_INTERNAL_CPLANE_OPS_H__
#define __CI_INTERNAL_CPLANE_OPS_H__


/*----------------------------------------------------------------------------
 * System call interface
 *---------------------------------------------------------------------------*/

#ifdef __ci_driver__

#define CICP_SYSCALL extern
#define CICP_SYSBODY(_body) ;

#else /* not part of the driver - generate system calls */

#include <cplane/ioctl.h>
#include <cplane/ul_syscalls.h>

#define CICP_SYSCALL ci_inline
#define CICP_SYSBODY(_body) { _body }

#endif /* __ci_driver__ */




#ifdef __cplusplus
extern "C" {
#endif



/*----------------------------------------------------------------------------
 * address resolution MIB
 *---------------------------------------------------------------------------*/



/*!
 * Confirm that an address resolution table entry is known correct
 *
 * \param cplane_netif    the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ver             ARP entry to update
 * \param confirm         confirm or send an ARP request?
 *
 * Update STALE entry in ARP table.  If we do not know if the entry is
 * really valid, tell OS to re-validate it via ARP request.
 * If we know the entry is valid (UDP MSG_CONFIRM or TCP ACK received),
 * jusr tell OS the entry is OK.
 */
CICP_SYSCALL void
cicp_mac_update(cicp_handle_t *control_plane, cicp_mac_verinfo_t *ver, 
                ci_ip_addr_t ip, ci_ifid_t ifindex,
                const ci_uint8 *mac, int confirm)
CICP_SYSBODY(
    cp_mac_update_t op;

    op.ver = *ver;
    op.ip = ip;
    memcpy(&op.mac, mac, sizeof(op.mac));
    op.ifindex = ifindex;
    op.confirm = confirm;

    (void)cp_sys_ioctl(control_plane->fd, CICP_IOC_MAC_UPDATE, &op);
)




    
/*----------------------------------------------------------------------------
 * Control Plane user-visible information 
 *---------------------------------------------------------------------------*/

/*! Lookup details of a local (home) IP address.
 *
 * \param cplane_netif    the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ref_ip_be32     location of the IP home IP address to check
 * \param out_hwport      hardware port of the home LLAP interface 
 * \param out_ifindex     home LLAP interface ID
 * \param out_mac         MAC address of the home LLAP interface ID
 * \param out_mtu         MTU of the LLAP
 * \param out_encap       Encapsulation of the LLAP
 *
 * returns
 *   0 if \c *ref_ip_be32 is a local IP address
 *   -ENODATA if *ref_ip_be32 is not a local IP address
 *   -EINVAL if the corresponding LLAP could not be found
 *
 * NB. If duplicate IP addresses are present in the IPIF table, we return
 * info about the first one found.
 *
 * out_hwport, out_ifindex, out_mac, out_mtu and out_encap may be NULL.
 */
CICP_SYSCALL int /* rc */
cicp_user_find_home(cicp_handle_t *cplane_netif,
		    const ci_ip_addr_t *ref_ip_be32,
                    ci_hwport_id_t *out_hwport, 
                    ci_ifid_t *out_ifindex, ci_mac_addr_t *out_mac,
                    ci_mtu_t *out_mtu, cicp_encap_t *out_encap)
CICP_SYSBODY(
    cp_src_addr_checks_t op;
    int rc;

    CI_IP_ADDR_SET(&op.ip_be32, ref_ip_be32);
    rc = cp_sys_ioctl(cplane_netif->fd, CICP_IOC_USER_FIND_HOME, &op);
    if( rc != 0 )
      return -rc;
    
    if (out_hwport != NULL)
        *out_hwport = op.hwport;
    if (out_ifindex != NULL)
        *out_ifindex = op.ifindex;
    if (out_mac != NULL)
        CI_MAC_ADDR_SET(out_mac, op.mac);
    if (out_mtu != NULL)
        *out_mtu = op.mtu;
    if (out_encap != NULL)
        *out_encap = op.encap;

    return 0;
)


#ifdef __cplusplus
}
#endif



#endif /* __CI_INTERNAL_CPLANE_OPS_H__ */

/*! \cidoxg_end */
