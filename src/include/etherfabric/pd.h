/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2012-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Protection Domains for EtherFabric Virtual Interface HAL.
** \date      2015/02/16
** \copyright Copyright &copy; 2015 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_PD_H__
#define __EFAB_PD_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/* src/tool/solar_clusterd will need updating if you change this
 * enum */
/*! \brief Flags for a protection domain */
enum ef_pd_flags {
  /** Default flags */
  EF_PD_DEFAULT          = 0x0,
  /** Protection domain supports virtual filters */
  EF_PD_VF               = 0x1,
  /** Protection domain supports physical addressing mode */
  EF_PD_PHYS_MODE        = 0x2,
  /** Protection domain supports packed streams */
  EF_PD_RX_PACKED_STREAM = 0x4,  /* ef10 only */
  /** Protection domain supports virtual ports */
  EF_PD_VPORT            = 0x8,  /* ef10 only */
};


/*! \brief May be passed to ef_pd_alloc_with_vport() to indicate that the PD
 * is not associated with a particular VLAN.
 */
#define EF_PD_VLAN_NONE  -1


/*! \brief A protection domain */
typedef struct ef_pd {
  /** Flags for the protection domain */
  enum ef_pd_flags pd_flags;
  /** Resource ID of the protection domain */
  unsigned         pd_resource_id;
  /** Name of the interface associated with the protection domain */
  char*            pd_intf_name;

  /* Support for application clusters */
  /** Name of the application cluster associated with the protection domain */
  char*            pd_cluster_name;
  /** Socket for the application cluster associated with the protection
  **  domain */
  int              pd_cluster_sock;
  /** Driver handle for the application cluster associated with the protection
  **  domain */
  ef_driver_handle pd_cluster_dh;
  /** Resource ID of the virtual interface set for the application cluster
  **  associated with the protection domain */
  unsigned         pd_cluster_viset_resource_id;
} ef_pd;


/*! \brief Allocate a protection domain
**
** \param pd      Memory to use for the allocated protection domain.
** \param pd_dh   The ef_driver_handle to associate with the protection
**                domain.
** \param ifindex Index of the interface to use for the protection domain.
** \param flags   Flags to specify protection domain properties.
**
** \return 0 on success, or a negative error code.
**
** Allocate a protection domain.
**
** Allocates a 'protection domain' which specifies how memory should be
** protected for your VIs.
**
** \note If you are using a 'hardened' kernel (e.g. Gentoo-hardened) then
**       this is the first call which will probably fail. Currently, the
**       only workaround to this is to run as root.
**
** Use "if_nametoindex" to find the index of an interface, which needs to
** be the physical interface (i.e. eth2, not eth2.6 or bond0 or similar.)
*/
extern int ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh, int ifindex,
                       enum ef_pd_flags flags);


/*! \brief Allocate a protection domain, trying first from a cluster, and
**         then from an interface
**
** \param pd                   Memory to use for the allocated protection
**                             domain.
** \param pd_dh                The ef_driver_handle to associate with the
**                             protection domain.
** \param cluster_or_intf_name Name of cluster, or name of interface.
** \param flags                Flags to specify protection domain
**                             properties.
**
** \return 0 on success, or a negative error code.
**
** Allocate a protection domain, trying first from a cluster, and then from
** an interface.
*/
extern int ef_pd_alloc_by_name(ef_pd* pd, ef_driver_handle pd_dh,
                               const char* cluster_or_intf_name,
                               enum ef_pd_flags flags);


/*! \brief Allocate a protection domain with vport support
**
** \param pd        Memory to use for the allocated protection domain.
** \param pd_dh     The ef_driver_handle to associate with the protection
**                  domain.
** \param intf_name Name of interface to use for the protection domain.
** \param flags     Flags to specify protection domain properties.
** \param vlan_id   The vlan id to associate with the protection domain.
**
** \return 0 on success, or a negative error code.
**
** Allocate a protection domain with vport support.
*/
extern int ef_pd_alloc_with_vport(ef_pd* pd, ef_driver_handle pd_dh,
                                  const char* intf_name,
                                  enum ef_pd_flags flags, int vlan_id);

/*! \brief Look up the interface being used by the protection domain
**
** \param pd Memory used by the protection domain.
**
** \return The interface being used by the protection domain.
**
** Look up the interface being used by the protection domain.
*/
extern const char* ef_pd_interface_name(ef_pd* pd);

/*! \brief Free a protection domain
**
** \param pd    Memory used by the protection domain.
** \param pd_dh The ef_driver_handle associated with the protection domain.
**
** \return 0 on success, or a negative error code.
**
** Free a protection domain.
**
** To free up all resources, you must also close the associated driver
** handle.
**
** You should call this when you're finished; although they will be cleaned
** up when the application exits, if you don't.
**
** Be very sure that you don't try and re-use the vi/pd/driver structure
** after it has been freed.
*/
extern int ef_pd_free(ef_pd* pd, ef_driver_handle pd_dh);

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PD_H__ */
