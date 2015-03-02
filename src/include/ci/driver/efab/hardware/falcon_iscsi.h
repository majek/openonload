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
   ** \author  mjs
   **  \brief  EtherFabric NIC - EFXXXX (aka Falcon) iSCSI interface
   **   \date  2006/05
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
      *//*
        \************************************************************************* */

/*! \cidoxg_include_ci_driver_efab_hardware  */

#ifndef __CI_DRIVER_EFAB_HARDWARE_FALCON_ISCSI_H__
#define __CI_DRIVER_EFAB_HARDWARE_FALCON_ISCSI_H__

/*----------------------------------------------------------------------------
 *
 * Interface to hardware configuration for iSCSI digest offload
 *
 *---------------------------------------------------------------------------*/

extern void falcon_iscsi_update_tx_q_flags(struct efhw_nic * nic, uint dmaq,
					   uint flags);

extern void falcon_iscsi_update_rx_q_flags(struct efhw_nic * nic, uint dmaq,
					   uint flags);

#endif /* __CI_DRIVER_EFAB_HARDWARE_FALCON_ISCSI_H__ */

/*! \cidoxg_end */
