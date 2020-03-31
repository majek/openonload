/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  Paul Emberson <pemberson@solarflare.com>
**  \brief  Configure which errors cause rx discard
**   \date  2016/01
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
#include <etherfabric/vi.h>
#include "ef_vi_internal.h"
#include <ci/tools/byteorder.h>

static int
falcon_ef_vi_receive_set_discards(ef_vi* vi, unsigned discard_err_flags)
{
  /* Initialise with non-maskable errors */
  uint64_t mask = 1LL << RX_EV_FRM_TRUNC_LBN
                  | 1LL << RX_EV_BUF_OWNER_ID_ERR_LBN;

  /* Inner checksum discard flags are ignored */
  if( discard_err_flags & EF_VI_DISCARD_RX_TOBE_DISC )
    mask |= 1LL << RX_EV_TOBE_DISC_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_L4_CSUM_ERR )
    mask |= 1LL << RX_EV_TCP_UDP_CHKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_L3_CSUM_ERR )
    mask |= 1LL << RX_EV_IP_HDR_CHKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_ETH_FCS_ERR )
    mask |= 1LL << RX_EV_ETH_CRC_ERR_LBN;

  vi->rx_discard_mask = CI_BSWAPC_LE64(mask);

  return 0;
}


static int
ef10_ef_vi_receive_set_discards(ef_vi* vi, unsigned discard_err_flags)
{
  uint64_t mask = 0;

  if( discard_err_flags & EF_VI_DISCARD_RX_ETH_LEN_ERR )
    mask |= 1LL << ESF_DZ_RX_ECC_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_L4_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_TCPUDP_CKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_L3_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_IPCKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_INNER_L4_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_INNER_TCPUDP_CKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_INNER_L3_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_INNER_IPCKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_ETH_FCS_ERR )
    mask |= 1LL << ESF_DZ_RX_ECRC_ERR_LBN;

  vi->rx_discard_mask = CI_BSWAPC_LE64(mask);
  return 0;
}


int
ef_vi_receive_set_discards(ef_vi* vi, unsigned discard_err_flags)
{
  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_FALCON:
    return falcon_ef_vi_receive_set_discards(vi, discard_err_flags);
  case EF_VI_ARCH_EF10:
    return ef10_ef_vi_receive_set_discards(vi, discard_err_flags);
  default:
    EF_VI_BUG_ON(1);
    return -EINVAL;
  }
}

