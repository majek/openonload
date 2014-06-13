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
** <L5_PRIVATE L5_HEADER >
** \author  as
**  \brief  Templated sends definitions
**   \date  2013/08/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_tmpl_types */

#ifndef __CI_INTERNAL_TMPL_TYPES_H__
#define __CI_INTERNAL_TMPL_TYPES_H__


struct oo_msg_template {
  /* To verify subsequent templated calls are used with the same socket */
  oo_sp    oomt_sock_id;

  /* The interface that we have PIO space allocated in. */
  ci_int32 oomt_intf_i;

  /* The offset into the PIO region this templated send is using */
  ci_int32 oomt_pio_offset;

  /* Size of the PIO region this templated send is using */
  ci_int32 oomt_pio_order;

  /* For chaining up templated sends on a socket */
  oo_pkt_p oomt_next_pkt_id;
};


extern void ci_tcp_tmpl_free_all(ci_netif* ni, ci_tcp_state* ts);
extern void ci_tcp_tmpl_handle_nic_reset(ci_netif* ni);

#endif /* __CI_INTERNAL_TMPL_TYPES_H__ */

/*! \cidoxg_end */
