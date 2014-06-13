/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
** \author  ctk
**  \brief  Socket options for setsockopt and getsockopt
**          compatability layer
**   \date  2004/1/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_SOCKOPTS_H__
#define __CI_NET_SOCKOPTS_H__

/* setsockopt and getsockopt option numbers for compatability layer */

#define __SO_L5_BASE       0x55500
#define CI_SO_L5_GET_SOCK_STATS       (__SO_L5_BASE+0x01)
#define CI_SO_L5_GET_NETIF_STATS      (__SO_L5_BASE+0x02)
#define CI_SO_L5_DUMP_SOCK_STATS      (__SO_L5_BASE+0x03)
#define CI_SO_L5_DUMP_NETIF_STATS     (__SO_L5_BASE+0x04)
#define CI_SO_L5_CONFIG_SOCK_STATS    (__SO_L5_BASE+0x05)
#define CI_SO_L5_CONFIG_NETIF_STATS   (__SO_L5_BASE+0x06)


/* CI_UDP_ENCAP types. Encapsulation for IPSec/NAT */
#define CI_UDP_ENCAP_ESPINUDP_NON_IKE 1
#define CI_UDP_ENCAP_ESPINUDP         2


/* For CI_TCP_INFO */

#define CI_TCPI_OPT_TIMESTAMPS  1
#define CI_TCPI_OPT_SACK        2
#define CI_TCPI_OPT_WSCALE      4
#define CI_TCPI_OPT_ECN         8


enum ci_tcp_ca_state
{
  CI_TCP_CA_Open = 0,
#define CI_TCPF_CA_Open	(1<<CI_TCP_CA_Open)
  CI_TCP_CA_Disorder = 1,
#define CI_TCPF_CA_Disorder (1<<CI_TCP_CA_Disorder)
  CI_TCP_CA_CWR = 2,
#define CI_TCPF_CA_CWR	(1<<CI_TCP_CA_CWR)
  CI_TCP_CA_Recovery = 3,
#define CI_TCPF_CA_Recovery (1<<CI_TCP_CA_Recovery)
  CI_TCP_CA_Loss = 4
#define CI_TCPF_CA_Loss	(1<<CI_TCP_CA_Loss)
};


struct ci_tcp_info
{
  ci_uint8  tcpi_state;
  ci_uint8  tcpi_ca_state;
  ci_uint8  tcpi_retransmits;
  ci_uint8  tcpi_probes;
  ci_uint8  tcpi_backoff;
  ci_uint8  tcpi_options;
  ci_uint8  tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

  ci_uint32 tcpi_rto;
  ci_uint32 tcpi_ato;
  ci_uint32 tcpi_snd_mss;
  ci_uint32 tcpi_rcv_mss;

  ci_uint32 tcpi_unacked;
  ci_uint32 tcpi_sacked;
  ci_uint32 tcpi_lost;
  ci_uint32 tcpi_retrans;
  ci_uint32 tcpi_fackets;

  ci_uint32 tcpi_last_data_sent;
  ci_uint32 tcpi_last_ack_sent;
  ci_uint32 tcpi_last_data_recv;
  ci_uint32 tcpi_last_ack_recv;

  ci_uint32 tcpi_pmtu;
  ci_uint32 tcpi_rcv_ssthresh;
  ci_uint32 tcpi_rtt;
  ci_uint32 tcpi_rttvar;
  ci_uint32 tcpi_snd_ssthresh;
  ci_uint32 tcpi_snd_cwnd;
  ci_uint32 tcpi_advmss;
  ci_uint32 tcpi_reordering;
};

#endif /* __CI_NET_SOCKOPTS_H__ */

/*! \cidoxg_end */
