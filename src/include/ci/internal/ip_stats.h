/*
** Copyright 2005-2018  Solarflare Communications Inc.
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
** \author  stg
**  \brief  Statistics support internal to the IP library
**   \date  2004/07/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_include_ci_internal  */
  
#ifndef __CI_INTERNAL_IP_STATS_H__
#define __CI_INTERNAL_IP_STATS_H__


/* Define CI_APPLICATION_USE_STATS before including this file
 * to allow it to be used in a non-CI calling application 
 * (which is getting data via the sockopt mechanism) */
#if defined (CI_INSTRUMENT_APPLICATION) || defined (CI_APPLICATION_USE_STATS)
/* Use only generic types */
# define __NI_STRUCT__ void
# define __STATE_STRUCT__ void
# define __TIME_TYPE__ long
# define CI_IP_STATS_TYPE unsigned

#else
/* Can use internal types */
# include <onload/primitive_types.h>
# define __NI_STRUCT__ struct ci_netif_s
  struct ci_netif_s;
# define __STATE_STRUCT__ struct ci_tcp_state_s
  struct ci_tcp_state_s;
# define __TIME_TYPE__ ci_iptime_t
# define CI_IP_STATS_TYPE ci_uint32
#endif

#define CI_IP_STATS_MIN_VAL 0
#define CI_IP_STATS_MAX_VAL 0xffffffff

/** IPv4 group of statistics reported in /proc/net/snmp */
typedef struct {
#define OO_STAT(desc, type, name, kind)  type name CI_ALIGN(sizeof(type));
#include <ci/internal/ipv4_stats_count_def.h>
#undef OO_STAT
} ci_ipv4_stats_count;
/** this macro is used to get the number of fields in
 * @e ci_ipv4_stats_count structure */
#define CI_IPV4_STATS_COUNT_LEN \
  (sizeof(ci_ipv4_stats_count)/sizeof( CI_IP_STATS_TYPE))

/** ICMP group of statistics reported in /proc/net/snmp */
typedef struct {
  /** the number of invalid ICMP messages received */
  CI_IP_STATS_TYPE icmp_in_msgs;
  /** the number of incorrect ICMP messages received */
  CI_IP_STATS_TYPE icmp_in_errs;
  /** the number of ICMP Destination Unreachable messages received */
  CI_IP_STATS_TYPE icmp_in_dest_unreachs;
  /** the number of ICMP Time Exceeded messages received */
  CI_IP_STATS_TYPE icmp_in_time_excds;
  /** the number of ICMP Parameter Problem messages received */
  CI_IP_STATS_TYPE icmp_in_parm_probs;
  /** the number of ICMP Source Quench messages received */
  CI_IP_STATS_TYPE icmp_in_src_quenchs;
  /** the number of ICMP Redirect messages received */
  CI_IP_STATS_TYPE icmp_in_redirects;
  /** the number of ICMP Echo (request) messages received */
  CI_IP_STATS_TYPE icmp_in_echos;
  /** the number of ICMP Echo (reply) messages received */
  CI_IP_STATS_TYPE icmp_in_echo_reps;
  /** the number of ICMP Timestamp (request) messages received */
  CI_IP_STATS_TYPE icmp_in_timestamps;
  /** the number of ICMP Timestamp (reply) messages received */
  CI_IP_STATS_TYPE icmp_in_timestamp_reps;
  /** the number of ICMP Address Mask (request) messages received */
  CI_IP_STATS_TYPE icmp_in_addr_masks;
  /** the number of ICMP Address Mask (reply) messages received */
  CI_IP_STATS_TYPE icmp_in_addr_mask_reps;

  /** the total number of ICMP messages which this entity 
   * attempted to send */
  CI_IP_STATS_TYPE icmp_out_msgs;
  /** the number of ICMP messages which this entity did not send due to
   * problems discovered within ICMP */
  CI_IP_STATS_TYPE icmp_out_errs;
  /** the number of ICMP Destination Unreachable messages sent */
  CI_IP_STATS_TYPE icmp_out_dest_unreachs;
  /** the number of ICMP Time Exceeded messages sent */
  CI_IP_STATS_TYPE icmp_out_time_excds;
  /** the number of ICMP Parameter Problem messages sent */
  CI_IP_STATS_TYPE icmp_out_parm_probs;
  /** the number of ICMP Source Quench messages sent */
  CI_IP_STATS_TYPE icmp_out_src_quenchs;
  /** the number of ICMP Redirect messages sent */
  CI_IP_STATS_TYPE icmp_out_redirects;
  /** the number of ICMP Echo (request) messages sent */
  CI_IP_STATS_TYPE icmp_out_echos;
  /** the number of ICMP Echo (reply) messages sent */
  CI_IP_STATS_TYPE icmp_out_echo_reps;
  /** the number of ICMP Timestamp (request) messages sent */
  CI_IP_STATS_TYPE icmp_out_timestamps;
  /** the number of ICMP Timestamp (reply) messages sent */
  CI_IP_STATS_TYPE icmp_out_timestamp_reps;
  /** the number of ICMP Address Mask (request) messages sent */
  CI_IP_STATS_TYPE icmp_out_addr_masks;
  /** the number of ICMP Address Mask (reply) messages sent */
  CI_IP_STATS_TYPE icmp_out_addr_mask_reps;
} ci_icmp_stats_count;
/** this macro is used to get the number of fields in
 * @e ci_icmp_stats_count structure */
#define CI_ICMP_STATS_COUNT_LEN \
  (sizeof(ci_icmp_stats_count)/sizeof( CI_IP_STATS_TYPE))

/** TCP group of statistics reported in /proc/net/snmp */
typedef struct {
#define OO_STAT(desc, type, name, kind)  type name CI_ALIGN(sizeof(type));
#include <ci/internal/tcp_stats_count_def.h>
#undef OO_STAT
} ci_tcp_stats_count;

/** UDP group of statistics reported in /proc/net/snmp */
typedef struct {
#define OO_STAT(desc, type, name, kind)  type name CI_ALIGN(sizeof(type));
#include <ci/internal/udp_stats_count_def.h>
#undef OO_STAT
} ci_udp_stats_count;
/** this macro is used to get the number of fields in
 * @p ci_udp_stats_count structure */
#define CI_UDP_STATS_COUNT_LEN \
    (sizeof(ci_udp_stats_count)/sizeof( CI_IP_STATS_TYPE))

/** statistics reported in /proc/net/netstat */
typedef struct {
#define OO_STAT(desc, type, name, kind)  type name CI_ALIGN(sizeof(type));
#include <ci/internal/tcp_ext_stats_count_def.h>
#undef OO_STAT
} ci_tcp_ext_stats_count;


/** main ip statistics structure */
typedef struct {
  __TIME_TYPE__ now;
  ci_ipv4_stats_count     ipv4;    /**< /proc/net/snmp, IPv4 group */
  ci_icmp_stats_count     icmp;    /**< /proc/net/snmp, ICMP group */
  ci_tcp_stats_count      tcp;     /**< /proc/net/snmp, TCP group  */
  ci_udp_stats_count      udp;     /**< /proc/net/snmp, UDP group  */
  ci_tcp_ext_stats_count  tcp_ext; /**< /proc/net/netstat          */
} ci_ip_stats;

/** per socket statistics structure */
typedef struct {
  /** number of times retransmission timer expires */
  CI_IP_STATS_TYPE rtto;
  /** not specified what this parameter means, explanation from L5 team
   * is missed */
  CI_IP_STATS_TYPE cong;

  /** the total number of accepted bytes on the L5-socket */
  CI_IP_STATS_TYPE rx_byte;
  /** the total number of accepted IP packets on the L5-socket */
  CI_IP_STATS_TYPE rx_pkt;
  /** the number of rx segments processed on solw path */
  CI_IP_STATS_TYPE rx_slowpath;
  /** the number of segments came with unacceptable sequence number */
  CI_IP_STATS_TYPE rx_seqerr;
  /** the number of segments that acknowledge sequence numbers of 
   * bytes haven't sent from the connection */
  CI_IP_STATS_TYPE rx_ackerr;
  /** the nuber of segments rejected due to PAWS algorithm */
  CI_IP_STATS_TYPE rx_pawserr;
  /** the total number of duplicate ACK segments received */
  CI_IP_STATS_TYPE rx_dupack;
  /** the number of duplicate ACK segments that lead to run fast 
   * retransmit/recovery algorithm */
  CI_IP_STATS_TYPE rx_dupack_frec;
  /** the number of duplicate ACK segments received in congested state
   * and with turned on fast retransmit/recovery algorithm */
  CI_IP_STATS_TYPE rx_dupack_congfrec;
  /** the number of ACKs received that advertise zero window */
  CI_IP_STATS_TYPE rx_zwin;
  /** the number of out-of-order segments received on the connection */
  CI_IP_STATS_TYPE rx_ooo;
  /** the nuber of incorrect SYNs received in SYN-REECEIVED state */
  CI_IP_STATS_TYPE rx_badsyn;
  /** the number of SYNs whose sequence number dades not fit in 
   * advertised window */
  CI_IP_STATS_TYPE rx_badsynseq;
  /** the numbber of duplicated SYNs received in SYN-RECEIVED state */
  CI_IP_STATS_TYPE rx_syndup;
  /** the number of SYN ACKs with incorrect ACK field */
  CI_IP_STATS_TYPE rx_synbadack;
  /** the number of segments received with ACK bit reset while being 
   * in SYN-RECEIVED */
  CI_IP_STATS_TYPE rx_synnonack;
  /** the number of times L5-socket was sleeping while waiting for 
   * incoming data */
  CI_IP_STATS_TYPE rx_sleep;
  /** the number of times L5-socket was pooling while waiting for 
   * invoming data */
  CI_IP_STATS_TYPE rx_wait;

  /** the number of bytes sent to the connection */
  CI_IP_STATS_TYPE tx_byte;
  /** the number of segments sent to the connection */
  CI_IP_STATS_TYPE tx_pkt;
  /** It is not specified what this parameter means */
  CI_IP_STATS_TYPE tx_slowpath;
  /** the number of times packets were retransmitted */
  CI_IP_STATS_TYPE tx_retrans_pkt;
  /** number of times L5-socket was sleeping while waiting for a chance to
   * send some data to the socket */
  CI_IP_STATS_TYPE tx_sleep;
  /** the number of times any data cannot be  immediately sent from
   * L5-socket because tx queue id full or there is no free buffers 
   * for the data */
  CI_IP_STATS_TYPE tx_stuck;

} ci_ip_sock_stats_count;
/** this macro is used to get the number of fields in
 * @p ci_ip_sock_stats_count */
#define CI_IP_SOCK_STATS_COUNT_LEN \
  (sizeof(ci_ip_sock_stats_count)/sizeof( CI_IP_STATS_TYPE))

/* extend this list with any fields that are needed as current/min/max */
typedef struct {
  /** receiver window */
  CI_IP_STATS_TYPE rx_win;
  /** receiver windoww scale */
  CI_IP_STATS_TYPE rx_wscl;
  /** sender window (window advertised in SYN) */
  CI_IP_STATS_TYPE tx_win;
  /** sender window scale */
  CI_IP_STATS_TYPE tx_wscl;
  /** round trip time value */
  CI_IP_STATS_TYPE rtt;
  /** smoothed round trip time value */
  CI_IP_STATS_TYPE srtt;
  /** retransmit timeout value */
  CI_IP_STATS_TYPE rto;
  /** the number of tx buffers available */
  CI_IP_STATS_TYPE tx_buffree;
  /** the time socket spent sleeping while waiting for a chance to
   * send some data to the socket */
  CI_IP_STATS_TYPE tx_sleeptime;
  /** the time socket spent sleeping while waiting for invoming data */
  CI_IP_STATS_TYPE rx_sleeptime;
} ci_ip_sock_stats_range;
/** this macro is used to get the number of fields in
 * @p ci_ip_sock_stats_range */
#define CI_IP_SOCK_STATS_RANGE_LEN \
  (sizeof(ci_ip_sock_stats_min)/sizeof( CI_IP_STATS_TYPE))

typedef ci_ip_sock_stats_range ci_ip_sock_stats_actual;
/** this macro is used to get the number of fields in
 * @p ci_ip_sock_stats_actual structure */
#define CI_IP_SOCK_STATS_ACTUAL_LEN \
  (sizeof(ci_ip_sock_stats_actual)/sizeof( CI_IP_STATS_TYPE))

typedef ci_ip_sock_stats_range ci_ip_sock_stats_min;
/** this macro is used to get the number of fields in
 * @p ci_ip_sock_stats_min structure */
#define CI_IP_SOCK_STATS_MIN_LEN \
  (sizeof(ci_ip_sock_stats_min)/sizeof( CI_IP_STATS_TYPE))

typedef ci_ip_sock_stats_range ci_ip_sock_stats_max;
/** this macro is used to get the number of fields in
 * @p ci_ip_sock_stats_max structure */
#define CI_IP_SOCK_STATS_MAX_LEN \
  (sizeof(ci_ip_sock_stats_max)/sizeof( CI_IP_STATS_TYPE))

/* Main structure for stats */
typedef struct ci_ip_sock_stats_s {
  __TIME_TYPE__ now;
  ci_ip_sock_stats_count count;
  ci_ip_sock_stats_range actual;
  ci_ip_sock_stats_range min;
  ci_ip_sock_stats_range max;
} ci_ip_sock_stats;


/* display types (in tcp_state.stats_text & as a 
 * param to timer handler */
typedef enum {
  CI_IP_STATS_OUTPUT_NONE = 0,
  CI_IP_STATS_OUTPUT_TEXT = 1,
  CI_IP_STATS_OUTPUT_XML  = 2,
} ci_ip_stats_output_fmt;

#define CI_IP_STATS_OUTPUT_DEFAULT CI_IP_STATS_OUTPUT_NONE


/* action codes passed to ci_tcp_stats_action() - the "end" reason
 * will also stop the timer, so there should be no further timeout
 * logs. After "end".  The "start" reason 
 */

typedef enum {
  CI_IP_STATS_START, /**< start gathering stats */
  CI_IP_STATS_END,   /**< stop gathering stats */
  CI_IP_STATS_FLUSH, /**< merge current snapshot with cummulative statistics */
  CI_IP_STATS_GET,   /**< get the current value of statistics gathered
                          and do CI_IP_STATS_FLASH */
  CI_IP_STATS_REPORT,/**< generate report in text or xml format */
} ci_ip_stats_action_type;

/* structure that is used in sockopts to control statistics gathering */
typedef struct ci_ip_stats_config {
  ci_ip_stats_action_type     action_type; /**< action to perform */
  ci_ip_stats_output_fmt      output_fmt;  /**< Text or XML output format */
  unsigned                    timeout;     /**< new timeout for statistics timer */
} ci_ip_stats_config;


#endif /*  __CI_INTERNAL_IP_STATS_H__ */
/*! \cidoxg_end */
