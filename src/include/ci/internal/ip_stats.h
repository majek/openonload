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
  /** the total number of recieved datagrams */
  CI_IP_STATS_TYPE in_recvs;
  
  /** the number of datagrams discarded due to errors in their IP headers */
  CI_IP_STATS_TYPE in_hdr_errs;
  
  /** the number of datagrams discarded due to value of IP destination 
   * adress */
  CI_IP_STATS_TYPE in_addr_errs;
  
  /** the number of forwarded datagrams */
  CI_IP_STATS_TYPE forw_dgrams;
  
  /** the number of datagrams destined to unknown or unsupported 
   * protocols */
  CI_IP_STATS_TYPE in_unknown_protos;
  
  /** the number of input IP datagrams for which no problems were 
   * encountered to prevent their continued processing, but which 
   * were discarded (e.g., for lack of buffer space) */
  CI_IP_STATS_TYPE in_discards;
  
  /** the total numver of input datagrams successfully delivered to IP 
   * user-protocols */
  CI_IP_STATS_TYPE in_delivers;
  
  /** the total numver of IP datagrams which local IP user-protocols 
   * (including ICMP) supplied to IP in request for transmission */
  CI_IP_STATS_TYPE out_requests;
  
  /** the number of output IP datagrams for which no problems
   * were ecountered to prevent their countinued processing, but
   * which were discarded (e.g., for lack of buffer space */
  CI_IP_STATS_TYPE out_discards;

  /** the number of IP datagrams discarded because no route could
   * be found to transmit them to their destination */
  CI_IP_STATS_TYPE out_no_routes;

  /** this set of counters deal with IP fragmentation, which is not
   * supported, so they should be zero [RFC1213]*/
  CI_IP_STATS_TYPE reasm_timeout;
  CI_IP_STATS_TYPE reasm_reqds;
  CI_IP_STATS_TYPE reasm_oks;
  CI_IP_STATS_TYPE reasm_fails;
  CI_IP_STATS_TYPE frag_oks;
  CI_IP_STATS_TYPE frag_fails;
  CI_IP_STATS_TYPE frag_creates;
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
  /** the number of times TCP connections have made a direct 
   * transition to the @e SYN-SENT state from the @e CLOSED state */
  CI_IP_STATS_TYPE tcp_active_opens;

  /** the number of times TCP connections have made a direct
   * transition to the @e SYN-RCVD state from the @e LISTEN state */
  CI_IP_STATS_TYPE tcp_passive_opens;

  /** the number of times TCP connection have made a direct
   * transition to the @e CLOSED state from the @e SYN-SENT state or the 
   * @e SYN-RCVD state, plus the number of times TCP connections have 
   * made a direct transition to the @e LISTEN state from 
   * the @e SYN-RCVD state */
  CI_IP_STATS_TYPE tcp_attempt_fails;

  /** the number of times TCP connections have made a direct transition to 
   * the CLOSED state from either the @e ESTABLISHED state or the @e CLOSE-WAIT 
   * state */
  CI_IP_STATS_TYPE tcp_estab_resets;

  /** the number of TCP connections for which the current state is either
   * @e ESTABLISHED or @e CLOSE-WAIT */
  CI_IP_STATS_TYPE tcp_curr_estab;

  /** the total number of segments received, including those 
   * received in error */
  CI_IP_STATS_TYPE tcp_in_segs;

  /** the total number of segments sent, including those on current 
   * connections but excluding those containing only retransmitted octets */
  CI_IP_STATS_TYPE tcp_out_segs;

  /** the total number of segments retransmitted */
  CI_IP_STATS_TYPE tcp_retran_segs;

  /** the number of erroneous segments received */
  CI_IP_STATS_TYPE tcp_in_errs;

  /** the number of RST segments sent */
  CI_IP_STATS_TYPE tcp_out_rsts;
} ci_tcp_stats_count;
/** this macro is used to get the number of fields in
 * @p ci_tcp_stats_count structure */
#define CI_TCP_STATS_COUNT_LEN \
  (sizeof(ci_tcp_stats_count)/sizeof( CI_IP_STATS_TYPE))

/** UDP group of statistics reported in /proc/net/snmp */
typedef struct {
  /** the total number of UDP datagrams delivered to UDP users */
  CI_IP_STATS_TYPE udp_in_dgrams;
  
  /** the total number of received UDP datagrams for which
   * there was no application at the destination port */
  CI_IP_STATS_TYPE udp_no_ports;

  /** the number of received UDP datagrams that could not be delivered
   * for reason other than the lack of an application at the destination 
   * port */
  CI_IP_STATS_TYPE udp_in_errs;

  /** the total number of UDP datagrams sent from this entity */
  CI_IP_STATS_TYPE udp_out_dgrams;
} ci_udp_stats_count;
/** this macro is used to get the number of fields in
 * @p ci_udp_stats_count structure */
#define CI_UDP_STATS_COUNT_LEN \
    (sizeof(ci_udp_stats_count)/sizeof( CI_IP_STATS_TYPE))

/** statistics reported in /proc/net/netstat */
typedef struct {
  /** the number of SYN/ACKs sent with ISN chosen according to SYN 
   * cookie technique */
  CI_IP_STATS_TYPE syncookies_sent; 

  /** the number of times syncookie in incoming ACK segments are accessed */
  CI_IP_STATS_TYPE syncookies_recv;

  /** the number of times syncookie in incoming ACK segments fail 
   * validation */
  CI_IP_STATS_TYPE syncookies_failed; 

  /** the number of times connection estatblishment procedure was aborted in
   * SYN-RECEIVED state */
  CI_IP_STATS_TYPE embrionic_rsts;

  /** the number of times procedure for finding an additional memory for 
   * RX buffer is calle */
  CI_IP_STATS_TYPE prune_called;

  /** the number of times procedure fails to find an additional room for 
   * incoming data */
  CI_IP_STATS_TYPE rcv_pruned;

  /** the number of times out-of-order queue was destructed to liberate an
   * additional memory for incoming data */
  CI_IP_STATS_TYPE ofo_pruned;

  /** the number of ICMP messages received in response to a TCP segment whose
   * sequence number is out of the current window */
  CI_IP_STATS_TYPE out_of_window_icmps;

  /** the number of dropped ICMP messages due to connection is busy and
   * cannot process it */
  CI_IP_STATS_TYPE lock_dropped_icmps;

  /* it is not obvious what it meand, currently it is set to zero */
  CI_IP_STATS_TYPE arp_filter;

  /** the number of sockets that passed from @e TIME-WAIT to @e CLOSED state by
   * timeout specified for @e TIME-WAIT state */
  CI_IP_STATS_TYPE time_waited;

  /** the number of connections that were recycled in @e TIME-WAIT queue before
   * the timeout expires */
  CI_IP_STATS_TYPE time_wait_recycled;
  /** the number of connections that were killed in @e TIME-WAIT queue before
   * the timeout expires */
  CI_IP_STATS_TYPE time_wait_killed;

  /** the number of SYN segments destined to a socket in @e LISTENING state
   * that were rejected due to @e PAWS checking fails */
  CI_IP_STATS_TYPE paws_passive_rejected;

  /** the number of ACK segments destined to a socket in @e SYN-SEND state
   * that were rejected due to the failure of checking against "TSecr" 
   * field of timestamp option */
  CI_IP_STATS_TYPE paws_active_rejected;

  /** the number of segments rejected due to PAWS checking fails */
  CI_IP_STATS_TYPE paws_estab_rejected;

  /** the number of ACKs sent in delayed manner */
  CI_IP_STATS_TYPE delayed_ack;

  /** the number of times procedure of sending delayed ACK was 
   * initiated on locked socket */
  CI_IP_STATS_TYPE delayed_ack_locked;

  /** the number of segments whose end sequence number is less than RCV.NXT
   * value */
  CI_IP_STATS_TYPE delayed_ack_lost;

  /** the number of times established connection was dropped due to the lack
   * of room in accept queue of listening socket */
  CI_IP_STATS_TYPE listen_overflows;

  /** the number of times listening socket drops established connections after 
   * receiving ACK from the peer due to some reason */
  CI_IP_STATS_TYPE listen_drops;

  /** the following set of counters deals with linux-specific buffering 
   * scheme, L5-stack does not use these way of buffering */
  CI_IP_STATS_TYPE tcp_prequeued;
  CI_IP_STATS_TYPE tcp_direct_copy_from_backlog;
  CI_IP_STATS_TYPE tcp_direct_copy_from_prequeue;
  CI_IP_STATS_TYPE tcp_prequeue_dropped;
  
  /** the number of times data segment passed through "header prediction"
   * mechanism and its data put into receive queue */
  CI_IP_STATS_TYPE tcp_hp_hits;

  /** the number of times data segment passes through "header prediction"
   * mechanism and the data is put directly into user_prepared buffer instead
   * of receive queue */
  CI_IP_STATS_TYPE tcp_hp_hits_to_user;

  /** the number of pure ACKs received - segments with only ACK bit set and 
   * without any data */
  CI_IP_STATS_TYPE tcp_pure_acks;

  /** the number of received ACK segments that force shifting unacknowledged
   * sequence number and processed over fast path */
  CI_IP_STATS_TYPE tcp_hp_acks;

  /** the number of times connections entered in recovery state with SACK
   * disabled */
  CI_IP_STATS_TYPE tcp_reno_recovery;

  /** the number of times connections entered in recovery state with SACK
   * enabled */
  CI_IP_STATS_TYPE tcp_sack_recovery;

  /** the number of times we receiber ACK segments that acknowledges sequence
   * number inside the interval of SACKed sequence numbers */
  CI_IP_STATS_TYPE tcp_sack_reneging;

  /** each counter in the following group is responsible for the number of 
   * reorders detected basing on a particular type of detection */
  CI_IP_STATS_TYPE tcp_fack_reorder;
  CI_IP_STATS_TYPE tcp_sack_reorder;
  CI_IP_STATS_TYPE tcp_reno_reorder;
  CI_IP_STATS_TYPE tcp_ts_reorder;

  /** this is the number of acknowledgements received for the last SN sent, 
   * but not acknowledged yet when the connection was not in the LOSS state */
  CI_IP_STATS_TYPE tcp_full_undo;

  /** the number of acknowledgements we receive from the range
   * ( the last SN acknowledged by ACK; the last SN sent, but not ackn. yet ),
   * after which we leaved recovery state */
  CI_IP_STATS_TYPE tcp_partial_undo;
  /** this is the number of acknowledgements received for the last SN sent, 
   * but not acknowledged yet when the connection was in the LOSS state */
  CI_IP_STATS_TYPE tcp_loss_undo;
  
  /** this counter deals with DSACK and linux-specific state machine, so in
   * L5-stack it should be set to zero */
  CI_IP_STATS_TYPE tcp_sack_undo;

  /** the number of data loss detected by SACK */
  CI_IP_STATS_TYPE tcp_loss;

  /** the number of retransmitted segments that were lost as it was
   * discovered by SACK */
  CI_IP_STATS_TYPE tcp_lost_retransmit;

  /** the following set of counters is incremented depending of
   * the state of NewReno/SCK/FACK/ECN state machine (linux-specific)
   * **************************************************************
   * * State    *           SACK         *        Not SACK        *
   * **************************************************************
   * * Recovery * tcp_sack_recovery_fail * tcp_reno_recovery_fail *
   * **************************************************************
   * * Disorder *    tcp_sack_failures   *    tcp_reno_failures   *
   * **************************************************************
   * * Loss     *    tcp_loss_failures   *    tcp_loss_failures   *
   * **************************************************************
   * * Other    *       tcp_timeouts     *       tcp_timeouts     *
   * **************************************************************
   */
  CI_IP_STATS_TYPE tcp_reno_failures;
  CI_IP_STATS_TYPE tcp_sack_failures;
  CI_IP_STATS_TYPE tcp_loss_failures;
  CI_IP_STATS_TYPE tcp_timeouts;
  CI_IP_STATS_TYPE tcp_reno_recovery_fail;
  CI_IP_STATS_TYPE tcp_sack_recovery_fail;
  
  /** the number of retransmitis made in recovery state (fast retransmits)*/
  CI_IP_STATS_TYPE tcp_fast_retrans;

  /** the number of retransmits made while the connection runs slow start
   * algorithm */
  CI_IP_STATS_TYPE tcp_forward_retrans;

  /** not @p tcp_fast_retrans nor @p tcp_forward_retrans */
  CI_IP_STATS_TYPE tcp_slow_start_retrans;
  
  /** this counter deals with scheduler of delayed ACKs and so far, 
   * in L5-stack it should be zero */
  CI_IP_STATS_TYPE tcp_scheduler_failures;

  /** the number of received segments collapsed for some reason from 
   * out-of-order or receive queues */
  CI_IP_STATS_TYPE tcp_rcv_collapsed;

  /** L5 stack does not support DSACK extendion of TCP, so the following set
   * of counters in it should be set to zero */
  CI_IP_STATS_TYPE tcp_dsack_old_sent;
  CI_IP_STATS_TYPE tcp_dsack_ofo_sent;
  CI_IP_STATS_TYPE tcp_dsack_recv;
  CI_IP_STATS_TYPE tcp_dsack_ofo_recv;
  
  /** the number of SYN segments that caused a connection to be aborted
   * ( [RFC1213] page 71) */
  CI_IP_STATS_TYPE tcp_abort_on_syn;

  /** the number of times socket was destroyed due to one of the following:
   * * on closing the socket has no unread data in its receive queue and it
   *   also has @c SO_LINGER option set with @e l_linger field equals to zero
   * * data segment arrives on socket being in @e FIN-WAIT-1 or @e FIN_WAIT-2 
   * state */
  CI_IP_STATS_TYPE tcp_abort_on_data;

  /** the number of times socket was closed remaining unread data in its 
   * receive queue */ 
  CI_IP_STATS_TYPE tcp_abort_on_close;

  /** the number of times orphan socket was destroyed due to the lack 
   * of resources */
  CI_IP_STATS_TYPE tcp_abort_on_memory;

  /** the number of times socket was destroyed due to some retransmission
   * timer expires */
  CI_IP_STATS_TYPE tcp_abort_on_timeout;

  /** the number of times socket was destroyed just after close operation due
   * to the value of @c TCP_LINGER2 socket option is set to some negative 
   * value */
  CI_IP_STATS_TYPE tcp_abort_on_linger;

  /** the number of times socket was destroyed just after close operation due 
   * to incomplete onload_delegated_send operation */
  CI_IP_STATS_TYPE tcp_abort_on_delegated_send;

  /** the number of times sending RST segment from a socket being terminated
   * fails */
  CI_IP_STATS_TYPE tcp_abort_failed;

  /** some value related to memory management in linx TCP/IP stack */
  CI_IP_STATS_TYPE tcp_memory_pressures;
} ci_tcp_ext_stats_count;
/** this macro is used to get the number of fields in
 * @p ci_tcp_ext_stats_count structure */
#define CI_TCP_EXT_STATS_COUNT_LEN \
  (sizeof(ci_tcp_ext_stats_count)/sizeof( CI_IP_STATS_TYPE))

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
