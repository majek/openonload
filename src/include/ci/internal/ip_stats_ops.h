/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

#ifndef __CI_INTERNAL_IP_STATS_OPS_H__
#define __CI_INTERNAL_IP_STATS_OPS_H__


#if CI_CFG_TCP_SOCK_STATS

/** Called to setup the UL stack statistics/logging */
extern void ci_tcp_stats_init(__NI_STRUCT__ *ni, __STATE_STRUCT__ *ts) CI_HF;

/** Called when the netif stats report timer fires OR at start/end of the
    session. */
extern void ci_tcp_stats_action(__NI_STRUCT__ *ni,
                                __STATE_STRUCT__ *ts,
                                ci_ip_stats_action_type action,
                                ci_ip_stats_output_fmt fmt,
                                void *data,
                                socklen_t *size) CI_HF;

#endif

#if CI_CFG_SUPPORT_STATS_COLLECTION

/** Called to setup the UL stack statistics/logging */
extern void ci_netif_stats_init(__NI_STRUCT__ *ni ) CI_HF;

/** Called when the stats report timer fires OR at start/end of the session. */
extern void ci_netif_stats_action(__NI_STRUCT__ *ni,
                                  ci_ip_stats_action_type action,
                                  ci_ip_stats_output_fmt fmt,
                                  void *data,
				  socklen_t *size) CI_HF;

#endif

/* Update global statistics */
extern void ci_ip_stats_update_global(ci_ip_stats *stats);

/* Clear ci_ip_stats structure */
ci_inline void
ci_ip_stats_clear(ci_ip_stats *stats)
{
  ci_assert( stats );
  memset(stats, 0, sizeof(ci_ip_stats));
}

/* Add statistics from source ci_ip_stats structure to destination */
ci_inline void
ci_ip_stats_update(ci_ip_stats *dest_stats, ci_ip_stats *src_stats) {
  unsigned ctr;

  CI_IP_STATS_TYPE* src;
  CI_IP_STATS_TYPE* dest;

  ci_assert(src_stats);
  ci_assert(dest_stats);
  
  if (dest_stats->now < src_stats->now)
    dest_stats->now = src_stats->now;
  
  /* Update ipv4 counters */
  src = (CI_IP_STATS_TYPE*)&src_stats->ipv4;
  dest = (CI_IP_STATS_TYPE*)&dest_stats->ipv4;
  for( ctr = 0; ctr < CI_IPV4_STATS_COUNT_LEN; ctr++ )
    dest[ctr] += src[ctr];

  /* Update icmp counters */
  src = (CI_IP_STATS_TYPE*)&src_stats->icmp;
  dest = (CI_IP_STATS_TYPE*)&dest_stats->icmp;
  for( ctr = 0; ctr < CI_ICMP_STATS_COUNT_LEN; ctr++ ) {
    dest[ctr] += src[ctr];
  }

  /* Update tcp counters */
  src = (CI_IP_STATS_TYPE*)&src_stats->tcp;
  dest = (CI_IP_STATS_TYPE*)&dest_stats->tcp;
  for( ctr = 0; ctr < CI_TCP_STATS_COUNT_LEN; ctr++ ) {
      dest[ctr] += src[ctr];
  }

  /* Update udp counters */
  src = (CI_IP_STATS_TYPE*)&src_stats->udp;
  dest = (CI_IP_STATS_TYPE*)&dest_stats->udp;
  for( ctr = 0; ctr < CI_UDP_STATS_COUNT_LEN; ctr++ ) {
      dest[ctr] += src[ctr];
  }

  /* Update tcp_ext counters */
  src = (CI_IP_STATS_TYPE*)&src_stats->tcp_ext;
  dest = (CI_IP_STATS_TYPE*)&dest_stats->tcp_ext;
  for( ctr = 0; ctr < CI_TCP_EXT_STATS_COUNT_LEN; ctr++ ) {
      dest[ctr] += src[ctr];
  }
}



/* Can stop stats being collected to see if they are affecting
 * performance in any way. */
#if CI_CFG_TCP_SOCK_STATS

# define __CI_SOCK_STATS_INC( ts, Fld ) do { \
  (ts)->stats_snapshot.count.Fld++; \
} while (0)

# define __CI_SOCK_STATS_ADD( ts, Fld, v ) do { \
  (ts)->stats_snapshot.count.Fld += (v); \
} while (0)

# define __CI_SOCK_STATS_VAL( ts, Fld, v ) do { \
  (ts)->stats_snapshot.actual.Fld=(v); \
  if((signed)(ts)->stats_snapshot.min.Fld > (v)) (ts)->stats_snapshot.min.Fld = (v); \
  if((signed)(ts)->stats_snapshot.max.Fld < (v)) (ts)->stats_snapshot.max.Fld = (v); \
} while(0)

#else

# define __CI_SOCK_STATS_INC(ts, Fld)
# define __CI_SOCK_STATS_ADD(ts, Fld, v)
# define __CI_SOCK_STATS_VAL(ts, Fld, v)

#endif

#if CI_CFG_SUPPORT_STATS_COLLECTION

# define __CI_NETIF_STATS_INC( netif, Grp, Fld ) do { \
  (netif)->state->stats_snapshot.Grp.Fld++; \
} while(0)

# define __CI_NETIF_STATS_DEC( netif, Grp, Fld ) do { \
  (netif)->state->stats_snapshot.Grp.Fld--; \
} while(0)

# define __CI_NETIF_STATS_MINMAX_SET( netif, Grp, Fld) do { \
  int v = ((netif)->state)->stats_snapshot.Grp.range.Fld; \
  if(((netif)->state)->stats_snapshot.Grp.min.Fld > v) \
    ((netif)->state)->stats_snapshot.Grp.min.Fld = v; \
  if(((netif)->state)->stats_snapshot.Grp.max.Fld < v) \
    ((netif)->state)->stats_snapshot.Grp.max.Fld = v; \
} while(0)


#else

# define __CI_NETIF_STATS_INC( netif, Grp, Fld )
# define __CI_NETIF_STATS_DEC( netif, Grp, Fld )
# define __CI_NETIF_STATS_MINMAX_SET( netif, Grp, Fld)

#endif


#define __CI_IPV4_STATS_INC( netif, Fld ) \
  __CI_NETIF_STATS_INC((netif), ipv4, Fld)

#define __CI_ICMP_STATS_INC( netif, Fld ) \
  __CI_NETIF_STATS_INC((netif), icmp, Fld)

#define __CI_TCP_COUNT_STATS_INC( netif, Fld ) \
  __CI_NETIF_STATS_INC((netif), tcp, Fld)

#define __CI_TCP_COUNT_STATS_DEC( netif, Fld ) \
  __CI_NETIF_STATS_DEC((netif), tcp, Fld)

#define __CI_UDP_STATS_INC( netif, Fld ) \
  __CI_NETIF_STATS_INC((netif), udp, Fld)

#define __CI_TCP_EXT_STATS_INC( netif, Fld ) \
  __CI_NETIF_STATS_INC((netif), tcp_ext, Fld)

/* Access macros */
#define CI_IP_SOCK_STATS_INC_RTTO( ts ) __CI_SOCK_STATS_INC( (ts), rtto )
#define CI_IP_SOCK_STATS_INC_CONG( ts ) __CI_SOCK_STATS_INC( (ts), cong )
#define CI_IP_SOCK_STATS_INC_RXSLOW( ts ) __CI_SOCK_STATS_INC( (ts), rx_slowpath )
#define CI_IP_SOCK_STATS_INC_TXSLOW( ts ) __CI_SOCK_STATS_INC( (ts), tx_slowpath )
#define CI_IP_SOCK_STATS_INC_SEQERR( ts ) __CI_SOCK_STATS_INC( (ts), rx_seqerr )
#define CI_IP_SOCK_STATS_INC_BADSYN( ts ) __CI_SOCK_STATS_INC( (ts), rx_badsyn )
#define CI_IP_SOCK_STATS_INC_SYNDUP( ts ) __CI_SOCK_STATS_INC( (ts), rx_syndup )
#define CI_IP_SOCK_STATS_INC_SYNBADACK( ts ) __CI_SOCK_STATS_INC( (ts), rx_synbadack )
#define CI_IP_SOCK_STATS_INC_SYNNONACK( ts ) __CI_SOCK_STATS_INC( (ts), rx_synnonack )
#define CI_IP_SOCK_STATS_INC_BADSYNSEQ( ts ) __CI_SOCK_STATS_INC( (ts), rx_badsynseq )
#define CI_IP_SOCK_STATS_INC_ACKERR( ts ) __CI_SOCK_STATS_INC( (ts), rx_ackerr )
#define CI_IP_SOCK_STATS_INC_DUPACK( ts ) __CI_SOCK_STATS_INC( (ts), rx_dupack )
#define CI_IP_SOCK_STATS_INC_DUPACKFREC( ts ) __CI_SOCK_STATS_INC( (ts), rx_dupack_frec )
#define CI_IP_SOCK_STATS_INC_DUPACKCONGFREC( ts ) __CI_SOCK_STATS_INC( (ts), rx_dupack_congfrec )
#define CI_IP_SOCK_STATS_INC_PAWSERR( ts ) __CI_SOCK_STATS_INC( (ts), rx_pawserr )
#define CI_IP_SOCK_STATS_INC_ZWIN( ts ) __CI_SOCK_STATS_INC( (ts), rx_zwin )
#define CI_IP_SOCK_STATS_INC_OOO( ts ) __CI_SOCK_STATS_INC( (ts), rx_ooo )
#define CI_IP_SOCK_STATS_INC_RETX( ts ) __CI_SOCK_STATS_INC( (ts), tx_retrans_pkt )
#define CI_IP_SOCK_STATS_INC_TXSTUCK( ts ) __CI_SOCK_STATS_INC( (ts), tx_stuck )
#define CI_IP_SOCK_STATS_INC_TXSLEEP( ts ) __CI_SOCK_STATS_INC( (ts), tx_sleep )
#define CI_IP_SOCK_STATS_INC_RXSLEEP( ts ) __CI_SOCK_STATS_INC( (ts), rx_sleep )
#define CI_IP_SOCK_STATS_INC_RXWAIT( ts ) __CI_SOCK_STATS_INC( (ts), rx_wait )

#define CI_IP_SOCK_STATS_ADD_RXBYTE( ts, b ) do { \
    __CI_SOCK_STATS_INC((ts), rx_pkt); __CI_SOCK_STATS_ADD((ts), rx_byte, (b)); \
  }while(0)
#define CI_IP_SOCK_STATS_ADD_TXBYTE( ts, b ) do { \
    __CI_SOCK_STATS_INC((ts), tx_pkt); __CI_SOCK_STATS_ADD((ts), tx_byte, (b)); \
  }while(0)
#define CI_IP_SOCK_STATS_VAL_RXSLEEPTIME( ts, v ) do { \
    __CI_SOCK_STATS_VAL((ts), rx_sleep_time, (v)); } while(0)
#define CI_IP_SOCK_STATS_VAL_TXSLEEPTIME( ts, v ) do { \
    __CI_SOCK_STATS_VAL((ts), tx_sleep_time, (v)); } while(0)
#define CI_IP_SOCK_STATS_VAL_TXBUFFREE( ts, v ) do { \
    __CI_SOCK_STATS_VAL((ts), tx_buffree, (v)); } while(0)
#define CI_IP_SOCK_STATS_VAL_RXWSCL( ts, s ) do { \
     __CI_SOCK_STATS_VAL((ts), rx_wscl, (s)); \
  } while(0)
#define CI_IP_SOCK_STATS_VAL_RXWIN( ts, w ) do { \
     __CI_SOCK_STATS_VAL((ts), rx_win, (w)); \
  } while(0)
#define CI_IP_SOCK_STATS_VAL_RXWIN_SCL( ts, w, s ) do { \
    __CI_SOCK_STATS_VAL((ts), rx_win, (w)); __CI_SOCK_STATS_VAL((ts), rx_wscl, (s)); \
  } while(0)
#define CI_IP_SOCK_STATS_VAL_TXWSCL( ts, s ) __CI_SOCK_STATS_VAL((ts), tx_wscl, (s))
#define CI_IP_SOCK_STATS_VAL_TXWIN( ts, w ) __CI_SOCK_STATS_VAL((ts), tx_win, (w))
#define CI_IP_SOCK_STATS_VAL_RTT_SRTT_RTO( ts, r, s, o ) do { \
    __CI_SOCK_STATS_VAL((ts), rtt, (r));  __CI_SOCK_STATS_VAL((ts), srtt, (s)); \
    __CI_SOCK_STATS_VAL((ts), rto, (o)); } while(0)

#define CI_IP_SOCK_STATS_VAL_TXSLEEP( ts, v ) do { \
    __CI_SOCK_STATS_VAL((ts), tx_sleep, (v)); } while(0)
#define CI_IP_SOCK_STATS_VAL_TXBUFFREE( ts, v ) do { \
    __CI_SOCK_STATS_VAL((ts), tx_buffree, (v)); } while(0)

/* all macros have names, which are based on the corresponding statistics
 * name:
 * if the xxx is a statistics parameter name, than 
 * CI_##GROUP##_STATS_INC_XXX( netif ) is the corresponding macros name,
 * where the GROUP is the name of the group this counter belongs to, and
 * XXX is usually the name of the counter in upper register */
/* macros to update ipv4 statistics */
#define CI_IPV4_STATS_INC_FORWARDING( netif ) \
      __CI_IPV4_STATS_INC( (netif), forwarding)
#define CI_IPV4_STATS_INC_DEFAULTT_TLL( netif ) \
      __CI_IPV4_STATS_INC( (netif), default_ttl)
#define CI_IPV4_STATS_INC_IN_RECVS( netif ) \
      __CI_IPV4_STATS_INC( (netif), in_recvs)
#define CI_IPV4_STATS_INC_IN_HDR_ERRS( netif ) \
      __CI_IPV4_STATS_INC( (netif), in_hdr_errs)
#define CI_IPV4_STATS_INC_IN_ADDR_ERRS( netif ) \
      __CI_IPV4_STATS_INC( (netif), in_addr_errs)
#define CI_IPV4_STATS_INC_FORW_DGRAMS( netif ) \
      __CI_IPV4_STATS_INC( (netif), forw_dgrams)
#define CI_IPV4_STATS_INC_IN_UNKNOWN_PROTOS( netif ) \
      __CI_IPV4_STATS_INC( (netif), in_unknown_protos)
#define CI_IPV4_STATS_INC_IN_DISCARDS( netif ) \
      __CI_IPV4_STATS_INC( (netif), in_discards)
#define CI_IPV4_STATS_INC_IN_DELIVERS( netif ) \
      __CI_IPV4_STATS_INC( (netif), in_delivers)
#define CI_IPV4_STATS_INC_OUT_REQUESTS( netif ) \
      __CI_IPV4_STATS_INC( (netif), out_requests)
#define CI_IPV4_STATS_INC_OUT_DISCARDS( netif ) \
      __CI_IPV4_STATS_INC( (netif), out_discards)
#define CI_IPV4_STATS_INC_OUT_NO_ROUTES( netif ) \
      __CI_IPV4_STATS_INC( (netif), out_no_routes)
#define CI_IPV4_STATS_INC_REASM_TIMEOUT( netif ) \
      __CI_IPV4_STATS_INC( (netif), reasm_timeout)
#define CI_IPV4_STATS_INC_REASM_REQDS( netif ) \
      __CI_IPV4_STATS_INC( (netif), reasm_reqds)
#define CI_IPV4_STATS_INC_REASM_OKS( netif ) \
      __CI_IPV4_STATS_INC( (netif), reasm_oks)
#define CI_IPV4_STATS_INC_REASM_FAILS( netif ) \
      __CI_IPV4_STATS_INC( (netif), reasm_fails)
#define CI_IPV4_STATS_INC_FRAG_OKS( netif ) \
      __CI_IPV4_STATS_INC( (netif), frag_oks)
#define CI_IPV4_STATS_INC_FRAG_FAILS( netif ) \
      __CI_IPV4_STATS_INC( (netif), frag_fails)
#define CI_IPV4_STATS_INC_FRAG_CREATES( netif ) \
      __CI_IPV4_STATS_INC( (netif), frag_creates)

/* macros to update icmp statistics */
#define CI_ICMP_STATS_INC_IN_MSGS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_msgs)
#define CI_ICMP_STATS_INC_IN_ERRS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_errs)
#define CI_ICMP_STATS_INC_IN_DEST_UNREACHS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_dest_unreachs)
#define CI_ICMP_STATS_INC_IN_TIME_EXCDS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_time_excds)
#define CI_ICMP_STATS_INC_IN_PARM_PROBS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_parm_probs)
#define CI_ICMP_STATS_INC_IN_SRC_QUENCHS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_src_quenchs)
#define CI_ICMP_STATS_INC_IN_REDIRECTS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_redirects)
#define CI_ICMP_STATS_INC_IN_ECHOS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_echos)
#define CI_ICMP_STATS_INC_IN_ECHO_REPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_echo_reps)
#define CI_ICMP_STATS_INC_IN_TIMESTAMPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_timestamps)
#define CI_ICMP_STATS_INC_IN_TIMESTAMPS_REPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_timestamp_reps)
#define CI_ICMP_STATS_INC_IN_ADDR_MASKS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_addr_masks)
#define CI_ICMP_STATS_INC_IN_ADDR_MASK_REPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_in_addr_mask_reps)

#define CI_ICMP_STATS_INC_OUT_MSGS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_msgs)
#define CI_ICMP_STATS_INC_OUT_ERRS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_errs)
#define CI_ICMP_STATS_INC_OUT_DEST_UNREACHS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_dest_unreachs)
#define CI_ICMP_STATS_INC_OUT_TIME_EXCDS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_time_excds)
#define CI_ICMP_STATS_INC_OUT_PARM_PROBS( netif ) \
      __CI_ICMP_STATS_INC( (netif),icmp_out_parm_probs )
#define CI_ICMP_STATS_INC_OUT_SRC_QUENCHS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_src_quenchs)
#define CI_ICMP_STATS_INC_OUT_REDIRECTS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_redirects)
#define CI_ICMP_STATS_INC_OUT_ECHOS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_echos)
#define CI_ICMP_STATS_INC_OUT_ECHO_REPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_echo_reps)
#define CI_ICMP_STATS_INC_OUT_TIMESTAMPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_timestamps)
#define CI_ICMP_STATS_INC_OUT_TIMESTAMPS_REPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_timestamp_reps)
#define CI_ICMP_STATS_INC_OUT_ADDR_MASKS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_addr_masks)
#define CI_ICMP_STATS_INC_OUT_ADDR_MASK_REPS( netif ) \
      __CI_ICMP_STATS_INC( (netif), icmp_out_addr_mask_reps)

/* macros to update tcp statistics */
#define CI_TCP_STATS_INC_ACTIVE_OPENS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_active_opens)
#define CI_TCP_STATS_INC_PASSIVE_OPENS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_passive_opens)
#define CI_TCP_STATS_INC_ATTEMPT_FAILS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_attempt_fails)
#define CI_TCP_STATS_INC_ESTAB_RESETS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_estab_resets)
#define CI_TCP_STATS_INC_CURR_ESTAB( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_curr_estab)
#define CI_TCP_STATS_DEC_CURR_ESTAB( netif ) \
      __CI_TCP_COUNT_STATS_DEC( (netif), tcp_curr_estab)
#define CI_TCP_STATS_INC_IN_SEGS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_in_segs)
#define CI_TCP_STATS_INC_OUT_SEGS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_out_segs)
#define CI_TCP_STATS_DEC_OUT_SEGS( netif ) \
      __CI_TCP_COUNT_STATS_DEC( (netif), tcp_out_segs)
#define CI_TCP_STATS_INC_RETRAN_SEGS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_retran_segs)
#define CI_TCP_STATS_INC_IN_ERRS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_in_errs)
#define CI_TCP_STATS_INC_OUT_ERRS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_out_errs)
#define CI_TCP_STATS_INC_OUT_RSTS( netif ) \
      __CI_TCP_COUNT_STATS_INC( (netif), tcp_out_rsts)


/* macros to update udp statistics */
#define CI_UDP_STATS_INC_IN_DGRAMS( netif ) \
      __CI_UDP_STATS_INC( (netif), udp_in_dgrams )
#define CI_UDP_STATS_INC_NO_PORTS( netif ) \
      __CI_UDP_STATS_INC( (netif), udp_no_ports )
#define CI_UDP_STATS_INC_IN_ERRS( netif ) \
      __CI_UDP_STATS_INC( (netif), udp_in_errs )
#define CI_UDP_STATS_INC_OUT_DGRAMS( netif ) \
      __CI_UDP_STATS_INC( (netif), udp_out_dgrams )

/* macros to update tcp ext statistics */
#define CI_TCP_EXT_STATS_INC_SYNCOOKIES_SENT( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), syncookies_sent )
#define CI_TCP_EXT_STATS_INC_SYNCOOKIES_RECV( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), syncookies_recv )
#define CI_TCP_EXT_STATS_INC_SYNCOOKIES_FAILED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), syncookies_failed )

#define CI_TCP_EXT_STATS_INC_EMBRIONIC_RSTS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), embrionic_rsts )

#define CI_TCP_EXT_STATS_INC_PRUNE_CALLED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), prune_called )
#define CI_TCP_EXT_STATS_INC_RCV_PRUNED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), rcv_pruned )
#define CI_TCP_EXT_STATS_INC_OFO_PRUNED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), ofo_pruned )

#define CI_TCP_EXT_STATS_INC_OUT_OF_WINDOW_ICMPS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), out_of_window_icmps )
#define CI_TCP_EXT_STATS_INC_LOCK_DROPPED_ICMPS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), lock_dropped_icmps )

#define CI_TCP_EXT_STATS_INC_ARP_FILTER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), arp_filter )

#define CI_TCP_EXT_STATS_INC_TIME_WAITED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), time_waited )
#define CI_TCP_EXT_STATS_INC_TIME_WAIT_RECYCLED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), time_wait_recycled )
#define CI_TCP_EXT_STATS_INC_TIME_WAIT_KILLED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), time_wait_killed )

#define CI_TCP_EXT_STATS_INC_PAWS_PASSIVE_REJECTED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), paws_passive_rejected )
#define CI_TCP_EXT_STATS_INC_PAWS_ACTIVE_REJECTED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), paws_active_rejected )
#define CI_TCP_EXT_STATS_INC_PAWS_ESTAB_REJECTED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), paws_estab_rejected )

#define CI_TCP_EXT_STATS_INC_DELAYED_ACK( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), delayed_ack )
#define CI_TCP_EXT_STATS_INC_DELAYED_ACK_LOCKED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), delayed_ack_locked )
#define CI_TCP_EXT_STATS_INC_DELAYED_ACK_LOST( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), delayed_ack_lost )

#define CI_TCP_EXT_STATS_INC_LISTEN_OVERFLOWS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), listen_overflows )
#define CI_TCP_EXT_STATS_INC_LISTEN_DROPS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), listen_drops )

#define CI_TCP_EXT_STATS_INC_TCP_PREQUEUED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_prequeued )
#define CI_TCP_EXT_STATS_INC_TCP_DIRECT_COPY_FROM_BACKLOG( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_direct_copy_from_backlog )
#define CI_TCP_EXT_STATS_INC_TCP_DIRECT_COPY_FROM_PREQUEUE( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_direct_copy_from_prequeue )
#define CI_TCP_EXT_STATS_INC_PREQUEUE_DROPPED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_prequeue_dropped )

#define CI_TCP_EXT_STATS_INC_HP_HITS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_hp_hits )
#define CI_TCP_EXT_STATS_INC_HP_HITS_TO_USER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_hp_hits_to_user )

#define CI_TCP_EXT_STATS_INC_TCP_PURE_ACKS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_pure_acks )
#define CI_TCP_EXT_STATS_INC_TCP_HP_ACKS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_hp_acks )

#define CI_TCP_EXT_STATS_INC_TCP_RENO_RECOVERY( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_reno_recovery )
#define CI_TCP_EXT_STATS_INC_TCP_SACK_RECOVERY( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_sack_recovery )

#define CI_TCP_EXT_STATS_INC_TCP_SACK_RENEGING( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_sack_reneging )

#define CI_TCP_EXT_STATS_INC_TCP_FACK_REORDER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_fack_reorder )
#define CI_TCP_EXT_STATS_INC_TCP_SACK_REORDER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_sack_reorder )
#define CI_TCP_EXT_STATS_INC_TCP_RENO_REORDER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_reno_reorder )
#define CI_TCP_EXT_STATS_INC_TCP_TS_REORDER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_ts_reorder )

#define CI_TCP_EXT_STATS_INC_TCP_FULL_UNDO( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_full_undo )
#define CI_TCP_EXT_STATS_INC_TCP_PARTIAL_UNDO( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_partial_undo )
#define CI_TCP_EXT_STATS_INC_TCP_LOSS_UNDO( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_loss_undo )
#define CI_TCP_EXT_STATS_INC_TCP_SACK_UNDO( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_sack_undo )

#define CI_TCP_EXT_STATS_INC_TCP_LOSS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_loss )
#define CI_TCP_EXT_STATS_INC_TCP_LOST_RETRANSMIT( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_lost_retransmit )

#define CI_TCP_EXT_STATS_INC_TCP_RENO_FAILURES( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_reno_failures )
#define CI_TCP_EXT_STATS_INC_TCP_SACK_FAILURES( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_sack_failures )
#define CI_TCP_EXT_STATS_INC_TCP_LOSS_FAILURES( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_loss_failures )

#define CI_TCP_EXT_STATS_INC_TCP_TIMEOUTS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_timeouts )

#define CI_TCP_EXT_STATS_INC_TCP_RENO_RECOVERY_FAIL( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_reno_recovery_fail )
#define CI_TCP_EXT_STATS_INC_TCP_SACK_RECOVERY_FAIL( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_sack_recovery_fail )

#define CI_TCP_EXT_STATS_INC_TCP_FAST_RETRANS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_fast_retrans )
#define CI_TCP_EXT_STATS_INC_TCP_FORWARD_RETRANS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_forward_retrans )
#define CI_TCP_EXT_STATS_INC_TCP_SLOW_START_RETRANS( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_slow_start_retrans )

#define CI_TCP_EXT_STATS_INC_TCP_SCHEDULER_FAILURES( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_scheduler_failures )

#define CI_TCP_EXT_STATS_INC_TCP_RCV_COLLAPSED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_rcv_collapsed )

#define CI_TCP_EXT_STATS_INC_TCP_DSACK_OLD_SENT( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_dsack_old_sent )
#define CI_TCP_EXT_STATS_INC_TCP_DSACK_OFO_SENT( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_dsack_ofo_sent )
#define CI_TCP_EXT_STATS_INC_TCP_DSACK_RECV( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_dsack_recv )
#define CI_TCP_EXT_STATS_INC_TCP_DSACK_OFO_RECV( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_dsack_ofo_recv )

#define CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_SYN( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_on_syn )
#define CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_DATA( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_on_data )
#define CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_CLOSE( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_on_close )
#define CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_MEMORY( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_on_memory )
#define CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_TIMEOUT( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_on_timeout )
#define CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_LINGER( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_on_linger )
#define CI_TCP_EXT_STATS_INC_TCP_ABORT_FAILED( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_abort_failed )

#define CI_TCP_EXT_STATS_INC_TCP_MEMORY_PRESSURES( netif ) \
      __CI_TCP_EXT_STATS_INC( (netif), tcp_memory_pressures )



/* macros to gather ICMP statistics in efab_ipp_icmp_validate function if
 * the driver 
 * /param netif NETIF
 * /param icmp  ICMP message
 * */
#if CI_CFG_SUPPORT_STATS_COLLECTION
#define CI_ICMP_IN_STATS_COLLECT( netif , icmp) do { \
    switch ((icmp)->type) {                                         \
      case CI_ICMP_DEST_UNREACH:                                  \
          CI_ICMP_STATS_INC_IN_DEST_UNREACHS( netif );            \
          break;                                                  \
      case CI_ICMP_TIME_EXCEEDED:                                 \
          CI_ICMP_STATS_INC_IN_TIME_EXCDS( netif );               \
          break;                                                  \
      case CI_ICMP_PARAMETERPROB:                                 \
          CI_ICMP_STATS_INC_IN_PARM_PROBS( netif );               \
          break;                                                  \
      case CI_ICMP_SOURCE_QUENCH:                                 \
          CI_ICMP_STATS_INC_IN_SRC_QUENCHS( netif );              \
          break;                                                  \
      case CI_ICMP_REDIRECT:                                      \
          CI_ICMP_STATS_INC_IN_REDIRECTS( netif );                \
          break;                                                  \
      case CI_ICMP_ECHO:                                          \
          CI_ICMP_STATS_INC_IN_ECHOS( netif );                    \
          break;                                                  \
      case CI_ICMP_ECHOREPLY:                                     \
          CI_ICMP_STATS_INC_IN_ECHO_REPS( netif );                \
          break;                                                  \
      case CI_ICMP_TIMESTAMP:                                     \
          CI_ICMP_STATS_INC_IN_TIMESTAMPS( netif );               \
          break;                                                  \
      case CI_ICMP_TIMESTAMPREPLY:                                \
          CI_ICMP_STATS_INC_IN_TIMESTAMPS_REPS( netif );          \
          break;                                                  \
      case CI_ICMP_ADDRESS:                                       \
          CI_ICMP_STATS_INC_IN_ADDR_MASKS( netif );               \
          break;                                                  \
      case CI_ICMP_ADDRESSREPLY:                                  \
          CI_ICMP_STATS_INC_IN_ADDR_MASK_REPS( netif );           \
          break;                                                  \
      default:                                                    \
          break;                                                  \
    }                                                             \
  }while (0)

/** Macros for gathering statistics in ci_icmp_send_error() function.
 * /param netif NETIF
 * /param icmp  ICMP message
 */
#define CI_ICMP_OUT_STATS_COLLECT( netif , icmp) do {             \
  switch ((icmp)->type) {                                                 \
    case CI_ICMP_ECHOREPLY:                                       \
      CI_ICMP_STATS_INC_OUT_ECHO_REPS( ni );                      \
      break;                                                      \
    case CI_ICMP_DEST_UNREACH:                                    \
      CI_ICMP_STATS_INC_OUT_DEST_UNREACHS( ni );                  \
      break;                                                      \
    case CI_ICMP_SOURCE_QUENCH:                                   \
      CI_ICMP_STATS_INC_OUT_SRC_QUENCHS( ni );                    \
      break;                                                      \
    case CI_ICMP_REDIRECT:                                        \
      CI_ICMP_STATS_INC_OUT_REDIRECTS( ni );                      \
      break;                                                      \
    case CI_ICMP_ECHO:                                            \
      CI_ICMP_STATS_INC_OUT_ECHOS( ni);                           \
      break;                                                      \
    case CI_ICMP_TIME_EXCEEDED:                                   \
      CI_ICMP_STATS_INC_OUT_TIME_EXCDS( ni );                     \
      break;                                                      \
    case CI_ICMP_PARAMETERPROB:                                   \
      CI_ICMP_STATS_INC_OUT_PARM_PROBS( ni );                     \
      break;                                                      \
    case CI_ICMP_TIMESTAMP:                                       \
      CI_ICMP_STATS_INC_OUT_TIMESTAMPS( ni );                     \
      break;                                                      \
    case CI_ICMP_TIMESTAMPREPLY:                                  \
      CI_ICMP_STATS_INC_OUT_TIMESTAMPS_REPS( ni );                \
      break;                                                      \
    case CI_ICMP_ADDRESS:                                         \
      CI_ICMP_STATS_INC_OUT_ADDR_MASKS( ni );                     \
      break;                                                      \
    case CI_ICMP_ADDRESSREPLY:                                    \
       CI_ICMP_STATS_INC_OUT_ADDR_MASK_REPS( ni );                \
       break;                                                     \
    default:                                                      \
       break;                                                     \
  }                                                               \
}while (0)


#else
#define CI_ICMP_OUT_STATS_COLLECT( netif , icmp )
#define CI_ICMP_IN_STATS_COLLECT( netif, icmp )
#endif


#endif  /* __CI_INTERNAL_IP_STATS_OPS_H__ */
