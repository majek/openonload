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
** \author  djr
**  \brief  Decls & defs for IP library internal to our libraries.
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_IP_H__
#define __CI_INTERNAL_IP_H__

#ifdef __ci_storport__

#include <ci/internal/transport_config_opt.h>
#include <ci/internal/ip_stats.h>
#include <ci/internal/cplane_types.h>
#include <ci/internal/ip_shared_types.h>
#include <ci/internal/ip_types.h>
#include <ci/internal/ip_shared_ops.h>
#include <ci/internal/ip_stats_ops.h>

#else

#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <ci/internal/ip_stats.h>
#include <ci/internal/cplane_types.h>
#include <etherfabric/ef_vi.h>
#include <onload/offbuf.h>
#include <ci/net/ipv4.h>
#include <ci/net/ethernet.h>
#include <ci/internal/ip_shared_types.h>

#include <ci/tools.h>
#include <ci/tools/istack.h>

#ifdef __KERNEL__
# include <ci/internal/ip_log.h>
# include <onload/shmbuf.h>
# include <onload/iobufset.h>
# include <onload/eplock_resource.h>
#endif

#include <etherfabric/base.h>
#include <ci/efrm/nic_set.h>
#include <ci/driver/efab/open.h>
#include <ci/internal/ip_types.h>
#include <onload/eplock.h>
#include <ci/internal/ip_shared_ops.h>
#include <ci/internal/ip_stats_ops.h>
#include <onload/pktq.h>
#include <onload/atomics.h>
#endif


/**********************************************************************
 ************************* Version management *************************
 **********************************************************************/

#ifdef __KERNEL__
extern const char* oo_uk_intf_ver;
#endif


/**********************************************************************
 **************************** Debug checks ****************************
 **********************************************************************/

#if ! CI_CFG_DETAILED_CHECKS || defined(NDEBUG)
# define CHECK_NI(ni)
# define CHECK_TS(ni,ts)
# define CHECK_TLS(ni,ts)
# define CHECK_TEP(ep)
# define CHECK_US(ni,ts)
# define CHECK_UEP(ep)
# define CHECK_TIMERS(ni)
# define CHECK_FREEPKTS(ni)
# define CHECK_TEP_NNL(ep)
#else

# define CHECK_NI(ni)                           \
    ci_netif_assert_valid(ni,__FILE__,__LINE__)

# define CHECK_TS(ni,ts)                                        \
    ci_tcp_state_assert_valid((ni), (ts), __FILE__,__LINE__)

# define CHECK_TLS(ni, tls)						\
    ci_tcp_state_listen_assert_valid((ni), (tls), __FILE__,__LINE__)

# define CHECK_TEP(ep)                                  \
    ci_tcp_ep_assert_valid(ep, __FILE__, __LINE__)

# define CHECK_US(ni,ts)                                        \
    ci_udp_state_assert_valid((ni), (ts), __FILE__, __LINE__)

# define CHECK_UEP(ep)                                  \
    ci_udp_ep_assert_valid(ep, __FILE__, __LINE__)

# define CHECK_TIMERS(ni)                                       \
    ci_ip_timer_state_assert_valid((ni), __FILE__, __LINE__)

# define CHECK_FREEPKTS(ni)                             \
  ci_netif_verify_freepkts(ni, __FILE__, __LINE__);  

/* This is intended to allow some checking to be done without the netif
 * lock held. At the moment it does nothing. */
# define CHECK_TEP_NNL(ep)

#endif


/*********************************************************************
*********************** Indirected linked lists **********************
*********************************************************************/

/* Get pointer from an address in the ci_netif_state address space. */


# define ci_ni_dllist_iter(ni, l)           \
            ((l) = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, (l)->next))
# define ci_ni_dllist_backiter(ni, l)       \
            ((l) = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, (l)->prev))


/*! \TODO Move these into their own header. */

#define CI_ILL_UNUSED           -2
#define CI_ILL_END              -1

#define _ci_ill_assert_valid(i, file, line) \
        _ci_assert_ge((int)(i), CI_ILL_END, (file), (line))

/* A singly linked list. */
#define ci_ill_assert_valid(i)  _ci_ill_assert_valid((i), __FILE__, __LINE__)
#define ci_ill_is_empty(i)      ((i) == CI_ILL_END)
#define ci_ill_not_empty(i)     ((i) != CI_ILL_END)

/* A singly linked list with tail pointer. */
#define ci_ill2_assert_valid(h,t)  do{                  \
  ci_assert((h) >= CI_ILL_END);                         \
  ci_assert((h) == CI_ILL_END || (t) >= CI_ILL_END);    \
  }while(0)

/* A double linked list. */
#define ci_idll_assert_valid(h,t)  do{                  \
  ci_assert((h) >= CI_ILL_END);                         \
  ci_assert((t) >= CI_ILL_END);                         \
  ci_assert((h) != CI_ILL_END || (t) == CI_ILL_END);    \
  ci_assert((h) == CI_ILL_END || (t) != CI_ILL_END);    \
  }while(0)


extern void ci_ip_queue_drop(ci_netif*, ci_ip_pkt_queue*) CI_HF;


/*********************************************************************
********************** Timers and management *************************
*********************************************************************/

#define TIME_LT(x, y)  ((ci_int32)((x)-(y)) <  0)
#define TIME_LE(x, y)  ((ci_int32)((x)-(y)) <= 0)
#define TIME_GT(x, y)  ((ci_int32)((x)-(y)) >  0)
#define TIME_GE(x, y)  ((ci_int32)((x)-(y)) >= 0)


/* debugging hook called if CI_IP_TIMER_DEBUG_HOOK set */
typedef void (*ci_ip_timer_debug_fn_t)(ci_netif*, int, int);
extern ci_ip_timer_debug_fn_t ci_ip_timer_debug_fn;

/*! Set a non-pending ip timer
**  \param netif  A pointer to the netif for this timer
**  \param ts     A pointer to the timer structure
**  \param t      The time at which the timer should fire in ticks
*/
extern void __ci_ip_timer_set(ci_netif*, ci_ip_timer* ts, ci_iptime_t t) CI_HF;

#define ci_ip_timer_set(ni, ts, t)  do{			\
    ci_assert(! ci_ip_timer_pending((ni), (ts)));	\
    __ci_ip_timer_set((ni), (ts), (t));			\
  }while(0)

/*! Modify a pending timer 
**  \param netif  A pointer to the netif for this timer
**  \param ts     A pointer to the timer structure
**  \param t      The time at which the timer should now fire in ticks
*/
#define ci_ip_timer_modify(ni, ts, t)  do{	\
    ci_ni_dllist_remove((ni), &(ts)->link);	\
    __ci_ip_timer_set((ni), (ts), (t));		\
  }while(0)

/*! Poll the ip timer scheduler to run the timer wheel and fire any
**  expiring timers.
**  \param netif  A pointer to the netif structure
*/
extern void ci_ip_timer_poll(ci_netif* netif) CI_HF;

/*! Initialise the ip timer management structure shared state in netif,
**  includes calibration and wheel setup.
**  \param netif  A pointer to the netif to initialise
**  \param cpu_khz CPU speed in kHz
*/
extern void ci_ip_timer_state_init(ci_netif* netif, unsigned cpu_khz) CI_HF;

/*! Initialise user-level timer related stuff in netif (not shared state) */
extern void ci_ip_timer_state_init_ul(ci_netif *ni);

/*! Dump out state of timers
**  \param netif  A pointer to the netif to initialise
*/
extern void ci_ip_timer_state_dump(ci_netif* ni) CI_HF;

CI_DEBUG(extern void ci_ip_timer_state_assert_valid(ci_netif*,
                                                    const char*, int) CI_HF;)


/*********************************************************************
******************** Socket Level IP State Cache *********************
*********************************************************************/

#define CI_PMTU_MAX_MTU  9000

#define LOG_PMTU(x) LOG_IPP(x)

/* Path MTU plateau table entries (stored in ci_tcp_state) */
#define CI_PMTU_PLATEAU_ENTRIES					\
  { 68, 296, 508, 1006, 1492, 2002, 4352, 8166, 32000, 65535 }
#define CI_PMTU_PLATEAU_ENTRY_MAX	9


extern void
ci_pmtu_state_init(ci_netif* ni, ci_sock_cmn *s, ci_pmtu_state_t* pmtus,
                   int func_code);
extern void
ci_pmtu_state_reinit(ci_netif* ni, ci_sock_cmn *s, ci_pmtu_state_t* pmtus);

extern void ci_pmtu_set(ci_netif *ni, ci_pmtu_state_t *pmtus, unsigned pmtu);

/*! IP timer callback for Path MTU discovery process */
extern void ci_pmtu_timeout_pmtu(ci_netif* ni, ci_tcp_state* tso) CI_HF;
extern void ci_pmtu_timeout_pmtu_2(ci_netif* ni, ci_udp_state* tso) CI_HF;

extern void ci_pmtu_update_fast(ci_netif *ni, ci_ip_cached_hdrs *ipcache,
                                unsigned mtu) CI_HF;
extern void ci_pmtu_update_slow(ci_netif *ni, ci_ip_cached_hdrs *ipcache,
                                unsigned mtu) CI_HF;

#define CI_PMTU_STOP_TIMER ((ci_iptime_t)0)
#define CI_PMTU_IMMEDIATE_TIMEOUT ((ci_iptime_t)1)


#define CI_PMTU_TIMER_SET_FAST(ni, p)					   \
  ci_pmtu_discover_timer((ni), (p), NI_CONF(ni).tconst_pmtu_discover_fast)
#define CI_PMTU_TIMER_SET_SLOW(ni, p)					   \
  ci_pmtu_discover_timer((ni), (p), NI_CONF(ni).tconst_pmtu_discover_slow)
#define CI_PMTU_TIMER_SET_RECOVER(ni, p)				      \
  ci_pmtu_discover_timer((ni), (p), NI_CONF(ni).tconst_pmtu_discover_recover)
#define CI_PMTU_TIMER_KILL(ni, p)				\
  ci_pmtu_discover_timer( (ni), (p), CI_PMTU_STOP_TIMER )
#define CI_PMTU_TIMER_NOW(ni, p)					\
  ci_pmtu_discover_timer( (ni), (p), CI_PMTU_IMMEDIATE_TIMEOUT )



#if !defined(NDEBUG)
  #define ci_ip_cache_check(ipcache)                    \
    do {                                                \
    } while(0)
#else
  #define ci_ip_cache_check(ipcache) do {} while(0)
#endif

/*! Initializes an IP cache
 *  (to use this macro include <ci/internal/cplane_ops.h>)
 */
#define ci_ip_cache_init(ipcache)                               \
do {                                                            \
  (ipcache)->status = retrrc_noroute;                           \
  (ipcache)->mac_integrity.row_index = 0;                       \
  (ipcache)->mac_integrity.row_version = CI_VERLOCK_BAD;        \
  (ipcache)->intf_i = -1;                                       \
  (ipcache)->hwport = CI_HWPORT_ID_BAD;                         \
  (ipcache)->ether_type = CI_ETHERTYPE_IP;                      \
  (ipcache)->flags = 0;                                         \
} while (0)


/*! Invalidates a ci_ip_cached_hdrs struct i.e. all state becomes out-of-date.
 *  NOTE: the struct must be in a valid/legal state already. If not, use
 *        ci_ip_cache_init() or ci_ip_cache_set().
 *  (to use this macro include <ci/internal/cplane_ops.h>)
 */
#define ci_ip_cache_invalidate(ipcache)			\
{ ci_ip_cache_check(ipcache);				\
  (ipcache)->mac_integrity.row_version = CI_VERLOCK_BAD; \
}




/*********************************************************************
*************************** Packet buffers ***************************
*********************************************************************/

/* Total length of TX packet */
#define TX_PKT_LEN(pkt) (pkt)->tx_pkt_len

/* Offset from start of [ci_ip_pkt_fmt] to start of packet payload.
 * Mostly used to set up DMA RX buffer;
 * TX offset depends on VLAN tag presence.
 * (NB. This may not always be the start of the DMA buffer for receive).
 */
#define PKT_START_OFF() CI_MEMBER_OFFSET(ci_ip_pkt_fmt, ether_base)

/* Offset of current buffer position from start of TCP payload. */
#define PKT_RX_BUF_OFF(pkt)                                                 \
  ((ci_uint32)(oo_offbuf_ptr(&(pkt)->buf) - CI_TCP_PAYLOAD(PKT_TCP_HDR(pkt))))

/* Sequence number at the current buffer position. */
#define PKT_RX_BUF_SEQ(pkt)                                     \
  (CI_BSWAP_BE32(PKT_TCP_HDR(pkt)->tcp_seq_be32) + PKT_RX_BUF_OFF(pkt))


#define PKT_TCP_RX_BUF_ASSERT_VALID(ni, pkt)            \
  OO_OFFBUF_ASSERT_VALID(&(pkt)->buf, PKT_START(pkt),   \
			 (pkt) + CI_CFG_PKT_BUF_SIZE)


#define PKT_START(pkt)       oo_ether_dhost(pkt)

#define PKT_TCP_HDR(pkt)                                        \
  ((ci_tcp_hdr*) (oo_ether_data(pkt) + CI_IP4_IHL(oo_ip_hdr(pkt))))

/*! Find the amount of data in an outgoing packet */
#define PKT_TCP_TX_SEQ_SPACE(pkt)                             \
   (SEQ_SUB((pkt)->pf.tcp_tx.end_seq, (pkt)->pf.tcp_tx.start_seq))

#define TX_PKT_TCP(pkt)  ((ci_tcp_hdr*) oo_tx_ip_data(pkt))
#define TX_PKT_UDP(pkt)  ((ci_udp_hdr*) oo_tx_ip_data(pkt))
#define TX_PKT_SPORT_BE16(pkt)  (((ci_uint16*) oo_tx_ip_data(pkt))[0])
#define TX_PKT_DPORT_BE16(pkt)  (((ci_uint16*) oo_tx_ip_data(pkt))[1])

/*! Get re-order buffer structure from TCP packet */
#define PKT_TCP_RX_ROB(pkt) (&(pkt)->pf.tcp_rx.misc.rob)

/*! Get tsval from timestamp option.  This had better be a TCP packet with
** a timestamp option!  (Horribly inefficient; only use for logging). */
#define PKT_TCP_TSO_TSVAL(pkt)                                          \
  CI_BSWAP_BE32(*(ci_uint32*) (CI_TCP_HDR_OPTS(PKT_TCP_HDR(pkt)) + 4))



/* TODO: replace PKT_UDP_HDR and PKT_IOVEC_UDP_PFX by TX-specific and
 * generic function; see oo_tx_ip_hdr() performance notes. */
#define PKT_UDP_HDR(pkt)       ((ci_udp_hdr*)&(oo_ip_hdr(pkt))[1])


/**********************************************************************
**************************** TCP RX packet ****************************
**********************************************************************/

typedef struct {
  struct ci_netif_poll_state* poll_state;
  ci_netif*      ni;
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr*    tcp;

  /* [flags] can take any of the following values, or any of the tcp
  ** options flags (e.g. CI_TCPT_FLAG_*). */
#define CI_TCP_PAWS_FAILED       0x80000000
#define CI_TCP_SACKED            0x20000000 /* Something is really SACKed */
#define CI_TCP_DSACK             0x10000000 /* First SACK block is duplicate */

  ci_uint32     flags;
  ci_uint32     timestamp;       /* pointer to timeval, host endian */
  ci_uint32     timestamp_echo;  /* pointer to timeval, host endian */
  ci_uint32     sack[8];         /* pointer to first block, host endian */
  ci_int32      sack_blocks;
  ci_uint32     ack,seq;         /* ACK and SEQ values in host endian */
} ciip_tcp_rx_pkt;



/**********************************************************************
************************** Network interface **************************
**********************************************************************/

/* The following are used in netic_init.c to decode EF_UDP_OPTIONS */
#define CI_EF_UDP_UL_RECV_M     0x00000007
#define CI_EF_UDP_UL_RECV_S              0

#define CI_EF_UDP_RECV_FAST_M   0x00000008
#define CI_EF_UDP_RECV_FAST_S            3

#define CI_EF_UDP_UL_POLL_M     0x00000070
#define CI_EF_UDP_UL_POLL_S              4


#define NI_ID(ni)    ((ni)->state->stack_id)
#define NI_CONF(ni)  ((ni)->state->conf)
#ifdef __KERNEL__
# define NI_OPTS(ni)  ((ni)->opts)
#else
# define NI_OPTS(ni)  ((ni)->state->opts)
#endif
#define NI_IPID(ni)  (&(ni)->state->ipid)


#define IPTIMER_STATE(ni) (&(ni)->state->iptimer_state)


extern void ci_netif_config_opts_rangecheck(ci_netif_config_opts* opts) CI_HF;
extern void ci_netif_config_opts_getenv(ci_netif_config_opts* opts) CI_HF;
extern void ci_netif_config_opts_defaults(ci_netif_config_opts* opts) CI_HF;
#ifdef __KERNEL__
extern void ci_netif_state_init(ci_netif* ni, int cpu_khz, 
                                const char* name) CI_HF;
extern int  ci_netif_ctor(ci_netif**, const ci_netif_config_opts*,
                          unsigned flags) CI_HF;
#else
extern int  ci_netif_ctor(ci_netif*, ef_driver_handle, const char* name,
                          unsigned flags) CI_HF;
#endif
extern int  ci_netif_restore_id(ci_netif*, unsigned stack_id) CI_HF;
extern int citp_netif_by_id(ci_uint32 stack_id, ci_netif** out_ni) CI_HF;
extern int  ci_netif_restore_name(ci_netif*, const char*) CI_HF;
extern int  ci_netif_restore(ci_netif* ni, ci_fd_t fd,
			     unsigned netif_mmap_bytes) CI_HF;
extern int  ci_netif_dtor(ci_netif*) CI_HF;

extern void ci_netif_error_detected(ci_netif*, unsigned error_flag,
                                    const char* caller) CI_HF;

extern int  ci_netif_poll_intf_fast(ci_netif*, int intf_i, ci_uint64 now_frc)
  CI_HF;
extern int  ci_netif_poll_n(ci_netif*, int max_evs) CI_HF;
#define     ci_netif_poll(ni)  ci_netif_poll_n((ni), 0x7fffffff)

extern void ci_netif_send(ci_netif*, ci_ip_pkt_fmt* pkt) CI_HF;
extern void ci_netif_rx_post(ci_netif* netif, int nic_index) CI_HF;
#ifdef __KERNEL__
extern int  ci_netif_set_rxq_limit(ci_netif*) CI_HF;
extern int  ci_netif_init_fill_rx_rings(ci_netif*) CI_HF;
#endif
extern unsigned ci_netif_purge_deferred_socket_list(ci_netif* ni) CI_HF;
extern void ci_netif_mem_pressure_pkt_pool_fill(ci_netif*) CI_HF;
extern int  ci_netif_mem_pressure_try_exit(ci_netif*) CI_HF;

extern void ci_netif_timeout_remove(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_netif_timeout_leave(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern int  ci_netif_timeout_reap(ci_netif* ni) CI_HF;
extern void ci_netif_timeout_state(ci_netif* ni) CI_HF;
extern void ci_netif_timewait_restart(ci_netif *ni, ci_tcp_state *ts) CI_HF;

extern void ci_netif_timewait_enter(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern int  ci_netif_timewait_try_to_free_filter(ci_netif* ni) CI_HF;
extern void ci_netif_fin_timeout_enter(ci_netif* ni, ci_tcp_state* ts) CI_HF;

extern void ci_netif_dump(ci_netif* ni) CI_HF;
extern void ci_netif_dump_extra(ci_netif* ni) CI_HF;
extern void ci_netif_dump_sockets(ci_netif* ni) CI_HF;
extern void ci_netif_dump_dmaq(ci_netif* ni, int dump) CI_HF;
extern void ci_netif_dump_timeoutq(ci_netif* ni) CI_HF;
extern void ci_netif_dump_reap_list(ci_netif* ni, int verbose) CI_HF;
extern void ci_netif_dump_vi(ci_netif*, int intf_i) CI_HF;
extern void ci_netif_config_opts_dump(ci_netif_config_opts* opts);
extern void ci_netif_pkt_dump_all(ci_netif* ni) CI_HF;
extern int  ci_netif_pkt_prefault(ci_netif* ni) CI_HF;
extern void ci_netif_pkt_queue_dump(ci_netif* ni, ci_ip_pkt_queue* q,
                                    int is_recv, int dump) CI_HF;
extern void ci_netif_pkt_list_dump(ci_netif* ni, oo_pkt_p head,
				   int is_recv, int dump) CI_HF;
extern void ci_netif_pkt_dump(ci_netif* ni, ci_ip_pkt_fmt*, int is_recv, 
                              int dump) CI_HF;
extern int  ci_netif_bad_hwport(ci_netif*, ci_hwport_id_t) CI_HF;
extern void ci_tcp_rx_checks(ci_netif*, ci_tcp_state*, ci_ip_pkt_fmt*) CI_HF;
extern void ci_tcp_listen_rx_checks(ci_netif*, ci_tcp_socket_listen*,
				    ci_ip_pkt_fmt*) CI_HF;

extern int  ci_netif_force_wake(ci_netif* ni, int everyone) CI_HF;

CI_DEBUG(extern void ci_netif_assert_valid(ci_netif*, const char*, int);)
CI_DEBUG(extern void ci_netif_verify_freepkts(ci_netif *, const char *, int);)

#ifdef CI_HAVE_OS_NOPAGE
#define ASSERT_VALID_NETIF_ADDR(ni, addr, size)  do{            \
  ci_assert(ci_to_int(addr) >= 0);                              \
  ci_assert((addr) < (ni)->state->netif_mmap_bytes);            \
  ci_assert((addr) + (size) <= (ni)->state->netif_mmap_bytes);  \
  }while(0)
#else
#define ASSERT_VALID_NETIF_ADDR(ni, addr, size)  do{            \
  ci_assert(ci_to_int(addr) >= 0);                              \
  }while(0)
#endif


/*********************************************************************
************************* Packet buffer mgmt *************************
*********************************************************************/

#if !defined(CI_HAVE_OS_NOPAGE)
#define PKT_BUFSET_ALLOCATED(ni, id) \
        ((ni)->state->pkt_sets_n > (id))  
#endif


/* Assert packet is empty - but may contain payload */
#ifndef NDEBUG 
#define ASSERT_PKT_PAYLOAD_EMPTY(p) ci_assert_equal(p->tx_pkt_len, 0);
#else
#define ASSERT_PKT_PAYLOAD_EMPTY(p)
#endif


/* True if [id] is in legal range. */
#define IS_VALID_PKT_ID(ni, pp)  OO_PP_EQ((pp), VALID_PKT_ID((ni), (pp)))

/* Validate packet id. */
#define ASSERT_VALID_PKT_ID(ni, id)                     \
  ci_ss_assert((ni), IS_VALID_PKT_ID((ni), (id)))
#define __ASSERT_VALID_PKT_ID(ni, id, file, line)       \
  ci_ss_assertfl((ni), IS_VALID_PKT_ID((ni), (id)), file, line)


#ifdef NDEBUG
# define ASSERT_VALID_PKT(ni, pkt)
# define ASSERT_VALID_PKT_NNL(ni, pkt)
# define ASSERT_VALID_PKT_MAYBE_NNL(ni, pkt, ni_locked)
#else
# define ASSERT_VALID_PKT(ni, pkt)                                      \
      ci_assert_valid_pkt((ni), (pkt), CI_TRUE, __FILE__, __LINE__)
# define ASSERT_VALID_PKT_NNL(ni, pkt)                                  \
      ci_assert_valid_pkt((ni), (pkt), CI_FALSE, __FILE__, __LINE__)
# define ASSERT_VALID_PKT_MAYBE_NNL(ni, pkt, ni_locked)                 \
      ci_assert_valid_pkt((ni), (pkt), (ni_locked), __FILE__, __LINE__)
#endif


/*********************************************************************
*************************** Packet buffers ***************************
*********************************************************************/

#ifdef __KERNEL__
# define IS_VALID_SOCK_ID(ni, id)  ((unsigned) (id) < (ni)->ep_tbl_n)
#else
# define IS_VALID_SOCK_ID(ni, id)  ((unsigned) (id) < (ni)->state->n_ep_bufs)
#endif

#define IS_VALID_SOCK_P(ni, sockp)  IS_VALID_SOCK_ID((ni), OO_SP_TO_INT(sockp))


# define PKT_DBG_FMT                    "[id=%d flgs=%x]"
# define PKT_DBG_ARGS(p)                OO_PKT_FMT(p), (p)->flags


extern void ci_netif_pkt_free(ci_netif* ni, ci_ip_pkt_fmt* pkt) CI_HF;

extern ci_ip_pkt_fmt* ci_netif_pkt_alloc_slow(ci_netif*, int for_tx) CI_HF;
extern void ci_netif_pkt_try_to_free(ci_netif* ni, int desperation) CI_HF;
extern void ci_netif_try_to_reap(ci_netif* ni, int stop_once_freed_n) CI_HF;
extern void ci_netif_rxq_low_on_recv(ci_netif*, ci_sock_cmn*,
                                     int bytes_freed) CI_HF;

/*! Allocate a packet buffer, blocking if necessary.  At userlevel this
 * function will never fail.  In the kernel this function may return NULL
 * if interrupted by a signal.
 *
 * The stack lock may be grabbed or dropped by this function.  This call
 * does *not* "exit" the library, so if any signals occur when called from
 * userspace, they are deferred.
 *
 * See also ci_netif_pkt_alloc_block_was_interrupted().
 */
extern ci_ip_pkt_fmt* ci_netif_pkt_alloc_block(ci_netif*, int* ni_locked)CI_HF;

/*! Sleeps until a packet buffer becomes available, returning 0 on success.
 * At userlevel this function will never fail.  In the kernel it may return
 * -ERESTARTSYS if interrupted by a signal.
 *
 * On success, if CI_SLEEP_NETIF_RQ is set, the netif is locked on return.
 *
 *   [lock_flags] indicates whether the caller is holding the netif lock on
 *   entry (CI_SLEEP_NETIF_LOCKED), and whether it should be locked before
 *   return (CI_SLEEP_NETIF_RQ).
 *
 * See also ci_netif_pkt_wait_was_interrupted().
 */
extern int ci_netif_pkt_wait(ci_netif*, int lock_flags) CI_HF;


#if CI_CFG_FULL_IP_ID_HANDLING
/**********************************************************************
 ********************************* IP *********************************
 **********************************************************************/

/*! Handle the re-cycling of IP ID blocks.  This is 
 * only invoked when the inline allocator function determines
 * that it is required - should not be called directly.
 */
extern void ci_ipid_recycle( ci_netif* ni, ci_fd_t fd ) CI_HF;

#ifndef NDEBUG
extern void ci_ipid_assert_valid(ci_netif*, const char* file, int line) CI_HF;
#endif
#endif /* CI_CFG_FULL_IP_ID_HANDLING */

/*! Set-up the IPIDs for netif [ni].  
 * Called from ci_netif_ctor() in netif_init.c.
 *
 * READ ME - IT'S IMPORTANT
 * In the beta this function WILL FAIL cleanly if the IDs in the
 * char driver have been exhausted.  In that instance we MUST fail
 * the netif construction as well as, for efficiency, the IP ID 
 * allocator does NOT check that we have at least one block of 
 * addresses (and it won't fail if the ctor's not been called).
 * \return 0 - success, else -ENOMEM if no addresses available.
 */
extern int ci_ipid_ctor( ci_netif* ni, ci_fd_t fd ) CI_HF;
extern void ci_ipid_dtor( ci_netif* ni, ci_fd_t fd ) CI_HF;


/**********************************************************************
**************************** WIN32 Extra    ***************************
**********************************************************************/


/**********************************************************************
**************************** Socket buffers ***************************
**********************************************************************/

extern void oo_sock_cplane_init(struct oo_sock_cplane*) CI_HF;
extern void ci_sock_cmn_init(ci_netif*, ci_sock_cmn*) CI_HF;
extern void ci_sock_cmn_reinit(ci_netif*, ci_sock_cmn*) CI_HF;
extern void ci_sock_cmn_dump(ci_netif*, ci_sock_cmn*, const char* pf) CI_HF;


#if CI_CFG_SOCKP_IS_PTR
# define S_SP(ss)  ((oo_sp)CI_CONTAINER(citp_waitable_obj,waitable,&(ss)->s.b))
# define SC_SP(s)  CI_CONTAINER(citp_waitable_obj, waitable, &(s)->b)
# define W_SP(w)   CI_CONTAINER(citp_waitable_obj, waitable, (w))
#else
# define S_SP(ss)  ((ss)->s.b.bufid)
# define SC_SP(s)  ((s)->b.bufid)
# define W_SP(w)   ((w)->bufid)
#endif

#define S_ID(ss)   OO_SP_TO_INT(S_SP(ss))
#define SC_ID(s)   OO_SP_TO_INT(SC_SP(s))
#define W_ID(w)    OO_SP_TO_INT(W_SP(w))

#define S_FMT(ss)  OO_SP_FMT(S_SP(ss))
#define SC_FMT(s)  OO_SP_FMT(SC_SP(s))
#define W_FMT(w)   OO_SP_FMT(W_SP(w))


/* Wrappers to determine whether a socket has been bound, and if so, how */
#define CI_SOCK_EXPLICIT_BIND(s) ((s)->s_flags & CI_SOCK_FLAG_BOUND)
#define CI_SOCK_IMPLICIT_BIND(s) \
  (!CI_SOCK_EXPLICIT_BIND((s)) && sock_lport_be16((s)))
#define CI_SOCK_NOT_BOUND(s)     (!sock_lport_be16((s)))


/**********************************************************************
 ****************************** so_error ******************************
 **********************************************************************/

/* Note: we do not require a lock to set the so_error field */

/* [s] = ci_sock_cmn*, [e] is >= 0 error value */
#define CI_SET_SO_ERROR(s,e) do { \
  ci_assert_ge(e,0); if((e)) (s)->so_error=(e); } while(0)

/* [t] = ci_tcp_state*, [e] = +ve error value */
#define CI_SET_TCP_SO_ERROR(t,e) CI_SET_SO_ERROR(&(t)->s,(e))
/* [u] = ci_udp_state*, [e] = +ve error value */
#define CI_SET_UDP_SO_ERROR(u,e) CI_SET_SO_ERROR(&(u)->s,(e))

ci_inline ci_int32 ci_get_so_error(ci_sock_cmn *s)
{
  ci_int32 rc;
  do {
    rc = s->so_error;
  } while( rc != 0 && ci_cas32_fail(&s->so_error, rc, 0) );
  return rc;
}

/**********************************************************************
 ************************ rx_errno & tx_errno *************************
 **********************************************************************/

#define SOCK_TX_ERRNO(s)        ((s)->tx_errno)
#define SOCK_RX_ERRNO(s)        ((s)->rx_errno & 0x0fffffff)

/**********************************************************************
 **************************** ICMP/Errors *****************************
 **********************************************************************/

extern int
ci_icmp_send(ci_netif *ni, ci_ip_pkt_fmt *tx_pkt,
	     const ci_ip_addr_t *ref_ip_source,
	     const ci_ip_addr_t *ref_ip_dest,
	     const ci_mac_addr_t *mac_dest,
	     ci_uint8 type, ci_uint8 code, ci_uint16 data_len) CI_HF;

extern int __ci_icmp_send_error(ci_netif* ni, ci_ip4_hdr* rx_ip,
                                struct oo_eth_hdr* rx_eth, ci_uint8 type,
                                ci_uint8 code) CI_HF;

/**********************************************************************
********************************* UDP *********************************
**********************************************************************/

#define CI_UDP_INITIAL_MTU ETH_DATA_LEN
#define CI_UDP_MAX_PAYLOAD_BYTES \
  (0xffff - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))

#define UDP_FLAGS(us)           ((us)->udpflags)

#define UDP_SET_FLAG(us,f)      ((us)->udpflags|=(f))
#define UDP_CLR_FLAG(us,f)      ((us)->udpflags&=~(f))
#define UDP_GET_FLAG(us,f)      ((us)->udpflags&(f))

#define UDP_IP_HDR(us)          (&(us)->s.pkt.ip)

#define udp_lport_be16(us)      (sock_lport_be16(&us->s))
#define udp_laddr_be32(us)      (sock_laddr_be32(&us->s))
#define udp_frag_off_be16(us)   (UDP_IP_HDR((us))->ip_frag_off_be16)
#define udp_rport_be16(us)      (sock_rport_be16(&us->s))
#define udp_raddr_be32(us)      (sock_raddr_be32(&us->s))


#define UDP_RX_DONE(us)         (SOCK_RX_ERRNO(&(us)->s) & ~CI_SHUT_WR)
#define UDP_TX_ERRNO(us)        (SOCK_TX_ERRNO(&(us)->s))
#define UDP_RX_ERRNO(us)	(SOCK_RX_ERRNO(&(us)->s))
#define UDP_IS_SHUT_RD(us)      ((us)->s.rx_errno & CI_SHUT_RD)
#define UDP_IS_SHUT_WR(us)      ((us)->s.rx_errno & CI_SHUT_WR)
#define UDP_IS_SHUT_RDWR(us)				\
    (((us)->s.rx_errno & (CI_SHUT_RD | CI_SHUT_WR)) ==   \
     (CI_SHUT_RD | CI_SHUT_WR))


/***  udp.c  ***/

extern void ci_udp_state_dump(ci_netif*, ci_udp_state*, const char* pf) CI_HF;

/* Set the source IP address & UDP port */
extern void ci_udp_set_laddr(citp_socket*, unsigned laddr_be32, 
                             int lport_be16) CI_HF;

/* Set the IP TOS */
extern void ci_udp_set_tos( ci_udp_state* us, ci_uint32 tos );

extern void ci_udp_state_assert_valid(ci_netif*, ci_udp_state* ts,
				      const char* file, int line) CI_HF;

extern void ci_udp_ep_assert_valid(citp_socket* ep,
				   const char* file, int line) CI_HF;


/*** udp_rx.c ***/
extern void ci_udp_handle_rx(ci_netif*, ci_ip_pkt_fmt* pkt, ci_udp_hdr*,
                             int ip_paylen) CI_HF;


ci_inline 
void ci_pkt_init_from_ipcache_len(ci_ip_pkt_fmt *pkt,
                                  const ci_ip_cached_hdrs *ipcache,
                                  size_t header_len)
{
  ci_assert_equal(CI_IP4_IHL(&ipcache->ip), sizeof(ci_ip4_hdr));
  ci_assert_equal(ipcache->ether_type, CI_ETHERTYPE_IP);
  if (ipcache->ether_offset)
    oo_pkt_layout_set(pkt, CI_PKT_LAYOUT_TX_SIMPLE);
  else
    oo_pkt_layout_set(pkt, CI_PKT_LAYOUT_TX_VLAN);
  memcpy(PKT_START(pkt), ci_ip_cache_ether_hdr(ipcache),
         header_len + oo_ether_hdr_size(pkt));
  ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(pkt)), sizeof(ci_ip4_hdr));
  ci_assert_equal(oo_ether_type_get(pkt), CI_ETHERTYPE_IP);
}


ci_inline 
void ci_pkt_init_from_ipcache(ci_ip_pkt_fmt *pkt,
                              const ci_ip_cached_hdrs *ipcache)
{
  ci_pkt_init_from_ipcache_len(pkt, ipcache,
                               sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr));
}


/*
** External interface
*/

struct cmsg_state {
  struct msghdr* msg;
  struct cmsghdr* cm;
  int cmsg_bytes_used;
};

extern void ci_put_cmsg(struct cmsg_state *cmsg_state, int level, int type,
                        socklen_t len, const void *data) CI_HF;
extern int ci_ip_cmsg_send(const struct msghdr*, struct in_pktinfo**) CI_HF;

#ifndef __KERNEL__

/* extern int ci_tp_init(void); */
extern void ci_udp_ep_init_finish(citp_socket* ep, ci_netif* netif, 
                                  ci_udp_state* us
	                          CI_ARG_WIN(wf_provider_t* prov)) CI_HF;
extern ci_fd_t ci_udp_ep_ctor(citp_socket* ep, ci_netif* sh,
                              int domain, int type) CI_HF;
extern int ci_udp_bind(citp_socket* ep, ci_fd_t fd, 
	              const struct sockaddr* my_addr, socklen_t addrlen) CI_HF;
extern int ci_udp_bind_conclude(citp_socket* ep, 
                                const struct sockaddr* addr,
		                ci_uint16 lport ) CI_HF;
extern int ci_udp_connect(citp_socket*, ci_fd_t fd,
			  const struct sockaddr*, socklen_t addrlen) CI_HF;
extern int ci_udp_connect_conclude(citp_socket* ep, ci_fd_t fd,
                                   const struct sockaddr* serv_addr, 
                                   socklen_t addrlen, ci_fd_t os_sock) CI_HF;

extern int ci_udp_shutdown(citp_socket*, ci_fd_t fd, int how) CI_HF;
extern int __ci_udp_shutdown(ci_netif* netif, ci_udp_state* us, int how) CI_HF;
extern int ci_udp_getpeername(citp_socket*, struct sockaddr*,socklen_t*) CI_HF;

extern int ci_udp_getsockopt(citp_socket* ep, ci_fd_t fd, int level,
		     int optname, void *optval, socklen_t *optlen ) CI_HF;
extern int ci_udp_setsockopt(citp_socket* ep, ci_fd_t fd, int level,
		     int optname, const void*optval, socklen_t optlen) CI_HF;
extern int ci_udp_ioctl(citp_socket*, ci_fd_t, int request, void* arg) CI_HF;
#endif

/* Send/recv called from within kernel & user-library, so outside above #if */
extern int ci_udp_sendmsg(ci_udp_iomsg_args *a,
                          const struct msghdr*, int) CI_HF;
extern int ci_udp_recvmsg(ci_udp_iomsg_args *a, struct msghdr*, int flags 
                          CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;

#ifndef __KERNEL__
# if CI_CFG_ZC_RECV_FILTER
extern int ci_udp_filter_recved_pkts(ci_netif* ni, ci_udp_state* us) CI_HF;
# endif
#endif

#if CI_CFG_RECVMMSG
struct mmsghdr;
extern int ci_udp_recvmmsg(ci_udp_iomsg_args *a, struct mmsghdr* mmsg, 
                           unsigned int vlen, int flags, 
                           const struct timespec* timeout
                           CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;
#endif

#ifndef __KERNEL__
struct onload_zc_mmsg;
extern int ci_tcp_zc_send(ci_netif* ni, ci_tcp_state* ts, 
                          struct onload_zc_mmsg* msgs, int flags);
struct onload_zc_recv_args;
int ci_udp_zc_recv(ci_udp_iomsg_args* a, struct onload_zc_recv_args* args);

/* A special version of recvmsg to grab data from kernel stack when
 * doing zero-copy 
 */
extern int ci_udp_recvmsg_kernel(int fd, ci_netif* ni, ci_udp_state* us,
                                 struct msghdr* msg, int flags);
#endif

extern void ci_ip_cmsg_recv(ci_netif*, ci_udp_state*, const ci_ip_pkt_fmt*,
                            struct msghdr*, int netif_locked) CI_HF;
#ifdef __KERNEL__
extern void ci_udp_all_fds_gone(ci_netif* netif, oo_sp);
#endif
extern void ci_udp_state_free(ci_netif*, ci_udp_state*) CI_HF;
extern int ci_udp_csum_correct(ci_ip_pkt_fmt* pkt, ci_udp_hdr* udp) CI_HF;

extern void ci_udp_sendmsg_send_async_q(ci_netif*, ci_udp_state*) CI_HF;
extern void ci_udp_perform_deferred_socket_work(ci_netif*, ci_udp_state*)CI_HF;
extern void ci_udp_try_to_free_pkts(ci_netif*, ci_udp_state*,
                                    int desperation) CI_HF;

#if CI_CFG_USERSPACE_PIPE
extern int ci_pipe_read(ci_netif*, struct oo_pipe*, const struct iovec*,
                  size_t iovlen CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;
extern int ci_pipe_write(ci_netif*, struct oo_pipe*, const struct iovec*,
                  size_t iovlen CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;
extern int oo_pipe_alloc_bufs(ci_netif*, struct oo_pipe*, ci_uint32 num) CI_HF;
extern void oo_pipe_dump(ci_netif*, struct oo_pipe*, const char* pf) CI_HF;
#endif


#ifdef __KERNEL__
/* The following are used for the iscsi async io interface */ 


#include <asm/scatterlist.h>
typedef struct scatterlist ci_os_scatterlist_t;



#define CI_MEM_DESC_TYPE_UNUSED      0
#define CI_MEM_DESC_TYPE_SCATTERLIST 1
#define CI_MEM_DESC_TYPE_POINTER     2
#define CI_MEM_DESC_TYPE_IMMEDIATE   3

/* In the following, length means either:
 - how long the scatterlist is 
 - how long the buffer pointed to by ptr is.
 - unused for the "immediate" type
*/
struct ci_mem_desc {
  int type;
  unsigned length;
  union {
    ci_os_scatterlist_t *scatter;
    void* ptr;
    unsigned immediate;
  } mem;
};
#endif /* __KERNEL__ */


/**********************************************************************
 ********************************* TCP ********************************
 **********************************************************************/

#define SEQ_EQ(s1, s2)      ((ci_uint32)((s1) - (s2)) == 0u)
#define SEQ_LT(s1, s2)      ((ci_int32)((s1) - (s2)) < 0)
#define SEQ_LE(s1, s2)      ((ci_int32)((s1) - (s2)) <= 0)
#define SEQ_GT(s1, s2)      ((ci_int32)((s1) - (s2)) > 0)
#define SEQ_GE(s1, s2)      ((ci_int32)((s1) - (s2)) >= 0)
#define SEQ_SUB(s1, s2)     ((ci_int32)((s1) - (s2)))
#define SEQ(s)              ((unsigned) (s))

/* Is [s] between [sl] and [sh] (inclusive) */
#define SEQ_BTW(s, sl, sh)  ((sh) - (sl) >= (s) - (sl))

#define SEQ_MIN(x, y)           (SEQ_LE(x, y) ? (x) : (y))
#define SEQ_MAX(x, y)           (SEQ_LE(x, y) ? (y) : (x))


/* Flags for connection states.  These are used to determine whether
** certain things can/should be done in the current state.
*/
#define CI_TCP_STATE_SYNCHRONISED	0x001
#define CI_TCP_STATE_SLOW_PATH		0x002
#define CI_TCP_STATE_NOT_CONNECTED	0x004
#define CI_TCP_STATE_CAN_FIN		0x008
#define CI_TCP_STATE_ACCEPT_DATA	0x010
#define CI_TCP_STATE_TXQ_ACTIVE		0x020
#define CI_TCP_STATE_NO_TIMERS		0x040
#define CI_TCP_STATE_TIMEOUT_ORPHAN	0x080
#define CI_TCP_STATE_SOCKET		0x100
#define CI_TCP_STATE_TCP		0x200
#define CI_TCP_STATE_TCP_CONN		0x400
#define CI_TCP_STATE_RECVD_FIN		0x800

/* Connection states.  See also [tcp_misc.c] if you change these. */
#define CI_TCP_CLOSED          (0x0000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_NO_TIMERS)
#define CI_TCP_LISTEN          (0x1000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_NO_TIMERS)
#define CI_TCP_SYN_SENT        (0x2000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_TXQ_ACTIVE)
#define CI_TCP_ESTABLISHED     (0x3000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_CAN_FIN		\
                                       | CI_TCP_STATE_ACCEPT_DATA	\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_CLOSE_WAIT      (0x4000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_CAN_FIN		\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_LAST_ACK        (0x5000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_FIN_WAIT1       (0x6000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_ACCEPT_DATA	\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_FIN_WAIT2       (0x7000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_ACCEPT_DATA	\
                                       | CI_TCP_STATE_TIMEOUT_ORPHAN )
#define CI_TCP_CLOSING         (0x8000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_TIME_WAIT       (0x9000 | CI_TCP_STATE_SOCKET		\
				       | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       /* 2MSL timer doesn't count */	\
                                       | CI_TCP_STATE_NO_TIMERS)

/* Set in a socket that is freed. */
#define CI_TCP_STATE_FREE      (0xa000 | CI_TCP_STATE_NO_TIMERS)

/* Set in a socket that is UDP */
#define CI_TCP_STATE_UDP       (0xb000 | CI_TCP_STATE_SOCKET)

#if CI_CFG_USERSPACE_PIPE
/* Set in a waitable which is in fact a pipe meta (not a pipe end) */
#define CI_TCP_STATE_PIPE      (0xc000)
#endif

/* Reference to a socket in another stack; used in accept queue only */
#define CI_TCP_STATE_ALIEN     (0xd000)

/* Convert state to number in range 0->0xa */
#define CI_TCP_STATE_NUM(s)    (((s) & 0xf000) >> 12u)


/* Flags we don't expect to see in normal data packets. */
#define CI_TCP_OOB_FLAGS     (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN|  \
                              CI_TCP_FLAG_RST|CI_TCP_FLAG_ECE|  \
                              CI_TCP_FLAG_CWR)

/* For the fast path check we inspect header length and all flags other
** than PSH.
*/
#define CI_TCP_FAST_PATH_MASK       CI_BSWAPC_BE32(0xf0f70000)
#define CI_TCP_FAST_PATH_WORD(hdr)  (((ci_uint32*)(hdr))[3])

#ifndef MSG_NOSIGNAL    /* Introduced in glibc3. */
# define MSG_NOSIGNAL           0
#endif


#define tcp_outgoing_opts_len(ts)               \
  ((ts)->outgoing_hdrs_len - sizeof(ci_ip4_hdr) - sizeof(ci_tcp_hdr))

/* These names match the terminology used in the RFCs etc. */
#define tcp_snd_una(ts)  ((ts)->snd_una)
#define tcp_snd_nxt(ts)  ((ts)->snd_nxt)
#define tcp_snd_wnd(ts)  SEQ_SUB((ts)->snd_max, (ts)->snd_una)
#define tcp_snd_up(ts)   ((ts)->snd_up)

#define tcp_rcv_nxt(ts)  (TS_TCP(ts)->tcp_ack_be32)
#define tcp_rcv_buff(ts) ((ts)->s.so.rcvbuf)
#define tcp_rcv_usr(ts)  ((ts)->rcv_added - (ts)->rcv_delivered)
#define tcp_rcv_up(ts)   ((ts)->rcv_up)
#define tcp_rcv_wnd_advertised(ts)  ((ts)->rcv_wnd_advertised)
#define tcp_rcv_wnd_right_edge_sent(ts)  ((ts)->rcv_wnd_right_edge_sent)
#define tcp_rcv_wnd_current(ts) (tcp_rcv_buff((ts)) - tcp_rcv_usr(ts))

/* TCP packet urgent offset - named urgent offset
   to differantiate it from snd_up of the tcp state */
#define tcp_snd_urg_off(ts,tcp) \
  ( (ci_uint16) (tcp_snd_up(ts) - CI_BSWAP_BE32((tcp)->tcp_seq_be32)) )

/* Sequence number of next data to be inserted into TX queue. */
#define tcp_enq_nxt(ts)  (TS_TCP(ts)->tcp_seq_be32)

/* TCP urgent data definitions */
#define tcp_urg_data(ts) ((ts)->urg_data)
#define tcp_urg_data_invalidate(ts) ((ts)->urg_data &=~ \
  (CI_TCP_URG_IS_HERE|CI_TCP_URG_PTR_VALID|CI_TCP_URG_DATA_MASK));

/*! Returns true if we are not expecting an urgent byte. */
#define tcp_rx_urg_fast_path(ts) (~tcp_urg_data(ts) & CI_TCP_URG_COMING)


/* conversion from scaled sa and sv to real srtt and rttvar */
#define tcp_srtt(ts)     ((ts)->sa >> 3u)
#define tcp_rttvar(ts)   ((ts)->sv >> 2u) 

#define CI_SHUT_RD  0x80000000
#define CI_SHUT_WR  0x40000000 
#define TCP_RX_DONE(ts)  ((ts)->s.rx_errno)

#define TCP_RX_ERRNO(ts) (SOCK_RX_ERRNO(&(ts)->s))
#define TCP_TX_ERRNO(ts) (SOCK_TX_ERRNO(&(ts)->s))

/* We never transmit IP options (at the moment). */
#define S_TCP_HDR(s)  ((ci_tcp_hdr*) (&(s)->pkt.ip + 1))
#define TS_TCP(ts)    S_TCP_HDR(&(ts)->s)

/** Macro that initialises RX queue offset */
#define TS_QUEUE_RX_SET(ts, name)				\
  ((ts)->recv_off = CI_MEMBER_OFFSET(ci_tcp_state, name))

/** Get active RX queue (fast/slow as appropriate) from TCP state */
#define TS_QUEUE_RX(ts)				\
  ((ci_ip_pkt_queue*)				\
   ((ci_uintptr_t) (ts) + (ts)->recv_off))

/** Offset of TS within netif state. */
#define TS_OFF(ni, ts)  oo_sockp_to_statep((ni),S_SP(ts))
#define TS_MEMBER_OFF(ni, ts, member) ((ci_uint32)((char *)&(member)    \
                                       - (char*)(ts)        \
                                       + TS_OFF((ni),(ts)))) 
#define TS_FMT			"%d(%u)"
#define TS_ARG(ni,ts)		(S_SP(ts)), (unsigned) TS_OFF((ni),(ts))

#define TCP_STATE_FROM_LINK(lnk)                        \
  CI_CONTAINER(ci_tcp_state, timeout_q_link, (lnk))

/* Macros for controlling delayed ACK state */
#define TCP_FORCE_ACK(ts)   ((ts)->acks_pending |= CI_TCP_ACK_FORCED_FLAG)
#define TCP_NEED_ACK(ts)    (++(ts)->acks_pending)
#define TCP_ACK_FORCED(ts)  ((ts)->acks_pending & CI_TCP_ACK_FORCED_FLAG)

/* macros for getting source and dest addresses and ports */
#define sock_laddr_be32(s)	((s)->pkt.ip.ip_saddr_be32)
#define sock_raddr_be32(s)	((s)->pkt.ip.ip_daddr_be32)
#define sock_protocol(s)	((s)->pkt.ip.ip_protocol)
#define sock_lport_be16(s)	(((ci_uint16*) (&(s)->pkt.ip + 1))[0])
#define sock_rport_be16(s)	(((ci_uint16*) (&(s)->pkt.ip + 1))[1])
/* NB. Above two assume no IP options (which is true for now). */

#define tcp_laddr_be32(ts)	sock_laddr_be32(&(ts)->s)
#define tcp_raddr_be32(ts)	sock_raddr_be32(&(ts)->s)
#define tcp_protocol(ts)	sock_protocol(&(ts)->s)
#define tcp_lport_be16(ts)	sock_lport_be16(&(ts)->s)
#define tcp_rport_be16(ts)	sock_rport_be16(&(ts)->s)



/* Enable / disable the TCP fast path. */
# define ci_tcp_can_use_fast_path(ts)                   \
  ((~ts->s.b.state & CI_TCP_STATE_SLOW_PATH)    &&      \
   ci_ip_queue_is_empty(&(ts)->rob)             &&      \
   tcp_rx_urg_fast_path(ts)                     &&      \
   tcp_rcv_wnd_advertised(ts)                     )

/* In Windows we have to be able to put the state onto the timeout Q when
 * it's not orphaned (thanks to disconnectex) */
/* is state in FIN_WAIT2 and orphaned - if so we timeout */
#define ci_tcp_is_timeout_ophan(ts)			\
    ((ts->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN) &&	\
    (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN))

extern ci_tcp_state* ci_tcp_get_state_buf(ci_netif*) CI_HF;
extern void ci_tcp_state_init(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_reinit(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_init_rcv_wnd(ci_tcp_state*, const char* caller) CI_HF;
extern void ci_tcp_drop(ci_netif*, ci_tcp_state*, int so_error) CI_HF;
extern void ci_tcp_drop_rob(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_try_to_free_pkts(ci_netif* ni, ci_tcp_state* ts,
                                    int desperation) CI_HF;
extern void ci_tcp_state_free(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_free_now(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_free_now_nnl(ci_netif* ni, ci_tcp_state* ts) CI_HF;
#ifdef __KERNEL__
extern void ci_tcp_all_fds_gone(ci_netif* netif, ci_sock_cmn* s);
#endif
extern void ci_tcp_uncache_ep(ci_netif* ni, ci_tcp_state* ts);
extern void ci_tcp_rx_reap_rxq_bufs(ci_netif* netif, ci_tcp_state* ts) CI_HF;

extern void ci_tcp_state_dump(ci_netif* ni, ci_tcp_state*,
			      const char *line_prefix) CI_HF;
extern void ci_tcp_state_dump_id(ci_netif* ni, int ep_id) CI_HF;
extern void ci_tcp_state_dump_qs(ci_netif*, int ep_id, int hex_dump) CI_HF;
extern void ci_tcp_state_dump_rob(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_dump_retrans_blocks(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_state_dump_retrans(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_pkt_dump(ci_netif* ni, ci_ip_pkt_fmt* pkt, int is_recv, 
                            int dump) CI_HF;
extern void ci_tcp_socket_listen_dump(ci_netif*, ci_tcp_socket_listen*,
				      const char* pf) CI_HF;

extern int ci_tcp_add_fin(ci_tcp_state* ts, ci_netif* netif, int can_block);

/* Create a new tcp state in the context of [netif_out] and then
 * copy the important fields, to the newly created tcp state struct 
 *
 * Will only duplicate states in CLOSED state 
 *      i.e. with no filters, buffers....
 */
extern int ci_tcp_move_state(ci_netif* netif_in, ci_tcp_state* ts_in, 
                             ef_driver_handle fd, 
                             ci_netif* netif_out, ci_tcp_state** ts_out) CI_HF;

/**********************************************************************
****************************** PIPE ***********************************
**********************************************************************/

#if CI_CFG_USERSPACE_PIPE
extern void ci_pipe_all_fds_gone(ci_netif* netif, struct oo_pipe* p);

#if CI_CFG_SOCKP_IS_PTR
#define PIPE_BUF_SP(b) CI_CONTAINER(oo_pipe_buf, id, (b))
#else
#define PIPE_BUF_SP(b) ((b)->id)
#endif

#endif

/*********************************************************************
************************** citp_waitable_obj *************************
*********************************************************************/

extern void citp_waitable_reinit(ci_netif* ni, citp_waitable* w) CI_HF;
extern void citp_waitable_init(ci_netif* ni, citp_waitable* w, int id) CI_HF;
extern citp_waitable_obj* citp_waitable_obj_alloc(ci_netif* netif) CI_HF;
extern void citp_waitable_obj_free(ci_netif* ni, citp_waitable* w) CI_HF;
extern void citp_waitable_all_fds_gone(ci_netif*, oo_sp) CI_HF;
extern void citp_waitable_dump(ci_netif*, citp_waitable*, const char*) CI_HF;


/*********************************************************************
*********************************************************************/

extern void ci_tcp_listenq_insert(ci_netif*, ci_tcp_socket_listen*,
                                  ci_tcp_state_synrecv*)  CI_HF;
extern void ci_tcp_listenq_remove(ci_netif*, ci_tcp_socket_listen*,
                                  ci_tcp_state_synrecv*)  CI_HF;
extern ci_tcp_state_synrecv* ci_tcp_listenq_lookup(ci_netif* netif,
						   ci_tcp_socket_listen* tls,
						   ciip_tcp_rx_pkt*) CI_HF;
extern void ci_tcp_listenq_drop_oldest(ci_netif*, ci_tcp_socket_listen*) CI_HF;

extern int ci_tcp_listenq_try_promote(ci_netif*, ci_tcp_socket_listen*,
                                      ci_tcp_state_synrecv*, ciip_tcp_rx_pkt*,
                                      ci_ip_cached_hdrs*) CI_HF;


extern const char* ci_tcp_state_num_str(int state) CI_HF;
#define ci_tcp_state_str(state)  ci_tcp_state_num_str(CI_TCP_STATE_NUM(state))
#define state_str(ts)            ci_tcp_state_str((ts)->s.b.state)

extern const char* ci_tcp_congstate_str(unsigned state) CI_HF;
#define congstate_str(ts)  ci_tcp_congstate_str((ts)->congstate)


extern void ci_tcp_handle_rx(ci_netif*, struct ci_netif_poll_state*,
                             ci_ip_pkt_fmt*, ci_tcp_hdr*, int ip_paylen) CI_HF;
extern void ci_tcp_rx_deliver2(ci_tcp_state*,ci_netif*,ciip_tcp_rx_pkt*) CI_HF;

extern void ci_tcp_tx_change_mss(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_enqueue_no_data(ci_tcp_state* ts, ci_netif* netif,
                                   ci_ip_pkt_fmt* pkt) CI_HF;
extern int ci_tcp_send_sim_synack(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern int ci_tcp_synrecv_send(ci_netif* netif, ci_tcp_socket_listen* tls,
                               ci_tcp_state_synrecv* tsr, 
                               ci_ip_pkt_fmt* pkt, ci_uint8 tcp_flags,
                               ci_ip_cached_hdrs* ipcache_opt) CI_HF;
extern int ci_tcp_retrans_one(ci_tcp_state* ts, ci_netif* netif,
                              ci_ip_pkt_fmt* pkt) CI_HF;
extern void ci_tcp_retrans_recover(ci_netif* ni, ci_tcp_state* ts,
                                   int force_retrans_first) CI_HF;
extern void ci_tcp_enter_fast_recovery(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_recovered(ci_netif* ni, ci_tcp_state* ts) CI_HF;

extern void ci_tcp_clear_sacks(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_retrans_init_ptrs(ci_netif* ni, ci_tcp_state* ts,
                                     unsigned* recover_seq_out) CI_HF;
extern void ci_tcp_get_fack(ci_netif* ni, ci_tcp_state* ts,
                            unsigned* fack_out, int* retrans_data_out) CI_HF;


extern void ci_tcp_retrans_coalesce_block(ci_netif* ni, ci_tcp_state* ts,
                                          ci_ip_pkt_fmt* pkt) CI_HF;
extern int ci_tcp_tx_coalesce(ci_netif* ni, ci_tcp_state* ts,
			      ci_ip_pkt_queue* q, ci_ip_pkt_fmt* pkt,
                              ci_boolean_t is_sendq) CI_HF;
extern void ci_tcp_tx_insert_option_space(ci_netif* ni, ci_tcp_state* ts,
                                          ci_ip_pkt_fmt* pkt, int hdrlen,
					  int extra_opts) CI_HF;
extern int ci_tcp_tx_split(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_queue* qu,
                           ci_ip_pkt_fmt* pkt, int new_paylen, 
                           ci_boolean_t is_sendq) CI_HF;


extern void ci_tcp_tx_advance(ci_tcp_state* ts, ci_netif* netif) CI_HF;
extern void ci_tcp_tx_prequeue(ci_netif*, ci_tcp_state*,
                               ci_ip_pkt_fmt* fill_list)  CI_HF;
extern void ci_tcp_tx_free_prequeue(ci_netif* ni, ci_tcp_state* ts,
                                    int netif_locked) CI_HF;
extern void ci_tcp_send_rst(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_reply_with_rst(ci_netif* netif, ciip_tcp_rx_pkt* rxp) CI_HF;
extern int ci_tcp_reset_untrusted(ci_netif *netif, ci_tcp_state *ts) CI_HF;
extern void ci_tcp_send_zwin_probe(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_fill_small_window(ci_netif* netif, ci_tcp_state* ts) CI_HF;
#if CI_CFG_TAIL_DROP_PROBE
extern int ci_tcp_send_taildrop_probe(ci_netif* netif, ci_tcp_state* ts) CI_HF;
#endif
extern void ci_tcp_set_established_state(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_set_slow_state(ci_netif*, ci_tcp_state*, int state) CI_HF;
extern int ci_tcp_parse_options(ci_netif*, ciip_tcp_rx_pkt*,
				ci_tcp_options*) CI_HF;

extern void ci_ip_hdr_init_fixed(ci_ip4_hdr* ip, int protocol, unsigned ttl,
                                 unsigned tos) CI_HF;

extern void ci_tcp_send_ack(ci_netif*, ci_tcp_state*, ci_ip_pkt_fmt*) CI_HF;
extern void ci_tcp_send_ack_loopback(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern int  ci_tcp_send_wnd_update(ci_netif*, ci_tcp_state*) CI_HF;


/* TCP/UDP filter insertion */
extern void ci_netif_filter_init(ci_netif_filter_table* tbl,
				 int size_lg2) CI_HF;

extern ci_sock_cmn*
__ci_netif_filter_lookup(ci_netif* netif, unsigned daddr, unsigned dport,
			 unsigned saddr, unsigned sport, unsigned prot) CI_HF;

/* Returns table entry index, or -1 if lookup failed. */
extern int
ci_netif_filter_lookup(ci_netif* netif, unsigned laddr, unsigned lport,
		       unsigned raddr, unsigned rport, unsigned prot) CI_HF;

/* Invokes the callback on each socket that matches the supplied addressing
 * fields.  If the callback returns non-zero, then the search is
 * terminated.
 */
extern void
ci_netif_filter_for_each_match(ci_netif*, unsigned laddr, unsigned lport,
                               unsigned raddr, unsigned rport,
                               unsigned protocol, int intf_i, int vlan,
                               int (*callback)(ci_sock_cmn*, void*),
                               void* callback_arg) CI_HF;

extern int
ci_netif_filter_insert(ci_netif* netif, oo_sp sock_id,
		       unsigned laddr, unsigned lport,
		       unsigned raddr, unsigned rport, 
		       unsigned protocol) CI_HF;

extern int
ci_netif_filter_check(ci_netif* netif,
		      unsigned laddr, unsigned lport,
		      unsigned raddr, unsigned rport,
		      unsigned protocol) CI_HF;

extern void 
ci_netif_filter_remove(ci_netif* netif, oo_sp tcp_id,
		       unsigned laddr, unsigned lport,
		       unsigned raddr, unsigned rport,
		       unsigned protocol) CI_HF;

#define CI_NETIF_FILTER_ID_TO_SOCK_ID(ni, filter_id)            \
  OO_SP_FROM_INT((ni), (ni)->filter_table->table[filter_id].id)

/* Bind RX of socket to given interface.  Used by implementation of
 * SO_BINDTODEVICE and EF_MCAST_JOIN_BINDTODEVICE.  Returns 0 on success,
 * CI_SOCKET_HANDOVER otherwise.
 */
extern int ci_sock_rx_bind2dev(ci_netif*, ci_sock_cmn*, ci_ifid_t) CI_HF;

extern int
__ci_tcp_shutdown(ci_netif*, ci_tcp_state*, int how, int can_block) CI_HF;
extern void __ci_tcp_listen_shutdown(ci_netif*, ci_tcp_socket_listen*, ci_fd_t) CI_HF;
extern void ci_tcp_listen_shutdown_queues(ci_netif* netif,
                                          ci_tcp_socket_listen* tls) CI_HF;
extern void __ci_tcp_listen_to_normal(ci_netif*, ci_tcp_socket_listen*) CI_HF;

extern void ci_netif_filter_dump(ci_netif*) CI_HF;

extern unsigned int ci_tcp_wscl_by_buff(ci_netif *netif, int rcv_buff) CI_HF;


/* timer handlers */
#define ci_tcp_time_now(ni) ci_ip_time_now(ni)
#ifndef __KERNEL__
# define ci_tcp_time_ms2ticks(ni, x) ci_ip_time_ms2ticks_fast(ni, (x))
#else
# define ci_tcp_time_ms2ticks(ni, x) ci_ip_time_ms2ticks_slow(ni, (x))
#endif 
extern void ci_tcp_timer_init(ci_netif* netif) CI_HF;
extern void ci_tcp_timeout_listen(ci_netif* netif,
				  ci_tcp_socket_listen* tls) CI_HF;
extern void ci_tcp_timeout_kalive(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_zwin(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_delack(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_rto(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_cork(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_stop_timers(ci_netif* netif, ci_tcp_state* ts) CI_HF;
#if CI_CFG_TAIL_DROP_PROBE
extern void ci_tcp_timeout_taildrop(ci_netif *netif, ci_tcp_state *ts) CI_HF;
#endif

extern void ci_tcp_tx_pkt_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                       ci_ip_pkt_fmt*,
				       const char* f, int l)  CI_HF;
extern void ci_tcp_state_assert_valid(ci_netif*, ci_tcp_state* ts,
                                      const char* file, int line) CI_HF;
extern void ci_tcp_state_listen_assert_valid(ci_netif*, ci_tcp_socket_listen*,
					     const char* file, int line) CI_HF;
extern void ci_tcp_ep_assert_valid(citp_socket*, const char*, int ln) CI_HF;


/**********************************************************************
 * External interface.
 */

#ifndef __KERNEL__

extern int citp_rehome_closed_endpoint(citp_socket* ep, ci_fd_t fd, 
                                       ci_netif* new_ni ) CI_HF;

struct oo_per_thread;
typedef void (*citp_init_thread_callback)(struct oo_per_thread*);
extern int ci_tp_init(citp_init_thread_callback cb) CI_HF;
extern int ci_tcp_bind(citp_socket* ep, const struct sockaddr* my_addr,
                       socklen_t addrlen, ci_fd_t fd) CI_HF;
extern void ci_tcp_linger(ci_netif*, ci_tcp_state*) CI_HF;
extern int ci_tcp_getpeername(citp_socket*, struct sockaddr*, socklen_t*) CI_HF;

extern int ci_tcp_getsockopt(citp_socket* ep, ci_fd_t fd, int level, int optname,
			     void *optval, socklen_t *optlen) CI_HF;
extern int ci_tcp_setsockopt(citp_socket* ep, ci_fd_t fd, int level, int optname,
			     const void*optval, socklen_t optlen) CI_HF;
extern int ci_tcp_ioctl(citp_socket* ep, ci_fd_t fd, int request, void* arg) CI_HF;

#endif /* #ifndef __KERNEL__ */

extern int ci_tcp_listen(citp_socket* ep, ci_fd_t fd, int backlog) CI_HF;

/* Send/recv called from within kernel & user-library, so outside above #if */
extern int ci_tcp_recvmsg(const ci_tcp_recvmsg_args*) CI_HF;
extern int ci_tcp_sendmsg(ci_netif* ni, ci_tcp_state* ts,
                          const struct msghdr* msg, int flags
                          CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;
extern void ci_tcp_sendmsg_enqueue_prequeue_deferred(ci_netif*,
						     ci_tcp_state*) CI_HF;
extern void ci_tcp_sendmsg_enqueue_prequeue(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_perform_deferred_socket_work(ci_netif*, ci_tcp_state*)CI_HF;

/* Guarantees that deferred work will be performed at some point in the
 * near future, either by the calling thread (in this call), or deferred to
 * another thread.
 *
 * Returns 1 if the stack lock was grabbed, else 0.
 */
extern int  ci_netif_lock_or_defer_work(ci_netif*, citp_waitable*) CI_HF;


#ifndef __ci_driver__
extern ci_fd_t ci_tcp_ep_ctor(citp_socket* ep, ci_netif* netif,
                              int domain, int type);
#endif

/* Connect/close also called from within kernel now */

extern int ci_tcp_connect(citp_socket*, const struct sockaddr*, socklen_t,
                          ci_fd_t fd, int *p_moved) CI_HF;
extern int ci_tcp_shutdown(citp_socket*, int how, ci_fd_t fd) CI_HF;
extern int ci_tcp_close(ci_netif* netif, ci_tcp_state* ts, int block) CI_HF;

extern oo_sp ci_tcp_connect_find_local_peer(ci_netif *ni,
                                            ci_ip_addr_t dst_be32,
                                            int dport_be16) CI_HF;

#ifdef __KERNEL__
extern int ci_tcp_abort(citp_socket*) CI_HF;
extern int ci_tcp_connect_lo_samestack(ci_netif *ni, ci_tcp_state *ts,
                                       oo_sp tls_id) CI_HF;
extern int ci_tcp_connect_lo_toconn(ci_netif *c_ni, oo_sp c_id, ci_uint32 dst,
                                    ci_netif *l_ni, oo_sp l_id) CI_HF;
#endif

#if CI_CFG_LIMIT_AMSS || CI_CFG_LIMIT_SMSS
extern int ci_tcp_limit_mss(int mss, ci_netif_state* ni_state,
                            const char* caller) CI_HF;
#endif


/**********************************************************************
 ************************** Misc and tracing **************************
 **********************************************************************/

extern const char* /*??ci_*/ip_addr_str(unsigned addr_be32) CI_HF;
  /* Note that this function is not reentrant.  However, it won't cause
  ** seg-faults.  Two buffers are used alternately, so it can be used twice
  ** in an list of arguments.
  */

extern const char* /*??ci_*/domain_str(int domain) CI_HF;
extern const char* /*??ci_*/type_str(int type) CI_HF;

/*! Returns zero if a socket to the destination 'ip_be32' can
 *  be handled by the L5 stack.
 *  On failure, the return value is the error condition.
 */
extern int ci_can_handle_addr(ci_netif *netif, ci_uint32 ip_be32,
                              unsigned int proto, ci_uint32 *src_ip_be32_out,
                              unsigned *nic_i_out, unsigned *mtu_out) CI_HF;


#define NETIF_MAGIC     0xd


/**********************************************************************
************************** Per-socket locks ***************************
**********************************************************************/

extern int  ci_sock_lock_slow(ci_netif* ni, citp_waitable* w) CI_HF;
extern void ci_sock_unlock_slow(ci_netif*, citp_waitable*) CI_HF;


/**********************************************************************
******************************* Sleeping ******************************
**********************************************************************/

#define CI_SLEEP_NETIF_LOCKED           0x1
#define CI_SLEEP_SOCK_LOCKED            0x2
#define CI_SLEEP_NETIF_RQ               0x4
#define CI_SLEEP_SOCK_RQ                0x8

/*! Sleep until something happens.
**
**   [why] should be a combination of CI_SB_FLAG_WAKE_RX and
**   CI_SB_FLAG_WAKE_TX.
**
**   [lock_flags] indicates which locks the caller holds on entry, and
**   which locks the caller would like to grab post-exit.  It should be 0
**   or a combination of CI_SLEEP_NETIF_LOCKED, CI_SLEEP_SOCK_LOCKED,
**   CI_SLEEP_NETIF_RQ and CI_SLEEP_SOCK_RQ.
**
**   [sleep_seq] should be the value of [w->sleep_seq] before the sleep
**   condition was tested.
**
**   [timeout] IN: timeout in ms; 0 if no timeout.
**   OUT: the rest of timeout (may be passed to the next call
**   of this function).
*/
extern int ci_sock_sleep(ci_netif* ni, citp_waitable* w, ci_bits why,
                         unsigned lock_flags, ci_uint64 sleep_seq,
                         ci_uint32 *timeout_ms_p) CI_HF;


/**********************************************************************
******************************* Polling *******************************
**********************************************************************/

#define ci_netif_is_contention(ni)				\
  (ef_eplock_flags(&(ni)->state->lock) &			\
   (CI_EPLOCK_FL_NEED_WAKE | CI_EPLOCK_NETIF_SOCKET_LIST))


/**********************************************************************
 ************************* Errno wrappers etc. ************************
 **********************************************************************/

/*! Return value where a handover is required by a higher layer. */
#define CI_SOCKET_HANDOVER -2


/* *****************
 * Errno wrappers - note that errno should not be accessed directly 
 */
#ifdef __KERNEL__
# define CI_SET_ERROR(rc, e)	do{ (rc) = -(e); }while(0)
# define CI_GET_ERROR(rc)	(-(rc))
#else
# define CI_SET_ERROR(rc, e)	do{ errno = (e);			\
                                    (rc) = CI_SOCKET_ERROR; }while(0)
# define CI_GET_ERROR(rc)	(errno)
#endif

/* Sets errno to specified value and returns CI_SOCKET_ERROR */
#define RET_WITH_ERRNO(_errno)  do {      \
        int rc_;                          \
        CI_SET_ERROR(rc_, _errno);        \
        return rc_; } while (0)

/**********************************************************************
 **************************** OS-specific *****************************
**********************************************************************/

/* ************************** */
/*    Unix Implementation     */
/* ************************** */

/*! \i_ossock  Return value from failed socket calls.  In Linux this
 * is -1 and in Windows it's INVALID_SOCKET */
#define CI_INVALID_SOCKET -1

/*! \i_ossock  Return value from failed socket calls.  In Linux this
 * is -1 and in Windows it's SOCKET_ERROR */
#define CI_SOCKET_ERROR -1

/*! \i_ossock Verify that a file descriptor/handle is valid */
#define CI_IS_VALID_SOCKET(fd) ((fd) >= 0)

/*! \i_ossock Open the backing OS socket.  
 * Performs a "bulk standard" OS socket creation call (sys_socket() etc.).
 * Call this during socket() intercept handler. 
 * Windows: The OS backing socket handle is stored in [ep]
 * Linux:   The OS backing socket fd is not stored
 * \param ep     [in] Ptr to endpoint structure (ci_udp_ep or ci_tcp_ep)
 * \param dom    [in] Socket domain; AF_INET
 * \param type   [in] Socket type; SOCK_STREAM | SOCK_DGRAM
 * \param prot   [in] Protocol; IPPROTO_TCP | IPPROTO_UDP 
 * \return       Success: Socket fd. Fail CI_INVALID_SOCKET & errno set
 */
#define ci_open_os_sock(ep,dom,type,prot) ci_sys_socket((dom),(type),(prot))

/*! \i_ossock Failure case handler. 
 * Close a socket created by ci_open_os_sock(). 
 * Call this _only_ in socket() intercept failure case 
 * \param ep     [in] Ptr to endpoint structure (ci_udp_ep or ci_tcp_ep)
 * \param sock   [in] Socket fd created by ci_open_os_sock()
 * \return       Nothing
 */
#define ci_abort_os_sock(ep,sock) ci_tcp_helper_rel_sock_fd((sock))

/*! \i_ossock Close the OS backing/companion socket.
 * Closes the OS backing Call during close() interception.
 * Linux only: Does nothing
 * \param ep     [in] Ptr to endpoint structure (ci_udp_ep or ci_tcp_ep)
 * \return       Nothing
 */
#define ci_close_os_sock(ep)

/*! \i_ossock Get an Fd that can be used in UL calls to sys socket calls.
 * Windows: returns handle stored in UL
 * Linux:   call the TCP helper to get a temporary fd
 * \param ep     [in] Ptr to endpoint structure (citp_socket*)
 * \param fd     [in] Efab fd (the fd used by the application)
 * \return       Success: Fd (value > 0), Fail: error (value < 0)
 */
#define ci_get_os_sock_fd(ep, fd)  ci_tcp_helper_get_sock_fd(fd)

/*! \i_ossock Release the OS fd obtained through ci_get_os_sock_fd().
 * Windows: Does nothing
 * Linux:   call the TCP helper to get release the temporary fd
 * \param fd     [in] OS fd to release
 * \return       nothing
 */
#define ci_rel_os_sock_fd(fd) do { if((fd) != CI_INVALID_SOCKET) \
  ci_tcp_helper_rel_sock_fd((fd)); } while(0)


/* ************************** */
/*   Windows Implementation   */
/* ************************** */


/**********************************************************************
************************* Payload copying funcs ***********************
**********************************************************************/


/* Copy data from [piov] into [pkt].  [buf] identifies the buffer space
** into which data can be copied.
*/
extern int __ci_copy_iovec_to_pkt(ci_netif*, ci_ip_pkt_fmt*, ci_iovec_ptr*
                                  CI_KERNEL_ARG_UNIX(ci_addr_spc_t)) CI_HF;

#if defined(__KERNEL__) && defined(__unix__)
# define ci_copy_iovec_to_pkt(ni, pkt, piov, addr_spc)          \
   __ci_copy_iovec_to_pkt((ni), (pkt), (piov), (addr_spc))
#else
# define ci_copy_iovec_to_pkt(ni, pkt, piov)    \
   __ci_copy_iovec_to_pkt((ni), (pkt), (piov))
#endif

#if defined(__KERNEL__)
# define ci_ip_copy_pkt_to_user         __ci_ip_copy_pkt_to_user
extern ssize_t __ci_ip_copy_pkt_to_user(ci_netif*, ci_iovec*,
                                        ci_ip_pkt_fmt*, int peek_off,
                                        ci_addr_spc_t addr_spc) CI_HF;

# define ci_ip_copy_pkt_from_piov  __ci_ip_copy_pkt_from_piov
extern size_t __ci_ip_copy_pkt_from_piov(ci_netif*, ci_ip_pkt_fmt*, 
                                         ci_iovec_ptr*, ci_addr_spc_t) CI_HF;
#else /* __KERNEL__ */
# define ci_ip_copy_pkt_to_user(ni, iov, pkt, peek_off, aspc) \
  __ci_ip_copy_pkt_to_user((ni), (iov), (pkt), (peek_off))
extern ssize_t __ci_ip_copy_pkt_to_user(ci_netif*, ci_iovec*,
				        ci_ip_pkt_fmt*, int) CI_HF;

# define ci_ip_copy_pkt_from_piov(ni, pkt, iov, aspc)	\
  __ci_ip_copy_pkt_from_piov((ni), (pkt), (iov))
extern size_t __ci_ip_copy_pkt_from_piov(ci_netif*, ci_ip_pkt_fmt*,
                                         ci_iovec_ptr*) CI_HF;
#endif


extern const unsigned char ci_sock_states_linux_map[] CI_HV;


/**********************************************************************
************************* sendmsg/recvmsg code reuse ******************
**********************************************************************/

/* Flags to indicate that a lock is already locked so a blocking lock
** should not be attempted.  These flags may be used together with socket
** syscall flags (including MSG_DONTWAIT, MSG_OOB, MSG_WAITALL etc.) and so
** must not overlap with legitimate values.
*/
#define CI_MSG_NETIF_LOCKED         0x80000000
#define CI_MSG_SOCK_LOCKED          0x40000000
#define CI_MSG_SOCK_LOCK_NOT_NEEDED 0x20000000
#define CI_MSG_NO_WND_UPDATE        0x10000000
#define CI_MSG_NO_POLL              0x08000000


/* Windows only: Flag used to signal that an overlapped operations is being 
 * handled by our stack rather than the OS. Will never be seen in the context
 * of send/recv etc - only used in the WSAOVERLAPPED.Offset field.
 *
 * DJR: ?? Then why does it start with CI_MSG?  Just confusing...
 */
#define CI_MSG_OVERLAPPED_EFAB     0x20000000


/* Copy data from the receive queue to the specified buffers.  Returns the
** number of bytes copied.  This function also sends window updates as
** appropriate.
**
** User-level callers must hold the socket lock.  Other, trusted,
** stacks can get away without it as long as they avoid concurrent
** receives.  Use the flags arg and the CI_MSG_*_LOCKED constants to
** specify which locks are already held.
**
** When called at userlevel, this function can only be used to copy data
** into buffers in the current address space.
**
** When called in the kernel, it may be used to copy data into buffers in
** the kernel address space ([addr_spc] == CI_ADDR_SPC_KERNEL), or in the
** application's address space.  On some O/S's (eg. win32) it may only be
** possible to copy into the address space of an application when in
** certain contexts.
*/
extern int ci_tcp_recvmsg_get(const ci_tcp_recvmsg_args*, ci_iovec_ptr*) CI_HF;


extern int ci_tcp_fill_stolen_buffer(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                 ci_iovec_ptr* piov 
                                 CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;


extern void ci_tcp_sendmsg_prep_pkt_ool(ci_netif*, ci_tcp_state*,
                                        ci_ip_pkt_fmt*, unsigned seq) CI_HF;



/**********************************************************************
 ** IP stack parameters to get from OS.
 */
extern int ci_setup_ipstack_params(void);


/**********************************************************************
****************************** Statistics *****************************
**********************************************************************/

#if CI_CFG_STATS_NETIF
# define CITP_STATS_NETIF(x)		x
# define CITP_STATS_NETIF_INC(ni,x)	do{ ++(ni)->state->stats.x; }while(0)
# define CITP_STATS_NETIF_ADD(ni,x,v)	do{ (ni)->state->stats.x += v; }while(0)
#else
# define CITP_STATS_NETIF(x)
# define CITP_STATS_NETIF_INC(ni,x)
# define CITP_STATS_NETIF_ADD(ni,x,v)
#endif

#if CI_CFG_STATS_TCP_LISTEN
# define CITP_STATS_TCP_LISTEN(x)	x
#else
# define CITP_STATS_TCP_LISTEN(x)
#endif

#if CI_CFG_DETAILED_CHECKS
# define CITP_DETAILED_CHECKS(x)        x
#else
# define CITP_DETAILED_CHECKS(x)
#endif


/**********************************************************************
******************** Accessing trusted kernel state *******************
**********************************************************************/

#define ci_netif_ep_get(ni, s)  ((ni)->ep_tbl[OO_SP_TO_INT(s)])
#define ci_trs_ep_get(trs, s)   ci_netif_ep_get(&(trs)->netif, (s))

#define ci_netif_get_valid_ep(ni, sockp)                \
  ((ni)->ep_tbl[TRUSTED_SOCK_ID_FROM_P((ni), (sockp))])
#define ci_trs_get_valid_ep(trs, sock_id)               \
  ci_netif_get_valid_ep(&(trs)->netif, (sock_id))


/**********************************************************************
***************************** Misc macros *****************************
**********************************************************************/

#define OO_STACK_FOR_EACH_INTF_I(ni, _intf_i)                           \
  for( (_intf_i) = 0; (_intf_i) < oo_stack_intf_max(ni); ++(_intf_i) )


/*
**
**
**
**
**
**
**
**
**
** DO NOT PUT ANY INLINE FUNCTIONS ABOVE THIS POINT.
**
**
**
**
**
**
**
**
*/


/*********************************************************************
************************ Runtime config options **********************
*********************************************************************/

ci_inline ef_driver_handle ci_netif_get_driver_handle(const ci_netif* ni) {
#ifdef __KERNEL__
  return 0;
#else
  return ni->driver_handle;
#endif
}


ci_inline ef_vi* ci_netif_rx_vi(ci_netif* ni, int nic_i) {
  return &ni->nic_hw[nic_i].vi;
}

/* How many more descriptors can be posted into this VI?  Answer may be
 * negative, because rxq_limit changes dynamically.
 */
ci_inline int ci_netif_rx_vi_space(ci_netif* ni, ef_vi* vi)
{ return ni->state->rxq_limit - ef_vi_receive_fill_level(vi); }



ci_inline int oo_stack_intf_max(ci_netif* ni) {
#if CI_CFG_MAX_INTERFACES == 1
  return 1;
#elif defined(__KERNEL__)
  return ni->nic_n;
#else
  return ni->state->nic_n;
#endif
}


/**********************************************************************
 * Handling return from ci_netif_pkt_wait() and ci_netif_lock().
 */

ci_inline int ci_netif_pkt_wait_was_interrupted(int rc) {
#ifdef __KERNEL__
  ci_assert(rc == 0 || rc == -ERESTARTSYS);
  return rc < 0;
#else
  ci_assert_equal(rc, 0);
  return 0;
#endif
}


ci_inline int ci_netif_pkt_alloc_block_was_interrupted(ci_ip_pkt_fmt* pkt) {
#ifdef __KERNEL__
  return pkt == NULL;
#else
  return 0;
#endif
}


ci_inline int ci_netif_lock_was_interrupted(int rc) {
#ifdef __KERNEL__
  ci_assert(rc == 0 || rc == -EINTR);
  return rc < 0;
#else
  ci_assert_equal(rc, 0);
  return 0;
#endif
}


/*********************************************************************
******************************** Bit arrays **************************
*********************************************************************/

ci_inline void oo_bit_array_set(ci_uint32* array, int id)
{
  array[id >> 5] |= 1 << (id & 31);
}

ci_inline void oo_bit_array_clear(ci_uint32* array, int id)
{
  array[id >> 5] &= ~(1 << (id & 31));
}

ci_inline int oo_bit_array_get(ci_uint32* array, int id)
{
  return (array[id >> 5] >> (id & 31)) & 1;
}


/*********************************************************************
************************** citp_waitable_obj *************************
*********************************************************************/

ci_inline ci_udp_state* SOCK_TO_UDP(ci_sock_cmn* s) {
  ci_assert(s->b.state == CI_TCP_STATE_UDP);
  return CI_CONTAINER(ci_udp_state, s, s);
}

#ifdef NDEBUG
ci_inline ci_tcp_state* SOCK_TO_TCP(ci_sock_cmn* s)
{ return CI_CONTAINER(ci_tcp_state, s, s); }
#else
ci_inline ci_tcp_state* SOCK_TO_TCP_DEBUG(ci_sock_cmn*s, const char*file,
                                          int line) {
  _ci_assert(s->b.state & CI_TCP_STATE_TCP, file, line);
  _ci_assert(s->b.state == CI_TCP_CLOSED ||
             (s->b.state & CI_TCP_STATE_TCP_CONN), file, line);
  return CI_CONTAINER(ci_tcp_state, s, s);
}

# define SOCK_TO_TCP(s) SOCK_TO_TCP_DEBUG(s, __FILE__, __LINE__)
#endif

ci_inline ci_tcp_socket_listen* SOCK_TO_TCP_LISTEN(ci_sock_cmn* s) {
  ci_assert(s->b.state == CI_TCP_LISTEN);
  return CI_CONTAINER(ci_tcp_socket_listen, s, s);
}

ci_inline citp_waitable_obj* SOCK_TO_WAITABLE_OBJ(ci_sock_cmn* s)
{ return CI_CONTAINER(citp_waitable_obj, sock, s); }


ci_inline int oo_sock_id_is_waitable(ci_netif* ni, int sock_id) {
#if CI_CFG_USERSPACE_PIPE
  return oo_bit_array_get(ni->state->ep_buf_is_ep, sock_id);
#else
  return 1;
#endif
}


/*********************************************************************
************************** UDP Receive queue *************************
*********************************************************************/

ci_inline void ci_udp_recv_q_init(ci_udp_recv_q* q) {
  q->head = q->extract = OO_PP_NULL;
  q->pkts_reaped = q->pkts_delivered = q->pkts_added = 0;
  q->bytes_delivered = q->bytes_added = 0;
#if CI_CFG_ZC_RECV_FILTER
  q->filter = OO_PP_NULL;
  q->pkts_filter_passed = q->pkts_filter_dropped = 0;
  q->bytes_filter_passed = q->bytes_filter_dropped = 0;
#endif
}

ci_inline int ci_udp_recv_q_is_empty(ci_udp_state* us)
{
#if CI_CFG_ZC_RECV_FILTER
  return us->recv_q.pkts_added == (us->recv_q.pkts_delivered + 
                                   us->recv_q.pkts_filter_dropped);
#else
  return us->recv_q.pkts_added == us->recv_q.pkts_delivered;
#endif
}

ci_inline int ci_udp_recv_q_not_empty(ci_udp_state* us)
{ 
#if CI_CFG_ZC_RECV_FILTER
  return us->recv_q.pkts_added != (us->recv_q.pkts_delivered +
                                   us->recv_q.pkts_filter_dropped);
#else
  return us->recv_q.pkts_added != us->recv_q.pkts_delivered;
#endif
}

ci_inline int ci_udp_recv_q_readable(ci_netif* ni, ci_udp_state* us)
{
#if CI_CFG_ZC_RECV_FILTER
  if( ci_udp_recv_q_is_empty(us) )
    return 0;
# ifndef __KERNEL__
  else if( us->recv_q_filter )
    return ci_udp_filter_recved_pkts(ni, us);
# endif
  /* not empty and no filter => readable */
  return 1;
#else
  return ci_udp_recv_q_not_empty(us);
#endif
}

ci_inline int ci_udp_recv_q_not_readable(ci_netif* ni, ci_udp_state* us)
{
#if CI_CFG_ZC_RECV_FILTER
  if( ci_udp_recv_q_is_empty(us) )
    return 1;
# ifndef __KERNEL__
  else if( us->recv_q_filter )
    return !ci_udp_filter_recved_pkts(ni, us);
# endif
  /* not empty and no filter => readable */
  return 0;
#else
  return ci_udp_recv_q_is_empty(us);
#endif
}

ci_inline int ci_udp_recv_q_pkts(ci_udp_recv_q* q)
{
#if CI_CFG_ZC_RECV_FILTER
  return q->pkts_added - q->pkts_delivered - q->pkts_filter_dropped;
#else
  return q->pkts_added - q->pkts_delivered; 
#endif
}

ci_inline int ci_udp_recv_q_reapable(ci_udp_recv_q* q)
{ 
#if CI_CFG_ZC_RECV_FILTER
  return q->pkts_delivered + q->pkts_filter_dropped - q->pkts_reaped;
#else
  return q->pkts_delivered - q->pkts_reaped;
#endif
}

ci_inline int ci_udp_recv_q_bytes(ci_udp_recv_q* q)
{ 
#if CI_CFG_ZC_RECV_FILTER
  return q->bytes_added - q->bytes_delivered - q->bytes_filter_dropped;
#else
  return q->bytes_added - q->bytes_delivered;
#endif
}


/*********************************************************************
********************** Timers and management *************************
*********************************************************************/

/*! This function gets the current cached time in ticks
**  \param its  A pointer to the ci_ip_timer_state management block
**  \return     The current cached time in ticks 
*/
ci_inline ci_iptime_t ci_ip_time_now(ci_netif *ni)
{ return IPTIMER_STATE(ni)->ci_ip_time_real_ticks; }

/*! This function sets the initial current free cycle counter time in ticks 
**  \param its  A pointer to the ci_ip_timer_state management block
*/
ci_inline void ci_ip_time_initial_sync(ci_ip_timer_state* its) {
#if defined(CI_HAVE_FRC64) 
  ci_frc64(&its->frc);  
  its->ci_ip_time_real_ticks =
    (ci_iptime_t)(its->frc >> its->ci_ip_time_frc2tick);
#else
# error need a frc64 routine to compile iptimer support
#endif  
}

ci_inline void ci_ip_time_update(ci_ip_timer_state* its, ci_uint64 new_frc) {
  if(CI_LIKELY( new_frc >= its->frc )) {
    ci_iptime_t new_ticks;
    new_ticks = (ci_iptime_t) (new_frc >> its->ci_ip_time_frc2tick);
    its->ci_ip_time_real_ticks = new_ticks;
    its->frc = new_frc;
  }
}

/*! This function updates the current free cycle counter time in ticks 
**  \param its  A pointer to the ci_ip_timer_state management block
*/
ci_inline void ci_ip_time_resync(ci_ip_timer_state* its) {
  ci_uint64 new_frc;
  ci_frc64(&new_frc);  
  ci_ip_time_update(its, new_frc);
}

/*! This function gets the current free cycle counter time in ticks 
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    An out parameter to write the return into
*/
ci_inline void ci_ip_time_get(ci_ip_timer_state* its, ci_iptime_t* ticks) {
#if defined(CI_HAVE_FRC64)  
  ci_uint64 frc;
  ci_frc64(&frc);  
  *ticks = (ci_iptime_t)(frc >> its->ci_ip_time_frc2tick);
#else
# error need a frc64 routine to compile iptimer support
#endif  
}

/*! This function gets the current free cycle counter time in us
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    An out parameter to write the return into
*/
ci_inline void ci_ip_time_get_us(ci_ip_timer_state* its, ci_iptime_t* t) {
#if defined(CI_HAVE_FRC64)  
  ci_uint64 frc;
  ci_frc64(&frc);  
  *t = (ci_iptime_t)(frc >> its->ci_ip_time_frc2us);
#else
# error need a frc64 routine to compile iptimer support
#endif  
}

#ifndef __KERNEL__

/*! Convert a time measure in ms to the number of ticks
**  \param ni   A pointer to the netif 
**  \param t    The time in ms
**  \return     The time t in ticks
**
**  This function uses a floating point field ci_ip_time_tick2ms and floating
**  point calculations (note: floating point may not be available in the
**  kernel).
*/
ci_inline ci_iptime_t ci_ip_time_ms2ticks_fast(ci_netif *ni, ci_uint32 t) 
{
  /* Only call this function from userland */
  
  /* uses floating point arithmetic to ease overflow worries */
  t = (ci_iptime_t) (((double)t)/ni->ci_ip_time_tick2ms); 
  /* rounds up 0 timers... */
  return t ? t : 1;
}

#endif

/*! Convert a time measure in ms to the number of ticks
**  \param ni   The netif
**  \param t    The time in ms
**  \return     The time t in ticks
**
**  This function uses only the field ci_ip_time_frc2tick and only integer
**  calculations (floating point may not be available in the kernel).
*/
ci_inline ci_iptime_t ci_ip_time_ms2ticks_slow(ci_netif* ni, ci_uint32 t)
{
  ci_ip_timer_state *its = IPTIMER_STATE(ni);
  /* 
   * cycles
   * ------ x t
   *   ms
   * ----------
   *   cycles
   *   ------
   *    tick
   *
   */
  
  unsigned high, middle1, middle2, low;
  low=(its->khz&0x0000ffff) * (t&0x0000ffff);
  middle1=((its->khz&0xffff0000)>>16) * (t&0x0000ffff);
  middle2=(its->khz&0x0000ffff) * ((t&0xffff0000)>>16);
  high=((its->khz&0xffff0000)>>16) * ((t&0xffff0000)>>16);
  low=low>>its->ci_ip_time_frc2tick;
  
  if ( its->ci_ip_time_frc2tick > 16 ) {
    low+=middle1>>(its->ci_ip_time_frc2tick-16);
    low+=middle2>>(its->ci_ip_time_frc2tick-16);
  }
  else {
    low+=middle1<<(16-its->ci_ip_time_frc2tick);
    low+=middle2<<(16-its->ci_ip_time_frc2tick);
  }
  ci_assert( its->ci_ip_time_frc2tick<=32 );
  low+=high>>(32-its->ci_ip_time_frc2tick);
  return low ? low : 1;
}

#ifndef __KERNEL__
/*! Convert a time measure in ticks to ms
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    The time in ticks
**  \return     The time t in ms
*/
ci_inline ci_uint32 ci_ip_time_ticks2ms(ci_netif* ni, ci_iptime_t t) {
  return (ci_uint32) (t*ni->ci_ip_time_tick2ms);
}
#else

/* TODO FIXME HACK to get kernel version working */

/*! Convert a time measure in ticks to ms
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    The time in ticks
**  \return     The time t in ms
*/
ci_inline ci_uint32 ci_ip_time_ticks2ms(ci_netif* ni, ci_iptime_t t)
{
  ci_ip_timer_state *its = IPTIMER_STATE(ni);
  return (ci_uint32)((t * 
		      (1u<<its->ci_ip_time_frc2tick))/its->khz);
}
#endif

#ifndef __KERNEL__
/*! Get the current time in mS */
ci_inline ci_uint32 ci_ip_time_now_ms(ci_netif *ni) 
{ 
  return ci_ip_time_ticks2ms(ni, ci_ip_time_now(ni));
}
#endif





/*! Returns true if an ARP path exists i.e. arp_seq_num >= 2 */
ci_inline int ci_ip_cache_is_installed(ci_ip_cached_hdrs *ipcache)
{
  return (ipcache->flags & CI_IP_CACHE_IS_LOCALROUTE) |
         (ipcache->mac_integrity.row_version != CI_VERLOCK_BAD);
}


ci_inline const ci_int8* ci_netif_get_blacklist_intf_i(ci_netif* ni) {
#ifdef __KERNEL__
  return ni->blacklist_intf_i;
#else
  return ni->state->blacklist_intf_i;
#endif
}

ci_inline unsigned ci_netif_get_blacklist_length(ci_netif* ni) {
#ifdef __KERNEL__
  return ni->blacklist_length;
#else
  return (unsigned)ni->state->blacklist_length;
#endif
}

ci_inline const ci_int8* ci_netif_get_hwport_to_intf_i(ci_netif* ni) {
#ifdef __KERNEL__
  return ni->hwport_to_intf_i;
#else
  return ni->state->hwport_to_intf_i;
#endif
}


ci_inline int __ci_hwport_to_intf_i(ci_netif* ni, ci_hwport_id_t hwport) {
  ci_assert((unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES);
  return ci_netif_get_hwport_to_intf_i(ni)[hwport];
}


ci_inline int ci_hwport_to_intf_i(ci_netif* ni, ci_hwport_id_t hwport) {
  if(CI_LIKELY( (unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES ))
    return ci_netif_get_hwport_to_intf_i(ni)[hwport];
  return ci_netif_bad_hwport(ni, hwport);
}




ci_inline int ci_netif_may_poll(ci_netif* ni)
{
  return NI_OPTS(ni).poll_on_demand;
}


/* Cheap test that returns true if the stack is "primed".  i.e. Will
** generate an interrupt when an event next arrives.
*/
ci_inline int ci_netif_is_primed(ci_netif* ni)
{ return ni->nic_set.nics == ni->state->evq_primed; }

/* Cheap test that returns true if the stack is not "primed".  i.e. Not all
** event queues have been primed to generate an interrupt when the next
** event arrives.
*/
ci_inline int ci_netif_not_primed(ci_netif* ni)
{ return ni->nic_set.nics != ni->state->evq_primed; }


/* Returns true if there are any hardware events outstanding on the given
 * interface.
 */
ci_inline int ci_netif_intf_has_event(ci_netif* ni, int intf_i)
{ return ef_eventq_has_event(&ni->nic_hw[intf_i].vi); }


/* Returns true if there are any hardware events outstanding on any
 * interface.
 */
ci_inline int ci_netif_has_event(ci_netif* ni) {
  int intf_i, rc = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ci_netif_intf_has_event(ni, intf_i) ) {
      rc = 1;
      break;
    }
  if( OO_PP_NOT_NULL(ni->state->looppkts) )
    rc = 1;
  return rc;
}


/* Returns true if there are many hardware events outstanding. */
ci_inline int ci_netif_has_many_events(ci_netif* ni, int lookahead) {
  int intf_i, rc = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ef_eventq_has_many_events(&ni->nic_hw[intf_i].vi, lookahead) ) {
      rc = 1;
      break;
    }
  return rc;
}


ci_inline int ci_netif_need_timer_prime(ci_netif* ni, ci_uint64 frc_now) {
  return frc_now - ni->state->evq_last_prime > ni->state->timer_prime_cycles;
}


/* See ci_netif_need_poll() for description.  Use this when you already
** know a recent frc.
*/
ci_inline int ci_netif_need_poll_frc(ci_netif* ni, ci_uint64 frc_now) {
  return ( ci_netif_not_primed(ni) &&
           ( ci_netif_has_event(ni) ||
             ci_netif_need_timer_prime(ni, frc_now) ) );
}


/* Indicates whether some work might be done if the stack is polled.  It is
** expected that this will normally be called by threads that don't hold
** the lock.
**
** Returns true if the stack is not 'primed' and there are events
** outstanding or it has been a while since the stack was last polled.
*/
ci_inline int ci_netif_need_poll(ci_netif* ni)
{ return ci_netif_need_poll_frc(ni, ci_frc64_get()); }


ci_inline int ci_netif_need_poll_spinning(ci_netif* ni, ci_uint64 frc_now)
{ return ci_netif_has_event(ni) || ci_netif_need_timer_prime(ni, frc_now); }


ci_inline int ci_netif_need_poll_maybe_spinning(ci_netif* ni, ci_uint64 frc_now,
                                         int spinning) {
  if( spinning )
    return ci_netif_need_poll_spinning(ni, frc_now);
  else
    return ci_netif_need_poll_frc(ni, frc_now);
}


/*********************************************************************
*********************** Indirected linked lists **********************
*********************************************************************/

/* Get the code for the linked lists. */
#define CI_MK_ID(x)             ci_ni_dllist##x
#define CI_ILL_PTR(ctx, a)      ((ci_ni_dllist_link*) CI_NETIF_PTR((ctx), (a)))
#define CI_ILL_ADDR_EQ(a, b)    OO_P_EQ((a), (b))
#define CI_ILL_ADDR_T           oo_p
#define CI_ILL_ADDR_NULL        OO_P_NULL
#define CI_ILL_CTX_T            ci_netif*
#if CI_CFG_OOP_IS_PTR
# define CI_ILL_ADDR(ctx,lnk)	((oo_p) (lnk))
#endif
#define CI_ILL_NO_TYPES
#include <ci/tools/idllist.h.tmpl>


/*! Debug function to see if the list link behind the timer is valid */
ci_inline int ci_ip_timer_is_link_valid(ci_netif* ni, ci_ip_timer* ts)
{ return ci_ni_dllist_is_valid(ni, &ts->link); }

/*! Clear a timer (whether or not its pending).
**  \param netif  A pointer to the netif for this timer
**  \param ts     A pointer to the timer structure
*/
ci_inline void ci_ip_timer_clear(ci_netif* netif, ci_ip_timer* ts)
{ ci_ni_dllist_remove_safe(netif, &ts->link); }

/*! Check if a timer is pending 
**  \param ts     A pointer to the ip timer structure to check 
**  \return       0 if not pending, 1 if pending
*/
ci_inline int ci_ip_timer_pending(ci_netif* netif, ci_ip_timer* ts)
{ return ! ci_ni_dllist_is_self_linked(netif, &ts->link); }

/*! Initialise a new timer. */
ci_inline void ci_ip_timer_init(ci_netif* netif, ci_ip_timer* t,
                                oo_p t_sp, const char* name) {
  OO_P_ADD(t_sp, CI_MEMBER_OFFSET(ci_ip_timer, link));
  ci_assert(CI_NETIF_PTR(netif, t_sp) == (char*) &t->link);
  ci_ni_dllist_link_init(netif, &t->link, t_sp, name);
  ci_ni_dllist_self_link(netif, &t->link);
}


/*********************************************************************
********************** Packet buffer allocation **********************
*********************************************************************/

ci_inline void __ci_netif_pkt_clean(ci_ip_pkt_fmt* pkt) 
{
  pkt->flags &= CI_PKT_FLAG_NONB_POOL;
  pkt->n_buffers = 1;
  pkt->frag_next = OO_PP_NULL;
  oo_pkt_layout_set(pkt, CI_PKT_LAYOUT_INVALID);
}


ci_inline ci_ip_pkt_fmt* ci_netif_pkt_get(ci_netif* ni) {
  ci_ip_pkt_fmt* pkt;
  ci_assert_gt(ni->state->n_freepkts, 0);
  ci_assert(OO_PP_NOT_NULL(ni->state->freepkts));
  pkt = PKT(ni, ni->state->freepkts);
  ni->state->freepkts = pkt->next;
  --ni->state->n_freepkts;
  pkt->refcount = 1;
  CI_DEBUG(pkt->intf_i = -1);
  CHECK_FREEPKTS(ni);
  return pkt;
}


ci_inline ci_ip_pkt_fmt* ci_netif_pkt_alloc(ci_netif* ni) {
  ci_ip_pkt_fmt* pkt;
  ci_assert( ci_netif_is_locked(ni) );
  if(CI_LIKELY( OO_PP_NOT_NULL(ni->state->freepkts) ))
    pkt = ci_netif_pkt_get(ni);
  else
    pkt = ci_netif_pkt_alloc_slow(ni, 0);
  return pkt;
}


#if ! CI_CFG_PP_IS_PTR

ci_inline int ci_netif_pkt_nonb_pool_is_empty(ci_netif* ni)
{ return (ni->state->nonb_pkt_pool & 0xffffffff) == 0xffffffff; }

ci_inline int ci_netif_pkt_nonb_pool_not_empty(ci_netif* ni)
{ return (ni->state->nonb_pkt_pool & 0xffffffff) != 0xffffffff; }

#else

ci_inline int ci_netif_pkt_nonb_pool_is_empty(ci_netif* ni)
{ return 1; }

ci_inline int ci_netif_pkt_nonb_pool_not_empty(ci_netif* ni)
{ return 0; }

#endif


#define CI_NETIF_PKT_POOL_MIN_LEVEL  512


/* Number of packet bufs currently allocated to TX paths.  Packets in the
 * non-blocking free pool count as being allocated to TX.
 */
ci_inline int ci_netif_pkt_tx_n(ci_netif* ni) {
  return ni->state->n_pkts_allocated - ni->state->n_rx_pkts
    - ni->state->n_freepkts;
}


/* Returns true if we are allowed to allocate a buffer for the TX path from
 * the free pool.  ie. This returns false if we've reached the limit as to
 * the number of buffers that TX path can use.
 *
 * Just because you are permitted to allocate a packet for TX does not mean
 * it is possible at the moment -- there may be none free.  See
 * ci_netif_pkt_tx_can_alloc_now().
 */
ci_inline int ci_netif_pkt_tx_may_alloc(ci_netif* ni) {
  int n_tx_pkts = ci_netif_pkt_tx_n(ni);
  return
    /* TX is not yet using all of the packet buffers that are exclusively
     * reserved for its use.
     */
    (n_tx_pkts < NI_OPTS(ni).max_packets - NI_OPTS(ni).max_rx_packets) ||
    /* The RX rings are nice and full, and TX hasn't hit its limit. */
    (ni->state->mem_pressure == 0 && n_tx_pkts < NI_OPTS(ni).max_tx_packets);
}


/* Returns true if it is permitted and possible to allocate a packet buffer
 * for the TX path -- either from the free pool of the non-blocking pool.
 */
ci_inline int ci_netif_pkt_tx_can_alloc_now(ci_netif* ni) {
  return ( (ci_netif_pkt_tx_may_alloc(ni) && ni->state->n_freepkts > 0) ||
           ci_netif_pkt_nonb_pool_not_empty(ni) );
}


/* Allocate a packet for the TCP TX path.  Such packets may get stuck in
 * the send queue or retransmit queue for a long time, so we must be
 * careful not to deplete the pool of free buffers too much.
 */
ci_inline ci_ip_pkt_fmt* ci_netif_pkt_tx_tcp_alloc(ci_netif* ni) {
  ci_assert(ci_netif_is_locked(ni));
  if(CI_LIKELY( ci_netif_pkt_tx_may_alloc(ni) && ni->state->n_freepkts > 0 ))
    return ci_netif_pkt_get(ni);
  else
    return ci_netif_pkt_alloc_slow(ni, 1);
}


#if ! CI_CFG_PP_IS_PTR

ci_inline ci_ip_pkt_fmt* ci_netif_pkt_alloc_nonb(ci_netif* ni) 
{
  volatile ci_uint64 *nonb_pkt_pool_ptr;
  ci_uint64 link, new_link;
  unsigned id;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp;

  nonb_pkt_pool_ptr = &(ni->state->nonb_pkt_pool);
 again:
  pkt = NULL;
  link = *nonb_pkt_pool_ptr;
  id = link & 0xffffffff;
  if( id != 0xffffffff ) {
    OO_PP_INIT(ni, pp, id);
    pkt = PKT(ni, pp);
    new_link = ((unsigned)OO_PP_ID(pkt->next)) | (link & 0xffffffff00000000llu);
    if( ci_cas64u_fail(nonb_pkt_pool_ptr, link, new_link) )
      goto again;
    ci_assert(pkt->refcount == 0);
    pkt->refcount = 1;
    CI_DEBUG(pkt->intf_i = -1);
  }
  return pkt;
}


ci_inline void ci_netif_pkt_free_nonb_list(ci_netif *ni, oo_pkt_p pkt_list,
                                             ci_ip_pkt_fmt *pkt_list_tail) 
{
  volatile ci_uint64 *nonb_pkt_pool_ptr;
  ci_uint64 new_link, link;

  nonb_pkt_pool_ptr = &(ni->state->nonb_pkt_pool);
  do {
    link = *nonb_pkt_pool_ptr;
    OO_PP_INIT(ni, pkt_list_tail->next, link & 0xffffffff);
    new_link = ((unsigned)OO_PP_ID(pkt_list)) | 
      ((link + 0x0000000100000000llu) & 0xffffffff00000000llu);
  } while( ci_cas64u_fail(nonb_pkt_pool_ptr, link, new_link) );
}

#endif

ci_inline void ci_netif_pkt_hold(ci_netif* ni, ci_ip_pkt_fmt* pkt) {
  ci_assert_gt(pkt->refcount, 0);
  ++pkt->refcount;
}

ci_inline void ci_netif_pkt_release(ci_netif* ni, ci_ip_pkt_fmt* pkt) {
  ci_assert_gt(pkt->refcount, 0);
  ci_assert( ci_netif_is_locked(ni) );
  if( --pkt->refcount == 0 )
    ci_netif_pkt_free(ni, pkt);
}


/* This is an optimised route for freeing packets when we know there is
** only one reference.
*/
#if CI_CFG_TCP_RX_1REF
ci_inline void ci_netif_pkt_release_1ref(ci_netif* ni, ci_ip_pkt_fmt* pkt) {
  ci_assert_equal(pkt->refcount, 1);
  pkt->refcount = 0;
  ci_netif_pkt_free(ni, pkt);
}
#else
#define ci_netif_pkt_release_1ref(ni, pkt)      \
  ci_netif_pkt_release(ni, pkt)
#endif


#define ci_netif_pkt_release_rx_1ref(ni, pkt)   \
  ci_netif_pkt_release_1ref(ni, pkt)

#define ci_netif_pkt_release_rx(ni, pkt)        \
  ci_netif_pkt_release(ni, pkt)

ci_inline void ci_netif_pkt_release_check_keep(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  /* If this flag is set it counts as another reference, as the single
   * reference gets shared between UDP receive queue and application
   * if app returns ONLOAD_ZC_KEEP
   */
  if( (pkt->pf.udp.rx_flags & CI_IP_PKT_FMT_PREFIX_UDP_RX_KEEP) )
    /* Remove flag so other context (app or reap) will free it */
    pkt->pf.udp.rx_flags &=~ CI_IP_PKT_FMT_PREFIX_UDP_RX_KEEP;
  else 
    ci_netif_pkt_release(ni, pkt);  
}

/*********************************************************************
*************************** ci_ip_pkt_queue **************************
*********************************************************************/

#define CI_IP_QUEUE_UNLIMITED   INT_MAX

ci_inline void ci_ip_queue_init(ci_ip_pkt_queue *qu) {
  qu->num = 0;
  qu->head = OO_PP_NULL;
  /* tail undefined when queue is empty */
}


ci_inline int ci_ip_queue_is_empty(ci_ip_pkt_queue *qu)
{ return qu->num == 0; }

ci_inline int ci_ip_queue_not_empty(ci_ip_pkt_queue *qu)
{ return qu->num; }


ci_inline int ci_ip_queue_is_valid(ci_netif* netif, ci_ip_pkt_queue* qu)
{
  if( qu->num == 0 )
    return OO_PP_IS_NULL(qu->head);
  else
    return IS_VALID_PKT_ID(netif, qu->head) && 
      IS_VALID_PKT_ID(netif, qu->tail) &&
      OO_PP_IS_NULL(PKT(netif, qu->tail)->next);
}

#ifndef NDEBUG
/* This function should be NEVER used in production!
 * For temporary debugging only! */
ci_inline int ci_ip_queue_is_valid_long(ci_netif* netif, ci_ip_pkt_queue* qu, 
                                        const char *name)
{
  int i = 0, found_tail = 0;
  oo_pkt_p id;

  if( !ci_ip_queue_is_valid(netif, qu) )
    return 0;
  for( id = qu->head; OO_PP_NOT_NULL(id); 
       id = PKT(netif, id)->next ) {
    ci_ip_pkt_fmt *pkt = PKT(netif, id);
    i++;
    ci_log("%s queue %d: %d %08x-%08x", name, i, OO_PP_FMT(id),
           pkt->pf.tcp_tx.start_seq, pkt->pf.tcp_tx.end_seq);
    if( OO_PP_EQ(qu->tail, id) )
      found_tail = 1;
  }
  if( i != qu->num ) {
    ci_log("validation of %s queue failed: %d real members, %d declared", 
           name, i, qu->num);
    return 0;
  }
  if( i && ! found_tail ) {
    ci_log("validation of %s queue failed: tail %d not in queue", 
           name, OO_PP_FMT(qu->tail));
    return 0;
  }
  return 1;
}
#endif


ci_inline void ci_ip_queue_enqueue(ci_netif* netif, ci_ip_pkt_queue* qu,
                                   ci_ip_pkt_fmt* pkt)
{
  pkt->next = OO_PP_NULL;
  if( ci_ip_queue_is_empty(qu) )
    qu->head = OO_PKT_P(pkt);
  else {
    /* This assumes the netif lock is held, so use
       ci_ip_queue_enqueue_nnl() if it's not */
    PKT(netif, qu->tail)->next = OO_PKT_P(pkt);
  }
  qu->tail = OO_PKT_P(pkt);
  qu->num++;
}

ci_inline void ci_ip_queue_dequeue(ci_netif* netif, ci_ip_pkt_queue* qu,
                                   ci_ip_pkt_fmt* head)
{
  ci_assert(IS_VALID_PKT_ID(netif, qu->head));
  ci_assert(qu->num > 0);
  ci_assert(PKT(netif, qu->head) == head);

  qu->head = head->next;
  --qu->num;

  ci_assert((qu->num == 0) == OO_PP_IS_NULL(qu->head));
}

/* Move [num] packets from the start of [from] to the tail of [to].  [last]
** must point at the last packet in the chain to be moved.
*/
ci_inline void ci_ip_queue_move(ci_netif* netif, ci_ip_pkt_queue* from,
                                ci_ip_pkt_queue *to,
                                ci_ip_pkt_fmt *last, int num)
{
  oo_pkt_p originalfromhead;

  ci_assert(num);
  ci_assert_ge(from->num, num);

  originalfromhead = from->head;
  /*
   * First, cut off the bit of the from queue we are moving
   */
  from->head = last->next;
  from->num -= num;
  last->next = OO_PP_NULL;
  ci_wmb();
  /* 
   * cat the to list and the new list 
   */
  if( ci_ip_queue_is_empty(to) )
    to->head = originalfromhead;
  else
    PKT(netif, to->tail)->next = originalfromhead;
  to->tail = OO_PKT_P(last);
  to->num += num;
}

/* Move entire queue [from] to [to] and re-init [from]. [to] need not
 * be initialised. */
ci_inline void ci_ip_queue_move_all(ci_netif* netif, ci_ip_pkt_queue* from,
                                    ci_ip_pkt_queue *to)
{
  ci_assert(netif);
  ci_assert(from);
  ci_assert(to);
  *to = *from;
  ci_wmb();
  ci_ip_queue_init(from);
}

/**********************************************************************
********************************* IP **********************************
**********************************************************************/

#if CI_CFG_FULL_IP_ID_HANDLING
/*! Get the next IP ID to use */
ci_inline ci_uint16 ci_ip_get_ipid( ci_netif* ni, ci_fd_t fd ) {
  ci_uint16 id;
  ci_assert(ni);
  id = NI_IPID(ni)->range[NI_IPID(ni)->current_index].next--;
  if( CI_UNLIKELY( id == 
                   NI_IPID(ni)->range[NI_IPID(ni)->current_index].base )) {
    ci_ipid_recycle( ni, fd );
  }
  return id;
}
# define NEXT_IP_ID(ni)  (ci_ip_get_ipid((ni), (ni)->fd))

#else
/* Limited IPID handling - just run around the block we get at start-up */
# include <ci/internal/ipid.h>
# define NEXT_IP_ID(ni)  (NI_IPID(ni)->base | \
                         (NI_IPID(ni)->next++ & CI_IPID_BLOCK_MASK))
                           
#endif


/**********************************************************************
**************************** citp_waitable ****************************
**********************************************************************/

ci_inline int
citp_waitable_lock_or_set_flag(citp_waitable* w, ci_uint32 flag)
{
  ci_uint32 l, new_l;
  int rc;

  do {
    l = w->lock.wl_val;
    if( ! (l & OO_WAITABLE_LK_LOCKED) ){
      new_l = l | OO_WAITABLE_LK_LOCKED;
      rc = 1;
    }
    else{
      new_l = l | flag;
      rc = 0;
    }
  } while(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, l, new_l) ));
  return rc;
}


ci_inline void
citp_waitable_lock_set_flag(citp_waitable* w, ci_uint32 flag)
{
  ci_uint32 l;
  do {
    l = w->lock.wl_val;
  } while(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, l, l | flag) ));
}

ci_inline void
citp_waitable_lock_clear_flag(citp_waitable* w, ci_uint32 flag)
{
  ci_uint32 l;
  do {
    l = w->lock.wl_val;
  } while(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, l, l & ~flag) ));
}


/**********************************************************************
***************************** ICMP/Errors *****************************
**********************************************************************/

#define ci_icmp_send_error(ni, rx_pkt, type, code)              \
  __ci_icmp_send_error((ni), oo_ip_hdr(rx_pkt),                 \
                       oo_ether_hdr(rx_pkt), (type), (code))

#define ci_icmp_send_port_unreach(ni, rx_pkt)                   \
  ci_icmp_send_error((ni), (rx_pkt), CI_ICMP_DEST_UNREACH,      \
                                     CI_ICMP_DU_PORT_UNREACH)


/**********************************************************************
*********************** Call-down abstraction *************************
**********************************************************************/



/**********************************************************************
********************************* UDP *********************************
**********************************************************************/

ci_inline void ci_udp_dec_tx_count(ci_udp_state* us, ci_ip_pkt_fmt* pkt) {
  ci_assert(pkt->flags & CI_PKT_FLAG_UDP);
  ci_assert_ge((int) us->tx_count, (int) pkt->pf.udp.tx_length);
  us->tx_count -= pkt->pf.udp.tx_length;
}


/* Returns true if there is sufficient space in the send queue that it is
** worth telling the app.  ie. Used to decide when to wake a thread, and
** when to indicate writable in select() and poll().
*/
ci_inline int ci_udp_tx_advertise_space(ci_udp_state* us)
{ return (int) (us->s.so.sndbuf - us->tx_count) > (int) (us->tx_count >> 1u); }


/*********************************************************************
************************** UDP Receive queue *************************
*********************************************************************/

extern void ci_udp_recv_q_drop(ci_netif*, ci_udp_recv_q*) CI_HF;
extern void ci_udp_recv_q_reap(ci_netif*, ci_udp_recv_q*) CI_HF;


ci_inline void ci_udp_recv_q_put(ci_netif* ni, ci_udp_state* us,
				 ci_ip_pkt_fmt* pkt) 
{
  ci_udp_recv_q* q = &us->recv_q;
  q->bytes_added += pkt->pay_len;
  pkt->next = OO_PP_NULL;
  if( OO_PP_NOT_NULL(q->head) ) {
    PKT_CHK(ni, q->tail)->next = OO_PKT_P(pkt);
    ci_udp_recv_q_reap(ni, q);
  }
  else {
    ci_assert(OO_PP_IS_NULL(q->extract));
    q->head = q->extract = OO_PKT_P(pkt);
#if CI_CFG_ZC_RECV_FILTER
    ci_assert(OO_PP_IS_NULL(q->filter));
    q->filter = OO_PKT_P(pkt);
#endif
  }
  q->tail = OO_PKT_P(pkt);
  ci_wmb();
  ++q->pkts_added;
}


/*********************************************************************
***************************** TCP timers *****************************
*********************************************************************/


/* RTO handlers */
ci_inline void ci_tcp_rto_check_and_set(ci_netif* netif, ci_tcp_state* ts) {
  /* shouldn't set an RTO if no data to send */
  ci_assert(!ci_ip_queue_is_empty(&ts->retrans)); 
  /* shouldn't set an RTO timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  if( !ci_ip_timer_pending(netif, &ts->rto_tid) )
    ci_ip_timer_set(netif, &ts->rto_tid, ci_tcp_time_now(netif) + ts->rto);
}

ci_inline void ci_tcp_rto_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->rto_tid); }

ci_inline void ci_tcp_rto_restart(ci_netif* netif, ci_tcp_state* ts) {
  /* shouldn't set an RTO if retrans queue is empty */
  ci_assert(!ci_ip_queue_is_empty(&ts->retrans)); 
  /* shouldn't set an RTO timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  ci_ip_timer_modify(netif, &ts->rto_tid, ci_tcp_time_now(netif) + ts->rto);
}

ci_inline void ci_tcp_rto_set_with_timeout(ci_netif* netif, ci_tcp_state* ts,
                                           ci_iptime_t timeout) {
  /* shouldn't set an RTO if retrans queue is empty */
  ci_assert(!ci_ip_queue_is_empty(&ts->retrans)); 
  /* shouldn't set an RTO timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  ci_ip_timer_set(netif, &ts->rto_tid, ci_tcp_time_now(netif) + timeout);
}

#define ci_tcp_rto_set(ni, ts) ci_tcp_rto_set_with_timeout((ni), (ts), \
                                                           (ts)->rto)

ci_inline void ci_tcp_rto_bound(ci_netif* netif, ci_tcp_state* ts) {
  ts->rto = CI_MIN(NI_CONF(netif).tconst_rto_max, ts->rto);
  ts->rto = CI_MAX(NI_CONF(netif).tconst_rto_min, ts->rto);
}

/* delayed ack timers */
ci_inline void ci_tcp_delack_check_and_set(ci_netif* netif, 
                                           ci_tcp_state* ts) {
  /* shouldn't set a timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  if( !ci_ip_timer_pending(netif, &ts->delack_tid) )
    ci_ip_timer_set(netif, &ts->delack_tid, ci_tcp_time_now(netif) +
                    NI_CONF(netif).tconst_delack);
}

ci_inline void ci_tcp_delack_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->delack_tid); }

#if CI_CFG_DYNAMIC_ACK_RATE
ci_inline void ci_tcp_delack_soon(ci_netif* netif, ci_tcp_state* ts) 
{
  /* shouldn't set a timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  ci_assert_gt(ts->acks_pending & CI_TCP_ACKS_PENDING_MASK, 1);
  ts->acks_pending |= CI_TCP_DELACK_SOON_FLAG;
  if( ci_ip_timer_pending(netif, &ts->delack_tid) )
    ci_ip_timer_modify(netif, &ts->delack_tid, ci_tcp_time_now(netif)+1);
  else
    ci_ip_timer_set(netif, &ts->delack_tid, ci_tcp_time_now(netif)+1);
}
#endif

#if CI_CFG_TAIL_DROP_PROBE
/* tail drop timers */
ci_inline void ci_tcp_taildrop_check_and_set(ci_netif* netif, 
                                             ci_tcp_state* ts) {
  unsigned offset;

  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  ci_assert(NI_OPTS(netif).tail_drop_probe);

  offset = tcp_srtt(ts) << 1;
  offset = CI_MAX(offset, 2);

  if ( !ci_ip_timer_pending(netif, &ts->taildrop_tid))
    ci_ip_timer_set(netif, &ts->taildrop_tid, ci_tcp_time_now(netif) 
                    + offset);
}

ci_inline void ci_tcp_taildrop_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->taildrop_tid); }

ci_inline void ci_tcp_taildrop_restart(ci_netif *netif, ci_tcp_state *ts) {
  ci_assert(ci_ip_timer_pending(netif, &ts->taildrop_tid));

  ci_tcp_taildrop_clear(netif, ts);
  ci_tcp_taildrop_check_and_set(netif, ts);
}
#endif

/* keep alive timers */

/*
 * Restart keepalive timer in case CI_TCPT_FLAG_KALIVE flag is set on the
 * socket. It runs timer if it is not running yet.
 *
 * @param netif    Network interface data structure
 * @param ts     TCP control block
 * @param t        Relative time when keepalive timer should expire
 */
ci_inline void ci_tcp_kalive_restart(ci_netif *netif, ci_tcp_state* ts, 
                                     ci_iptime_t t) {
  /* 
   * Actually, if there are such situations remove this assert, 
   * but now I can't see any cases when this is false.
   */
  /* ?? Why not use ts->s.b.state & CI_TCP_STATE_NO_TIMERS?? */
  ci_assert( ts->s.b.state != CI_TCP_CLOSED && 
             ts->s.b.state != CI_TCP_LISTEN );

  if( ts->s.s_flags & CI_SOCK_FLAG_KALIVE )
    ci_ip_timer_modify(netif, &ts->kalive_tid, ci_tcp_time_now(netif) + t);
  else
    /*
     * ka_probes is not cleared somewhere, as soon as with disabled
     * keepalive feature this field should be zero 
     */
    ci_assert(ts->ka_probes == 0);
}

/*
 * Gets the value of keepalive IDLE time - time before start sending 
 * keepalive probes.
 *
 * @param ts  TCP control block
 */
ci_inline ci_iptime_t ci_tcp_kalive_idle_get(ci_tcp_state* ts)
{ return ts->c.t_ka_time; }

/*
 * Gets the value of keepalive IDLE time in seconds - time before 
 * start sending keepalive probes.
 *
 * @param ts  TCP control block
 */
ci_inline ci_iptime_t ci_tcp_kalive_idle_in_secs_get(ci_tcp_state* ts)
{ return ts->c.t_ka_time_in_secs; }

/*
 * Gets the value of keepalive probe interval - interval between two
 * consequent probes.
 *
 * @param ts    TCP control block
 * @param netif netif
 */
ci_inline ci_iptime_t ci_tcp_kalive_intvl_get(ci_netif* netif,
                                              ci_tcp_state* ts)
{
  return ts->c.t_ka_intvl;
}

/*
 * Gets the value of keepalive probe interval in seconds- interval between 
 * two consequent probes.
 *
 * @param ts  TCP control block
 */
ci_inline ci_iptime_t ci_tcp_kalive_intvl_in_secs_get(ci_tcp_state* ts)
{
  return ts->c.t_ka_intvl_in_secs;
}

/*
 * Gets the maximum number of keepalive probes.
 *
 * @param ts  TCP control block
 */
ci_inline unsigned ci_tcp_kalive_probes_get(ci_tcp_state* ts)
{ return ts->c.ka_probe_th; }

ci_inline void ci_tcp_kalive_check_and_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->kalive_tid); }


/* Sort out the keepalive timer when an ACK is received */
ci_inline void ci_tcp_kalive_reset(ci_netif *netif, ci_tcp_state *ts)
{
  if (ts->ka_probes) {
    /* This is a bit pointless, but necessary to get through WHQL for
     * chimney.  We have to restart the timer here rather than just
     * let it expire and sort things out then because if the interval
     * time is greater than the idle time, it will expire too late and
     * fail some WHQL tests.  For now we ignore the time that has
     * expired on this timer so far */
    ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_idle_get(ts));
 }

  ts->ka_probes = 0;
}


ci_inline void ci_tcp_zwin_set(ci_netif* netif, ci_tcp_state* ts)
{
  ci_iptime_t t;
  ci_assert( ! (ts->s.b.state & CI_TCP_STATE_NO_TIMERS) );
  if( ts->zwin_probes == 0 )
    t = ts->rto << ts->zwin_acks;
  else
    t = ts->rto << ts->zwin_probes;
  ci_assert(TIME_GT(t, 0));
  ci_ip_timer_set(netif, &ts->zwin_tid, ci_tcp_time_now(netif) + t);
}


/**********************************************************************
****************************** TCP sendq ******************************
**********************************************************************/


ci_inline int ci_tcp_sendq_is_empty(ci_tcp_state* ts)
{ return ci_ip_queue_is_empty(&ts->send); }

ci_inline int ci_tcp_sendq_not_empty(ci_tcp_state* ts)
{ return ci_ip_queue_not_empty(&ts->send); }

ci_inline void ci_tcp_sendq_drop(ci_netif* ni, ci_tcp_state* ts)
{ 
  ts->send_out += ts->send.num;
  ci_ip_queue_drop(ni, &ts->send);
}

ci_inline void ci_tcp_retrans_drop(ci_netif* ni, ci_tcp_state* ts)
{ ci_ip_queue_drop(ni, &ts->retrans); }



/**********************************************************************
****************************** TCP socket *****************************
**********************************************************************/

ci_inline int ci_tcp_is_cached(ci_tcp_state* ts)
{
#if CI_CFG_FD_CACHING
  return ts->cached_on_fd != -1;
#else
  return 0;
#endif
}


ci_inline ci_uint32 tcp_eff_mss(const ci_tcp_state* ts) {
  if( ts->s.b.state != CI_TCP_CLOSED ) {
    ci_assert(ts->s.b.state != CI_TCP_LISTEN);
    ci_assert_gt(CI_CFG_TCP_MINIMUM_MSS, tcp_outgoing_opts_len(ts));
    ci_assert_ge(ts->eff_mss,CI_CFG_TCP_MINIMUM_MSS-tcp_outgoing_opts_len(ts));
  }
  return ts->eff_mss;
}


ci_inline void ci_tcp_fast_path_enable(ci_tcp_state* ts) {
  ts->fast_path_check  = ts->incoming_tcp_hdr_len << 26u;
  ts->fast_path_check |= CI_TCP_FLAG_ACK << 16u;
  ts->fast_path_check  = CI_BSWAP_BE32(ts->fast_path_check);
  ci_assert(ci_tcp_can_use_fast_path(ts));
}

ci_inline void ci_tcp_fast_path_disable(ci_tcp_state* ts) {
  ci_assert(!ci_tcp_can_use_fast_path(ts));
  ts->fast_path_check = ~CI_TCP_FAST_PATH_MASK;
}


ci_inline int ci_tcp_recv_not_blocked(ci_tcp_state* ts)
{
  /* We are not blocked if there is data available or the connection has
   * been shut down.
   * NB. does not return not blocked IFF single OOB byte in recv queue
   */
  int bytes = tcp_rcv_usr(ts);
  return TCP_RX_DONE(ts) ||
      (bytes >= ts->s.so.rcvlowat +
       ((tcp_urg_data(ts) & CI_TCP_URG_IS_HERE) ? 1 : 0));
}


/* Use a 4us clock to generate ISN see p27 of RFC793.  ?? TODO We want
** something more secure. */
ci_inline unsigned ci_tcp_initial_seqno(ci_netif* ni) {
#if defined(CI_HAVE_FRC64)  
  ci_uint64 frc;
  ci_frc64(&frc);  
  return (ci_iptime_t)(frc >> (IPTIMER_STATE(ni)->ci_ip_time_frc2us -2));
#elif defined(CI_HAVE_FRC32)
  /* ?? TODO support for FRC32 */
  return ci_ip_time_now(ni);
#else
  return 0;
#endif
}


ci_inline void ci_tcp_set_sndbuf(ci_tcp_state* ts) {
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);
  ci_assert(tcp_eff_mss(ts));
  ts->send_max = (ts->s.so.sndbuf + tcp_eff_mss(ts) - 1) / tcp_eff_mss(ts);
}

ci_inline void ci_tcp_set_flags(ci_tcp_state* ts, unsigned flags) {
  ci_tcp_hdr* tcp = TS_TCP(ts);
  tcp->tcp_flags = (ci_uint8)flags;
}

ci_inline void ci_tcp_set_hdr_len(ci_tcp_state* ts, unsigned len) {
  ci_tcp_hdr* tcp = TS_TCP(ts);
  CI_TCP_HDR_SET_LEN(tcp, len);
}

ci_inline void ci_tcp_set_peer(ci_tcp_state* ts, unsigned addr, unsigned port){
  ts->s.pkt.ip.ip_daddr_be32 = addr;
  TS_TCP(ts)->tcp_dest_be16 = (ci_uint16)port;
  ts->s.pkt.dport_be16 = port;
}


/* We'll send window updates whenever the window increases by this much. */
ci_inline int ci_tcp_ack_trigger_delta(ci_tcp_state* ts)
{ return tcp_rcv_buff(ts) >> 3; }


#if CI_CFG_TCP_FASTSTART

# define CITP_TCP_FASTSTART(x)           do{ x; }while(0)

ci_inline void ci_tcp_reduce_faststart(ci_tcp_state* ts, unsigned reduction) {
  if(CI_LIKELY( ts->faststart_acks <= reduction ))
    ts->faststart_acks = 0;
  else
    ts->faststart_acks -= reduction;
}

ci_inline int ci_tcp_is_in_faststart(ci_tcp_state* ts)
{ return ts->faststart_acks != 0; }

#else

# define CITP_TCP_FASTSTART(x)           do{}while(0)
# define ci_tcp_reduce_faststart(ts, n)  do{}while(0)
# define ci_tcp_is_in_faststart(ts)      (0)

#endif


/*!
 * Window in SYN and SYN-ACK packets is not scaled.
 *
 * \param tcphdr    TCP header
 * \param wscl      Window scale
 *
 * \return Window size.
 */
ci_inline unsigned int ci_tcp_wnd_from_hdr(ci_tcp_hdr* tcphdr, unsigned wscl) {
  unsigned tmp = CI_BSWAP_BE16(tcphdr->tcp_window_be16);
  return (tcphdr->tcp_flags & CI_TCP_FLAG_SYN) ? tmp : (tmp << wscl);
}


/*!
 * Set dupack threshold based on reorder length.
 *
 * \param ts        TCP state to set dupack threshold
 * \param reord     reorder length ro use
 */
ci_inline void ci_tcp_set_dupack_thresh(ci_tcp_state *ts, unsigned reord) {
  unsigned thresh = reord + 1;
  thresh = CI_MAX(thresh, CI_CFG_TCP_DUPACK_THRESH_BASE);
  thresh = CI_MIN(thresh, CI_CFG_TCP_DUPACK_THRESH_MAX);
  ts->dup_thresh = thresh;
}

/* congestion control functions */

/* set the initial congestion window as in rfc3390/rfc2581/rfc2001 */ 
ci_inline void ci_tcp_set_initialcwnd(ci_netif* ni, ci_tcp_state* ts) {
  if( NI_OPTS(ni).initial_cwnd == 0 ) {
#if CI_CFG_TCP_INITIAL_CWND_RFC == 3390
    /* rfc3390: IW = min (4*SMSS, max (2*SMSS, 4380 bytes)) */
    unsigned mss4 = tcp_eff_mss(ts) << 2;
    unsigned mss2 = tcp_eff_mss(ts) << 1;
    ts->cwnd = CI_MAX(mss2, 4380);
    ts->cwnd = CI_MIN(ts->cwnd, mss4);
#elif CI_CFG_TCP_INITIAL_CWND_RFC == 2581
    /* rfc2581: "IW, the initial value of cwnd, MUST be less than or equal to
     * 2*SMSS bytes and MUST NOT be more than 2 segments."
     */
    ts->cwnd = tcp_eff_mss(ts) <<1;
#elif CI_CFG_TCP_INITIAL_CWND_RFC == 2001
    /* rfc2001: IW = ts->eff_mss */
    ts->cwnd = tcp_eff_mss(ts);
#else
# error Bad CI_CFG_TCP_INITIAL_CWND_RFC
#endif
  }
  else {
    ts->cwnd = NI_OPTS(ni).initial_cwnd;
  }
  ts->ssthresh = 65535;
}

/*! ?? \TODO should we use fackets to make things more exact ? */ 
ci_inline unsigned ci_tcp_inflight(ci_tcp_state* ts)
{ return SEQ_SUB(ts->snd_nxt, ts->snd_una);  }

/* New value for [ssthresh] after loss (RFC2581 p5). */
ci_inline unsigned ci_tcp_losswnd(ci_tcp_state* ts) {
  unsigned x = ci_tcp_inflight(ts) >> 1u;
  unsigned y = tcp_eff_mss(ts) << 1u;
  return CI_MAX(x, y);
}


/* find effective MSS value based on smss, PMTU and MTU and optional user
 * value */
ci_inline void ci_tcp_set_eff_mss(ci_netif* netif, ci_tcp_state* ts) {
  unsigned x;

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  x = ts->s.pkt.pmtus.pmtu - sizeof(ci_tcp_hdr) - sizeof(ci_ip4_hdr);
  x = CI_MIN(x, ts->smss);
  ts->eff_mss = CI_MAX(x, CI_CFG_TCP_MINIMUM_MSS) - tcp_outgoing_opts_len(ts);

  /* Increase ssthresh & cwndif eff_mss has increased */
  ts->ssthresh = CI_MAX(ts->ssthresh, ts->eff_mss << 1u);
  if( ts->cwnd < ts->eff_mss )
    ci_tcp_set_initialcwnd(netif, ts);

  /* This resets [ts->send_max]. */
  ci_tcp_set_sndbuf(ts);
}


#if CI_CFG_BURST_CONTROL
ci_inline unsigned ci_tcp_burst_exhausted(ci_netif* ni, ci_tcp_state* ts) {
  int extra, retrans_data;
  unsigned fack;
  ci_tcp_get_fack(ni, ts, &fack, &retrans_data);
  extra = SEQ_SUB(fack, tcp_snd_una(ts)) - retrans_data;
  extra = CI_MAX(extra, 0);
  return ci_tcp_inflight(ts) - extra > ts->burst_window;
}
#endif


ci_inline int ci_tcp_can_stripe(ci_netif* ni, unsigned laddr_be32,
				unsigned raddr_be32) {
#if CI_CFG_PORT_STRIPING
  unsigned mask = NI_OPTS(ni).stripe_netmask_be32;
  return (laddr_be32 & mask) == (raddr_be32 & mask);
#else
  return 0;
#endif
}


/* Return number of packets in the sendq, including prequeue.  Note that
 * any of these counters may be updated concurrently wrt this function, so
 * we have to protect against the result going negative.
 */
ci_inline int ci_tcp_sendq_n_pkts(ci_tcp_state* ts) {
  int n = oo_atomic_read(&ts->send_prequeue_in) + ts->send_in - ts->send_out;
  return n >= 0 ? n : 0;
}

/* This test is used to decide whether we should indicate to the app that
** it can enqueue more data on a socket.  ie. It is used to decide when to
** wake a blocking thread, and to decide whether to indicate the socket is
** writable in select() and poll().
*/
ci_inline int ci_tcp_tx_advertise_space(ci_tcp_state* ts) {
  int bytes_enqueued = SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts));
  return ( ts->send_max > ci_tcp_sendq_n_pkts(ts) ) &&
         ( (int) (ts->s.so.sndbuf - bytes_enqueued) >
           (int) (bytes_enqueued >> 1u) );
}


/* helpers for RTT sampling without TS option */
ci_inline void ci_tcp_clear_rtt_timing(ci_tcp_state* ts) {
  ts->timed_seq = tcp_snd_una(ts) - 1;
}

ci_inline void ci_tcp_set_rtt_timing(ci_netif* netif, 
                                     ci_tcp_state* ts, ci_tcp_hdr* tcp) {
  ts->timed_seq = CI_BSWAP_BE32(tcp->tcp_seq_be32);
  ts->timed_ts = ci_tcp_time_now(netif);
}


ci_inline void ci_tcp_tx_pkt_set_end(ci_tcp_state* ts, ci_ip_pkt_fmt* pkt) {
  pkt->buf.end = (unsigned) (oo_tx_ether_data(pkt) + ts->outgoing_hdrs_len +
                             tcp_eff_mss(ts) - (char*) &pkt->buf);
}


ci_inline int ci_tcp_tx_n_pkts_needed(int eff_mss, int maxbytes,
                                      int maxbufs, int sendq_credit) {
  /* Calculate how many packet buffers we need to accommodate <maxbytes>,
  ** assuming each will hold <eff_mss> bytes, but do not exceed <maxbufs>.
  */
  int n = (maxbytes + eff_mss - 1) / eff_mss;
  if( n > sendq_credit )  n = sendq_credit;
  if( n > maxbufs      )  n = maxbufs;
  return n;
}


ci_inline void ci_tcp_tx_pkt_init(ci_ip_pkt_fmt* pkt, int hdrlen, int maxlen) {
  ci_assert_equal(pkt->pkt_layout, CI_PKT_LAYOUT_INVALID);
  oo_pkt_layout_set(pkt, CI_PKT_LAYOUT_TX_SIMPLE);
  oo_offbuf_init(&pkt->buf, oo_tx_ether_data(pkt) + hdrlen, maxlen);
  pkt->buf_len = pkt->tx_pkt_len = hdrlen + oo_ether_hdr_size(pkt);
  pkt->pf.tcp_tx.start_seq = hdrlen;
  pkt->pf.tcp_tx.end_seq = 0;
}


/* DJR: Linux 2.4 uses sysctl_max_syn_backlog for this value.  The default
** is 1024.  ?? TODO: We ought to get the value from linux dynamically. */
ci_inline int ci_tcp_listenq_max(ci_netif* ni)
{ return 1024; }


/**********************************************************************
************************** Per-socket locks ***************************
**********************************************************************/

ci_inline int ci_sock_trylock(ci_netif* ni, citp_waitable* w)
{
  ci_uint32 l = w->lock.wl_val;
  return ! (l & OO_WAITABLE_LK_LOCKED) &&
    ci_cas32u_succeed(&w->lock.wl_val, l, l | OO_WAITABLE_LK_LOCKED);
}

/* Always returns 0 (success) at userland.  Returns -ERESTARTSYS if
 * interrupted when invoked in kernel.  (TODO: Check that is right --
 * possibly EINTR?).  Return value *must* be checked when invoked in
 * kernel, else risk of proceeding without the lock held.
 */
ci_inline int ci_sock_lock(ci_netif*, citp_waitable*)
  OO_MUST_CHECK_RET_IN_KERNEL;
ci_inline int ci_sock_lock(ci_netif* ni, citp_waitable* w)
{
  if(CI_LIKELY( ci_cas32u_succeed(&w->lock.wl_val, 0, OO_WAITABLE_LK_LOCKED) ))
    return 0;
#ifdef __KERNEL__
  return ci_sock_lock_slow(ni, w);
#else
  /* Ensure the compiler knows we're returning zero, so it can optimise out
   * any code conditional on the return value.
   */
  (void) ci_sock_lock_slow(ni, w);
  return 0;
#endif
}

/* Use of this macro indicates code that needs to be fixed!  ie. In-kernel
 * callers of ci_sock_lock() that are not checking the return value.
 */
#define ci_sock_lock_fixme(ni, w)                                       \
  do {                                                                  \
    int rc = ci_sock_lock((ni), (w));                                   \
    if( rc != 0 ) {                                                     \
      LOG_E(ci_log("%s: ERROR: failed to grab sock lock", __FUNCTION__)); \
      LOG_E(ci_log("FIXME: file=%s line=%d", __FILE__, __LINE__));      \
    }                                                                   \
  } while( 0 )

ci_inline void ci_sock_unlock(ci_netif* ni, citp_waitable* w)
{
  if(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, OO_WAITABLE_LK_LOCKED, 0) ))
    ci_sock_unlock_slow(ni, w);
}

ci_inline int  ci_sock_is_locked(ci_netif* ni, citp_waitable* w)
{
  return w->lock.wl_val & OO_WAITABLE_LK_LOCKED;
}


/*********************************************************************
************************** TCP accept queue **************************
*********************************************************************/

/* Use this if you don't own the [get] lock. */
#define ci_tcp_acceptq_n(tls)			\
  ((tls)->acceptq_n_in - (tls)->acceptq_n_out)

/* Use this if you do own the [get] lock. */
#define ci_tcp_acceptq_not_empty(tls)                                   \
  (((tls)->acceptq_put >= 0) | OO_SP_NOT_NULL((tls)->acceptq_get))


ci_inline void ci_tcp_acceptq_put(ci_netif* ni,
                                  ci_tcp_socket_listen* tls,
				  citp_waitable* w) {
  ci_assert(OO_SP_IS_NULL(w->wt_next));
  ci_assert(ci_netif_is_locked(ni));
  do
    w->wt_next = OO_SP_FROM_INT(ni, tls->acceptq_put);
  while( ci_cas32_fail(&tls->acceptq_put,
                       OO_SP_TO_INT(w->wt_next), W_ID(w)) );
  ++tls->acceptq_n_in;
}

/* Should not be called directly, use ci_tcp_acceptq_get() and
 * ci_tcp_acceptq_peek(). */
ci_inline void ci_tcp_acceptq_get_swizzle(ci_netif* ni,
					  ci_tcp_socket_listen* tls) {
  ci_int32 from;
  oo_sp from_sp;
  ci_tcp_state* ts;
  /* Atomically grab the contents of the [put] list. */
  do
    from = tls->acceptq_put;
  while( ci_cas32_fail(&tls->acceptq_put, from, CI_ILL_END) );
  /* Reverse the list onto [get]. */
  ci_assert(from >= 0);
  ci_assert(OO_SP_IS_NULL(tls->acceptq_get));
  from_sp = OO_SP_FROM_INT(ni, from);
  do {
    ts = SP_TO_TCP(ni, from_sp);
    from_sp = ts->s.b.wt_next;
    ts->s.b.wt_next = tls->acceptq_get;
    tls->acceptq_get = S_SP(ts);
  } while( OO_SP_NOT_NULL(from_sp) );
}


/* Only call this if ci_tcp_acceptq_not_empty() is true. */
ci_inline citp_waitable* ci_tcp_acceptq_get(ci_netif* ni,
					   ci_tcp_socket_listen* tls) {
  citp_waitable* w;
  ci_assert(ci_sock_is_locked(ni, &tls->s.b) ||
            (tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
  ++tls->acceptq_n_out;
  if( OO_SP_IS_NULL(tls->acceptq_get) )  ci_tcp_acceptq_get_swizzle(ni, tls);
  ci_assert(OO_SP_NOT_NULL(tls->acceptq_get));
  w = SP_TO_WAITABLE(ni, tls->acceptq_get);
  tls->acceptq_get = w->wt_next;
  CI_DEBUG(w->wt_next = OO_SP_NULL);
  return w;
}


#ifndef __ci_driver__
/* Only call this if ci_tcp_acceptq_not_empty() is true. */
ci_inline ci_tcp_state* ci_tcp_acceptq_peek(ci_netif* ni,
					    ci_tcp_socket_listen* tls) {
  ci_assert(ci_sock_is_locked(ni, &tls->s.b));
  if( OO_SP_IS_NULL(tls->acceptq_get) )  ci_tcp_acceptq_get_swizzle(ni, tls);
  ci_assert(OO_SP_NOT_NULL(tls->acceptq_get));
  return SP_TO_TCP(ni, tls->acceptq_get);
}

#endif


/*********************************************************************
******************************** Netif *******************************
*********************************************************************/

/* Does exactly what it says on the tin! */
ci_inline void ci_tcp_synrecv_free(ci_netif* ni, ci_tcp_state_synrecv* tsr) {
  tsr->link.next = ni->state->free_synrecvs;
  ni->state->free_synrecvs = oo_ptr_to_statep(ni, tsr);
}


ci_inline void ci_netif_put_on_post_poll(ci_netif* ni, citp_waitable* sb)
{
  ci_ni_dllist_remove(ni, &sb->post_poll_link);
  ci_ni_dllist_put(ni, &ni->state->post_poll_list, &sb->post_poll_link);
}


ci_inline void ci_netif_poll_free_pkts(ci_netif* ni,
                                       struct ci_netif_poll_state* ps)
{
  ci_ip_pkt_fmt* tail = CI_CONTAINER(ci_ip_pkt_fmt, next,
                                     ps->tx_pkt_free_list_insert);
  ci_netif_pkt_free_nonb_list(ni, ps->tx_pkt_free_list, tail);
  ni->state->n_async_pkts += ps->tx_pkt_free_list_n;
  CITP_STATS_NETIF_ADD(ni, pkt_nonb, ps->tx_pkt_free_list_n);
}


extern void ci_netif_tx_pkt_complete_udp(ci_netif* ni,
                                         struct ci_netif_poll_state* ps,
                                         ci_ip_pkt_fmt* pkt);


ci_inline void ci_netif_tx_pkt_complete(ci_netif* ni,
                                        struct ci_netif_poll_state* ps,
                                        ci_ip_pkt_fmt* pkt)
{
  /* debug check - take back ownership of buffer from NIC */
  ci_assert(pkt->flags & CI_PKT_FLAG_TX_PENDING);
  pkt->flags &=~ CI_PKT_FLAG_TX_PENDING;
  ni->state->nic[pkt->intf_i].tx_bytes_removed += TX_PKT_LEN(pkt);
  ci_assert((int) (ni->state->nic[pkt->intf_i].tx_bytes_added -
                   ni->state->nic[pkt->intf_i].tx_bytes_removed) >=0);
#if CI_CFG_UDP
  if( pkt->flags & CI_PKT_FLAG_UDP )
    ci_netif_tx_pkt_complete_udp(ni, ps, pkt);
  else
#endif
    ci_netif_pkt_release(ni, pkt);
}


ci_inline int citp_shutdown_how_is_valid(int how)
{
  switch( how ) {
    case SHUT_RD:
    case SHUT_WR:
    case SHUT_RDWR:
      return CI_TRUE;
    default:
      return CI_FALSE;
  }
}

/**********************************************************************
********************************* PMTU ********************************
**********************************************************************/

/*! Manage the discovery timer.  If the time is CI_PMTU_STOP_TIMER then 
 * the timer will be  killed. If the timer is pending it will be modified
 *  otherwise it will be set */
ci_inline void ci_pmtu_discover_timer(ci_netif* ni,  ci_pmtu_state_t* pmtus, 
                                      ci_iptime_t timeout) {
  ci_ip_timer_clear(ni, &pmtus->tid );
  if( timeout != CI_PMTU_STOP_TIMER )
    ci_ip_timer_set(ni, &pmtus->tid, ci_tcp_time_now(ni) + timeout);
}


/**********************************************************************
***************************** O/S socket ******************************
**********************************************************************/



/*********************************************************************
************************* IPv4/IPv6 address helpers ******************
*********************************************************************/

union ci_sockaddr_u {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if CI_CFG_FAKE_IPV6
  struct sockaddr_in6 sin6;
#endif
};

#if CI_CFG_FAKE_IPV6
/*!
 * Test it this IPv6 address may be considered as IPv4 one.
 * This function DOES NOT check sa->family, because it is used in bind(),
 * and Linux bind() should not check address family.
 */
ci_inline int ci_tcp_ipv6_is_ipv4(const struct sockaddr* sa)
{
  if (CI_IP6_IS_V4MAPPED(&CI_SIN6(sa)->sin6_addr) || 
      CI_IP6_IS_ADDR_ANY(&CI_SIN6(sa)->sin6_addr)) {
    return 1;
  }
  return 0;
}
#endif


/* Get IPv4 address from IPv4 or IPv6 address structure */
ci_inline ci_uint32 ci_get_ip4_addr(int family, const struct sockaddr* sa)
{
#if CI_CFG_FAKE_IPV6
  ci_assert(family == AF_INET || family == AF_INET6);
#else
  ci_assert(family == AF_INET);
#endif

#if CI_CFG_FAKE_IPV6
  if (family == AF_INET)
    return CI_SIN(sa)->sin_addr.s_addr;
  else { /* IPv6 */
    ci_assert(ci_tcp_ipv6_is_ipv4(sa));
    return ((ci_uint32 *)(&CI_SIN6(sa)->sin6_addr))[3];
  }
#else
  return CI_SIN(sa)->sin_addr.s_addr;
#endif
}

/* Make a sockaddr structure from a given port/ip4address. */
ci_inline void
ci_make_sockaddr(struct sockaddr_in *sin,
                 sa_family_t domain, ci_uint16 port_be16, ci_uint32 addr_be32)
{
  sin->sin_family = domain;
  sin->sin_port = port_be16;
  sin->sin_addr.s_addr = addr_be32;
}

#if CI_CFG_FAKE_IPV6
ci_inline void
ci_make_sockaddr6(struct sockaddr_in6 *sin,
                  sa_family_t domain, ci_uint16 port_be16, ci_uint32 addr_be32)
{
  sin->sin6_family = domain;
  sin->sin6_port = port_be16;
  CI_IP_TO_IP6_MAPPED(&sin->sin6_addr, addr_be32);
}
#endif

/* Minimum IPv6 address size. It may be included from <net/ipv6.h> */
#define SIN6_LEN_RFC2133 24

/* Copy sockaddr structure to user-supplied pointer and update its length. */
ci_inline void
ci_addr_to_user(struct sockaddr *sa, socklen_t *sa_len,
                sa_family_t domain, ci_uint16 port_be16, ci_uint32 addr_be32)
{
  socklen_t len_min, len_max;
  len_min = len_max = sizeof(struct sockaddr_in);

#if CI_CFG_FAKE_IPV6
  ci_assert(domain == AF_INET || domain == AF_INET6);

  if (domain == AF_INET6) {
    len_min = SIN6_LEN_RFC2133;
    len_max = sizeof(struct sockaddr_in6);
  }
#else 
  ci_assert(domain == AF_INET);
#endif

  if (CI_LIKELY(*sa_len >= len_min)) {
    *sa_len = CI_MIN(*sa_len, len_max);
    memset(sa, 0, *sa_len);
#if CI_CFG_FAKE_IPV6
    if (domain == AF_INET)
      ci_make_sockaddr(CI_SIN(sa), domain, port_be16, addr_be32);
    else 
      ci_make_sockaddr6(CI_SIN6(sa), domain, port_be16, addr_be32);
#else
    ci_make_sockaddr(CI_SIN(sa), domain, port_be16, addr_be32);
#endif
  } 
  else {
    union ci_sockaddr_u ss_u;

    if (*sa_len == 0) {
      *sa_len = len_min;
      return;
    }

    memset(&ss_u.sa, 0, len_min);
#if CI_CFG_FAKE_IPV6
    if (domain == AF_INET)
      ci_make_sockaddr(&ss_u.sin, domain, port_be16, addr_be32);
    else
      ci_make_sockaddr6(&ss_u.sin6, domain, port_be16, addr_be32);
#else
    ci_make_sockaddr(&ss_u.sin, domain, port_be16, addr_be32);
#endif

    memcpy(sa, &ss_u.sa, *sa_len);
    *sa_len = len_min;
  }
}


/*********************************************************************
 * ci_tcp_recvmsg()
 */

ci_inline void __ci_tcp_recvmsg_args_init(ci_tcp_recvmsg_args* a,
                                     ci_netif* ni, ci_tcp_state* ts,
                                     struct msghdr* msg, int flags
                                     CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) {
  a->ni = ni;
  a->ts = ts;
  a->msg = msg;
  a->flags = flags;
#ifdef __KERNEL__
  a->addr_spc = addr_spc;
#endif
}


#define ci_tcp_recvmsg_args_init(a, ni, ts, msg, flags, addr_spc)       \
  __ci_tcp_recvmsg_args_init((a), (ni), (ts), (msg), (flags)            \
                             CI_KERNEL_ARG(addr_spc))



/*********************************************************************
***************************** Tcpdump support ************************
*********************************************************************/
#if CI_CFG_TCPDUMP
/** Current length of dump queue. */
ci_inline int oo_tcpdump_queue_len(ci_netif *ni)
{
  return (ci_uint8)(ni->state->dump_write_i - ni->state->dump_read_i);
}
/* Should we dump this packet? */
ci_inline int oo_tcpdump_check(ci_netif *ni, ci_ip_pkt_fmt *pkt, int intf_i)
{
  return ni->state->dump_intf[intf_i] &&
      oo_tcpdump_queue_len(ni) < CI_CFG_DUMPQUEUE_LEN - 1;
}

/* Release the packet we are going to overwrite and, possibly, some others.
 * Return 1 if we can dump one more packet. */
ci_inline int oo_tcpdump_free_pkts(ci_netif *ni)
{
  ci_uint8 i = ni->state->dump_write_i;
  oo_pkt_p id;

  ci_assert(ci_netif_is_locked(ni));

  /* If reader is too slow, do not dump anything */
  if( i - ni->state->dump_read_i >= CI_CFG_DUMPQUEUE_LEN )
    return 0;

  /* Free this packet */
  id = ni->state->dump_queue[i % CI_CFG_DUMPQUEUE_LEN];
  if( id == OO_PP_NULL )
    return 1;

  /* If we are going to free something, let's free everything possible */
  do {
    if( id != OO_PP_NULL ) {
      ci_ip_pkt_fmt *pkt = PKT_CHK(ni, id);
      ni->state->dump_queue[i % CI_CFG_DUMPQUEUE_LEN] = OO_PP_NULL;
      ci_wmb();
      if( pkt->n_buffers == 1 )
        ci_netif_pkt_release(ni, pkt);
      else {
        do {
          pkt = PKT_CHK(ni, id);
          id = pkt->frag_next;
          ci_netif_pkt_release(ni, pkt);
        } while( id != OO_PP_NULL );
      }
    }
    i++;
    id = ni->state->dump_queue[i % CI_CFG_DUMPQUEUE_LEN];
  } while( i - ni->state->dump_read_i >= CI_CFG_DUMPQUEUE_LEN );
  return 1;
}

/* Dump this packet */
ci_inline void oo_tcpdump_dump_pkt(ci_netif *ni, ci_ip_pkt_fmt *pkt)
{
  if( !oo_tcpdump_free_pkts(ni) )
    return;

  ci_assert_equal(ni->state->dump_queue[ni->state->dump_write_i %
                  CI_CFG_DUMPQUEUE_LEN], OO_PP_NULL);
  pkt->refcount++;
  ni->state->dump_queue[ni->state->dump_write_i %
                        CI_CFG_DUMPQUEUE_LEN] = OO_PKT_P(pkt);
  ni->state->dump_write_i++;
  if( pkt->n_buffers > 1 ) {
    do {
      pkt = PKT(ni, pkt->frag_next);
      pkt->refcount++;
    } while( OO_PP_NOT_NULL(pkt->frag_next) );
  }

}
#else
#define oo_tcpdump_check(ni, pkt, intf_i) 0
#define oo_tcpdump_dump_pkt(ni, pkt)
#endif


/*********************************************************************
**************************** OS socket status ************************
*********************************************************************/

/* _bit_set() always increment seqno, even if the bit is already set */
ci_inline void
oo_os_sock_status_bit_set(ci_sock_cmn *s, ci_int32 bits)
{
  ci_uint32 tmp;
  do {
    tmp = s->os_sock_status;
  } while( ci_cas32u_fail(&s->os_sock_status, tmp,
                          (tmp + (1 << OO_OS_STATUS_SEQ_SHIFT)) | bits) );
}
/* _bit_clear() does not increment seqno if the bit is already unset or
 * the condition if true */
#define oo_os_sock_status_bit_clear(s, bits, cond) \
  do {                                                              \
    ci_uint32 tmp;                                                  \
    do {                                                            \
      tmp = (s)->os_sock_status;                                    \
      if( (tmp & (bits)) == 0 )                                     \
        break;                                                      \
      if( cond )                                                    \
        break;                                                      \
    } while( ci_cas32u_fail(&(s)->os_sock_status, tmp,              \
                          (tmp + (1 << OO_OS_STATUS_SEQ_SHIFT)) &   \
                          ~(bits)) );                               \
  } while(0)


#endif  /* __CI_INTERNAL_IP_H__ */
/*! \cidoxg_end */
