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

#ifndef __FTL_DEFS_H__
#define __FTL_DEFS_H__

#ifdef IGNORE
#undef IGNORE
#endif

#ifdef DO
#undef DO
#endif

#define DO(x) x
#define IGNORE(x) 

#ifndef NDEBUG
#define ON_DEBUG DO
#else
#define ON_DEBUG IGNORE
#endif

#define ON_SUN IGNORE
#define NO_SUN DO

#define ON_FALCON DO

#if defined(__unix__) && (!defined(NDEBUG) || CI_CFG_STATS_NETIF)
#define ON_PID_SUPPORT DO
#else
#define ON_PID_SUPPORT IGNORE
#endif

#if CI_CFG_PP_IS_PTR
#error "Not handled yet"
#endif

#if ! CI_CFG_PP_IS_PTR
#define ON_NO_CI_CFG_PP_IS_PTR DO
#else
#define ON_NO_CI_CFG_PP_IS_PTR IGNORE
#endif

#if CI_CFG_SUPPORT_STATS_COLLECTION
#define ON_CI_CFG_SUPPORT_STATS_COLLECTION DO
#else
#define ON_CI_CFG_SUPPORT_STATS_COLLECTION IGNORE
#endif

#if CI_CFG_TCP_SOCK_STATS
#define ON_CI_CFG_TCP_SOCK_STATS DO
#else
#define ON_CI_CFG_TCP_SOCK_STATS IGNORE
#endif

#if CI_CFG_ZC_RECV_FILTER
#define ON_CI_CFG_ZC_RECV_FILTER DO
#else
#define ON_CI_CFG_ZC_RECV_FILTER IGNORE
#endif

#if CI_CFG_FD_CACHING
#define ON_CI_CFG_FD_CACHING DO
#else
#define ON_CI_CFG_FD_CACHING IGNORE
#endif

#if CI_CFG_PIO
#define ON_CI_HAVE_PIO DO
#else
#define ON_CI_HAVE_PIO IGNORE
#endif

#ifndef NDEBUG
#if CI_CFG_PIO
#define ON_CI_HAVE_PIO_DEBUG DO
#else
#define ON_CI_HAVE_PIO_DEBUG IGNORE
#endif
#else
#define ON_CI_HAVE_PIO_DEBUG IGNORE
#endif

#if CI_CFG_SENDFILE
#define ON_CI_HAVE_SENDFILE DO
#else
#define ON_CI_HAVE_SENDFILE IGNORE
#endif

#if CI_CFG_STATS_NETIF
#define ON_CI_CFG_STATS_NETIF DO
#else
#define ON_CI_CFG_STATS_NETIF IGNORE
#endif

#if CI_CFG_FULL_IP_ID_HANDLING==0
#define ON_NO_CI_CFG_FULL_IP_ID_HANDLING DO
#else
#define ON_NO_CI_CFG_FULL_IP_ID_HANDLING IGNORE
#endif

#if CI_CFG_NO_IP_ID_FAILURE
#define ON_CI_CFG_NO_IP_ID_FAILURE DO
#else
#define ON_CI_CFG_NO_IP_ID_FAILURE IGNORE
#endif

#if CI_CFG_PORT_STRIPING
#define ON_CI_CFG_PORT_STRIPING DO
#else
#define ON_CI_CFG_PORT_STRIPING IGNORE
#endif

#if CI_CFG_BURST_CONTROL
#define ON_CI_CFG_BURST_CONTROL DO
#else
#define ON_CI_CFG_BURST_CONTROL IGNORE
#endif

#if CI_CFG_TCP_FASTSTART
#define ON_CI_CFG_TCP_FASTSTART DO
#else
#define ON_CI_CFG_TCP_FASTSTART IGNORE
#endif

#if CI_CFG_TAIL_DROP_PROBE
#define ON_CI_CFG_TAIL_DROP_PROBE DO
#else
#define ON_CI_CFG_TAIL_DROP_PROBE IGNORE
#endif

#if CI_CFG_CONGESTION_WINDOW_VALIDATION
#define ON_CI_CFG_CONGESTION_WINDOW_VALIDATION DO
#else
#define ON_CI_CFG_CONGESTION_WINDOW_VALIDATION IGNORE
#endif

#if CI_CFG_STATS_TCP_LISTEN
#define ON_CI_CFG_STATS_TCP_LISTEN DO
#else
#define ON_CI_CFG_STATS_TCP_LISTEN IGNORE
#endif

#if CI_CFG_PKTS_AS_HUGE_PAGES
#define ON_CI_CFG_PKTS_AS_HUGE_PAGES DO
#else
#define ON_CI_CFG_PKTS_AS_HUGE_PAGES IGNORE
#endif

#if CI_CFG_TCPDUMP
#define ON_CI_CFG_TCPDUMP DO
#else
#define ON_CI_CFG_TCPDUMP IGNORE
#endif

#if CI_CFG_SPIN_STATS
#define ON_CI_CFG_SPIN_STATS DO
#else
#define ON_CI_CFG_SPIN_STATS IGNORE
#endif

#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
#define ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE DO
#else
#define ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE IGNORE
#endif

#if CI_CFG_BURST_CONTROL
#define ON_CI_CFG_BURST_CONTROL DO
#else
#define ON_CI_CFG_BURST_CONTROL IGNORE
#endif

#if CI_CFG_PIO
#define ON_CI_CFG_PIO DO
#else
#define ON_CI_CFG_PIO IGNORE
#endif


#define STRUCT_NS_MMAP_INFO(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, cicp_ns_mmap_info_t,)			      \
    FTL_TFIELD_INT(ctx, cicp_ns_mmap_info_t, ci_uint32, mac_mmap_len)	      \
    FTL_TFIELD_INT(ctx, cicp_ns_mmap_info_t, ci_uint32, fwdinfo_mmap_len)     \
    FTL_TFIELD_INT(ctx, cicp_ns_mmap_info_t, ci_uint32, bondinfo_mmap_len)    \
    FTL_TSTRUCT_END(ctx)					

typedef struct {
    ci_uint32  a;
    ci_uint32  b;
} efhw_event_t_opaque_t;

#define UNION_EFAB_EVENT_OPAQUE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, efhw_event_t_opaque_t,)                            \
    FTL_TFIELD_INT(ctx, efhw_event_t_opaque_t, ci_uint32, a)                  \
    FTL_TFIELD_INT(ctx, efhw_event_t_opaque_t, ci_uint32, b)                  \
    FTL_TSTRUCT_END(ctx)

#define UNION_EFAB_EVENT(ctx) \
    UNION_EFAB_EVENT_OPAQUE(ctx)                                              \
    FTL_TUNION_BEGIN(ctx, efhw_event_t,)                                      \
    FTL_TFIELD_INT(ctx, efhw_event_t, ci_uint64, u64)                         \
    FTL_TFIELD_STRUCT(ctx, efhw_event_t, efhw_event_t_opaque_t, opaque)       \
    FTL_TUNION_END(ctx)

#define STRUCT_EF_EVENTQ_STATE(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ef_eventq_state,)                              \
  FTL_TFIELD_INT(ctx, ef_eventq_state, ef_eventq_ptr, evq_ptr)          \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_timestamp_major)  \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_timestamp_minor)  \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_timestamp_synchronised) \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_flags) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CI_NI_DLLINK(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ni_dllist_link, )                               \
    FTL_TFIELD_INT(ctx, ci_ni_dllist_link, ci_uint32, addr)                   \
    FTL_TFIELD_INT(ctx, ci_ni_dllist_link, ci_uint32, prev)                   \
    FTL_TFIELD_INT(ctx, ci_ni_dllist_link, ci_uint32, next)                   \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_CI_NI_DLLIST(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ni_dllist_t, )                                  \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, ci_ni_dllist_link, l)              \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_PIO_BUDDY_ALLOCATOR(ctx)         \
  FTL_TSTRUCT_BEGIN(ctx, ci_pio_buddy_allocator, )                        \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_pio_buddy_allocator, ci_ni_dllist_t, \
                           free_lists, CI_PIO_BUDDY_MAX_ORDER + 1)      \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_pio_buddy_allocator, ci_ni_dllist_link, \
                           links, 1ul << CI_PIO_BUDDY_MAX_ORDER)        \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_pio_buddy_allocator, ci_uint8, orders,  \
                        1ul << CI_PIO_BUDDY_MAX_ORDER)                  \
  FTL_TFIELD_INT(ctx, ci_pio_buddy_allocator, ci_int32, initialised) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_TIMESPEC(ctx)         \
  FTL_TSTRUCT_BEGIN(ctx, struct oo_timespec, )                        \
  FTL_TFIELD_INT(ctx, struct oo_timespec, ci_int32, tv_sec) \
  FTL_TFIELD_INT(ctx, struct oo_timespec, ci_int32, tv_nsec) \
  FTL_TSTRUCT_END(ctx)


#define STRUCT_NETIF_STATE_NIC(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_state_nic_t, )                        \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, timer_quantum_ns) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, rx_prefix_len)   \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_int32, rx_ts_correction) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, vi_flags)        \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, vi_out_flags)    \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, oo_vi_flags)     \
  ON_CI_HAVE_PIO(                                                       \
    FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32,           \
                        pio_io_mmap_bytes)                              \
    FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32,           \
                        pio_io_len)                                     \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t,                        \
                      ci_pio_buddy_allocator, pio_buddy)                \
  ) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32, vi_mem_mmap_bytes) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32, vi_io_mmap_bytes) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32, vi_evq_bytes) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16, vi_instance) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16, vi_rxq_size) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16, vi_txq_size) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint8, vi_arch)     \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint8, vi_variant)  \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint8, vi_revision) \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state_nic_t, char, pci_dev, 20) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t, oo_pktq, dmaq)           \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_bytes_added)  \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_bytes_removed) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_dmaq_insert_seq) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32,                  \
                 tx_dmaq_insert_seq_last_poll)                          \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_dmaq_done_seq) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t, ci_ni_dllist_t, tx_ready_list) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_int32, rx_frags)         \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, pd_owner)        \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t, struct oo_timespec,      \
                    last_rx_timestamp)                                  \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CI_EPLOCK(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_eplock_t,)                                      \
    FTL_TFIELD_INT(ctx, ci_eplock_t, ci_uint32, lock)                         \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_NETIF_CONFIG(ctx)                                        \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_config, )                             \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_rto_initial) \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_rto_min)     \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_rto_max)     \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_delack)      \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_idle)        \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_keepalive_time) \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_keepalive_time_in_secs)            \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_keepalive_intvl) \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_keepalive_intvl_in_secs)           \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_int32, keepalive_probes)      \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_zwin_max)    \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_paws_idle)   \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_2msl_time)   \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_fin_timeout) \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_pmtu_discover_slow)                \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_pmtu_discover_fast)                \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_pmtu_discover_recover)             \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_stats)       \
  FTL_TSTRUCT_END(ctx)                                                 


typedef struct {                                                           
    ci_uint16 base;
    ci_uint16 next;
} ns_range_t;

#define STRUCT_NS_RANGE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ns_range_t, )                                      \
    FTL_TFIELD_INT(ctx, ns_range_t, ci_uint16, base)			      \
    FTL_TFIELD_INT(ctx, ns_range_t, ci_uint16, next)			      \
    FTL_TSTRUCT_END(ctx)                                                      \

#define STRUCT_NETIF_IPID_CB(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_ipid_cb_t, )                              \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_iptime_t, loop_start_time)     \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_iptime_t, low_use_start_time)  \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_int32, current_index)          \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_int32, max_index)              \
    ON_NO_CI_CFG_FULL_IP_ID_HANDLING(                                         \
      FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_uint16, base)                \
      FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_uint16, next)                \
    )                                                                         \
    ON_CI_CFG_NO_IP_ID_FAILURE(                                               \
      FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_int32, no_free)              \
    )                                                                         \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_ipid_cb_t,                         \
                             ns_range_t, range, CI_TP_IPID_RANGES)            \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_IP_TIMER_STATE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_timer_state, )                               \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_iptime_t, sched_ticks)          \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_iptime_t, ci_ip_time_real_ticks)\
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint64, frc)                    \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint32, ci_ip_time_frc2tick)    \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint32, ci_ip_time_frc2us)      \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint32, khz)                    \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer_state, ci_ni_dllist_t, fire_list)      \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ip_timer_state,                          \
                             ci_ni_dllist_t, warray, CI_IPTIME_WHEELSIZE)     \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_IP_TIMER(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_timer, )                                     \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, ci_ni_dllist_link, link)	      \
    FTL_TFIELD_INT(ctx, ci_ip_timer, ci_iptime_t, time)                       \
    FTL_TFIELD_INT(ctx, ci_ip_timer, ci_iptime_callback_param_t, param1)      \
    FTL_TFIELD_INT(ctx, ci_ip_timer, ci_iptime_callback_fn_t, fn)             \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_EF_VI_TXQ_STATE(ctx)                             \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_txq_state, )                     \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, previous)     \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, added)        \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, removed)      \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, ts_nsec)      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_RXQ_STATE(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_rxq_state, )                             \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, prev_added)           \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, added)                \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, removed)              \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, in_jumbo)             \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, bytes_acc)            \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint16, rx_ps_pkt_count)      \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint16, rx_ps_credit_avail)   \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_STATE(ctx)                                 \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_state, )                         \
  FTL_TFIELD_STRUCT(ctx, ef_vi_state, ef_eventq_state, evq)     \
  FTL_TFIELD_STRUCT(ctx, ef_vi_state, ef_vi_txq_state, txq)     \
  FTL_TFIELD_STRUCT(ctx, ef_vi_state, ef_vi_rxq_state, rxq)     \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_stats, )                                  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, k_polls)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, u_polls)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_evs)              \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_evs)              \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, periodic_polls)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, periodic_evs)              \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, periodic_lock_contends) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupts)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_polls)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_evs)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_wakes)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_primes)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_no_events)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_lock_contends)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, deferred_polls)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupts)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_polls)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_evs) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_wakes) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_no_events) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_lock_contends) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, select_primes)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_sleeps)               \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_sleep_primes)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_rx)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_tx)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_rx_os)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_tx_os)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_signal)          \
    ON_CI_CFG_PKTS_AS_HUGE_PAGES(                                       \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_huge_pages) \
    ) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_nonb)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_nonb_steal)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_wakes)                 \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_scramble0)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_scramble1)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_scramble2)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_wait_spin)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow)               \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_pkt_waiter) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_socket_list) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_need_prime) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_wake)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_swf_update) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_close)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_syscall) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, lock_wakes)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, stack_lock_buzz)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, deferred_work)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_lock_sleeps)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_lock_buzz)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_send_nonb_pool_empty) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_send_ni_lock_contends) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_send_ni_lock_contends) \
    FTL_TFIELD_INT(ctx, ci_netif_stats,                                       \
		   ci_uint32, getsockopt_ni_lock_contends)                    \
    FTL_TFIELD_INT(ctx, ci_netif_stats,                                       \
		   ci_uint32, setsockopt_ni_lock_contends)                    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_send_mcast_loop) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_send_mcast_loop_drop) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, active_opens)              \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_socket)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_bind)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_listen)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_connect)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_setsockopt)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_socket)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_bind)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_connect)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_setsockopt)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_bind_no_filter)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_connect_no_filter) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timewait_reap)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timewait_reap_filter)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_max_hops)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_mean_hops)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_n_entries)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_n_slots)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rtos)                  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_acceptq)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_synrecv)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_has_recvq)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_has_sendq)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_has_unack)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_unacceptable)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_unacceptable_ack) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_synrecv_bad_syn) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_synrecv_bad_ack) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_listen_got_ack) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_bad_options) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_bad_seq)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_no_match)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unacceptable_acks)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_drop_cant_fin)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_retransmits)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_send_fails)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_timeouts)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_purge)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, syn_drop_busy)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, listen2synrecv)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv2established)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, ul_accepts)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, accept_eagain)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, accepts_deferred)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, acks_sent)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, wnd_updates_sent)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_slow)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_out_of_order)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_rob_non_empty)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, retransmits)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_error_events)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_csum_bad) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_mcast_mismatch) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_crc_bad)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_trunc)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_rights)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_other)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_refill_recv)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, reap_rx_limited)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, reap_buf_limited)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkts_reaped)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, refill_rx_limited)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, refill_buf_limited)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, defer_work_limited)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_dma_max)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_dma_doorbells)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_discard_alien_route)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, bufset_alloc_fails)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, bufset_alloc_nospace) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, mss_limitations)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_enter) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_exit_poll) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_exit_recv) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_drops) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_rx_no_match_drops) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_free_with_tx_active) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sw_filter_insert_table_full) \
    ON_CI_HAVE_PIO(                                                           \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pio_pkts)                \
    )                                                                         \
    ON_CI_HAVE_PIO_DEBUG(                                                     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, no_pio_too_long)         \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, no_pio_busy)             \
    )                                                                         \
    ON_CI_HAVE_PIO(                                                           \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, no_pio_err)              \
    ) \
    ON_CI_HAVE_SENDFILE(                                                      \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_sendpages)           \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, poll_no_pkt)         \
    ON_CI_CFG_SPIN_STATS(                                               \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_recv)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_send)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_udp_send)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_udp_recv)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_pipe_read)    \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_pipe_write)   \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_accept)   \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_pkt_wait)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_select)       \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_poll)         \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_epoll)        \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_epoll_kernel) \
    ) \
    ON_CI_CFG_FD_CACHING(                                               \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_cached)  \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_contention) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_stacklim) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_socklim) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_hit)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_hit_reap) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_miss_intmismatch) \
    ) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_rob_guilty) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_recv_coalesced) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_recv_guilty)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_rob_desperate) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_badly)   \
    FTL_TSTRUCT_END(ctx)

#if CI_CFG_SUPPORT_STATS_COLLECTION

#define STRUCT_IPV4_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ipv4_stats_count, )                             \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_recvs)      \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_hdr_errs)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_addr_errs)  \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, forw_dgrams)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count,                                  \
		   CI_IP_STATS_TYPE, in_unknown_protos)                       \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_discards)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_delivers)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, out_requests)  \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, out_discards)  \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, out_no_routes) \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_timeout) \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_reqds)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_oks)     \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_fails)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, frag_oks)      \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, frag_fails)    \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, frag_creates)  \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ICMP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_icmp_stats_count, )                             \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE, icmp_in_msgs)  \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE, icmp_in_errs)  \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_dest_unreachs)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_time_excds)					      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_parm_probs)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_src_quenchs)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_redirects)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_echos)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_echo_reps)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_timestamps)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_timestamp_reps)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_addr_masks)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_addr_mask_reps)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_msgs)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_errs)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_dest_unreachs)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_time_excds)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_parm_probs)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_src_quenchs)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_redirects)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_echos)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_echo_reps)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_timestamps)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_timestamp_reps)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_addr_masks)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_addr_mask_reps)				      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_stats_count, )                              \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_active_opens)                                          \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_passive_opens)                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
   		   tcp_attempt_fails)                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_estab_resets)                                          \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_curr_estab)                                            \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_in_segs)                                               \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_out_segs)                                              \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_retran_segs)                                           \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_in_errs)                                               \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_out_rsts)                                              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_stats_count, )                              \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_in_dgrams)                                             \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_no_ports)                                              \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_in_errs)                                               \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_out_dgrams)                                            \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_EXT_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_ext_stats_count, )                          \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   syncookies_sent)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   syncookies_recv)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   syncookies_failed)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   embrionic_rsts)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   prune_called)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   rcv_pruned)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   ofo_pruned)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   out_of_window_icmps)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   lock_dropped_icmps)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   arp_filter)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   time_waited)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   time_wait_recycled)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   time_wait_killed)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   paws_passive_rejected)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   paws_active_rejected)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   paws_estab_rejected)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   delayed_ack)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   delayed_ack_locked)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   delayed_ack_lost)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   listen_overflows)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   listen_drops)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_prequeued)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_direct_copy_from_backlog)			      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_direct_copy_from_prequeue)			      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_prequeue_dropped)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_hp_hits)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_hp_hits_to_user)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_pure_acks)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_hp_acks)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_recovery)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_recovery)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_reneging)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_fack_reorder)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_reorder)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_reorder)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_ts_reorder)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_full_undo)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_partial_undo)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_loss_undo)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_undo)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_loss)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_lost_retransmit)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_failures)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_failures)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_loss_failures)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_timeouts)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_recovery_fail)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_recovery_fail)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_fast_retrans)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_forward_retrans)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_slow_start_retrans)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_scheduler_failures)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_rcv_collapsed)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_old_sent)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_ofo_sent)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_recv)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_ofo_recv)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_syn)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_data)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_close)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_memory)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_timeout)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_linger)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_delegated_send)                               \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_failed)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_memory_pressures)			              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_stats, )                                     \
    FTL_TFIELD_INT(ctx, ci_ip_stats, __TIME_TYPE__, now)                      \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_ipv4_stats_count,    ipv4)         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_icmp_stats_count,    icmp)         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_tcp_stats_count,     tcp)          \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_udp_stats_count,     udp)          \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_tcp_ext_stats_count, tcp_ext)      \
    FTL_TSTRUCT_END(ctx)

#endif  /* CI_CFG_SUPPORT_STATS_COLLECTION */

#define STRUCT_NETIF_DBG_MAX(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_dbg_max_t, )                              \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t, ci_uint16, poll_l5_max, 2) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t, ci_uint16, poll_os_max, 2) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t,                            \
			  ci_uint16, select_l5_max, 2)                        \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t,                            \
			  ci_uint16, select_os_max, 2)                        \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_THRD_INFO(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_thrd_info_t, )                            \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, index)                \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, id)                   \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_thrd_info_t,                          \
		          ci_uint32, ep_id, NETIF_INFO_MAX_EPS_PER_THREAD)    \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, lock_status)          \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_lock_contentions)  \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_select)            \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_poll)            \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_fork)              \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_exec)              \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_accept)	      \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_fini)              \
    FTL_TFIELD_STRUCT(ctx, ci_netif_thrd_info_t, ci_netif_dbg_max_t, max)     \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_STATS(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_stats, )                                  \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, rx_ev_lost)             \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, rx_ev_bad_desc_i)         \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, rx_ev_bad_q_label)        \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, evq_gap)                  \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_STATE(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_state, )                              \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state, ci_netif_state_nic_t,   \
                           nic, CI_CFG_MAX_INTERFACES)                  \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, nic_n)                  \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, evq_last_prime)        \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, cicp_ns_mmap_info_t, control_mmap) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, stack_id)              \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, char, pretty_name,         \
                        CI_CFG_STACK_NAME_LEN + 8)                      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, netif_mmap_bytes)      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, vi_mem_mmap_offset)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, vi_io_mmap_offset)     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pio_io_mmap_offset)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, vi_state_bytes)        \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, max_mss)               \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, flags)                 \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, error_flags)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, evq_primed)            \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_int8,                   \
                        hwport_to_intf_i, CI_CFG_MAX_REGISTER_INTERFACES)   \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_int8,                   \
                        intf_i_to_hwport, CI_CFG_MAX_INTERFACES)        \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, n_spinners)            \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int8, is_spinner)              \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int8, poll_work_outstanding)   \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, last_spin_poll_frc)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, last_sleep_frc)        \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_eplock_t, lock)             \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, freepkts)               \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_freepkts)             \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, looppkts)               \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_looppkts)             \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_rx_pkts)              \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rxq_low)                \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rxq_limit)              \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, mem_pressure)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, mem_pressure_pkt_pool)  \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, mem_pressure_pkt_pool_n) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_async_pkts)           \
  ON_NO_CI_CFG_PP_IS_PTR(                                               \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, nonb_pkt_pool)       \
  ) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_ipid_cb_t, ipid)      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, vi_ofs)                \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, table_ofs)             \
  ON_CI_CFG_PKTS_AS_HUGE_PAGES(                                         \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, buf_ofs)             \
  ) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pkt_sets_n)            \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pkt_sets_max)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_pkts_allocated)       \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_timer_state, iptimer_state) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_timer, timeout_tid)      \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state, ci_ni_dllist_t, timeout_q, \
                           OO_TIMEOUT_Q_MAX)                            \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ni_dllist_t, reap_list)     \
  ON_CI_CFG_SUPPORT_STATS_COLLECTION(                                   \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, stats_fmt)            \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_timer, stats_tid)      \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_stats, stats_snapshot) \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_stats, stats_cumulative) \
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, free_eps_head)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, deferred_free_eps_head) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, max_ep_bufs)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, n_ep_bufs)             \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state, ci_ni_dllist_t,         \
                           ready_lists, CI_CFG_N_READY_LISTS)           \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_uint32,                 \
                        ready_list_flags, CI_CFG_N_READY_LISTS)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, ready_lists_in_use)    \
  ON_CI_CFG_PIO(                                                        \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pio_bufs_ofs)        \
  ) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, ep_ofs)                \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, aux_ofs)               \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, free_aux_mem)           \
  ON_CI_CFG_FD_CACHING(                                                 \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, cache_avail_stack)       \
  )                                                                     \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_config, conf)         \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_config_opts, opts)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, sock_spin_cycles)      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, buzz_cycles)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, timer_prime_cycles)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, cplane_bytes)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, io_mmap_bytes)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, buf_mmap_bytes)        \
  ON_CI_CFG_PIO(                                                        \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pio_mmap_bytes)      \
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, poll_did_wake)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, in_poll)               \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ni_dllist_t, post_poll_list) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rx_defrag_head)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rx_defrag_tail)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, send_may_poll)          \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, char, name,                \
                        CI_CFG_STACK_NAME_LEN + 1)                      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, pid)                    \
  FTL_TFIELD_INT(ctx, ci_netif_state, uid_t, uid)                       \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, defer_work_count)      \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_uint8, hash_salt, 16)   \
  ON_CI_CFG_STATS_NETIF(                                                \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_stats, stats)       \
  )                                                                     \
  ON_CI_CFG_TCPDUMP(                                                    \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_int32, dump_queue,    \
                          CI_CFG_DUMPQUEUE_LEN)                         \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_uint8, dump_intf,     \
                          OO_INTF_I_NUM)                                \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint8, dump_read_i)          \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint8, dump_write_i)         \
  ) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ef_vi_stats, vi_stats) \
  FTL_TSTRUCT_END(ctx)



#define STRUCT_USER_PTR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_user_ptr_t, )                                   \
    FTL_TFIELD_INT(ctx, ci_user_ptr_t, ci_uint64, ptr)                        \
    FTL_TSTRUCT_END(ctx)


typedef struct {
    ci_uint32  rx;
    ci_uint32  tx;
} ci_sleep_seq_t_rw_t;

#define UNION_SLEEP_SEQ_RW(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_sleep_seq_t_rw_t,)                              \
    FTL_TFIELD_INT(ctx, ci_sleep_seq_t_rw_t, ci_uint32, rx)                   \
    FTL_TFIELD_INT(ctx, ci_sleep_seq_t_rw_t, ci_uint32, tx)                   \
    FTL_TSTRUCT_END(ctx)


#define UNION_SLEEP_SEQ(ctx) \
    UNION_SLEEP_SEQ_RW(ctx)                                                   \
    FTL_TUNION_BEGIN(ctx, ci_sleep_seq_t,)                                    \
    FTL_TFIELD_INT(ctx, ci_sleep_seq_t, ci_uint64, all)                       \
    FTL_TFIELD_STRUCT(ctx, ci_sleep_seq_t, ci_sleep_seq_t_rw_t, rw)           \
    FTL_TUNION_END(ctx)



#define STRUCT_WAITABLE(ctx)					     	      \
    FTL_TSTRUCT_BEGIN(ctx, citp_waitable, )                                   \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_sleep_seq_t, sleep_seq)    \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint64, spin_cycles)          \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, bufid)                       \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, state)                      \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, wake_request)         \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, sb_flags)                   \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, sb_aflags)                  \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_ni_dllist_link, post_poll_link)  \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, lock)                  \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, wt_next)               \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, next_id)               \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_ni_dllist_link, ready_link)  \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, ready_list_id)         \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_user_ptr_t, eitem)         \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, sigown)                \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, moved_to_stack_id)    \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, moved_to_sock_id)      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ETHER_HDR(ctx)						      \
    FTL_TSTRUCT_BEGIN(ctx, ci_ether_hdr, )                                    \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_ether_hdr, ci_uint8, ether_dhost, ETH_ALEN) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_ether_hdr, ci_uint8, ether_shost, ETH_ALEN) \
    FTL_TFIELD_INT(ctx, ci_ether_hdr, ci_uint16, ether_type)                  \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP4_HDR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip4_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_ihl_version)                 \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_tos)                         \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint16, ip_tot_len_be16)               \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint16, ip_id_be16)                    \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint16, ip_frag_off_be16)              \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_ttl)                         \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_protocol)                    \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint16, ip_check_be16)                 \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint16, ip_saddr_be32)                 \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint16, ip_daddr_be32)                 \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_HDR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_source_be16)               \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_dest_be16)                 \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_len_be16)                  \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_check_be16)                \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP4_PSEUDO_HDR(ctx)                                            \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip4_pseudo_hdr, )                               \
    FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint32, ip_saddr_be32)          \
    FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint32, ip_daddr_be32)          \
    FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint8, zero)                    \
    FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint8, ip_protocol)             \
    FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint16, length_be16)            \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_CICP_VERINFO(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, cicp_mac_verinfo_t, )                              \
    FTL_TFIELD_INT(ctx, cicp_mac_verinfo_t, ci_verlock_value_t, row_version)  \
    FTL_TFIELD_INT(ctx, cicp_mac_verinfo_t, ci_int32, row_index)        \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_PMTU_STATE(ctx)                                                \
    FTL_TSTRUCT_BEGIN(ctx, ci_pmtu_state_t, )                                 \
    FTL_TFIELD_STRUCT(ctx, ci_pmtu_state_t, ci_ip_timer, tid)                 \
    FTL_TFIELD_INT(ctx, ci_pmtu_state_t, ci_uint16, pmtu)                     \
    FTL_TFIELD_INT(ctx, ci_pmtu_state_t, ci_uint8, plateau_id)                \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ATOMIC(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_atomic_t, )                                     \
    FTL_TFIELD_INT(ctx, ci_atomic_t, int, n)                                  \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_IP_HDRS(ctx)                                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_cached_hdrs, )                               \
    FTL_TFIELD_STRUCT(ctx, ci_ip_cached_hdrs, cicp_mac_verinfo_t,             \
		      mac_integrity)					      \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_ip_addr_t, ip_saddr_be32) \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint16, dport_be16)       \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_int8, status)       \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint8, flags)       \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_ip_addr_t, nexthop)             \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_mtu_t, mtu)                     \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_ifid_t, ifindex)                \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, cicp_encap_t, encap)                \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_int32, intf_i)            \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_hwport_id_t, hwport)            \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint8, ether_offset)            \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_ip_cached_hdrs, ci_uint8, ether_header,     \
			  2 * ETH_ALEN + 4)				      \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint16, ether_type)             \
    FTL_TFIELD_STRUCT(ctx, ci_ip_cached_hdrs, ci_ip4_hdr, ip)                 \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_HDR(ctx)                                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_source_be16)               \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_dest_be16)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint32, tcp_seq_be32)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint32, tcp_ack_be32)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint8, tcp_hdr_len_sl4)                \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint8, tcp_flags)                      \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_window_be16)               \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_check_be16)                \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_urg_ptr_be16)              \
    FTL_TSTRUCT_END(ctx)

typedef union {
  ci_tcp_hdr          space_for_tcp_hdr;
  ci_udp_hdr          space_for_udp_hdr;
} space_for_hdrs_t;

#define STRUCT_HDR_SPACE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, space_for_hdrs_t, )                                \
    FTL_TFIELD_STRUCT(ctx, space_for_hdrs_t, ci_tcp_hdr, space_for_tcp_hdr)   \
    FTL_TFIELD_STRUCT(ctx, space_for_hdrs_t, ci_udp_hdr, space_for_udp_hdr)   \
    FTL_TSTRUCT_END(ctx)

typedef struct oo_timeval oo_timeval;

#define STRUCT_TIMEVAL(ctx)                             \
    FTL_TSTRUCT_BEGIN(ctx, oo_timeval, )                \
    FTL_TFIELD_INT(ctx, oo_timeval, ci_int32, tv_sec)   \
    FTL_TFIELD_INT(ctx, oo_timeval, ci_int32, tv_usec)  \
    FTL_TSTRUCT_END(ctx)

typedef struct {
    /* This contains only sockopts that are inherited from the listening
    ** socket by newly accepted TCP sockets.
    */
    ci_int32            sndbuf;
    ci_int32            rcvbuf;
    ci_uint32           rcvtimeo_msec;
    ci_uint32           sndtimeo_msec;
    ci_uint32           linger;
    ci_int32            rcvlowat;
    ci_int32            so_debug; /* Flags for dummy options */
} socket_inoption_t;

#define STRUCT_SOCK_OPTS(ctx)                                           \
  FTL_TSTRUCT_BEGIN(ctx, socket_inoption_t, )                           \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_int32, sndbuf)              \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_int32, rcvbuf)              \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_uint32, rcvtimeo_msec)   \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_uint32, sndtimeo_msec)   \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_uint32, linger)             \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_int32, rcvlowat)            \
  FTL_TFIELD_INT(ctx, socket_inoption_t, ci_int32, so_debug)            \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_sock_cplane oo_sock_cplane_t;

#define STRUCT_SOCK_CPLANE(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, oo_sock_cplane_t, )                            \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint32, ip_laddr_be32)       \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint16, lport_be16)          \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint16, so_bindtodevice)     \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint16, ip_multicast_if)     \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint32, ip_multicast_if_laddr_be32) \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint8, ip_ttl)               \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint8, ip_mcast_ttl)         \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint8, sock_cp_flags)        \
  FTL_TSTRUCT_END(ctx)


#define STRUCT_SOCK(ctx)                                                \
  FTL_TSTRUCT_BEGIN(ctx, ci_sock_cmn, )                                 \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, citp_waitable, b)                 \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, s_flags)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, s_aflags)                 \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, oo_sock_cplane_t, cp)             \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, ci_ip_cached_hdrs, pkt)           \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, space_for_hdrs_t, space_for_hdrs) \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, tx_errno)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, rx_errno)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, os_sock_status)           \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, socket_inoption_t, so)            \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_pkt_priority_t, so_priority)      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, so_error)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int16, rx_bind2dev_ifindex)       \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int16, rx_bind2dev_base_ifindex)  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int16, rx_bind2dev_vlan)          \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int8, cmsg_flags)                 \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint8, timestamping_flags)        \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint64, ino)                      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, uid)                      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, pid)                       \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint8, domain)                    \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, ci_ni_dllist_link, reap_link)     \
  FTL_TSTRUCT_END(ctx)
    
#define STRUCT_IP_PKT_QUEUE(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_pkt_queue, )                                 \
    FTL_TFIELD_INT(ctx, ci_ip_pkt_queue, ci_int32, head)                      \
    FTL_TFIELD_INT(ctx, ci_ip_pkt_queue, ci_int32, tail)                      \
    FTL_TFIELD_INT(ctx, ci_ip_pkt_queue, ci_int32, num)                       \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_PKTQ(ctx)                             \
    FTL_TSTRUCT_BEGIN(ctx, oo_pktq, )                   \
    FTL_TFIELD_INT(ctx, oo_pktq, ci_int32, head)        \
    FTL_TFIELD_INT(ctx, oo_pktq, ci_int32, tail)        \
    FTL_TFIELD_INT(ctx, oo_pktq, ci_int32, num)         \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_SOCKET_STATS(ctx)                                    \
  FTL_TSTRUCT_BEGIN(ctx, ci_udp_socket_stats, )                         \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_os)          \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_os_slow)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_os_error)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_eagain)      \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_overflow)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_mem_drop)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_pktinfo)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, max_recvq_depth)  \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_os)          \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_os_slow)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_onload_c)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_onload_uc)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_match)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_uc_lookup) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_c_lookup) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_a_lookup) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_no_mac)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_poll)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_pkt)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_snd)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_cp)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_defer)  \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_eagain)      \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_spin)        \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_block)       \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_poll_avoids_full) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_fragments)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_msg_confirm) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_os_late)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_unconnect_late) \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_tcp_socket_stats oo_tcp_socket_stats;

#define STRUCT_TCP_SOCKET_STATS(ctx)                                    \
  FTL_TSTRUCT_BEGIN(ctx, oo_tcp_socket_stats, )                         \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_rwnd)     \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_cwnd)     \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_more)     \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_nagle)    \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_app)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_nomac_defer)   \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_defer)         \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_msg_warm_abort) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_msg_warm)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_tmpl_alloc)    \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_tmpl_send_fast) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_tmpl_send_slow) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_tmpl_active)   \
  ON_CI_CFG_BURST_CONTROL(                                              \
     FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_burst) \
                                                                        ) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rtos)             \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, fast_recovers)    \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rx_seq_errs)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rx_ack_seq_errs)  \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rx_ooo_pkts)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rx_ooo_fill)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rx_isn)           \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_RECV_Q(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_recv_q, )                                   \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, head)                        \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, tail)                        \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_added)                 \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, bytes_added)                \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, extract)                     \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_delivered)             \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, bytes_delivered)            \
    ON_CI_CFG_ZC_RECV_FILTER(                                                 \
      FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, filter)                    \
      FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_filter_dropped)      \
      FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, bytes_filter_dropped)     \
      FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_filter_passed)       \
      FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, bytes_filter_passed)      \
    ) \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TIMESTAMP_Q(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ci_timestamp_q, )                              \
  FTL_TFIELD_STRUCT(ctx, ci_timestamp_q, ci_ip_pkt_queue, queue)        \
  FTL_TFIELD_INT(ctx, ci_timestamp_q, ci_int32, extract)                \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP(ctx)                                                 \
  FTL_TSTRUCT_BEGIN(ctx, ci_udp_state, )                                \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_sock_cmn, s)                  \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_ip_cached_hdrs, ephemeral_pkt) \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, udpflags)                \
  ON_CI_CFG_ZC_RECV_FILTER(                                             \
    FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint64, recv_q_filter)         \
    FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint64, recv_q_filter_arg)     \
  ) \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_udp_recv_q, recv_q)           \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_timestamp_q, timestamp_q)     \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_int32, zc_kernel_datagram)       \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, zc_kernel_datagram_count) \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, struct oo_timespec, stamp_cache)        \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint64, stamp)                   \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint64, stamp_pre_sots)          \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_int32, tx_async_q)               \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, tx_async_q_level)        \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, tx_count)                \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_udp_socket_stats, stats)      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS_COUNT(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats_count, )                          \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rtto)       \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, cong)       \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_byte)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_pkt)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_slowpath)\
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_seqerr)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_ackerr)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_pawserr) \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_dupack)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   rx_dupack_frec)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   rx_dupack_congfrec)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_zwin)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_ooo)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_badsyn)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   rx_badsynseq)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_syndup)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
                  rx_synbadack)					              \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
                   rx_synnonack)                             		      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_sleep)   \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_wait)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_byte)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_pkt)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_slowpath)\
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   tx_retrans_pkt)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_sleep)   \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_stuck)   \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS_RANGE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats_range, )                          \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rx_win)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rx_wscl)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, tx_win)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, tx_wscl)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rtt)        \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, srtt)       \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rto)        \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, tx_buffree) \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE,             \
                   tx_sleeptime)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE,             \
		   rx_sleeptime)		                              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats, )                                \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats, __TIME_TYPE__, now)                 \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_count, count)   \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_range, actual)  \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_range, min)     \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_range, max)     \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_COMMON(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_cmn, )                               \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_uint32, ka_probe_th)            \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_time)            \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_time_in_secs)    \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_intvl)     \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_intvl_in_secs) \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_uint32, user_mss)               \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_uint8, tcp_defer_accept)	      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_state, )                                    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_sock_cmn, s)                      \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_tcp_socket_cmn, c)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, local_peer)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, tmpl_head)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tcpflags)                    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_pmtu_state_t, pmtus)              \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, so_sndbuf_pkts)         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_window_max)        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, send_in)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, send_out)              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, send)               \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, retrans)            \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, recv1)              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, recv2)              \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, recv_off)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, recv1_extract)                \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, rob)                \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_tcp_state, ci_int32, last_sack,             \
                          CI_TCP_SACK_MAX_BLOCKS + 1)                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, dsack_start)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, dsack_end)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, dsack_block)                  \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_timestamp_q, timestamp_q)  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_check)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_nxt)                     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_max)                     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_una)                     \
    ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE(                                  \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_wl1)                   \
    ) \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_delegated)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, fast_path_check)             \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, outgoing_hdrs_len)           \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, amss)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, smss)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, eff_mss)                     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_up)                      \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_wnd_advertised)          \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_wnd_right_edge_sent)     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_added)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_delivered)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, ack_trigger)                 \
    ON_CI_CFG_BURST_CONTROL(                                            \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, burst_window)              \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_up)                      \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint8, rcv_wscl)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint8, snd_wscl)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, congstate)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, congrecover)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, retrans_ptr)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, retrans_seq)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, cwnd)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, cwnd_extra)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, ssthresh)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, bytes_acked)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, dup_acks)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, dup_thresh)                  \
    ON_CI_CFG_TCP_FASTSTART(                                                  \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, faststart_acks)            \
    )                                                                         \
    ON_CI_CFG_TAIL_DROP_PROBE(                                                \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, taildrop_state)            \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, taildrop_mark)             \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_prev_recv_payload) \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_recv_payload) \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_recv_ack)     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_sent)               \
    ON_CI_CFG_CONGESTION_WINDOW_VALIDATION(                                   \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_full)             \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, cwnd_used)                 \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, sa)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, sv)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, rto)                       \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, retransmits)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, timed_seq)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, timed_ts)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tsrecent)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tslastack)                   \
    ON_DEBUG(                                                                 \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tslastseq)                 \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, tspaws)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, acks_pending)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, ka_probes)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, zwin_probes)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, zwin_acks)             \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, incoming_tcp_hdr_len)         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, rto_tid)                \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, delack_tid)             \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, zwin_tid)               \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, kalive_tid)             \
    ON_CI_CFG_TCP_SOCK_STATS(                                                 \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, stats_tid)            \
    )                                                                         \
    ON_CI_CFG_TAIL_DROP_PROBE(                                                \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, taildrop_tid)         \
    )                                                                         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, cork_tid)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, urg_data)                    \
    ON_CI_CFG_TCP_SOCK_STATS(                                                 \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_sock_stats, stats_snapshot)  \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_sock_stats, stats_cumulative)\
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, stats_fmt)                  \
    )                                                                         \
    ON_CI_CFG_FD_CACHING(                                                     \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, cached_on_fd)               \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, cached_on_pid)              \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, epcache_link)   \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, send_prequeue)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, send_prequeue_in)         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, timeout_q_link)   \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, tx_ready_link)    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, oo_tcp_socket_stats, stats)          \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_SOCKET_LISTEN_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_listen_stats, )                      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_listenq_overflow)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_listenq_no_synrecv)				      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_acks_reset)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_acceptq_overflow)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_acceptq_no_sock)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_accept_loop2_closed)				      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_accept_os)					              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_accept_no_fd)				              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_syn)				              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_recv)                                      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_ts_rej)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_hash_rej)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_answ)			              \
    ON_CI_CFG_FD_CACHING(						      \
      FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,              \
  		   n_sockcache_hit)				              \
    ) \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_LISTEN(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_listen, )                            \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_sock_cmn, s)              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_tcp_socket_cmn, c)        \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, acceptq_max)         \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, acceptq_put)          \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, acceptq_n_in)        \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, acceptq_get)          \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, acceptq_n_out)       \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, n_listenq)            \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, n_listenq_new)        \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_tcp_socket_listen, ci_ni_dllist_t,       \
			     listenq, CI_CFG_TCP_SYNACK_RETRANS_MAX + 1)      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, bucket)               \
    ON_CI_CFG_FD_CACHING(                                                     \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_ni_dllist_t,            \
		        epcache_cache)				      \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_ni_dllist_t,            \
		        epcache_pending)				      \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_ni_dllist_t,            \
		        epcache_connected)				      \
      FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, cache_avail_sock)  \
    )                                                                         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_ip_timer, listenq_tid)    \
    ON_CI_CFG_STATS_TCP_LISTEN(  				              \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_tcp_socket_listen_stats,\
			stats)           			              \
    )                                                                         \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_WAITABLE_OBJ(ctx)				              \
    FTL_TSTRUCT_BEGIN(ctx, citp_waitable_obj, )                               \
    FTL_TFIELD_STRUCT(ctx, citp_waitable_obj, citp_waitable, waitable)        \
    FTL_TFIELD_STRUCT(ctx, citp_waitable_obj, ci_sock_cmn, sock)              \
    FTL_TFIELD_STRUCT(ctx, citp_waitable_obj, ci_tcp_state, tcp)              \
    FTL_TSTRUCT_END(ctx)
    

#define STRUCT_FILTER_TABLE_ENTRY(ctx)                                        \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table_entry, )                     \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table_entry, ci_int32, id)            \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table_entry, ci_int32, route_count)   \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table_entry, ci_uint32, laddr)        \
    FTL_TSTRUCT_END(ctx)
    

#define STRUCT_FILTER_TABLE(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table, )                           \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table, unsigned, table_size_mask)    \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_filter_table,                      \
			     ci_netif_filter_table_entry, table, 1)	      \
    FTL_TSTRUCT_END(ctx)
    
typedef struct {
  oo_pkt_p  pp;
  ci_uint32 offset;
} oo_pipe_read_ptr;

#define STRUCT_OO_PIPE_READ_PTR(ctx)                            \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe_read_ptr, )                    \
  FTL_TFIELD_INT(ctx, oo_pipe_read_ptr, ci_int32, pp)           \
  FTL_TFIELD_INT(ctx, oo_pipe_read_ptr, ci_uint32, offset)      \
  FTL_TSTRUCT_END(ctx)

typedef struct {
  oo_pkt_p  pp;
  oo_pkt_p pp_wait;
} oo_pipe_write_ptr;

#define STRUCT_OO_PIPE_WRITE_PTR(ctx)                            \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe_write_ptr, )                    \
  FTL_TFIELD_INT(ctx, oo_pipe_write_ptr, ci_int32, pp)           \
  FTL_TFIELD_INT(ctx, oo_pipe_write_ptr, ci_int32, pp_wait)      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_PIPE_BUF_LIST_T(ctx)                            \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe_buf_list_t, )                    \
  FTL_TFIELD_INT(ctx, oo_pipe_buf_list_t, ci_int32, pp)           \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_pipe oo_pipe;

#define STRUCT_OO_PIPE(ctx)                                              \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe, )                              \
  FTL_TFIELD_STRUCT(ctx, oo_pipe, citp_waitable, b)              \
  FTL_TFIELD_STRUCT(ctx, oo_pipe, oo_pipe_buf_list_t, pipe_bufs) \
  FTL_TFIELD_STRUCT(ctx, oo_pipe, oo_pipe_read_ptr, read_ptr)    \
  FTL_TFIELD_STRUCT(ctx, oo_pipe, oo_pipe_write_ptr, write_ptr)  \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, aflags)                \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bufs_num)              \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bufs_max)              \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bytes_added)           \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bytes_removed)         \
  FTL_TSTRUCT_END(ctx)


#endif /* __FTL_DEFS_H__ */
