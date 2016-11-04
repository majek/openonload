/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

#if CI_CFG_SEPARATE_UDP_RXQ
#define ON_CI_CFG_SEPARATE_UDP_RXQ DO
#else
#define ON_CI_CFG_SEPARATE_UDP_RXQ IGNORE
#endif


#define oo_timespec \
  struct oo_timespec

#define oo_waitable_lock \
  struct oo_waitable_lock

#define UNION_EFAB_EVENT(ctx)                                           \
  FTL_TUNION_BEGIN(ctx, efhw_event_t,)                                  \
  FTL_TFIELD_INT(ctx, efhw_event_t, uint64_t, u64, ORM_OUTPUT_STACK)                      \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, efhw_event_t, opaque, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_ANON_STRUCT(ctx, efhw_event_t, uint32_t, opaque, a)        \
  FTL_TFIELD_ANON_STRUCT(ctx, efhw_event_t, uint32_t, opaque, b)        \
  FTL_TFIELD_ANON_STRUCT_END(ctx, efhw_event_t, opaque)                 \
  FTL_TUNION_END(ctx)

#define STRUCT_EF_EVENTQ_STATE(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ef_eventq_state,)                              \
  FTL_TFIELD_INT(ctx, ef_eventq_state, ef_eventq_ptr, evq_ptr, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_timestamp_major, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_timestamp_minor, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_timestamp_synchronised, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ef_eventq_state, unsigned, sync_flags, ORM_OUTPUT_STACK) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CI_NI_DLLINK(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ni_dllist_link, )                               \
    FTL_TFIELD_INT(ctx, ci_ni_dllist_link, oo_p, addr, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_ni_dllist_link, oo_p, prev, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_ni_dllist_link, oo_p, next, ORM_OUTPUT_STACK)                   \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_CI_NI_DLLIST(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ni_dllist_t, )                                  \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, ci_ni_dllist_link, l, ORM_OUTPUT_STACK)              \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_PIO_BUDDY_ALLOCATOR(ctx)         \
  FTL_TSTRUCT_BEGIN(ctx, ci_pio_buddy_allocator, )                        \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_pio_buddy_allocator, ci_ni_dllist_t, \
                           free_lists, CI_PIO_BUDDY_MAX_ORDER + 1, ORM_OUTPUT_EXTRA)      \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_pio_buddy_allocator, ci_ni_dllist_link, \
                           links, 1ul << CI_PIO_BUDDY_MAX_ORDER, ORM_OUTPUT_EXTRA)        \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_pio_buddy_allocator, ci_uint8, orders,  \
                        1ul << CI_PIO_BUDDY_MAX_ORDER, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_pio_buddy_allocator, ci_int32, initialised, ORM_OUTPUT_STACK) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_TIMESPEC(ctx)                                \
  FTL_TSTRUCT_BEGIN(ctx, oo_timespec, )                        \
  FTL_TFIELD_INT(ctx, oo_timespec, ci_int32, tv_sec, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, oo_timespec, ci_int32, tv_nsec, ORM_OUTPUT_STACK)          \
  FTL_TSTRUCT_END(ctx)


#define STRUCT_NETIF_STATE_NIC(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_state_nic_t, )                        \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, timer_quantum_ns, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, rx_prefix_len, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_int16, rx_ts_correction, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_int16, tx_ts_correction, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, vi_flags, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, vi_out_flags, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, oo_vi_flags, ORM_OUTPUT_STACK)     \
  ON_CI_HAVE_PIO(                                                       \
    FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32,           \
                        pio_io_mmap_bytes, ORM_OUTPUT_STACK)                              \
    FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32,           \
                        pio_io_len, ORM_OUTPUT_STACK)                                     \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t,                        \
                      ci_pio_buddy_allocator, pio_buddy, ORM_OUTPUT_EXTRA)                \
  ) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32, vi_io_mmap_bytes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32, vi_evq_bytes, ORM_OUTPUT_STACK) \
  ON_CI_CFG_SEPARATE_UDP_RXQ(                                            \
    FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint32,            \
                        udp_rxq_vi_evq_bytes, ORM_OUTPUT_STACK)                            \
  )                                                                      \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16, vi_instance, ORM_OUTPUT_STACK) \
  ON_CI_CFG_SEPARATE_UDP_RXQ(                                            \
    FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16,            \
                         udp_rxq_vi_instance, ORM_OUTPUT_STACK)                            \
  )                                                                      \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16, vi_rxq_size, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint16, vi_txq_size, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint8, vi_arch, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint8, vi_variant, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_CONSTINT(ctx, ci_netif_state_nic_t, ci_uint8, vi_revision, ORM_OUTPUT_STACK) \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state_nic_t, char, pci_dev, 20, ORM_OUTPUT_STACK) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t, oo_pktq, dmaq, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_bytes_added, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_bytes_removed, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_dmaq_insert_seq, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32,                  \
                 tx_dmaq_insert_seq_last_poll, ORM_OUTPUT_STACK)                          \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, tx_dmaq_done_seq, ORM_OUTPUT_STACK) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t, ci_ni_dllist_t, tx_ready_list, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_int32, rx_frags, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_netif_state_nic_t, ci_uint32, pd_owner, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state_nic_t, oo_timespec,             \
                    last_rx_timestamp, ORM_OUTPUT_STACK)                                  \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CI_EPLOCK(ctx) \
  FTL_TSTRUCT_BEGIN(ctx, ci_eplock_t,)                                  \
  FTL_TFIELD_INT(ctx, ci_eplock_t, ci_uint64, lock, ORM_OUTPUT_STACK) \
  FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_NETIF_CONFIG(ctx)                                        \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_config, )                             \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_rto_initial, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_rto_min, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_rto_max, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_delack, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_idle, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_keepalive_time, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_keepalive_time_in_secs, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_keepalive_intvl, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_keepalive_intvl_in_secs, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_int32, keepalive_probes, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_zwin_max, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_paws_idle, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_2msl_time, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_fin_timeout, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_pmtu_discover_slow, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_pmtu_discover_fast, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_netif_config,                                  \
                 ci_iptime_t, tconst_pmtu_discover_recover, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_netif_config, ci_iptime_t, tconst_stats, ORM_OUTPUT_STACK)       \
  FTL_TSTRUCT_END(ctx)                                                 


#define STRUCT_NETIF_IPID_CB(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_ipid_cb_t, )                              \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_iptime_t, loop_start_time, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_iptime_t, low_use_start_time, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_int32, current_index, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_int32, max_index, ORM_OUTPUT_STACK)              \
    ON_NO_CI_CFG_FULL_IP_ID_HANDLING(                                         \
      FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_uint16, base, ORM_OUTPUT_STACK)                \
      FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_uint16, next, ORM_OUTPUT_STACK)                \
    )                                                                         \
    ON_CI_CFG_NO_IP_ID_FAILURE(                                               \
      FTL_TFIELD_INT(ctx, ci_netif_ipid_cb_t, ci_int32, no_free, ORM_OUTPUT_STACK)              \
    )                                                                         \
    FTL_TFIELD_ANON_ARRAYOFSTRUCT_BEGIN(ctx, ci_netif_ipid_cb_t,        \
                                        range, CI_TP_IPID_RANGES, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_ANON_ARRAYOFSTRUCT(ctx, ci_netif_ipid_cb_t,              \
                                  ci_uint16, range, base, CI_TP_IPID_RANGES) \
    FTL_TFIELD_ANON_ARRAYOFSTRUCT(ctx, ci_netif_ipid_cb_t,              \
                                  ci_uint16, range, next, CI_TP_IPID_RANGES) \
    FTL_TFIELD_ANON_ARRAYOFSTRUCT_END(ctx, ci_netif_ipid_cb_t,          \
                                      range, CI_TP_IPID_RANGES)         \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_IP_TIMER_STATE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_timer_state, )                               \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_iptime_t, sched_ticks, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_iptime_t, ci_ip_time_real_ticks, ORM_OUTPUT_STACK)\
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint64, frc, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint32, ci_ip_time_frc2tick, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint32, ci_ip_time_frc2us, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_ip_timer_state, ci_uint32, khz, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer_state, ci_ni_dllist_t, fire_list, ORM_OUTPUT_EXTRA)      \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ip_timer_state,                          \
                             ci_ni_dllist_t, warray, CI_IPTIME_WHEELSIZE, ORM_OUTPUT_EXTRA)     \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_IP_TIMER(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_timer, )                                     \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, ci_ni_dllist_link, link, ORM_OUTPUT_EXTRA)	      \
    FTL_TFIELD_INT(ctx, ci_ip_timer, ci_iptime_t, time, ORM_OUTPUT_STACK)                       \
    FTL_TFIELD_INT(ctx, ci_ip_timer, oo_sp, param1, ORM_OUTPUT_EXTRA)                     \
    FTL_TFIELD_INT(ctx, ci_ip_timer, ci_iptime_callback_fn_t, fn, ORM_OUTPUT_EXTRA)             \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_EF_VI_TXQ_STATE(ctx)                             \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_txq_state, )                     \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, previous, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, added, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, removed, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ef_vi_txq_state, ci_uint32, ts_nsec, ORM_OUTPUT_STACK)      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_RXQ_STATE(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_rxq_state, )                             \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, prev_added, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, added, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, removed, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, in_jumbo, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint32, bytes_acc, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint16, rx_ps_pkt_count, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ef_vi_rxq_state, ci_uint16, rx_ps_credit_avail, ORM_OUTPUT_STACK)   \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_STATE(ctx)                                 \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_state, )                         \
  FTL_TFIELD_STRUCT(ctx, ef_vi_state, ef_eventq_state, evq, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_STRUCT(ctx, ef_vi_state, ef_vi_txq_state, txq, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_STRUCT(ctx, ef_vi_state, ef_vi_rxq_state, rxq, ORM_OUTPUT_STACK)     \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_STATS(ctx) \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_stats, )                              \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, k_polls, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, u_polls, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_evs, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_evs, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, periodic_polls, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, periodic_evs, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, periodic_lock_contends, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupts, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_polls, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_evs, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_wakes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_primes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_no_events, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_lock_contends, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, interrupt_budget_limited, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, deferred_polls, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupts, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_polls, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_evs, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_wakes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_no_events, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timeout_interrupt_lock_contends, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, select_primes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_sleeps, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_sleep_primes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_rx, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_tx, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_rx_os, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_tx_os, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_wakes_signal, ORM_OUTPUT_STACK) \
  ON_CI_CFG_PKTS_AS_HUGE_PAGES(                                         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_huge_pages, ORM_OUTPUT_STACK) \
  ) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_nonb, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_nonb_steal, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_wakes, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_scramble0, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_scramble1, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_scramble2, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkt_wait_spin, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_pkt_waiter, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_socket_list, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_need_prime, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_wake, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_swf_update, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_close, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unlock_slow_syscall, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, lock_wakes, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, stack_lock_buzz, ORM_OUTPUT_STACK)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, deferred_work, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_lock_sleeps, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sock_lock_buzz, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_send_nonb_pool_empty, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_send_ni_lock_contends, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_send_ni_lock_contends, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats,                                       \
		   ci_uint32, getsockopt_ni_lock_contends, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_netif_stats,                                       \
		   ci_uint32, setsockopt_ni_lock_contends, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_send_mcast_loop, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_send_mcast_loop_drop, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, active_opens, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_socket, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_bind, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_listen, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_connect, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_handover_setsockopt, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_socket, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_bind, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_connect, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_handover_setsockopt, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_bind_no_filter, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_connect_no_filter, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timewait_reap, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, timewait_reap_filter, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_max_hops, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_mean_hops, ORM_OUTPUT_STACK)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_n_entries, ORM_OUTPUT_STACK)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, table_n_slots, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rtos, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_acceptq, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_synrecv, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_has_recvq, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_has_sendq, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_has_unack, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_recv_unacceptable, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_unacceptable_ack, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_synrecv_bad_syn, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_synrecv_bad_ack, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_listen_got_ack, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_bad_options, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_bad_seq, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rst_sent_no_match, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, unacceptable_acks, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_drop_cant_fin, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_retransmits, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_send_fails, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_timeouts, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv_purge, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, syn_drop_busy, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, syn_drop_no_return_route, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, listen2synrecv, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, synrecv2established, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, ul_accepts, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, accept_eagain, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, accepts_deferred, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, acks_sent, ORM_OUTPUT_STACK)           \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, wnd_updates_sent, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_slow, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_out_of_order, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_rob_non_empty, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, retransmits, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_error_events, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_csum_bad, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_mcast_mismatch, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_crc_bad, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_trunc, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_rights, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_discard_other, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, rx_refill_recv, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, reap_rx_limited, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, reap_buf_limited, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pkts_reaped, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, refill_rx_limited, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, refill_buf_limited, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, defer_work_limited, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_dma_max, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_dma_doorbells, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tx_discard_alien_route, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, bufset_alloc_fails, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, bufset_alloc_nospace, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, mss_limitations, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_enter, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_exit_poll, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_exit_recv, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, memory_pressure_drops, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_rx_no_match_drops, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, udp_free_with_tx_active, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sw_filter_insert_table_full, ORM_OUTPUT_STACK) \
    ON_CI_HAVE_PIO(                                                           \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, pio_pkts, ORM_OUTPUT_STACK)                \
    )                                                                         \
    ON_CI_HAVE_PIO_DEBUG(                                                     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, no_pio_too_long, ORM_OUTPUT_STACK)         \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, no_pio_busy, ORM_OUTPUT_STACK)             \
    )                                                                         \
    ON_CI_HAVE_PIO(                                                           \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, no_pio_err, ORM_OUTPUT_STACK)              \
    ) \
    ON_CI_HAVE_SENDFILE(                                                      \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_sendpages, ORM_OUTPUT_STACK)           \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, poll_no_pkt, ORM_OUTPUT_STACK)         \
    ON_CI_CFG_SPIN_STATS(                                               \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_recv, ORM_OUTPUT_STACK)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_send, ORM_OUTPUT_STACK)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_udp_send, ORM_OUTPUT_STACK)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_udp_recv, ORM_OUTPUT_STACK)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_pipe_read, ORM_OUTPUT_STACK)    \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_pipe_write, ORM_OUTPUT_STACK)   \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_accept, ORM_OUTPUT_STACK)   \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_tcp_connect, ORM_OUTPUT_STACK)  \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_pkt_wait, ORM_OUTPUT_STACK)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_select, ORM_OUTPUT_STACK)       \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_poll, ORM_OUTPUT_STACK)         \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_epoll, ORM_OUTPUT_STACK)        \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint64, spin_epoll_kernel, ORM_OUTPUT_STACK) \
    ) \
    ON_CI_CFG_FD_CACHING(                                               \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_cached, ORM_OUTPUT_STACK)  \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_contention, ORM_OUTPUT_STACK) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, passive_sockcache_stacklim, ORM_OUTPUT_STACK) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, active_sockcache_stacklim, ORM_OUTPUT_STACK) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_socklim, ORM_OUTPUT_STACK) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_hit, ORM_OUTPUT_STACK)     \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_hit_reap, ORM_OUTPUT_STACK) \
      FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, sockcache_miss_intmismatch, ORM_OUTPUT_STACK) \
    ) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_rob_guilty, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_recv_coalesced, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_recv_guilty, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_rob_desperate, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_rcvbuf_abused_badly, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_stats, ci_uint32, tcp_listen_synack_retrans_no_buffer, ORM_OUTPUT_STACK) \
    FTL_TSTRUCT_END(ctx)

#if CI_CFG_SUPPORT_STATS_COLLECTION

#define STRUCT_IPV4_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ipv4_stats_count, )                             \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_recvs, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_hdr_errs, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_addr_errs, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, forw_dgrams, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count,                                  \
		   CI_IP_STATS_TYPE, in_unknown_protos, ORM_OUTPUT_STACK)                       \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_discards, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, in_delivers, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, out_requests, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, out_discards, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, out_no_routes, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_timeout, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_reqds, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_oks, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, reasm_fails, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, frag_oks, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, frag_fails, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ipv4_stats_count, CI_IP_STATS_TYPE, frag_creates, ORM_OUTPUT_STACK)  \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ICMP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_icmp_stats_count, )                             \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE, icmp_in_msgs, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE, icmp_in_errs, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_dest_unreachs, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_time_excds, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_parm_probs, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_src_quenchs, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_redirects, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_echos, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_echo_reps, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_timestamps, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_timestamp_reps, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_addr_masks, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_in_addr_mask_reps, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_msgs, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_errs, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_dest_unreachs, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_time_excds, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_parm_probs, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_src_quenchs, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_redirects, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_echos, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_echo_reps, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_timestamps, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_timestamp_reps, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_addr_masks, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_icmp_stats_count, CI_IP_STATS_TYPE,                \
                  icmp_out_addr_mask_reps, ORM_OUTPUT_STACK)				      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_stats_count, )                              \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_active_opens, ORM_OUTPUT_STACK)                                          \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_passive_opens, ORM_OUTPUT_STACK)                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
   		   tcp_attempt_fails, ORM_OUTPUT_STACK)                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_estab_resets, ORM_OUTPUT_STACK)                                          \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_curr_estab, ORM_OUTPUT_STACK)                                            \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_in_segs, ORM_OUTPUT_STACK)                                               \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_out_segs, ORM_OUTPUT_STACK)                                              \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_retran_segs, ORM_OUTPUT_STACK)                                           \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_in_errs, ORM_OUTPUT_STACK)                                               \
    FTL_TFIELD_INT(ctx, ci_tcp_stats_count, CI_IP_STATS_TYPE,                 \
		   tcp_out_rsts, ORM_OUTPUT_STACK)                                              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_stats_count, )                              \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_in_dgrams, ORM_OUTPUT_STACK)                                             \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_no_ports, ORM_OUTPUT_STACK)                                              \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_in_errs, ORM_OUTPUT_STACK)                                               \
    FTL_TFIELD_INT(ctx, ci_udp_stats_count, CI_IP_STATS_TYPE,                 \
		   udp_out_dgrams, ORM_OUTPUT_STACK)                                            \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_EXT_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_ext_stats_count, )                          \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   syncookies_sent, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   syncookies_recv, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   syncookies_failed, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   embrionic_rsts, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   prune_called, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   rcv_pruned, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   ofo_pruned, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   out_of_window_icmps, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   lock_dropped_icmps, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   arp_filter, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   time_waited, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   time_wait_recycled, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   time_wait_killed, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   paws_passive_rejected, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   paws_active_rejected, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   paws_estab_rejected, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   delayed_ack, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   delayed_ack_locked, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   delayed_ack_lost, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   listen_overflows, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   listen_drops, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_prequeued, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_direct_copy_from_backlog, ORM_OUTPUT_STACK)			      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_direct_copy_from_prequeue, ORM_OUTPUT_STACK)			      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_prequeue_dropped, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_hp_hits, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_hp_hits_to_user, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_pure_acks, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_hp_acks, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_recovery, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_recovery, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_reneging, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_fack_reorder, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_reorder, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_reorder, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_ts_reorder, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_full_undo, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_partial_undo, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_loss_undo, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_undo, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_loss, ORM_OUTPUT_STACK)			                              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_lost_retransmit, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_failures, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_failures, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_loss_failures, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_timeouts, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_reno_recovery_fail, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_sack_recovery_fail, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_fast_retrans, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_forward_retrans, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_slow_start_retrans, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_scheduler_failures, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_rcv_collapsed, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_old_sent, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_ofo_sent, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_recv, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_dsack_ofo_recv, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_syn, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_data, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_close, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_memory, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_timeout, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_linger, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_on_delegated_send, ORM_OUTPUT_STACK)                               \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_abort_failed, ORM_OUTPUT_STACK)			                      \
    FTL_TFIELD_INT(ctx, ci_tcp_ext_stats_count, CI_IP_STATS_TYPE,             \
		   tcp_memory_pressures, ORM_OUTPUT_STACK)			              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_stats, )                                     \
    FTL_TFIELD_INT(ctx, ci_ip_stats, __TIME_TYPE__, now, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_ipv4_stats_count,    ipv4, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_icmp_stats_count,    icmp, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_tcp_stats_count,     tcp, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_udp_stats_count,     udp, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, ci_tcp_ext_stats_count, tcp_ext, ORM_OUTPUT_STACK)      \
    FTL_TSTRUCT_END(ctx)

#endif  /* CI_CFG_SUPPORT_STATS_COLLECTION */

#define STRUCT_NETIF_DBG_MAX(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_dbg_max_t, )                              \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t, ci_uint16, poll_l5_max, 2, ORM_OUTPUT_STACK) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t, ci_uint16, poll_os_max, 2, ORM_OUTPUT_STACK) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t,                            \
			  ci_uint16, select_l5_max, 2, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_dbg_max_t,                            \
			  ci_uint16, select_os_max, 2, ORM_OUTPUT_STACK)                        \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_THRD_INFO(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_thrd_info_t, )                            \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, index, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, id, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_thrd_info_t,                          \
		          ci_int32, ep_id, NETIF_INFO_MAX_EPS_PER_THREAD, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, lock_status, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_lock_contentions, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_select, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_poll, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_fork, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_exec, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_accept, ORM_OUTPUT_STACK)	      \
    FTL_TFIELD_INT(ctx, ci_netif_thrd_info_t, ci_int32, no_fini, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_STRUCT(ctx, ci_netif_thrd_info_t, ci_netif_dbg_max_t, max, ORM_OUTPUT_STACK)     \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_STATS(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_stats, )                                  \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, rx_ev_lost, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, rx_ev_bad_desc_i, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, rx_ev_bad_q_label, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ef_vi_stats, ci_uint32, evq_gap, ORM_OUTPUT_STACK)                  \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_SOCKET_CACHE(ctx)                                        \
  FTL_TSTRUCT_BEGIN(ctx, ci_socket_cache_t, )                           \
  FTL_TFIELD_STRUCT(ctx, ci_socket_cache_t, ci_ni_dllist_t, cache, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_STRUCT(ctx, ci_socket_cache_t, ci_ni_dllist_t, pending, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_STRUCT(ctx, ci_socket_cache_t, ci_ni_dllist_t, fd_states, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_socket_cache_t, ci_int32, avail_stack, ORM_OUTPUT_STACK)         \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_STATE(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_state, )                              \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state, ci_netif_state_nic_t,   \
                           nic, CI_CFG_MAX_INTERFACES, ORM_OUTPUT_EXTRA)                  \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, nic_n, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, evq_last_prime, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, stack_id, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, char, pretty_name,         \
                        CI_CFG_STACK_NAME_LEN + 8, ORM_OUTPUT_STACK)                      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, netif_mmap_bytes, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, vi_state_bytes, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint16, max_mss, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, flags, ORM_OUTPUT_STACK)                 \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, error_flags, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, evq_primed, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_int8,                   \
                        hwport_to_intf_i, CPLANE_MAX_REGISTER_INTERFACES, ORM_OUTPUT_STACK) \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_int8,                   \
                        intf_i_to_hwport, CI_CFG_MAX_INTERFACES, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, n_spinners, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int8, is_spinner, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int8, poll_work_outstanding, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, last_spin_poll_frc, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, last_sleep_frc, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_eplock_t, lock, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, looppkts, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_looppkts, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_rx_pkts, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, atomic_n_rx_pkts, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, atomic_n_async_pkts, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rxq_low, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rxq_limit, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, mem_pressure, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, mem_pressure_pkt_pool, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, mem_pressure_pkt_pool_n, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, n_async_pkts, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, nonb_pkt_pool, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_ipid_cb_t, ipid, ORM_OUTPUT_EXTRA) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, vi_ofs, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, table_ofs, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, buf_ofs, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_timer_state, iptimer_state, ORM_OUTPUT_STACK) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_timer, timeout_tid, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state, ci_ni_dllist_t, timeout_q, \
                           OO_TIMEOUT_Q_MAX, ORM_OUTPUT_STACK)                            \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ni_dllist_t, reap_list, ORM_OUTPUT_EXTRA)     \
  ON_CI_CFG_SUPPORT_STATS_COLLECTION(                                   \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, stats_fmt, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_timer, stats_tid, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_stats, stats_snapshot, ORM_OUTPUT_STACK) \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ip_stats, stats_cumulative, ORM_OUTPUT_STACK) \
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, free_eps_head, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, deferred_free_eps_head, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, max_ep_bufs, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, n_ep_bufs, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state, ci_ni_dllist_t,         \
                           ready_lists, CI_CFG_N_READY_LISTS, ORM_OUTPUT_EXTRA)           \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_uint32,                 \
                        ready_list_flags, CI_CFG_N_READY_LISTS, ORM_OUTPUT_EXTRA)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, ready_lists_in_use, ORM_OUTPUT_EXTRA)    \
  ON_CI_CFG_PIO(                                                        \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pio_bufs_ofs, ORM_OUTPUT_STACK)        \
  ) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, ep_ofs, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, free_aux_mem, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, n_free_aux_bufs, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, n_aux_bufs, ORM_OUTPUT_STACK)            \
  ON_CI_CFG_FD_CACHING(                                                 \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, passive_cache_avail_stack, ORM_OUTPUT_STACK)  \
  )                                                                     \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_config, conf, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_config_opts, opts, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, sock_spin_cycles, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, buzz_cycles, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint64, timer_prime_cycles, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, io_mmap_bytes, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, buf_mmap_bytes, ORM_OUTPUT_STACK)        \
  ON_CI_CFG_PIO(                                                        \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, pio_mmap_bytes, ORM_OUTPUT_STACK)      \
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, poll_did_wake, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, in_poll, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_ni_dllist_t, post_poll_list, ORM_OUTPUT_EXTRA) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rx_defrag_head, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, rx_defrag_tail, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, send_may_poll, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, char, name,                \
                        CI_CFG_STACK_NAME_LEN + 1, ORM_OUTPUT_STACK)                      \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, pid, ORM_OUTPUT_STACK)                    \
  FTL_TFIELD_INT(ctx, ci_netif_state, uid_t, uid, ORM_OUTPUT_STACK)                       \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, defer_work_count, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_uint8, hash_salt, 16, ORM_OUTPUT_EXTRA) \
  ON_CI_CFG_STATS_NETIF(                                                \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_netif_stats, stats, ORM_OUTPUT_STACK)       \
  )                                                                     \
  ON_CI_CFG_TCPDUMP(                                                    \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_int32, dump_queue,    \
                          CI_CFG_DUMPQUEUE_LEN, ORM_OUTPUT_EXTRA)                      \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_netif_state, ci_uint8, dump_intf,     \
                          OO_INTF_I_NUM, ORM_OUTPUT_STACK)                                \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint8, dump_read_i, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint8, dump_write_i, ORM_OUTPUT_STACK)         \
  ) \
  FTL_TFIELD_STRUCT(ctx, ci_netif_state, ef_vi_stats, vi_stats, ORM_OUTPUT_STACK) \
  ON_CI_CFG_SEPARATE_UDP_RXQ(                                           \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ef_vi_stats, udp_rxq_vi_stats, ORM_OUTPUT_STACK)\
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, creation_numa_node, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_int32, load_numa_node, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, packet_alloc_numa_nodes, ORM_OUTPUT_STACK)\
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, sock_alloc_numa_nodes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, interrupt_numa_nodes, ORM_OUTPUT_STACK)  \
  ON_CI_CFG_FD_CACHING(                                                 \
    FTL_TFIELD_STRUCT(ctx, ci_netif_state, ci_socket_cache_t, active_cache, ORM_OUTPUT_EXTRA)   \
    FTL_TFIELD_INT(ctx, ci_netif_state, ci_uint32, active_cache_avail_stack, ORM_OUTPUT_STACK)  \
  )                                                                     \
  FTL_TSTRUCT_END(ctx)



#define STRUCT_USER_PTR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_user_ptr_t, )                                   \
    FTL_TFIELD_INT(ctx, ci_user_ptr_t, ci_uint64, ptr, ORM_OUTPUT_STACK)                        \
    FTL_TSTRUCT_END(ctx)


#define UNION_SLEEP_SEQ(ctx)                                            \
  FTL_TUNION_BEGIN(ctx, ci_sleep_seq_t,)                                \
  FTL_TFIELD_INT(ctx, ci_sleep_seq_t, ci_uint64, all, ORM_OUTPUT_STACK)                   \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, ci_sleep_seq_t, rw, ORM_OUTPUT_STACK)                 \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sleep_seq_t, ci_uint32, rw, rx)        \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sleep_seq_t, ci_uint32, rw, tx)        \
  FTL_TFIELD_ANON_STRUCT_END(ctx, ci_sleep_seq_t, rw)                   \
  FTL_TUNION_END(ctx)



#define STRUCT_WAITABLE(ctx)					     	      \
    FTL_TSTRUCT_BEGIN(ctx, citp_waitable, )                                   \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, bufid, ORM_OUTPUT_STACK)                       \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, state, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_sleep_seq_t, sleep_seq, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint64, spin_cycles, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, wake_request, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, sb_flags, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, sb_aflags, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_ni_dllist_link, post_poll_link, ORM_OUTPUT_EXTRA)  \
    FTL_TFIELD_INT(ctx, citp_waitable, oo_waitable_lock, lock, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, wt_next, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, next_id, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_ni_dllist_link, ready_link, ORM_OUTPUT_EXTRA)  \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, ready_list_id, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, ci_user_ptr_t, eitem, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, eitem_pid, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, sigown, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_uint32, moved_to_stack_id, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, citp_waitable, ci_int32, moved_to_sock_id, ORM_OUTPUT_STACK)      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ETHER_HDR(ctx)						      \
    FTL_TSTRUCT_BEGIN(ctx, ci_ether_hdr, )                                    \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_ether_hdr, ci_uint8, ether_dhost, ETH_ALEN, ORM_OUTPUT_STACK) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_ether_hdr, ci_uint8, ether_shost, ETH_ALEN, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ether_hdr, ci_uint16, ether_type, ORM_OUTPUT_STACK)                  \
    FTL_TSTRUCT_END(ctx)

#define IP4_FRAG_OFFSET(ip_frag_off_be16)               \
  (unsigned) (CI_BSWAP_BE16(ip_frag_off_be16 & CI_IP4_OFFSET_MASK)) << 3

#define STRUCT_IP4_HDR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip4_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_ihl_version, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_tos, ORM_OUTPUT_STACK)                         \
    FTL_TFIELD_INT2(ctx, ci_ip4_hdr, ci_uint16, ip_tot_len_be16, "%d", (int) CI_BSWAP_BE16, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT2(ctx, ci_ip4_hdr, ci_uint16, ip_id_be16, "%u", (unsigned) CI_BSWAP_BE16, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT2(ctx, ci_ip4_hdr, ci_uint16, ip_frag_off_be16, "%u", IP4_FRAG_OFFSET, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_ttl, ORM_OUTPUT_STACK)                         \
    FTL_TFIELD_INT(ctx, ci_ip4_hdr, ci_uint8, ip_protocol, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT2(ctx, ci_ip4_hdr, ci_uint16, ip_check_be16, "%u", (unsigned) CI_BSWAP_BE16, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT2(ctx, ci_ip4_hdr, ci_uint32, ip_saddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT2(ctx, ci_ip4_hdr, ci_uint32, ip_daddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
    FTL_TSTRUCT_END(ctx)

/* TODO: needs converting to INT2 for _be16 fields. But currently unused */
#define STRUCT_UDP_HDR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_source_be16, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_dest_be16, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_len_be16, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_INT(ctx, ci_udp_hdr, ci_uint16, udp_check_be16, ORM_OUTPUT_STACK)                \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP4_PSEUDO_HDR(ctx)                                      \
  FTL_TSTRUCT_BEGIN(ctx, ci_ip4_pseudo_hdr, )                           \
  FTL_TFIELD_INT2(ctx, ci_ip4_pseudo_hdr, ci_uint32, ip_saddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT2(ctx, ci_ip4_pseudo_hdr, ci_uint32, ip_daddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint8, zero, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_ip4_pseudo_hdr, ci_uint8, ip_protocol, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT2(ctx, ci_ip4_pseudo_hdr, ci_uint16, length_be16, "%u", CI_BSWAP_BE16, ORM_OUTPUT_STACK) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CICP_VERINFO(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, cicp_mac_verinfo_t, )                              \
    FTL_TFIELD_INT(ctx, cicp_mac_verinfo_t, ci_verlock_value_t, row_version, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, cicp_mac_verinfo_t, ci_int32, row_index, ORM_OUTPUT_STACK)        \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_PMTU_STATE(ctx)                                                \
    FTL_TSTRUCT_BEGIN(ctx, ci_pmtu_state_t, )                                 \
    FTL_TFIELD_STRUCT(ctx, ci_pmtu_state_t, ci_ip_timer, tid, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_pmtu_state_t, ci_uint16, pmtu, ORM_OUTPUT_STACK)                     \
    FTL_TFIELD_INT(ctx, ci_pmtu_state_t, ci_uint8, plateau_id, ORM_OUTPUT_STACK)                \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ATOMIC(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_atomic_t, )                                     \
    FTL_TFIELD_INT(ctx, ci_atomic_t, int, n, ORM_OUTPUT_STACK)                                  \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_IP_HDRS(ctx)                                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_cached_hdrs, )                               \
    FTL_TFIELD_STRUCT(ctx, ci_ip_cached_hdrs, cicp_mac_verinfo_t,             \
		      mac_integrity, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT2(ctx, ci_ip_cached_hdrs, ci_ip_addr_t, ip_saddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT2(ctx, ci_ip_cached_hdrs, ci_uint16, dport_be16, OOF_PORT, OOFA_PORT, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_int8, status, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint8, flags, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_ip_addr_t, nexthop, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_mtu_t, mtu, ORM_OUTPUT_STACK)                     \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_ifid_t, ifindex, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, cicp_encap_t, encap, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_int32, intf_i, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_hwport_id_t, hwport, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint8, ether_offset, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_ip_cached_hdrs, ci_uint8, ether_header,     \
			  2 * ETH_ALEN + 4, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_ip_cached_hdrs, ci_uint16, ether_type, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_STRUCT(ctx, ci_ip_cached_hdrs, ci_ip4_hdr, ip, ORM_OUTPUT_STACK)                 \
    FTL_TSTRUCT_END(ctx)


/* TODO: needs converting to INT2 for _be16 fields. But currently unused */
#define STRUCT_TCP_HDR(ctx)                                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_source_be16, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_dest_be16, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT2(ctx, ci_tcp_hdr, ci_uint32, tcp_seq_be32, "%u", (unsigned) CI_BSWAP_BE32, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT2(ctx, ci_tcp_hdr, ci_uint32, tcp_ack_be32, "%u", (unsigned) CI_BSWAP_BE32, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint8, tcp_hdr_len_sl4, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint8, tcp_flags, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_window_be16, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_check_be16, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_tcp_hdr, ci_uint16, tcp_urg_ptr_be16, ORM_OUTPUT_STACK)              \
    FTL_TSTRUCT_END(ctx)

typedef struct oo_timeval oo_timeval;

#define STRUCT_TIMEVAL(ctx)                             \
    FTL_TSTRUCT_BEGIN(ctx, oo_timeval, )                \
    FTL_TFIELD_INT(ctx, oo_timeval, ci_int32, tv_sec, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, oo_timeval, ci_int32, tv_usec, ORM_OUTPUT_STACK)  \
    FTL_TSTRUCT_END(ctx)

typedef struct oo_sock_cplane oo_sock_cplane_t;

#define STRUCT_SOCK_CPLANE(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, oo_sock_cplane_t, )                            \
  FTL_TFIELD_INT2(ctx, oo_sock_cplane_t, ci_uint32, ip_laddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT2(ctx, oo_sock_cplane_t, ci_uint16, lport_be16, OOF_PORT, OOFA_PORT, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_ifid_t, so_bindtodevice, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_ifid_t, ip_multicast_if, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT2(ctx, oo_sock_cplane_t, ci_uint32, ip_multicast_if_laddr_be32, "\"" OOF_IP4 "\"", OOFA_IP4, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint8, ip_ttl, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint8, ip_mcast_ttl, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, oo_sock_cplane_t, ci_uint8, sock_cp_flags, ORM_OUTPUT_STACK)        \
  FTL_TSTRUCT_END(ctx)


#define STRUCT_SOCK(ctx)                                                \
  FTL_TSTRUCT_BEGIN(ctx, ci_sock_cmn, )                                 \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, citp_waitable, b, ORM_OUTPUT_STACK)                 \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, s_flags, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, s_aflags, ORM_OUTPUT_STACK)                 \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, oo_sock_cplane_t, cp, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, ci_ip_cached_hdrs, pkt, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_ANON_UNION_BEGIN(ctx, ci_sock_cmn, space_for_hdrs, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_ANON_UNION(ctx, ci_sock_cmn, ci_tcp_hdr, space_for_hdrs, space_for_tcp_hdr) \
  FTL_TFIELD_ANON_UNION(ctx, ci_sock_cmn, ci_udp_hdr, space_for_hdrs, space_for_udp_hdr) \
  FTL_TFIELD_ANON_UNION_END(ctx, ci_sock_cmn, space_for_hdrs)           \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, tx_errno, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, rx_errno, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, os_sock_status, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, ci_sock_cmn, so, ORM_OUTPUT_STACK)                    \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_int32, so, sndbuf)        \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_int32, so, rcvbuf)        \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_uint32, so, rcvtimeo_msec) \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_uint32, so, sndtimeo_msec) \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_uint32, so, linger)       \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_int32, so, rcvlowat)      \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_sock_cmn, ci_int32, so, so_debug)      \
  FTL_TFIELD_ANON_STRUCT_END(ctx, ci_sock_cmn, so)                      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_pkt_priority_t, so_priority, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, so_error, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int16, rx_bind2dev_ifindex, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int16, rx_bind2dev_base_ifindex, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int16, rx_bind2dev_vlan, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint8, cmsg_flags, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, timestamping_flags, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint64, ino, ORM_OUTPUT_STACK)                      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint32, uid, ORM_OUTPUT_STACK)                      \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_int32, pid, ORM_OUTPUT_STACK)                       \
  FTL_TFIELD_INT(ctx, ci_sock_cmn, ci_uint8, domain, ORM_OUTPUT_STACK)                    \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, ci_ni_dllist_link, reap_link, ORM_OUTPUT_EXTRA)     \
  FTL_TSTRUCT_END(ctx)
    
#define STRUCT_IP_PKT_QUEUE(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_pkt_queue, )                                 \
    FTL_TFIELD_INT(ctx, ci_ip_pkt_queue, ci_int32, head, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_INT(ctx, ci_ip_pkt_queue, ci_int32, tail, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_INT(ctx, ci_ip_pkt_queue, ci_int32, num, ORM_OUTPUT_STACK)                       \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_PKTQ(ctx)                             \
    FTL_TSTRUCT_BEGIN(ctx, oo_pktq, )                   \
    FTL_TFIELD_INT(ctx, oo_pktq, ci_int32, head, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, oo_pktq, ci_int32, tail, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, oo_pktq, ci_int32, num, ORM_OUTPUT_STACK)         \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_SOCKET_STATS(ctx)                                    \
  FTL_TSTRUCT_BEGIN(ctx, ci_udp_socket_stats, )                         \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_os, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_os_slow, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_os_error, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_eagain, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_overflow, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_mem_drop, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_rx_pktinfo, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, max_recvq_pkts, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_os, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_os_slow, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_onload_c, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_onload_uc, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_match, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_uc_lookup, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_c_lookup, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_a_lookup, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_cp_no_mac, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_poll, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_pkt, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_snd, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_cp, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_lock_defer, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_eagain, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_spin, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_block, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_poll_avoids_full, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_fragments, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_msg_confirm, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_os_late, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_udp_socket_stats, ci_uint32, n_tx_unconnect_late, ORM_OUTPUT_STACK) \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_tcp_socket_stats oo_tcp_socket_stats;

#define STRUCT_TCP_SOCKET_STATS(ctx)                                    \
  FTL_TSTRUCT_BEGIN(ctx, oo_tcp_socket_stats, )                         \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_rwnd, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_cwnd, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_more, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_nagle, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_app, ORM_OUTPUT_STACK)      \
  ON_CI_CFG_BURST_CONTROL(                                              \
     FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_stop_burst, ORM_OUTPUT_STACK) \
                                                                        ) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_nomac_defer, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_defer, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_msg_warm_abort, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_msg_warm, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_tmpl_send_fast, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, tx_tmpl_send_slow, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint32, rx_isn, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, tx_tmpl_active, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, rtos, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, fast_recovers, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, rx_seq_errs, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, rx_ack_seq_errs, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, rx_ooo_pkts, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, rx_ooo_fill, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, oo_tcp_socket_stats, ci_uint16, total_retrans, ORM_OUTPUT_STACK)    \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_RECV_Q(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_recv_q, )                                   \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, head, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, tail, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_added, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_reaped, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_int32, extract, ORM_OUTPUT_STACK)                     \
    FTL_TFIELD_INT(ctx, ci_udp_recv_q, ci_uint32, pkts_delivered, ORM_OUTPUT_STACK)             \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP(ctx)                                                 \
  FTL_TSTRUCT_BEGIN(ctx, ci_udp_state, )                                \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_sock_cmn, s, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_ip_cached_hdrs, ephemeral_pkt, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, udpflags, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_udp_recv_q, recv_q, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_udp_recv_q, timestamp_q, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_int32, zc_kernel_datagram, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, zc_kernel_datagram_count, ORM_OUTPUT_STACK) \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, oo_timespec, stamp_cache, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint64, stamp, ORM_OUTPUT_STACK)                   \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint64, stamp_pre_sots, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_int32, tx_async_q, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, ci_udp_state, oo_atomic_t, tx_async_q_level, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_udp_state, ci_uint32, tx_count, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_STRUCT(ctx, ci_udp_state, ci_udp_socket_stats, stats, ORM_OUTPUT_STACK)      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS_COUNT(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats_count, )                          \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rtto, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, cong, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_byte, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_pkt, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_slowpath, ORM_OUTPUT_STACK)\
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_seqerr, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_ackerr, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_pawserr, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_dupack, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   rx_dupack_frec, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   rx_dupack_congfrec, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_zwin, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_ooo, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_badsyn, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   rx_badsynseq, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_syndup, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
                  rx_synbadack, ORM_OUTPUT_STACK)					              \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
                   rx_synnonack, ORM_OUTPUT_STACK)                             		      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_sleep, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, rx_wait, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_byte, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_pkt, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_slowpath, ORM_OUTPUT_STACK)\
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE,             \
		   tx_retrans_pkt, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_sleep, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_count, CI_IP_STATS_TYPE, tx_stuck, ORM_OUTPUT_STACK)   \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS_RANGE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats_range, )                          \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rx_win, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rx_wscl, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, tx_win, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, tx_wscl, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rtt, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, srtt, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, rto, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE, tx_buffree, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE,             \
                   tx_sleeptime, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats_range, CI_IP_STATS_TYPE,             \
		   rx_sleeptime, ORM_OUTPUT_STACK)		                              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats, )                                \
    FTL_TFIELD_INT(ctx, ci_ip_sock_stats, __TIME_TYPE__, now, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_count, count, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_range, actual, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_range, min, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, ci_ip_sock_stats_range, max, ORM_OUTPUT_STACK)     \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_COMMON(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_cmn, )                               \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_uint32, ka_probe_th, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_time, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_time_in_secs, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_intvl, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_iptime_t, t_ka_intvl_in_secs, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_uint16, user_mss, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_cmn, ci_uint8, tcp_defer_accept, ORM_OUTPUT_STACK)	      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_state, )                                    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_sock_cmn, s, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_tcp_socket_cmn, c, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, local_peer, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, tmpl_head, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tcpflags, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_pmtu_state_t, pmtus, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, so_sndbuf_pkts, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_window_max, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, send_in, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, send_out, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, send, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, retrans, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, recv1, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, recv2, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, recv1_extract, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, recv_off, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, outgoing_hdrs_len, ORM_OUTPUT_STACK)           \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_pkt_queue, rob, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_tcp_state, ci_int32, last_sack,             \
                          CI_TCP_SACK_MAX_BLOCKS + 1, ORM_OUTPUT_STACK)                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, dsack_start, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, dsack_end, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, dsack_block, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_udp_recv_q, timestamp_q, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_check, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_nxt, ORM_OUTPUT_STACK)                     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_max, ORM_OUTPUT_STACK)                     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_una, ORM_OUTPUT_STACK)                     \
    ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE(                                  \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_wl1, ORM_OUTPUT_STACK)                   \
    ) \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_delegated, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, fast_path_check, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, snd_up, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, amss, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, smss, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, eff_mss, ORM_OUTPUT_STACK)                     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, retransmits, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_wnd_advertised, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_wnd_right_edge_sent, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_added, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_delivered, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, ack_trigger, ORM_OUTPUT_STACK)                 \
    ON_CI_CFG_BURST_CONTROL(                                            \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, burst_window, ORM_OUTPUT_STACK)              \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, rcv_up, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint8, rcv_wscl, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint8, snd_wscl, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, congstate, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, congrecover, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, retrans_ptr, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, retrans_seq, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, cwnd, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, cwnd_extra, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, ssthresh, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, bytes_acked, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, dup_acks, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, dup_thresh, ORM_OUTPUT_STACK)                  \
    ON_CI_CFG_TCP_FASTSTART(                                                  \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, faststart_acks, ORM_OUTPUT_STACK)            \
    )                                                                         \
    ON_CI_CFG_TAIL_DROP_PROBE(                                                \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, taildrop_state, ORM_OUTPUT_STACK)            \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, taildrop_mark, ORM_OUTPUT_STACK)             \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_prev_recv_payload, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_recv_payload, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_recv_ack, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_sent, ORM_OUTPUT_STACK)               \
    ON_CI_CFG_CONGESTION_WINDOW_VALIDATION(                                   \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, t_last_full, ORM_OUTPUT_STACK)             \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, cwnd_used, ORM_OUTPUT_STACK)                 \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, sa, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, sv, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, rto, ORM_OUTPUT_STACK)                       \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, timed_seq, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, timed_ts, ORM_OUTPUT_STACK)                  \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tsrecent, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tslastack, ORM_OUTPUT_STACK)                   \
    ON_DEBUG(                                                                 \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, tslastseq, ORM_OUTPUT_STACK)                 \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_iptime_t, tspaws, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, acks_pending, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, urg_data, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint32, ka_probes, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, zwin_probes, ORM_OUTPUT_STACK)                 \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_uint16, zwin_acks, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, incoming_tcp_hdr_len, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, rto_tid, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, delack_tid, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, zwin_tid, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, kalive_tid, ORM_OUTPUT_STACK)             \
    ON_CI_CFG_TCP_SOCK_STATS(                                                 \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, stats_tid, ORM_OUTPUT_STACK)            \
    )                                                                         \
    ON_CI_CFG_TAIL_DROP_PROBE(                                                \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, taildrop_tid, ORM_OUTPUT_STACK)         \
    )                                                                         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_timer, cork_tid, ORM_OUTPUT_STACK)               \
    ON_CI_CFG_TCP_SOCK_STATS(                                                 \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_sock_stats, stats_snapshot, ORM_OUTPUT_STACK)  \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ip_sock_stats, stats_cumulative, ORM_OUTPUT_STACK)\
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, stats_fmt, ORM_OUTPUT_STACK)                  \
    )                                                                         \
    ON_CI_CFG_FD_CACHING(                                                     \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, cached_on_fd, ORM_OUTPUT_STACK)               \
      FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, cached_on_pid, ORM_OUTPUT_STACK)              \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, epcache_link, ORM_OUTPUT_EXTRA)   \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, epcache_fd_link, ORM_OUTPUT_EXTRA)\
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_tcp_state, ci_int32, send_prequeue, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_tcp_state, oo_atomic_t, send_prequeue_in, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, timeout_q_link, ORM_OUTPUT_EXTRA)   \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, ci_ni_dllist_link, tx_ready_link, ORM_OUTPUT_EXTRA)    \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, oo_tcp_socket_stats, stats, ORM_OUTPUT_STACK)          \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_SOCKET_LISTEN_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_listen_stats, )                      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_listenq_overflow, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_listenq_no_synrecv, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_acks_reset, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_acceptq_overflow, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_acceptq_no_sock, ORM_OUTPUT_STACK)					      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_accept_loop2_closed, ORM_OUTPUT_STACK)				      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_accept_os, ORM_OUTPUT_STACK)					              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_accept_no_fd, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_syn, ORM_OUTPUT_STACK)				              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_recv, ORM_OUTPUT_STACK)                                      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_ts_rej, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_hash_rej, ORM_OUTPUT_STACK)			              \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,                \
		   n_syncookie_ack_answ, ORM_OUTPUT_STACK)			              \
    ON_CI_CFG_FD_CACHING(						      \
      FTL_TFIELD_INT(ctx, ci_tcp_socket_listen_stats, ci_uint32,              \
  		   n_sockcache_hit, ORM_OUTPUT_STACK)				              \
    ) \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_LISTEN(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_listen, )                            \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_sock_cmn, s, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_tcp_socket_cmn, c, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, acceptq_max, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, acceptq_put, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, acceptq_n_in, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, acceptq_get, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, acceptq_n_out, ORM_OUTPUT_STACK)       \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, n_listenq, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, n_listenq_new, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_tcp_socket_listen, ci_ni_dllist_t,       \
			     listenq, CI_CFG_TCP_SYNACK_RETRANS_MAX + 1, ORM_OUTPUT_EXTRA)      \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_int32, bucket, ORM_OUTPUT_STACK)               \
    FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, n_buckets, ORM_OUTPUT_STACK)           \
    ON_CI_CFG_FD_CACHING(                                                     \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_socket_cache_t, epcache, ORM_OUTPUT_STACK)\
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_ni_dllist_t,            \
		        epcache_connected, ORM_OUTPUT_EXTRA)				      \
      FTL_TFIELD_INT(ctx, ci_tcp_socket_listen, ci_uint32, cache_avail_sock, ORM_OUTPUT_STACK)  \
    )                                                                         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_ip_timer, listenq_tid, ORM_OUTPUT_STACK)    \
    ON_CI_CFG_STATS_TCP_LISTEN(  				              \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen, ci_tcp_socket_listen_stats,\
			stats, ORM_OUTPUT_STACK)           			              \
    )                                                                         \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_WAITABLE_OBJ(ctx)				              \
    FTL_TSTRUCT_BEGIN(ctx, citp_waitable_obj, )                               \
    FTL_TFIELD_STRUCT(ctx, citp_waitable_obj, citp_waitable, waitable, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_STRUCT(ctx, citp_waitable_obj, ci_sock_cmn, sock, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_STRUCT(ctx, citp_waitable_obj, ci_tcp_state, tcp, ORM_OUTPUT_STACK)              \
    FTL_TSTRUCT_END(ctx)
    

#define STRUCT_FILTER_TABLE_ENTRY(ctx)                                        \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table_entry, )                     \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table_entry, ci_int32, id, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table_entry, ci_int32, route_count, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table_entry, ci_uint32, laddr, ORM_OUTPUT_STACK)        \
    FTL_TSTRUCT_END(ctx)
    

#define STRUCT_FILTER_TABLE(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table, )                           \
    FTL_TFIELD_INT(ctx, ci_netif_filter_table, unsigned, table_size_mask, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_filter_table,                      \
			     ci_netif_filter_table_entry, table, 1, ORM_OUTPUT_STACK)	      \
    FTL_TSTRUCT_END(ctx)
    
#define STRUCT_OO_PIPE_BUF_LIST_T(ctx)                            \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe_buf_list_t, )                    \
  FTL_TFIELD_INT(ctx, oo_pipe_buf_list_t, ci_int32, pp, ORM_OUTPUT_STACK)           \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_pipe oo_pipe;

#define STRUCT_OO_PIPE(ctx)                                             \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe, )                                     \
  FTL_TFIELD_STRUCT(ctx, oo_pipe, citp_waitable, b, ORM_OUTPUT_STACK)                     \
  FTL_TFIELD_STRUCT(ctx, oo_pipe, oo_pipe_buf_list_t, pipe_bufs, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, oo_pipe, read_ptr, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pipe, oo_pkt_p, read_ptr, pp)          \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pipe, ci_uint32, read_ptr, offset)     \
  FTL_TFIELD_ANON_STRUCT_END(ctx, oo_pipe, read_ptr)                    \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, oo_pipe, write_ptr, ORM_OUTPUT_STACK)                 \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pipe, oo_pkt_p, write_ptr, pp)         \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pipe, oo_pkt_p, write_ptr, pp_wait)    \
  FTL_TFIELD_ANON_STRUCT_END(ctx, oo_pipe, write_ptr)                   \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, aflags, ORM_OUTPUT_STACK)                       \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bufs_num, ORM_OUTPUT_STACK)                     \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bufs_max, ORM_OUTPUT_STACK)                     \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bytes_added, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, oo_pipe, ci_uint32, bytes_removed, ORM_OUTPUT_STACK)                \
  FTL_TSTRUCT_END(ctx)


#endif /* __FTL_DEFS_H__ */
