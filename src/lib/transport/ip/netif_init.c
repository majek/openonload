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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2004/04/06
** Description: Initialisation of network interface.
** </L5_PRIVATE>
\**************************************************************************/

#include "ip_internal.h"
#include "uk_intf_ver.h"
#include <ci/internal/cplane_ops.h>
#include <ci/internal/efabcfg.h>
#include <onload/version.h>

#ifndef __KERNEL__
#include <ci/internal/efabcfg.h>
/*STG TO FIX*/
#include <etherfabric/vi.h>  /* For VI_MAPPINGS_SIZE */
#if CI_CFG_PKTS_AS_HUGE_PAGES
#include <sys/shm.h>
#endif
#endif

#ifdef NDEBUG
# define IS_DEBUG  0
#else
# define IS_DEBUG  1
#endif


#ifdef __KERNEL__
const char* oo_uk_intf_ver = OO_UK_INTF_VER;
#endif


/*****************************************************************************
 *                                                                           *
 *          Logging                                                          *
 *          =======                                                          *
 *                                                                           *
 *****************************************************************************/




ci_inline ci_uint64 usec_to_cycles64(ci_uint32 usec, int cpu_khz)
{
  if( usec == (ci_uint32) -1 )
    return (ci_uint64) -1;
#ifdef __KERNEL__
  /* We can't guarantee that the kernel will have support for 64-bit
   * division (__udivdi3).  So instead, we can approximate 1/1000 by
   * 1048/(2^20) (= 0.0009995).  1048 is an 11-bit number.  Assume cpu
   * speed <= 10GHz, so cpu_khz is 24 bits.  So we won't overflow a
   * ci_uint64 unless usec > 2^29.  That allows usec values of up to 536
   * seconds, which is good enough.
   */
  return (ci_uint64) (((ci_uint64) usec * cpu_khz * 1048) >> 20);
#else
  return (ci_uint64) usec * cpu_khz / 1000;
#endif
}


#ifdef __KERNEL__

#define assert_zero(x)  ci_assert_equal((x), 0)

void ci_netif_state_init(ci_netif* ni, int cpu_khz, const char* name)
{
  ci_netif_state_nic_t* nn;
  ci_netif_state* nis = ni->state;
  int nic_i;

  nis->opts = ni->opts;

  /* TX DMA overflow queue. */
  OO_STACK_FOR_EACH_INTF_I(ni, nic_i) {
    nn = &nis->nic[nic_i];
    oo_pktq_init(&nn->dmaq);
    assert_zero(nn->tx_bytes_added);
    assert_zero(nn->tx_bytes_removed);
    assert_zero(nn->tx_dmaq_insert_seq);
    assert_zero(nn->tx_dmaq_insert_seq_last_poll);
    assert_zero(nn->tx_dmaq_done_seq);
    ci_ni_dllist_init(ni, &nn->tx_ready_list, 
                      oo_ptr_to_statep(ni, &nn->tx_ready_list), "txrd");
    nn->rx_frags = OO_PP_NULL;
  }

  /* List of free packet buffers. */
  nis->freepkts = OO_PP_NULL;
  assert_zero(nis->n_freepkts);
  assert_zero(nis->n_rx_pkts);
  assert_zero(nis->rxq_low);
  assert_zero(nis->mem_pressure);
  nis->mem_pressure_pkt_pool = OO_PP_NULL;
  assert_zero(nis->mem_pressure_pkt_pool_n);
  nis->looppkts = OO_PP_NULL;

  /* Pool of packet buffers for transmit. */
  assert_zero(nis->n_async_pkts);
#if ! CI_CFG_PP_IS_PTR
  nis->nonb_pkt_pool = CI_ILL_END;
#endif

  /* Endpoint lookup table.
   * - table must be a power of two in size
   * - table must be large enough for one filter per connection +
   *   the extra filters required for wildcards i.e. "listen any" connections
   *   (so we use double the number of endpoints)
   */
  ci_netif_filter_init(ni->filter_table,
                       ci_log2_le(NI_OPTS(ni).max_ep_bufs) + 1);

  ci_ni_dllist_init(ni, &nis->timeout_q, 
                    oo_ptr_to_statep(ni, &nis->timeout_q),
                    "timq");
  ci_ip_timer_init(ni, &nis->timeout_tid,
                   oo_ptr_to_statep(ni, &nis->timeout_tid),
                   "ttid");

  nis->timeout_tid.param1 = OO_SP_NULL;
  nis->timeout_tid.fn = CI_IP_TIMER_NETIF_TIMEOUT;

#if CI_CFG_SUPPORT_STATS_COLLECTION
  ci_ip_timer_init(ni, &nis->stats_tid,
                   oo_ptr_to_statep(ni, &nis->stats_tid),
                   "stat");
  nis->stats_tid.param1 = OO_SP_NULL;
  nis->stats_tid.fn = CI_IP_TIMER_NETIF_STATS;

  ci_ip_stats_clear(&nis->stats_snapshot);
  ci_ip_stats_clear(&nis->stats_cumulative);
#endif

  ci_ni_dllist_init(ni, &nis->reap_list, 
                    oo_ptr_to_statep(ni, &nis->reap_list),
                    "reap");

  nis->free_eps_head = OO_SP_NULL;
#if CI_CFG_USERSPACE_PIPE
  nis->free_pipe_bufs = OO_SP_NULL;
#endif
  nis->deferred_free_eps_head = CI_ILL_END;
  assert_zero(nis->n_ep_bufs);
  nis->max_ep_bufs = NI_OPTS(ni).max_ep_bufs;

  assert_zero(nis->pkt_sets_n);
  nis->pkt_sets_max = ni->pkt_sets_max;

  /* Fragmented packet re-assembly list */
  nis->rx_defrag_head = OO_PP_NULL;
  nis->rx_defrag_tail = OO_PP_NULL;

  assert_zero(nis->send_may_poll);

  strncpy(nis->name, name, CI_CFG_STACK_NAME_LEN);
  nis->name[CI_CFG_STACK_NAME_LEN] = '\0';

  assert_zero(nis->in_poll);
  ci_ni_dllist_init(ni, &nis->post_poll_list,
                    oo_ptr_to_statep(ni, &nis->post_poll_list),
                    "pstp");

  nis->spin_cycles = usec_to_cycles64(NI_OPTS(ni).spin_usec, cpu_khz);
  nis->buzz_cycles = usec_to_cycles64(NI_OPTS(ni).buzz_usec, cpu_khz);
  nis->timer_prime_cycles = usec_to_cycles64(NI_OPTS(ni).timer_prime_usec, 
                                             cpu_khz);

  ci_ip_timer_state_init(ni, cpu_khz);
  nis->last_spin_poll_frc = IPTIMER_STATE(ni)->frc;
  nis->last_sleep_frc = IPTIMER_STATE(ni)->frc;
  
  oo_timesync_update(CICP_HANDLE(ni));

  assert_zero(nis->defer_work_count);


#if CI_CFG_TCPDUMP
  nis->dump_read_i = 0;
  nis->dump_write_i = 0;
  memset(nis->dump_intf, 0, sizeof(nis->dump_intf));
#endif

  nis->uid = ni->uid;
  nis->pid = current->tgid;

#if CI_CFG_FD_CACHING
  nis->epcache_n = nis->opts.epcache_max;
#endif

  /* This gets set appropriately in tcp_helper_init_max_mss() */
  nis->max_mss = 0;
}

#endif


static int citp_ipstack_params_inited = 0;
static ci_uint32 citp_tcp_sndbuf_min, citp_tcp_sndbuf_def, citp_tcp_sndbuf_max;
static ci_uint32 citp_tcp_rcvbuf_min, citp_tcp_rcvbuf_def, citp_tcp_rcvbuf_max;
static ci_uint32 citp_udp_sndbuf_max, citp_udp_sndbuf_def;
static ci_uint32 citp_udp_rcvbuf_max, citp_udp_rcvbuf_def;
static ci_uint32 citp_tcp_backlog_max, citp_tcp_adv_win_scale_max;
static ci_uint32 citp_fin_timeout;
static ci_uint32 citp_retransmit_threshold, citp_retransmit_threshold_syn,
          citp_retransmit_threshold_synack;
static ci_uint32 citp_keepalive_probes, citp_keepalive_time;
static ci_uint32 citp_keepalive_intvl;
static ci_uint32 citp_tcp_sack, citp_tcp_timestamps, citp_tcp_window_scaling;
static ci_uint32 citp_tcp_dsack;


#ifndef __KERNEL__
/* Interface for sysctl. */
ci_inline int ci_sysctl_get_values(char *path, ci_uint32 *ret, int n, 
                                   int quiet)
{
  char name[CI_CFG_PROC_PATH_LEN_MAX + strlen(CI_CFG_PROC_PATH)];
  char buf[CI_CFG_PROC_LINE_LEN_MAX];
  int buflen;
  char *p = buf;
  int fd;
  int i = 0;

  strcpy(name, CI_CFG_PROC_PATH);
  strncpy(name + strlen(CI_CFG_PROC_PATH), path, CI_CFG_PROC_PATH_LEN_MAX);
  fd = ci_sys_open(name, O_RDONLY);
  if (fd < 0) {
#ifndef NDEBUG 
    /* This message may apear if kernel is too old or in chroot */
    if( ! quiet )
      ci_log("%s: failed to open %s", __FUNCTION__, name);
#endif
    return fd;
  }
  buflen = ci_sys_read(fd, buf, sizeof(buf));
  ci_sys_close(fd);
  buf[buflen - 1] = '\0';
  for( i = 0; i < n && sscanf(p, "%u", &ret[i]) > 0; ++i ) {
    while( buf + buflen > p && p[0] != '\t' )
      p++;
    p++;
  }
  if( i < n ) {
    ci_log("%s: failed to parse %s: %s", __FUNCTION__, name, buf);
    return -1;
  }
  return 0;
}

/* Read /proc/sys/net parameters and store them is global variables to
 * re-use after possible chroot(). It really helps to ftp-servers in
 * passive mode, when they call listen(), accept(), chroot() and listen().
 */

int
ci_setup_ipstack_params(void)
{
  ci_uint32 opt[3];

  /* citp_ipstack_params_inited == 1 if:
   * - we have 2 netifs in one application;
   * - chroot() was called after another intercepted call.
   */
  if (citp_ipstack_params_inited)
    return 0;

  /* If /proc is not valid, we go away. */
  if (ci_sysctl_get_values("net/ipv4/ip_forward", opt, 1, 1) != 0)
    return -1;

  /* We will re-read following values in kernel mode for every socket,
   * but we need them before the first socket is initialized. */
  if( ci_sysctl_get_values("net/ipv4/tcp_wmem", opt, 3, 0) != 0 )
    return -1;
  citp_tcp_sndbuf_min = CI_CFG_TCP_SNDBUF_MIN;
  citp_tcp_sndbuf_def = opt[1];
  citp_tcp_sndbuf_max = opt[2];
  if( ci_sysctl_get_values("net/ipv4/tcp_rmem", opt, 3, 0) != 0 )
    return -1;
  citp_tcp_rcvbuf_min = CI_CFG_TCP_RCVBUF_MIN;
  citp_tcp_rcvbuf_def = opt[1];
  citp_tcp_rcvbuf_max = opt[2];
  if( ci_sysctl_get_values("net/core/wmem_max", opt, 1, 0) != 0 )
    return -1;
  citp_udp_sndbuf_max = opt[0];
  if( ci_sysctl_get_values("net/core/wmem_default", opt, 1, 0) != 0 )
    return -1;
  citp_udp_sndbuf_def = opt[0];
  if( ci_sysctl_get_values("net/core/rmem_max", opt, 1, 0) != 0 )
    return -1;
  citp_udp_rcvbuf_max = opt[0];
  if( ci_sysctl_get_values("net/core/rmem_default", opt, 1, 0) != 0 )
    return -1;
  citp_udp_rcvbuf_def = opt[0];

  if (ci_sysctl_get_values("net/ipv4/tcp_max_syn_backlog", opt, 1, 0) != 0)
    return -1;
  citp_tcp_backlog_max = opt[0];

  /* We should not use non-zero winscale if tcp_adv_win_scale == 0 */
  if (ci_sysctl_get_values("net/ipv4/tcp_adv_win_scale", opt, 1, 0) != 0)
    return -1;
  citp_tcp_adv_win_scale_max = CI_MIN(CI_TCP_WSCL_MAX, 3 * opt[0]);

  /* Get fin_timeout value from Linux if it is possible */
  if (ci_sysctl_get_values("net/ipv4/tcp_fin_timeout", opt, 1, 0) != 0)
    return -1;
  citp_fin_timeout = opt[0];

  /* Number of retransmits */
  if (ci_sysctl_get_values("net/ipv4/tcp_retries2", opt, 1, 0) != 0)
    return -1;
  citp_retransmit_threshold = opt[0];
  if (ci_sysctl_get_values("net/ipv4/tcp_syn_retries", opt, 1, 0) != 0)
    return -1;
  citp_retransmit_threshold_syn = opt[0];
  if (ci_sysctl_get_values("net/ipv4/tcp_synack_retries", opt, 1, 0) != 0)
    return -1;
  citp_retransmit_threshold_synack = opt[0];

  /* Keepalive parameters */
  if (ci_sysctl_get_values("net/ipv4/tcp_keepalive_probes", opt, 1, 0) != 0)
    return -1;
  citp_keepalive_probes = opt[0];
  /* These values are stored in secs, we scale to ms here */
  if (ci_sysctl_get_values("net/ipv4/tcp_keepalive_time", opt, 1, 0) != 0)
    return -1;
  citp_keepalive_time = opt[0] * 1000;
  if (ci_sysctl_get_values("net/ipv4/tcp_keepalive_intvl", opt, 1, 0) != 0)
    return -1;
  citp_keepalive_intvl = opt[0] * 1000;

  /* SYN options */
  if (ci_sysctl_get_values("net/ipv4/tcp_sack", opt, 1, 0) != 0)
    return -1;
  citp_tcp_sack = opt[0];
  if (ci_sysctl_get_values("net/ipv4/tcp_timestamps", opt, 1, 0) != 0)
    return -1;
  citp_tcp_timestamps = opt[0];
  if (ci_sysctl_get_values("net/ipv4/tcp_window_scaling", opt, 1, 0) != 0)
    return -1;
  citp_tcp_window_scaling = opt[0];

  if (ci_sysctl_get_values("net/ipv4/tcp_dsack", opt, 1, 0) != 0)
    return -1;
  citp_tcp_dsack = opt[0];

  citp_ipstack_params_inited = 1;
  return 0;
}

#else

int
ci_setup_ipstack_params(void)
{
  /*
   * XXX need an implementation.
   */

  citp_ipstack_params_inited = 0;
  return 0;
}

#endif /* __KERNEL__ */



void ci_netif_config_opts_defaults(ci_netif_config_opts* opts)
{
# undef  CI_CFG_OPTFILE_VERSION
# undef  CI_CFG_OPTGROUP
# undef  CI_CFG_OPT
# define CI_CFG_OPT(env, name, type, doc, type_modifider, group,     \
                    default, minimum, maximum, presentation)	      \
  opts->name = default;

# include <ci/internal/opts_netif_def.h>

  /* now modify defaults with information from the operating system */
  ci_setup_ipstack_params();
  if (citp_ipstack_params_inited) {
    opts->tcp_sndbuf_min = citp_tcp_sndbuf_min;
    opts->tcp_sndbuf_def = citp_tcp_sndbuf_def;
    opts->tcp_sndbuf_max = citp_tcp_sndbuf_max;
    opts->tcp_rcvbuf_min = citp_tcp_rcvbuf_min;
    opts->tcp_rcvbuf_def = citp_tcp_rcvbuf_def;
    opts->tcp_rcvbuf_max = citp_tcp_rcvbuf_max;

    opts->udp_sndbuf_max = citp_udp_sndbuf_max;
    opts->udp_sndbuf_def = citp_udp_sndbuf_def;
    opts->udp_rcvbuf_max = citp_udp_rcvbuf_max;
    opts->udp_rcvbuf_def = citp_udp_rcvbuf_def;

    opts->tcp_backlog_max = citp_tcp_backlog_max;
    opts->tcp_adv_win_scale_max = citp_tcp_adv_win_scale_max;
    opts->fin_timeout = citp_fin_timeout;

    opts->retransmit_threshold = citp_retransmit_threshold;
    opts->retransmit_threshold_syn = citp_retransmit_threshold_syn;
    opts->retransmit_threshold_synack = citp_retransmit_threshold_synack;

    opts->keepalive_probes = citp_keepalive_probes;
    opts->keepalive_time = citp_keepalive_time;
    opts->keepalive_intvl = citp_keepalive_intvl;

    opts->syn_opts = (citp_tcp_sack ? CI_TCPT_FLAG_SACK : 0) |
        (citp_tcp_timestamps ? CI_TCPT_FLAG_TSO : 0) |
        (citp_tcp_window_scaling ? CI_TCPT_FLAG_WSCL : 0);
    opts->use_dsack = citp_tcp_dsack;
    opts->inited = CI_TRUE;
  }
}

void ci_netif_config_opts_rangecheck(ci_netif_config_opts* opts)
{
  ci_uint64 MIN;
  ci_uint64 MAX;
  ci_int64  SMIN;
  ci_int64  SMAX;
  int _optbits;
  int _bitwidth;

  /* stop compiler complaining if these values are not used */
  (void)MIN; (void)MAX; (void)SMIN; (void)SMAX;
  (void)_optbits; (void)_bitwidth; 
  
#undef  CI_CFG_OPTFILE_VERSION
#undef  CI_CFG_OPTGROUP
#undef  CI_CFG_OPT

#define _CI_CFG_BITVAL   _optbits
#define _CI_CFG_BITVAL1  1
#define _CI_CFG_BITVAL2  2
#define _CI_CFG_BITVAL3  3
#define _CI_CFG_BITVAL4  4
#define _CI_CFG_BITVAL8  8
#define _CI_CFG_BITVAL16 16
#define _CI_CFG_BITVALA8 _CI_CFG_BITVAL

#undef MIN
#undef MAX
#undef SMIN
#undef SMAX
    
#define CI_CFG_REDRESS(opt, val) opt = val;
#define CI_CFG_MSG "ERROR"

#define CI_CFG_OPT(env, name, type, doc, bits, group, default, minimum, maximum, pres) \
{ type _val = opts->name;					          \
  type _max;								  \
  type _min;								  \
  _optbits=sizeof(type)*8;                                                \
  _bitwidth=_CI_CFG_BITVAL##bits;					  \
  MIN = 0;                                                                \
  MAX = ((1ull<<(_bitwidth-1))<<1) - 1ull;       			  \
  SMAX = MAX >> 1; SMIN = -SMAX-1;                                        \
  _max = (type)(maximum); /* try to stop the compiler warning */          \
  _min = (type)(minimum); /* about silly comparisons          */          \
  if (_val > _max) {                                                      \
    ci_log("config: "CI_CFG_MSG" - option " #name                         \
           " (%"CI_PRIu64") larger than maximum " #maximum" (%"CI_PRIu64")",		  \
           (ci_uint64)_val, (ci_uint64) _max);                                     \
    CI_CFG_REDRESS(opts->name, _max);                                     \
  }                                                                       \
  if (_val < _min) {                                                      \
    ci_log("config: "CI_CFG_MSG" - option " #name                         \
           " (%"CI_PRIu64") smaller than minimum " #minimum,		  \
           (ci_uint64)_val);                                              \
    CI_CFG_REDRESS(opts->name, _min);                                     \
  }                                                                       \
}                                               

# include <ci/internal/opts_netif_def.h>
}


#ifndef __KERNEL__

void ci_netif_config_opts_getenv(ci_netif_config_opts* opts)
{
  const char* s;

  /* These first options are sensitive to the order in which they are
   * initialised, because the value of one effects the default for
   * others...
   */

  if( (s = getenv("EF_POLL_USEC")) ) {
    opts->spin_usec = atoi(s);
    if( opts->spin_usec != 0 ) {
      /* Don't buzz for too long by default! */
      opts->buzz_usec = CI_MIN(opts->spin_usec, 100);
      /* Disable EF_INT_DRIVEN by default when spinning. */
      opts->int_driven = 0;
      /* These are only here to expose defaults through stackdump.  FIXME:
       * Would be much better to initialise these from the CITP options to
       * avoid potential inconsistency.
       */
      opts->sock_lock_buzz = 1;
      opts->stack_lock_buzz = 1;
      opts->ul_select_spin = 1;
      opts->ul_poll_spin = 1;
#if CI_CFG_USERSPACE_EPOLL
      opts->ul_epoll_spin = 1;
#endif
#if CI_CFG_UDP
      opts->udp_recv_spin = 1;
      opts->udp_send_spin = 1;
#endif
      opts->tcp_recv_spin = 1;
      opts->tcp_send_spin = 1;
      opts->pkt_wait_spin = 1;
    }
  }
  if( (s = getenv("EF_SPIN_USEC")) ) {
    opts->spin_usec = atoi(s);
    /* Disable EF_INT_DRIVEN by default when spinning. */
    if( opts->spin_usec != 0 )
      opts->int_driven = 0;
  }

  if( (s = getenv("EF_INT_DRIVEN")) )
    opts->int_driven = atoi(s);
  if( opts->int_driven )
    /* Disable count-down timer when interrupt driven. */
    opts->timer_usec = 0;
  if( (s = getenv("EF_HELPER_USEC")) ) {
    opts->timer_usec = atoi(s);
    if( opts->timer_usec != 0 )
      /* Set the prime interval to half the timeout by default. */
      opts->timer_prime_usec = opts->timer_usec / 2;
  }
  if( (s = getenv("EF_HELPER_PRIME_USEC")) )
    opts->timer_prime_usec = atoi(s);

  if( (s = getenv("EF_BUZZ_USEC")) ) {
    opts->buzz_usec = atoi(s);
    if( opts->buzz_usec != 0 ) {
      opts->sock_lock_buzz = 1;
      opts->stack_lock_buzz = 1;
    }
  }
  if( (s = getenv("EF_SOCK_LOCK_BUZZ")) )
    opts->sock_lock_buzz = atoi(s);
  if( (s = getenv("EF_STACK_LOCK_BUZZ")) )
    opts->stack_lock_buzz = atoi(s);

  /* The options that follow are (at time of writing) not sensitive to the
   * order in which they are read.
   */

#if CI_CFG_POISON_BUFS
  if( (s = getenv("EF_POISON")) )       opts->poison_rx_buf = atoi(s);
#endif
#if CI_CFG_RANDOM_DROP
  if( (s = getenv("EF_RX_DROP_RATE")) ) {
    int r = atoi(s);
    if( r )  opts->rx_drop_rate = RAND_MAX / r;
  }
#endif
  if( (s = getenv("EF_URG_RFC")) )
    opts->urg_rfc = atoi(s);
#if CI_CFG_UDP
  if( (s = getenv("EF_MCAST_RECV")) )
    opts->mcast_recv = atoi(s);
  if( (s = getenv("EF_FORCE_SEND_MULTICAST")) )
    opts->force_send_multicast = atoi(s);
  if( (s = getenv("EF_MULTICAST_LOOP_OFF")) )
    opts->multicast_loop_off = atoi(s);
#endif
  if( (s = getenv("EF_EVS_PER_POLL")) )
    opts->evs_per_poll = atoi(s);
  if( (s = getenv("EF_TCP_TCONST_MSL")) )
    opts->msl_seconds = atoi(s);
  if( (s = getenv("EF_TCP_FIN_TIMEOUT")) )
    opts->fin_timeout = atoi(s);
  if( (s = getenv("EF_TCP_ADV_WIN_SCALE_MAX")) )
    opts->tcp_adv_win_scale_max = atoi(s);

  if( (s = getenv("EF_TCP_SYN_OPTS")) ) {
    unsigned v;
    ci_verify(sscanf(s, "%x", &v) == 1);
    opts->syn_opts = v;
  }

  if ( (s = getenv("EF_MAX_PACKETS")) ) {
    int max_packets_rq = atoi(s);
    opts->max_packets = (max_packets_rq + PKTS_PER_SET - 1) &
                                                ~(PKTS_PER_SET - 1);
    if( opts->max_packets != max_packets_rq )
      /* ?? TODO: log message */
      ;
    opts->max_rx_packets = opts->max_packets * 3 / 4;
    opts->max_tx_packets = opts->max_packets * 3 / 4;
  }
  if ( (s = getenv("EF_MAX_RX_PACKETS")) ) {
    opts->max_rx_packets = atoi(s);
    if( opts->max_rx_packets > opts->max_packets )
      opts->max_rx_packets = opts->max_packets;
  }
  if ( (s = getenv("EF_MAX_TX_PACKETS")) ) {
    opts->max_tx_packets = atoi(s);
    if( opts->max_tx_packets > opts->max_packets )
      opts->max_tx_packets = opts->max_packets;
  }
  if ( (s = getenv("EF_RXQ_MIN")) )
    opts->rxq_min = atoi(s);
  if ( (s = getenv("EF_MIN_FREE_PACKETS")) )
    opts->min_free_packets = atoi(s);
  if( (s = getenv("EF_PREFAULT_PACKETS")) )
    opts->prefault_packets = atoi(s);
#if CI_CFG_PIO
  if ( (s = getenv("EF_PIO")) )
    opts->pio = atoi(s);
#endif
  if ( (s = getenv("EF_MAX_ENDPOINTS")) )
    opts->max_ep_bufs = atoi(s);
  if ( (s = getenv("EF_SHARE_WITH")) )
    opts->share_with = atoi(s);
#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( (s = getenv("EF_USE_HUGE_PAGES")) ) {
    opts->huge_pages = atoi(s);
  }
  if( opts->huge_pages != 0 && opts->share_with != 0 ) {
    ci_log("Turning huge pages off because the stack is going "
           "to be used by multiple users");
    opts->huge_pages = 0;
  }
#endif
  if ( (s = getenv("EF_RXQ_SIZE")) )
    opts->rxq_size = atoi(s);
  if ( (s = getenv("EF_RXQ_LIMIT")) )
    opts->rxq_limit = atoi(s);
  if ( (s = getenv("EF_TXQ_SIZE")) )
    opts->txq_size = atoi(s);
  if ( (s = getenv("EF_TXQ_LIMIT")) )
    opts->txq_limit = atoi(s);
  if ( (s = getenv("EF_SEND_POLL_THRESH")) )
    opts->send_poll_thresh = atoi(s);
  if ( (s = getenv("EF_SEND_POLL_MAX_EVS")) )
    opts->send_poll_max_events = atoi(s);
  if ( (s = getenv("EF_DEFER_WORK_LIMIT")) )
    opts->defer_work_limit = atoi(s);
#if CI_CFG_UDP
  if( (s = getenv("EF_UDP_SEND_UNLOCK_THRESH")) )
    opts->udp_send_unlock_thresh = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER_MIN")) )
    opts->udp_port_handover_min = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER_MAX")) )
    opts->udp_port_handover_max = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER2_MIN")) )
    opts->udp_port_handover2_min = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER2_MAX")) )
    opts->udp_port_handover2_max = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER3_MIN")) )
    opts->udp_port_handover3_min = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER3_MAX")) )
    opts->udp_port_handover3_max = atoi(s);
#endif
  if ( (s = getenv("EF_DELACK_THRESH")) )
    opts->delack_thresh = atoi(s);
#if CI_CFG_DYNAMIC_ACK_RATE
  if ( (s = getenv("EF_DYNAMIC_ACK_THRESH")) )
    opts->dynack_thresh = atoi(s);
  /* Always want this value to be >= delack_thresh to simplify code
   * that uses it 
   */
  opts->dynack_thresh = CI_MAX(opts->dynack_thresh, opts->delack_thresh);
#endif
#if CI_CFG_FD_CACHING
  if ( (s = getenv("EF_EPCACHE_MAX")) )
    opts->epcache_max = atoi(s);
#endif

#if CI_CFG_PORT_STRIPING
  /* configuration opttions for striping */
  if ( (s = getenv("EF_STRIPE_NETMASK")) ) {
    int a1, a2, a3, a4;
    sscanf(s, "%d.%d.%d.%d", &a1, &a2, &a3, &a4);
    opts->stripe_netmask_be32 = (a1 << 24) | (a2 << 16) | (a3 << 8) | a4;
    opts->stripe_netmask_be32 = CI_BSWAP_BE32(opts->stripe_netmask_be32);
  }
  if ( (s = getenv("EF_STRIPE_DUPACK_THRESH")) ) {
    opts->stripe_dupack_threshold = atoi(s);
    opts->stripe_dupack_threshold =
          CI_MAX(opts->stripe_dupack_threshold, CI_CFG_TCP_DUPACK_THRESH_BASE);
    opts->stripe_dupack_threshold  =
          CI_MIN(opts->stripe_dupack_threshold, CI_CFG_TCP_DUPACK_THRESH_MAX);
  }
  if( (s = getenv("EF_STRIPE_TCP_OPT")) )
    opts->stripe_tcp_opt = atoi(s);
#endif
  if( (s = getenv("EF_TX_PUSH")) )
    opts->tx_push = atoi(s);
  if( (s = getenv("EF_PACKET_BUFFER_MODE")) )
    opts->packet_buffer_mode = atoi(s);
  if( (s = getenv("EF_TCP_RST_DELAYED_CONN")) )
    opts->rst_delayed_conn = atoi(s);
  if( (s = getenv("EF_TCP_SNDBUF_MODE")) )
    opts->tcp_sndbuf_mode = atoi(s);
  if( (s = getenv("EF_POLL_ON_DEMAND")) )
    opts->poll_on_demand = atoi(s);
  if( (s = getenv("EF_INT_REPRIME")) )
    opts->int_reprime = atoi(s);
  if( (s = getenv("EF_IRQ_MODERATION")) )
    opts->irq_usec = atoi(s);
  if( (s = getenv("EF_NONAGLE_INFLIGHT_MAX")) )
    opts->nonagle_inflight_max = atoi(s);
  if( (s = getenv("EF_FORCE_TCP_NODELAY")) )
    opts->tcp_force_nodelay = atoi(s);
  if( (s = getenv("EF_IRQ_CORE")) )
    opts->irq_core = atoi(s);
  if( (s = getenv("EF_IRQ_CHANNEL")) )
    opts->irq_channel = atoi(s);
  if( (s = getenv("EF_TCP_LISTEN_HANDOVER")) )
    opts->tcp_listen_handover = atoi(s);
  if( (s = getenv("EF_TCP_CONNECT_HANDOVER")) )
    opts->tcp_connect_handover = atoi(s);
  if( (s = getenv("EF_UDP_CONNECT_HANDOVER")) )
    opts->udp_connect_handover = atoi(s);
#if CI_CFG_UDP_SEND_UNLOCK_OPT
  if( (s = getenv("EF_UDP_SEND_UNLOCKED")) )
    opts->udp_send_unlocked = atoi(s);
#endif
  if( (s = getenv("EF_UNCONFINE_SYN")) )
    opts->unconfine_syn = atoi(s) != 0;
  if( (s = getenv("EF_BINDTODEVICE_HANDOVER")) )
    opts->bindtodevice_handover = atoi(s) != 0;
  if( (s = getenv("EF_MCAST_JOIN_BINDTODEVICE")) )
    opts->mcast_join_bindtodevice = atoi(s) != 0;
#if CI_CFG_RATE_PACING
  if( (s = getenv("EF_TX_QOS_CLASS")) ) {
    opts->tx_qos_class = atoi(s) != 0;
    opts->tx_min_ipg_cntl = -1;
  }
#endif
  if( (s = getenv("EF_MCAST_JOIN_HANDOVER")) )
    opts->mcast_join_handover = atoi(s);

  if( (s = getenv("EF_TCP_SERVER_LOOPBACK")) )
    opts->tcp_server_loopback = atoi(s);
  if( (s = getenv("EF_TCP_CLIENT_LOOPBACK")) )
    opts->tcp_client_loopback = atoi(s);
  /* Forbid impossible combination of loopback options */
  if( opts->tcp_server_loopback == CITP_TCP_LOOPBACK_OFF &&
      opts->tcp_client_loopback == CITP_TCP_LOOPBACK_SAMESTACK )
    opts->tcp_client_loopback = CITP_TCP_LOOPBACK_OFF;

  if( (s = getenv("EF_TCP_RX_CHECKS")) ) {
    unsigned v;
    ci_verify(sscanf(s, "%x", &v) == 1);
    opts->tcp_rx_checks = v;
    if( (s = getenv("EF_TCP_RX_LOG_FLAGS")) ) {
      ci_verify(sscanf(s, "%x", &v) == 1);
      opts->tcp_rx_log_flags = v;
    }
  }
  if( (s = getenv("EF_SELECT_SPIN")) )
    opts->ul_select_spin = atoi(s);
  if( (s = getenv("EF_POLL_SPIN")) )
    opts->ul_poll_spin = atoi(s);
#if CI_CFG_USERSPACE_EPOLL
  if( (s = getenv("EF_EPOLL_SPIN")) )
    opts->ul_epoll_spin = atoi(s);
#endif
#if CI_CFG_UDP
  if( (s = getenv("EF_UDP_RECV_SPIN")) )
    opts->udp_recv_spin = atoi(s);
  if( (s = getenv("EF_UDP_SEND_SPIN")) )
    opts->udp_send_spin = atoi(s);
#endif
  if( (s = getenv("EF_TCP_RECV_SPIN")) )
    opts->tcp_recv_spin = atoi(s);
  if( (s = getenv("EF_TCP_SEND_SPIN")) )
    opts->tcp_send_spin = atoi(s);
  if( (s = getenv("EF_TCP_ACCEPT_SPIN")) )
    opts->tcp_accept_spin = atoi(s);
  if( (s = getenv("EF_PKT_WAIT_SPIN")) )
    opts->pkt_wait_spin = atoi(s);
#if CI_CFG_USERSPACE_PIPE
  if( (s = getenv("EF_PIPE_RECV_SPIN")) )
    opts->pipe_recv_spin = atoi(s);
  if( (s = getenv("EF_PIPE_SEND_SPIN")) )
    opts->pipe_send_spin = atoi(s);
#endif

  if( (s = getenv("EF_ACCEPTQ_MIN_BACKLOG")) )
    opts->acceptq_min_backlog = atoi(s);

  if ( (s = getenv("EF_TCP_SNDBUF")) )
    opts->tcp_sndbuf_user = atoi(s);
  if ( (s = getenv("EF_TCP_RCVBUF")) )
    opts->tcp_rcvbuf_user = atoi(s);
  if ( (s = getenv("EF_UDP_SNDBUF")) )
    opts->udp_sndbuf_user = atoi(s);
  if ( (s = getenv("EF_UDP_RCVBUF")) )
    opts->udp_rcvbuf_user = atoi(s);

  if( opts->tcp_sndbuf_user != 0 ) {
    opts->tcp_sndbuf_min = opts->tcp_sndbuf_max = opts->tcp_sndbuf_user;
    opts->tcp_sndbuf_def = oo_adjust_SO_XBUF(opts->tcp_sndbuf_user);
  }
  if( opts->tcp_rcvbuf_user != 0 ) {
    opts->tcp_rcvbuf_min = opts->tcp_rcvbuf_max = opts->tcp_rcvbuf_user;
    opts->tcp_rcvbuf_def = oo_adjust_SO_XBUF(opts->tcp_rcvbuf_user);
  }
  if( opts->udp_sndbuf_user != 0 ) {
    opts->udp_sndbuf_min = opts->udp_sndbuf_max = opts->udp_sndbuf_user;
    opts->udp_sndbuf_def = oo_adjust_SO_XBUF(opts->udp_sndbuf_user);
  }
  if( opts->udp_rcvbuf_user != 0 ) {
    opts->udp_rcvbuf_min = opts->udp_rcvbuf_max = opts->udp_rcvbuf_user;
    opts->udp_rcvbuf_def = oo_adjust_SO_XBUF(opts->udp_rcvbuf_user);
  }

  if ( (s = getenv("EF_RETRANSMIT_THRESHOLD_SYNACK")) )
    opts->retransmit_threshold_synack = atoi(s);

  if ( (s = getenv("EF_TCP_BACKLOG_MAX")) )
    opts->tcp_backlog_max = atoi(s);

  if ( (s = getenv("EF_TCP_INITIAL_CWND")) )
    opts->initial_cwnd = atoi(s);
  if ( (s = getenv("EF_TCP_LOSS_MIN_CWND")) )
    opts->loss_min_cwnd = atoi(s);
#if CI_CFG_TCP_FASTSTART
  if ( (s = getenv("EF_TCP_FASTSTART_INIT")) )
    opts->tcp_faststart_init = atoi(s);
  if ( (s = getenv("EF_TCP_FASTSTART_IDLE")) )
    opts->tcp_faststart_idle = atoi(s);
  if ( (s = getenv("EF_TCP_FASTSTART_LOSS")) )
    opts->tcp_faststart_loss = atoi(s);
#endif

  if ( (s = getenv("EF_RFC_RTO_INITIAL")))
    opts->rto_initial = atoi(s);
  if ( (s = getenv("EF_RFC_RTO_MIN")))
    opts->rto_min = atoi(s);
  if ( (s = getenv("EF_RFC_RTO_MAX")))
    opts->rto_max = atoi(s);
#ifndef NDEBUG
  if( (s = getenv("EF_TCP_MAX_SEQERR_MSGS")))
    opts->tcp_max_seqerr_msg = atoi(s);
#endif
#if CI_CFG_BURST_CONTROL
  if ( (s = getenv("EF_BURST_CONTROL_LIMIT")))
    opts->burst_control_limit = atoi(s);
#endif
#if CI_CFG_RATE_PACING
  if ( (s = getenv("EF_TX_MIN_IPG_CNTL")) )
    opts->tx_min_ipg_cntl = atoi(s);
#endif
#if CI_CFG_CONG_AVOID_NOTIFIED
  if ( (s = getenv("EF_CONG_NOTIFY_THRESH")))
    opts->cong_notify_thresh = atoi(s);
#endif
#if CI_CFG_TAIL_DROP_PROBE
  if ( (s = getenv("EF_TAIL_DROP_PROBE")))
    opts->tail_drop_probe = atoi(s);
#endif
#if CI_CFG_CONG_AVOID_SCALE_BACK
  if ( (s = getenv("EF_CONG_AVOID_SCALE_BACK")))
    opts->cong_avoid_scale_back = atoi(s);
#endif

  /* Get our netifs to inherit flags if the O/S is being forced to */
  if (CITP_OPTS.accept_force_inherit_nonblock)
    opts->accept_inherit_nonblock = 1;
  if (CITP_OPTS.accept_force_inherit_nodelay)
    opts->accept_inherit_nodelay  = 1;

  if ( (s = getenv("EF_FREE_PACKETS_LOW_WATERMARK")) )
    opts->free_packets_low = atoi(s);

#if CI_CFG_SENDFILE
  if ( (s = getenv("EF_MAX_EP_PINNED_PAGES")) )
    opts->max_ep_pinned_pages = atoi(s);
#endif

#if CI_CFG_PIO
  if( opts->pio == 0 )
    /* Makes for more efficient checking on fast data path */
    opts->pio_thresh = 0;
  else if ( (s = getenv("EF_PIO_THRESHOLD")) )
    opts->pio_thresh = atoi(s);
#endif
}

#endif


void ci_netif_config_opts_dump(ci_netif_config_opts* opts)
{
  const ci_netif_config_opts defaults = {
    #undef CI_CFG_OPTFILE_VERSION
    #undef CI_CFG_OPT
    #undef CI_CFG_OPTGROUP

    #define CI_CFG_OPTFILE_VERSION(version)
    #define CI_CFG_OPTGROUP(group, category, expertise)
    #define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
            default,

    #include <ci/internal/opts_netif_def.h>
  };

  #undef CI_CFG_OPTFILE_VERSION
  #undef CI_CFG_OPT
  #undef CI_CFG_OPTGROUP

  #define ci_uint32_fmt   "%u"
  #define ci_uint16_fmt   "%u"
  #define ci_int32_fmt    "%d"
  #define ci_int16_fmt    "%d"
  #define ci_iptime_t_fmt "%u"

  #define CI_CFG_OPTFILE_VERSION(version)
  #define CI_CFG_OPTGROUP(group, category, expertise)
  #define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
    if( strlen(env) != 0 ) {                                            \
      if( opts->name == defaults.name )                                 \
        ci_log("%30s: " type##_fmt, env, opts->name);                   \
      else                                                              \
        ci_log("%30s: " type##_fmt " (default: " type##_fmt")", env,    \
               opts->name, defaults.name);                              \
    }

  ci_log("                        NDEBUG: %d", ! IS_DEBUG);
  #include <ci/internal/opts_netif_def.h>
}


/*****************************************************************************
 *                                                                           *
 *          TCP-helper Construction                                          *
 *          =======================                                          *
 *                                                                           *
 *****************************************************************************/


#define NS_MMAP_SIZE(ns) \
  (ns->netif_mmap_bytes + cicp_mapped_bytes(&ns->control_mmap))


#ifndef __KERNEL__

static int netif_tcp_helper_mmap(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  void* p;
  int rc;

  /****************************************************************************
   * Create the I/O mapping.
   */
  if( ns->io_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          CI_NETIF_MMAP_ID_IO, ns->io_mmap_bytes, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap io %d", __FUNCTION__, rc));
      goto fail1;
    }
    ni->io_ptr = (char*) p;
  }

#if CI_CFG_PIO
  /****************************************************************************
   * Create the PIO mapping.
   */
  if( ns->pio_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          CI_NETIF_MMAP_ID_PIO, ns->pio_mmap_bytes, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap pio %d", __FUNCTION__, rc));
      goto fail1;
    }
    ni->pio_ptr = (uint8_t*) p;
  }
#endif

  /****************************************************************************
   * Create the I/O buffer mapping.
   */
  if( ns->buf_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          CI_NETIF_MMAP_ID_IOBUFS, ns->buf_mmap_bytes, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap iobufs %d", __FUNCTION__, rc));
      goto fail2;
    }
    ni->buf_ptr = (char*) p;
  }
#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( ns->buf_ofs == (ci_uint32)-1 )
    ni->pkt_shm_id = NULL;
  else
    ni->pkt_shm_id = (void *)(ni->buf_ptr + ns->buf_ofs);
#endif

  return 0;

 fail2:
  oo_resource_munmap(ci_netif_get_driver_handle(ni), ni->io_ptr,
                     ns->io_mmap_bytes);
 fail1:
  return rc;
}


static void netif_tcp_helper_munmap(ci_netif* ni)
{
  int rc;

  /* Buffer mapping. */
  {
    unsigned id;

    /* Unmap packets pages */
    for( id = 0; id < ni->state->pkt_sets_n; id++ ) {
      if( PKT_BUFSET_U_MMAPPED(ni, id) ) {
#if CI_CFG_PKTS_AS_HUGE_PAGES
        if( ni->pkt_shm_id && ni->pkt_shm_id[id] >= 0 )
          rc = shmdt(ni->pkt_sets[id]);
        else
#endif
        {
          rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                                  ni->pkt_sets[id],
                                  CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
        }
        if( rc < 0 )
          LOG_NV(ci_log("%s: munmap packets %d", __FUNCTION__, rc));
      }
    }
  }
  rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                          ni->buf_ptr, ni->state->buf_mmap_bytes);
  if( rc < 0 )  LOG_NV(ci_log("%s: munmap bufs %d", __FUNCTION__, rc));

#if CI_CFG_PIO
  if( ni->state->pio_mmap_bytes != 0 ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->pio_ptr, ni->state->pio_mmap_bytes);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap pio %d", __FUNCTION__, rc));
  }
#endif

  rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                          ni->io_ptr, ni->state->io_mmap_bytes);
  if( rc < 0 )  LOG_NV(ci_log("%s: munmap io %d", __FUNCTION__, rc));

  rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                          ni->state, ni->mmap_bytes);
  if( rc < 0 )  LOG_NV(ci_log("%s: munmap shared state %d", __FUNCTION__, rc));
}


static int netif_tcp_helper_build(ci_netif* ni)
{
  /* On entry we require the following to be initialised:
  **
  **   ni->state (for both user and kernel builds)
  **   ci_netif_get_driver_handle(ni), ni->tcp_mmap (for user builds only)
  */
  ci_netif_state* ns = ni->state;
  struct ef_vi_nic_type nic_type;
  int rc, nic_i;
  char* mmap_ptr;
  unsigned vi_io_offset, vi_mem_offset, vi_state_offset;
  char vi_data[VI_MAPPINGS_SIZE];
  int vi_state_bytes;
  int vi_io_offset_full;
#if CI_CFG_PIO
  unsigned pio_io_offset, pio_buf_offset = 0;
#endif

  /****************************************************************************
   * Do other mmaps.
   */
  rc = netif_tcp_helper_mmap(ni);
  if( rc < 0 )  return rc;

  /****************************************************************************
   * Breakout the VIs.
   */

  /* The array of nic_hw is potentially sparse, but the memory mapping is
  ** not, so we keep a count to calculate offsets rather than use
  ** nic_index.
  */
  vi_io_offset = ns->vi_io_mmap_offset;
#if CI_CFG_PIO
  pio_io_offset = ns->pio_io_mmap_offset;
#endif
  vi_mem_offset = ns->vi_mem_mmap_offset;
  vi_state_offset = sizeof(*ni->state);

  OO_STACK_FOR_EACH_INTF_I(ni, nic_i) {
    ci_netif_state_nic_t* nsn = &ns->nic[nic_i];
    char* io_mmap = ni->buf_ptr + vi_mem_offset +
      (( nsn->vi_evq_bytes + CI_PAGE_SIZE - 1) & CI_PAGE_MASK);

    LOG_NV(ci_log("%s: ni->io_ptr=%p io_offset=%d mem_offset=%d state_offset=%d",
                __FUNCTION__, ni->io_ptr,
                vi_io_offset, vi_mem_offset, vi_state_offset));

    ci_assert((vi_mem_offset & (CI_PAGE_SIZE - 1)) == 0);

    rc = ef_vi_arch_from_efhw_arch(nsn->vi_arch);
    CI_TEST(rc >= 0);
    nic_type.arch = (unsigned char) rc;
    nic_type.variant = nsn->vi_variant;
    nic_type.revision = nsn->vi_revision;
    nic_type.flags = nsn->vi_hw_flags;

#if CI_PAGE_SIZE > 8192
    /******** WARNING *******
     * This is a possible security threat. On x86 as
     * 8192 is greater then PAGE_SIZE we're mapping individual pages for
     * each VI's RX_DESC_UPD, TX_DESC_UPD. But on POWER they get into the
     * same OS page grouped by 8 (64k / 8k). So we have to map them all
     * together meaning that an application will have access to somebodies
     * dbells. Not sure if anything can be done here.*/

    /* 8192 is a hardcoded constant. It is current _STEP for all tables in
     * question for all existing HW (falcon, siena, ef10). This may need
     * fixing when new HW is out */
    vi_io_offset_full = vi_io_offset +
	    (nsn->vi_instance & ((CI_PAGE_SIZE / 8192) - 1)) * 8192;
#else
    vi_io_offset_full = vi_io_offset;
#endif

    memset(vi_data, 0, sizeof(vi_data));
    ef_vi_init_mapping_evq(vi_data, nic_type, nsn->vi_instance,
                           ni->io_ptr + vi_io_offset_full,
                           nsn->vi_evq_bytes,
                           ni->buf_ptr + vi_mem_offset,
                           ni->io_ptr + vi_io_offset_full + nsn->evq_timer_offset,
                           nsn->timer_quantum_ns);
    ef_vi_init_mapping_vi(vi_data, nic_type, nsn->vi_rxq_size,
                          nsn->vi_txq_size, nsn->vi_instance,
                          ni->io_ptr + vi_io_offset_full,
                          io_mmap, io_mmap, nsn->vi_flags,
                          nsn->rx_prefix_len);
    ef_vi_init(&ni->nic_hw[nic_i].vi, vi_data,
               (ef_vi_state*) ((char*) ni->state + vi_state_offset),
               &nsn->evq_state, nsn->vi_flags);
    ef_vi_add_queue(&ni->nic_hw[nic_i].vi, &ni->nic_hw[nic_i].vi);
    ef_vi_set_stats_buf(&ni->nic_hw[nic_i].vi, &ni->state->vi_stats);

    vi_state_bytes = ef_vi_calc_state_bytes(nsn->vi_rxq_size,
                                            nsn->vi_txq_size);
    ci_assert(vi_state_bytes == ns->vi_state_bytes);
    vi_state_offset += vi_state_bytes;
    vi_io_offset += nsn->vi_io_mmap_bytes;
    vi_mem_offset += nsn->vi_mem_mmap_bytes;

#if CI_CFG_PIO
    if( NI_OPTS(ni).pio &&
        (ns->nic[nic_i].oo_vi_flags & OO_VI_FLAGS_PIO_EN) ) {
      /* There should be a mapping for this NIC */
      ci_assert(nsn->pio_io_mmap_bytes != 0);
      /* There should be some left in the all-NICs count */
      ci_assert_lt(pio_io_offset, ns->pio_mmap_bytes);
      /* The length for this NIC is smaller than the mapping for this NIC */
      ci_assert_le(nsn->pio_io_len, nsn->pio_io_mmap_bytes);
      /* Although the PIO regions are each in their own page, we have a
       * dense mapping for the host memory copy, starting at pio_bufs_ofs
       */
      ni->nic_hw[nic_i].pio.pio_buffer = (uint8_t*)ns + ns->pio_bufs_ofs + 
        pio_buf_offset;
      pio_buf_offset += nsn->pio_io_len;
      /* And set up rest of PIO struct so we can call ef_vi_pio_memcpy */
      ni->nic_hw[nic_i].pio.pio_io = ni->pio_ptr + pio_io_offset;
      ni->nic_hw[nic_i].pio.pio_len = nsn->pio_io_len;
      ni->nic_hw[nic_i].vi.linked_pio = &ni->nic_hw[nic_i].pio;
      pio_io_offset += nsn->pio_io_mmap_bytes;
    }
#endif
  }


  ni->pkt_sets = CI_ALLOC_ARRAY(char*, ns->pkt_sets_max);
  CI_ZERO_ARRAY(ni->pkt_sets, ni->state->pkt_sets_max);

  mmap_ptr = (char*) ni->state + ns->netif_mmap_bytes;

  /* Initialise timer related stuff that is only used at user level */
  ci_ip_timer_state_init_ul(ni);

  /****************************************************************************
   * Initialise control plane table handles in ci_netif.
   */

  cicp_ni_build(&ni->cplane, &ns->control_mmap, mmap_ptr);

  if( ns->table_ofs !=
      (sizeof(ci_netif_state) + ns->vi_state_bytes * oo_stack_intf_max(ni)) ) {
    /* This typically happens if someone puts a variable width type such as
     * long in ci_netif_state_s, and a 32 bit user level library is used
     * with a 64 bit driver.  (Or if user and kernel get out of sync).
     */
    ci_log("ERROR: data structure layout mismatch between kernel and "
           "user level detected!");
    ci_log("ns->table_ofs=%d != %zd + %d * %d", ns->table_ofs,
           sizeof(ci_netif_state), ns->vi_state_bytes, oo_stack_intf_max(ni));
    return -EINVAL;
  }

  return 0;
}

#endif


static void netif_tcp_helper_build2(ci_netif* ni)
{
  ni->filter_table =
    (ci_netif_filter_table*) ((char*) ni->state + ni->state->table_ofs);
}


#ifndef __KERNEL__

static int
netif_tcp_helper_restore(ci_netif* ni, unsigned netif_mmap_bytes)
{
  void* p;
  int rc;

  rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                        CI_NETIF_MMAP_ID_STATE, netif_mmap_bytes, &p);
  if( rc < 0 ) {
    LOG_NV(ci_log("netif_tcp_helper_restore: oo_resource_mmap %d", rc));
    return rc;
  }
  ni->state = (ci_netif_state*) p;
  ni->mmap_bytes = netif_mmap_bytes;

  rc = netif_tcp_helper_build(ni);
  if( rc < 0 ) {
    ci_log("%s: netif_tcp_helper_build %d", __FUNCTION__, rc);
    oo_resource_munmap(ci_netif_get_driver_handle(ni),
                       ni->state, netif_mmap_bytes);
    return rc;
  }
  netif_tcp_helper_build2(ni);

  return rc;
}

#endif


ci_inline void netif_tcp_helper_free(ci_netif* ni)
{
#ifdef __KERNEL__
  efab_thr_release(netif2tcp_helper_resource(ni));
#else
  netif_tcp_helper_munmap(ni);
#endif
}


static void init_resource_alloc(ci_resource_onload_alloc_t* ra,
                                const ci_netif_config_opts* opts,
                                unsigned flags, const char* name)
{
  memset(ra, 0, sizeof(*ra));
  CI_USER_PTR_SET(ra->in_opts, opts);
  ra->in_flags = (ci_uint16) flags;
  /* No need to NULL terminate these -- driver must assume they're not in
   * any case.
   */
  strncpy(ra->in_version, ONLOAD_VERSION, sizeof(ra->in_version));
  strncpy(ra->in_uk_intf_ver, OO_UK_INTF_VER, sizeof(ra->in_uk_intf_ver));
  if( name != NULL )
    strncpy(ra->in_name, name, CI_CFG_STACK_NAME_LEN);
}


#ifndef __KERNEL__

static int
netif_tcp_helper_alloc_u(ef_driver_handle fd, ci_netif* ni,
                         const ci_netif_config_opts* opts, unsigned flags,
                         const char* stack_name)
{
  ci_resource_onload_alloc_t ra;
  int rc;
  ci_netif_state* ns;
  void* p;

  /****************************************************************************
   * Allocate the TCP Helper resource.
   */
  init_resource_alloc(&ra, opts, flags, stack_name);

  rc = oo_resource_alloc(fd, &ra);
  if( rc < 0 ) {
    switch( rc ) {
    case -ELIBACC: {
      static int once;
      if( ! once ) {
        once = 1;
        ci_log("ERROR: Driver/Library version mismatch detected.");
        ci_log("This application will not be accelerated.");
        ci_log("HINT: Most likely you need to reload the sfc and onload "
               "drivers");
      }
      break;
    }
    case -EEXIST:
      /* This is not really an error.  It means we "raced" with another thread
       * to create a stack with this name, and the other guy won the race.  We
       * return the error code and further up the call-chain we'll retry to
       * attach to the stack with the given name.
       */
      break;
    case -ENODEV:
      LOG_E(ci_log("%s: This error can occur if no Solarflare network "
		   "interfaces are active/UP. Please check your config with "
		   "ip addr or ifconfig", __FUNCTION__));
      break;
    default:
      LOG_E(ci_log("%s: ERROR: Failed to allocate stack (rc=%d)",
                   __FUNCTION__, rc));
      break;
    }
    return rc;
  }

  /****************************************************************************
   * Perform post-alloc driver setup.
   */
  ni->nic_set = ra.out_nic_set;
  LOG_NC(ci_log("%s: nic set " EFRM_NIC_SET_FMT, __FUNCTION__,
	                efrm_nic_set_pri_arg(&ni->nic_set)));
  ni->mmap_bytes = ra.out_netif_mmap_bytes;

  /****************************************************************************
   * Set up the mem mmaping.
   */
  rc = oo_resource_mmap(fd, CI_NETIF_MMAP_ID_STATE,
                        ra.out_netif_mmap_bytes, &p);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: oo_resource_mmap %d", __FUNCTION__, rc));
    /* nothing to clear up: return */
    return rc;
  }

  ns = ni->state = (ci_netif_state*) p;
  ci_assert_equal(ra.out_netif_mmap_bytes, NS_MMAP_SIZE(ns));

#ifndef CI_HAVE_OS_NOPAGE
  {
    int shmbuflistlen;
    shmbuflistlen = ((opts->max_ep_bufs + EP_BUF_BLOCKNUM - 1)
                     >> EP_BUF_BLOCKSHIFT) + 1;
    ni->u_shmbufs = ci_alloc(sizeof(void *) * shmbuflistlen);
    if( ! ni->u_shmbufs ) {
      ci_log("Driver memory allocation failed");
      rc=-ENOMEM;
      goto fail;
    }
    memset(ni->u_shmbufs, 0, sizeof(void*) * shmbuflistlen);
    ni->u_shmbufs[0] = ns;
  }
#endif

  /****************************************************************************
   * Final Debug consistency check
   */
  if( !!(ns->flags & CI_NETIF_FLAG_DEBUG) != CI_DEBUG(1+)0 ) {
    ci_log("ERROR: Driver/Library debug build mismatch detected (%d,%d)",
           !!(ns->flags & CI_NETIF_FLAG_DEBUG), CI_DEBUG(1+)0 );
    rc = -ELIBACC;
    goto fail;
  }

  if( ns->flags & CI_NETIF_FLAG_ONLOAD_UNSUPPORTED ) {
    ci_log("*** Warning: use of "ONLOAD_PRODUCT" with this adapter is likely");
    ci_log("***  to show suboptimal performance for all cases other than the");
    ci_log("***  most trivial benchmarks.  Please see your Solarflare");
    ci_log("***  representative/reseller to obtain an Onload-capable");
    ci_log("***  adapter.");
  }

  /****************************************************************************
   * Construct / attach to resources which are described in the shared state
   */
  rc = netif_tcp_helper_build(ni);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: netif_tcp_helper_build failed rc=%d", __FUNCTION__, rc));
    goto fail;
  }
  netif_tcp_helper_build2(ni);

  return 0;

 fail:
  netif_tcp_helper_free(ni);
  return rc;
}

#else  /* __KERNEL__ */

static int
netif_tcp_helper_alloc_k(ci_netif** ni_out, const ci_netif_config_opts* opts,
                         unsigned flags, const int* ifindices,
                         int ifindices_len)
{
  ci_resource_onload_alloc_t ra;
  tcp_helper_resource_t* trs;
  ci_netif* ni;
  int rc;

  init_resource_alloc(&ra, opts, flags, NULL);
  rc = tcp_helper_alloc_kernel(&ra, opts, ifindices, ifindices_len, &trs);
  if( rc < 0 ) {
    ci_log("%s: tcp_helper_alloc_kernel() failed (%d)", __FUNCTION__, rc);
    return rc;
  }

  ni = &trs->netif;
  ni->nic_set = ra.out_nic_set;
  netif_tcp_helper_build2(ni);

  *ni_out = ni;
  return 0;
}

#endif


/*****************************************************************************
 *                                                                           *
 *          Netif Creation and Destruction                                   *
 *          ==============================                                   *
 *                                                                           *
 *****************************************************************************/



static void ci_netif_sanity_checks(void)
{
  /* These had better be true, or there'll be trouble! */
  ci_assert_le(sizeof(citp_waitable_obj), CI_PAGE_SIZE);
  ci_assert_equal(EP_BUF_SIZE * EP_BUF_PER_PAGE, CI_PAGE_SIZE);
  ci_assert_le(sizeof(citp_waitable_obj), EP_BUF_SIZE);
  ci_assert_equal((1u << CI_SB_FLAG_WAKE_RX_B), CI_SB_FLAG_WAKE_RX);
  ci_assert_equal((1u << CI_SB_FLAG_WAKE_TX_B), CI_SB_FLAG_WAKE_TX);
#ifndef NDEBUG
  {
    int i = CI_MEMBER_OFFSET(ci_ip_cached_hdrs, ip);
    int e = CI_MEMBER_OFFSET(ci_ip_cached_hdrs, ether_header);
    int h = CI_MEMBER_OFFSET(ci_ip_cached_hdrs, hwport);
    ci_assert_equal(i - e, ETH_HLEN + 4);
    ci_assert_equal(i - h, ETH_HLEN + 4 + 2);
  }
#endif

  /* Warn if we're wasting memory. */
  if( sizeof(citp_waitable_obj) * 2 <= EP_BUF_SIZE )
    ci_log("%s: EP_BUF_SIZE=%d larger than necessary (%d)", __FUNCTION__,
           (int) sizeof(citp_waitable_obj), EP_BUF_SIZE);
}


static int ci_netif_pkt_reserve(ci_netif* ni, int n, oo_pkt_p* p_pkt_list)
{
  ci_ip_pkt_fmt* pkt;
  int i;

  for( i = 0; i < n; ++i ) {
    if( (pkt = ci_netif_pkt_alloc(ni)) == NULL )
      break;
    *p_pkt_list = OO_PKT_P(pkt);
    p_pkt_list = &pkt->next;
  }
  *p_pkt_list = OO_PP_NULL;
  return i;
}


static void ci_netif_pkt_reserve_free(ci_netif* ni, oo_pkt_p pkt_list, int n)
{
  ci_ip_pkt_fmt* pkt;
  while( OO_PP_NOT_NULL(pkt_list) ) {
    CI_DEBUG(--n);
    pkt = PKT_CHK(ni, pkt_list);
    pkt_list = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }

  ci_assert_equal(n, 0);
  ci_assert(OO_PP_IS_NULL(pkt_list));
}


#ifndef __KERNEL__

static int ci_netif_pkt_prefault(ci_netif* ni)
{
  /* Touch all allocated packet buffers so we don't incur the cost of
   * faulting them info this address space later.
   *
   * The return value is not useful, and only exists to prevent
   * optimisations that would render this function useless.  This is also
   * the reason the function is not static.
   *
   * Similarly, the cast into volatile is designed to prevent compiler
   * optimisations.
   */
  ci_ip_pkt_fmt* pkt;
  int i, n;
  int rc = 0;

  if( NI_OPTS(ni).prefault_packets ) {
    n = ni->state->n_pkts_allocated;
    for( i = 0; i < n; ++i ) {
      pkt = PKT(ni, i);
      rc += *(volatile ci_int32*)(&pkt->refcount);
    }
  }
  return rc;
}


static void ci_netif_pkt_prefault_reserve(ci_netif* ni)
{
  oo_pkt_p pkt_list;
  int n;

  if( ! NI_OPTS(ni).prefault_packets )
    return;

  ci_netif_lock(ni);
  n = ci_netif_pkt_reserve(ni, NI_OPTS(ni).prefault_packets, &pkt_list);
  if( n < NI_OPTS(ni).prefault_packets )
    LOG_E(ci_log("%s: Prefaulted only %d of %d",
                 __FUNCTION__, n, NI_OPTS(ni).prefault_packets));
  ci_netif_pkt_reserve_free(ni, pkt_list, n);
  ci_netif_unlock(ni);
}


int ci_netif_ctor(ci_netif* ni, ef_driver_handle fd, const char* stack_name,
                  unsigned flags)
{
  ci_netif_config_opts* opts;
  struct oo_per_thread* per_thread;
  int rc;

  per_thread = oo_per_thread_get();
  opts = per_thread->thread_local_netif_opts != NULL?
    per_thread->thread_local_netif_opts:
    &ci_cfg_opts.netif_opts;

  ci_assert(ni);
  ci_netif_sanity_checks();

  ni->driver_handle = fd;


  /***************************************
  * Allocate kernel helper and link into netif
  */
  if( (rc = netif_tcp_helper_alloc_u(fd, ni, opts, flags, stack_name)) < 0 )
    return rc;

  CI_MAGIC_SET(ni, NETIF_MAGIC);
  ci_netif_pkt_prefault(ni);
  ci_netif_pkt_prefault_reserve(ni);
  oo_atomic_set(&ni->ref_count, 0);
  ni->flags = 0;
  ni->error_flags = 0;

  ci_log("Using "ONLOAD_PRODUCT" "ONLOAD_VERSION" "ONLOAD_COPYRIGHT" [%s]",
         ni->state->pretty_name);
  return 0;
}

#else  /* __KERNEL__ */

int ci_netif_set_rxq_limit(ci_netif* ni)
{
  int intf_i, n_intf, max_ring_pkts, fill_limit;
  int rc = 0, rxq_cap = 0;

  /* Ensure we use a sensible [rxq_limit] when packet buf constrained.
   * This is necessary to ensure that the first interface doesn't fill its
   * RX ring at the expense of the last.
   */
  n_intf = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ef_vi* vi = ci_netif_rx_vi(ni, intf_i);
    rxq_cap = ef_vi_receive_capacity(vi);
    ++n_intf;
  }
  /* We allow up to 80% of the total RX packet buf allocation to go in the
   * rings.  If we let the full allocation go in the rings it can be
   * impossible to get out of OO_MEM_PRESSURE_CRITICAL, due to rounding
   * effects.
   */
  max_ring_pkts = NI_OPTS(ni).max_rx_packets * 4 / 5;
  fill_limit = rxq_cap;
  if( fill_limit * n_intf > max_ring_pkts )
    fill_limit = max_ring_pkts / n_intf;
  if( fill_limit < NI_OPTS(ni).rxq_limit ) {
    if( fill_limit < rxq_cap )
      LOG_W(ci_log("WARNING: "N_FMT "RX ring fill level reduced from %d to %d "
                   "max_ring_pkts=%d rxq_cap=%d n_intf=%d",
                   N_PRI_ARGS(ni), NI_OPTS(ni).rxq_limit, fill_limit,
                   max_ring_pkts, rxq_cap, n_intf));
    ni->opts.rxq_limit = fill_limit;
    ni->state->opts.rxq_limit = fill_limit;
  }
  if( ni->nic_n == 0 ) {
    /* we do not use .rxq_limit, but let's make all checkers happy */
     NI_OPTS(ni).rxq_limit = CI_CFG_RX_DESC_BATCH;
  }
  else if( NI_OPTS(ni).rxq_limit < NI_OPTS(ni).rxq_min ) {
    /* Do not allow user to create a stack that is too severely
     * constrained.
     */
    LOG_E(ci_log("ERROR: "N_FMT "rxq_limit=%d is too small (rxq_min=%d)",
                 N_PRI_ARGS(ni), NI_OPTS(ni).rxq_limit, NI_OPTS(ni).rxq_min);
          ci_log("HINT: Use a larger value for EF_RXQ_LIMIT or "
                 "EF_MAX_RX_PACKETS or EF_MAX_PACKETS"));
    rc = -EINVAL;
    /* NB. This isn't just called at init time -- it is also called after
     * failure to allocate more packet buffers.  So we must leave
     * [rxq_limit] with a legal value.
     */
    NI_OPTS(ni).rxq_limit = 2 * CI_CFG_RX_DESC_BATCH + 1;
  }
  ni->state->rxq_limit = NI_OPTS(ni).rxq_limit;
  return rc;
}


static int __ci_netif_init_fill_rx_rings(ci_netif* ni)
{
  /* Saving rxq_limit as it may get modified during call to
   * ci_netif_rx_post().
   */
  int intf_i, rxq_limit = ni->state->rxq_limit;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ci_netif_rx_post(ni, intf_i);
    if( ef_vi_receive_fill_level(ci_netif_rx_vi(ni, intf_i)) < rxq_limit )
      return -ENOMEM;
  }
  return 0;
}


int ci_netif_init_fill_rx_rings(ci_netif* ni)
{
  oo_pkt_p pkt_list;
  int lim, rc, n;

#if CI_CFG_PKTS_AS_HUGE_PAGES
  ni->huge_pages_flag = NI_OPTS(ni).huge_pages;
#endif
  ci_netif_mem_pressure_pkt_pool_fill(ni);
  if( (rc = ci_netif_set_rxq_limit(ni)) < 0 )
    return rc;

  /* Reserve some packet buffers for the free pool. */
  n = ci_netif_pkt_reserve(ni, NI_OPTS(ni).min_free_packets, &pkt_list);
  if( n < NI_OPTS(ni).min_free_packets ) {
    LOG_E(ci_log("%s: ERROR: Insufficient packet buffers available for "
                 "EF_MIN_FREE_PACKETS=%d", __FUNCTION__,
                 NI_OPTS(ni).min_free_packets));
    return -ENOMEM;
  }

  /* Fill the RX rings a little at a time.  Reason is to ensure that if we
   * are short of packet buffers, we don't fill some rings completely and
   * leave others empty.
   */
  for( lim = CI_CFG_RX_DESC_BATCH; lim <= NI_OPTS(ni).rxq_limit;
       lim += CI_CFG_RX_DESC_BATCH ) {
    ni->state->rxq_limit = lim;
    if( (rc = __ci_netif_init_fill_rx_rings(ni)) < 0 || ni->state->rxq_low ) {
      rc = -ENOMEM;
      if( lim < NI_OPTS(ni).rxq_min )
        LOG_E(ci_log("%s: ERROR: Insufficient packet buffers to fill RX rings "
                     "(rxq_limit=%d rxq_low=%d rxq_min=%d)", __FUNCTION__,
                     NI_OPTS(ni).rxq_limit, ni->state->rxq_low,
                     NI_OPTS(ni).rxq_min));
#if CI_CFG_PKTS_AS_HUGE_PAGES
      else if( ni->huge_pages_flag == 2 )
        LOG_E(ci_log("%s: ERROR: Failed to allocate huge pages to fill RX "
                     "rings", __FUNCTION__));
      else
#endif
        rc = 0;
      break;
    }
  }

  ci_netif_pkt_reserve_free(ni, pkt_list, n);
  ni->state->rxq_limit =  NI_OPTS(ni).rxq_limit;

#if CI_CFG_PKTS_AS_HUGE_PAGES
  /* Initial packets allocated: allow other packets to be in non-huge pages
   * if necessary.
   */
  if( ni->huge_pages_flag == 2 )
    ni->huge_pages_flag = 1;
#endif
  return rc;
}


int ci_netif_ctor(ci_netif** ni_out, const ci_netif_config_opts* opts_in,
                  unsigned flags)
{
  ci_netif_config_opts* opts;
  ci_netif* ni;

  ci_assert(ni_out);
  ci_netif_sanity_checks();

  ni = *ni_out = NULL;

  if( opts_in )
    opts = (ci_netif_config_opts*)opts_in;
  else {
    /* Allocate opts from the heap, do not use the stack. */
    if( (opts = ci_alloc(sizeof(*opts))) == NULL )
      return -ENOMEM;
    ci_netif_config_opts_defaults(opts);
  }

  /***************************************
  * Allocate kernel helper and link into netif
  */
  /* TODO: Let caller specify the nics to use. */
  CI_TRY_RET(netif_tcp_helper_alloc_k(&ni, opts, flags, NULL, 0));

  /* sanity -- killme */
  ci_assert_equal(ni->ep_ofs, ni->state->ep_ofs);

  if( !opts_in )
    ci_free(opts);

  ni->flags |= CI_NETIF_FLAGS_IS_TRUSTED;

  *ni_out = ni;
  return 0;
}

#endif


int ci_netif_dtor(ci_netif* ni)
{
  ci_assert(ni);

  /* \TODO Check if we should be calling ci_ipid_dtor() here. */
  /* Free the TCP helper resource */
  netif_tcp_helper_free(ni);

  return 0;
}


#ifndef __KERNEL__

static int install_stack_by_id(ci_fd_t fp, unsigned id)
{
  ci_uint32 stack_id = id;
  return oo_resource_op(fp, OO_IOC_INSTALL_STACK_BY_ID, &stack_id);
}


static int install_stack_by_name(ci_fd_t fd, const char* name)
{
  struct oo_op_install_stack op;
  /* NB. No need to ensure it is NULL terminated: kernel has to anyway. */
  strncpy(op.in_name, name, CI_CFG_STACK_NAME_LEN);
  return oo_resource_op(fd, OO_IOC_INSTALL_STACK, &op);
}


/* This is used by utilities such as stackdump to restore an abitrary netif */
int ci_netif_restore_id(ci_netif* ni, unsigned thr_id)
{
  ef_driver_handle fd, fd2;
  ci_uint32 map_size;
  int rc;

  ci_assert(ni);

  LOG_NV(ci_log("%s: %u", __FUNCTION__, thr_id));

  /* Create a new fd, and attach the netif to it.  This is just a stepping
   * stone to give us something we can pass to ci_tcp_helper_stack_attach().
   */
  CI_TRY(ef_onload_driver_open(&fd2, 1));
  rc = install_stack_by_id(fd2, thr_id);
  if( rc != 0 ) {
    CI_TRY(ef_onload_driver_close(fd2));
    return rc;
  }
  fd = ci_tcp_helper_stack_attach(fd2, &ni->nic_set, &map_size);
  if( fd < 0 )
    return fd;
  CI_TRY(ef_onload_driver_close(fd2));
  return ci_netif_restore(ni, fd, map_size);
}


int ci_netif_restore_name(ci_netif* ni, const char* name)
{
  ef_driver_handle fd, fd2;
  ci_uint32 map_size;
  int rc;

  ci_assert(ni);

  LOG_NV(ci_log("%s: %s", __FUNCTION__, name));

  /* Create a new fd, and attach the netif to it.  This is just a stepping
   * stone to give us something we can pass to ci_tcp_helper_stack_attach().
   */
  if( (rc = ef_onload_driver_open(&fd2, 1)) < 0 )
    goto fail1;
  if( (rc = install_stack_by_name(fd2, name)) < 0 )
    goto fail2;
  if( (rc = fd = ci_tcp_helper_stack_attach(fd2,
                                            &ni->nic_set, &map_size)) < 0 )
    goto fail3;
  if( (rc = ci_netif_restore(ni, fd, map_size)) < 0 )
    goto fail4;
  ef_onload_driver_close(fd2);
  ci_log("Sharing "ONLOAD_PRODUCT" "ONLOAD_VERSION" "ONLOAD_COPYRIGHT
         " [%s]", ni->state->pretty_name);
  return 0;

 fail4:
  ef_onload_driver_close(fd);
 fail3:
 fail2:
  ef_onload_driver_close(fd2);
 fail1:
  return rc;
}


/* this is called by ci_netif_resource_using_handle, and also when tranferring
 * a netif to a new process (e.g. if the fd is used after a fork/exec). For
 * now we still need the handle but this parameter may be removed one day.
 */
int ci_netif_restore(ci_netif* ni, ef_driver_handle fd,
                     unsigned netif_mmap_bytes)
{
  int rc = 0;
  ci_assert(ni);
  
  LOG_NV(ci_log("%s: fd=%d", __FUNCTION__, fd));

  ni->driver_handle = fd;
  ni->flags = 0;

  CI_TRY_RET(netif_tcp_helper_restore(ni, netif_mmap_bytes));

#ifndef CI_HAVE_OS_NOPAGE
  {
    int shmbuflistlen;
    shmbuflistlen = ((ni->state->max_ep_bufs + EP_BUF_BLOCKNUM -1)
                     >> EP_BUF_BLOCKSHIFT) + 1;
    ni->u_shmbufs = ci_alloc(shmbuflistlen * sizeof(void*));
    if( ! ni->u_shmbufs )  return -ENOMEM;
    memset(ni->u_shmbufs, 0,  shmbuflistlen * sizeof(void*));
    ni->u_shmbufs[0] = ni->state;
  }
#endif

  /* We do not want this stack to be used as default */
  ni->flags |= CI_NETIF_FLAGS_DONT_USE_ANON;

  CI_MAGIC_SET(ni, NETIF_MAGIC);

  /* We don't CHECK_NI(ni) here, as it needs the netif lock and we have
   * the fdtable lock at this point.  The netif will be checked later
   * when used.
   */

  return rc;
}

#endif

/*! \cidoxg_end */
