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
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Map in shared state of U/L stack, dump info, and do stuff.
**   \date  2005/01/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */
#include <stdlib.h>
#include <ci/internal/ip.h>
#include <ci/internal/cplane_ops.h>
#include <ci/internal/cplane_handle.h>
#include <onload/driveraccess.h>
#include <onload/ioctl.h>
#include <onload/debug_intf.h>
#include <onload/debug_ops.h>
#include <onload/ul/tcp_helper.h>
#include <ci/app.h>
#include <etherfabric/vi.h>
#include "libstack.h"
#include <ci/internal/ip_signal.h>
#include <dirent.h>

#undef DO
#undef IGNORE

#define DO(_x) _x
#define IGNORE(_x)


#if CI_CFG_USERSPACE_PIPE
# define CI_TCP_STATE_PIPE_BUF_NUM (CI_TCP_STATE_NUM(CI_TCP_STATE_PIPE)+1)
# define N_STATES  (CI_TCP_STATE_NUM(CI_TCP_STATE_PIPE) + 2)
#else
# define N_STATES  (CI_TCP_STATE_NUM(CI_TCP_STATE_UDP) + 1)
#endif


typedef struct {
  unsigned        rx_evs_per_poll;
  unsigned        tx_evs_per_poll;
} dstats_t;


typedef struct {
  unsigned        states[N_STATES + 1];
  unsigned        sock_orphans;
  unsigned        sock_wake_needed_rx;
  unsigned        sock_wake_needed_tx;
  unsigned        tcp_has_recvq;
  unsigned        tcp_recvq_bytes;
  unsigned        tcp_recvq_pkts;
  unsigned        tcp_has_recv_reorder;
  unsigned        tcp_recv_reorder_pkts;
  unsigned        tcp_has_sendq;
  unsigned        tcp_sendq_bytes;
  unsigned        tcp_sendq_pkts;
  unsigned        tcp_has_inflight;
  unsigned        tcp_inflight_bytes;
  unsigned        tcp_inflight_pkts;
  unsigned        tcp_n_in_listenq;
  unsigned        tcp_n_in_acceptq;
  unsigned        udp_has_recvq;
  unsigned        udp_recvq_bytes;
  unsigned        udp_recvq_pkts;
  unsigned        udp_has_sendq;
  unsigned        udp_sendq_bytes;
  unsigned        udp_tot_recv_pkts_ul;
  unsigned        udp_tot_recv_drops_ul;
  unsigned        udp_tot_recv_pkts_os;
  unsigned        udp_tot_send_pkts_ul;
  unsigned        udp_tot_send_pkts_os;
  unsigned        ef_vi_rx_ev_lost;
  unsigned        ef_vi_rx_ev_bad_desc_i;
  unsigned        ef_vi_rx_ev_bad_q_label;
  unsigned        ef_vi_evq_gap;
} more_stats_t;


typedef struct {
  int		stack;
  int		id;
  void*		s;	/* misc state */
} socket_t;


typedef struct {
  unsigned	offset;
  unsigned	size;
  const char*	name;
  const char*   description;
# define STAT_COUNT     0x1
# define STAT_TCP       0x2
# define STAT_UDP       0x4
  unsigned	flags;
} stat_desc_t;


#define stat_initialiser(type_t, field, name_, desc_, flags_)   \
  { .offset = CI_MEMBER_OFFSET(type_t, field),                  \
    .size = CI_MEMBER_SIZE(type_t, field),                      \
    .name = (name_),                                            \
    .description = (desc_),                                     \
    .flags = (flags_)                                           \
  }

#define stat_desc_nm(type_t, field, nm, flags)          \
  stat_initialiser(type_t, field, (nm), NULL, (flags))

#define stat_desc(type_t, field, flags)             \
  stat_desc_nm(type_t, field, (#field), (flags))

#undef  OO_STAT
#define OO_STAT(desc, datatype, name, kind)     \
  OO_STAT_##kind(name, (desc)),
#define OO_STAT_count(name, desc)                                       \
  stat_initialiser(ci_netif_stats, name, (#name), (desc), STAT_COUNT)
#define OO_STAT_val(name, desc)                                 \
  stat_initialiser(ci_netif_stats, name, (#name), (desc), 0)


static stat_desc_t netif_stats_fields[] = {
#include <ci/internal/stats_def.h>
};
#define N_NETIF_STATS_FIELDS                                    \
  (sizeof(netif_stats_fields) / sizeof(netif_stats_fields[0]))


static stat_desc_t netif_dstats_fields[] = {
#define ns(x)  stat_desc_nm(dstats_t, x, (#x), 0)
  ns(rx_evs_per_poll),
  ns(tx_evs_per_poll),
#undef ns
};
#define N_NETIF_DSTATS_FIELDS                                    \
  (sizeof(netif_dstats_fields) / sizeof(netif_dstats_fields[0]))


static stat_desc_t more_stats_fields[] = {
#define ss(x)                                                           \
   stat_desc_nm(more_stats_t, states[CI_TCP_STATE_NUM(CI_##x)], #x, 0)
#define ns(x)   stat_desc(more_stats_t, x, 0)
#define nsa(x)  stat_desc(more_stats_t, x, STAT_COUNT)
#define ts(x)   stat_desc(more_stats_t, x, STAT_TCP)
#define us(x)   stat_desc(more_stats_t, x, STAT_UDP)
#define usa(x)  stat_desc(more_stats_t, x, STAT_UDP | STAT_COUNT)
  ss(TCP_CLOSED),
  ss(TCP_LISTEN),
  ss(TCP_SYN_SENT),
  ss(TCP_ESTABLISHED),
  ss(TCP_CLOSE_WAIT),
  ss(TCP_LAST_ACK),
  ss(TCP_FIN_WAIT1),
  ss(TCP_FIN_WAIT2),
  ss(TCP_CLOSING),
  ss(TCP_TIME_WAIT),
  ss(TCP_STATE_FREE),
  ss(TCP_STATE_UDP),
#if CI_CFG_USERSPACE_PIPE
  ss(TCP_STATE_PIPE),
  stat_desc_nm(more_stats_t, states[CI_TCP_STATE_PIPE_BUF_NUM],
               "PIPE_BUFS", 0),
#endif
  stat_desc_nm(more_stats_t, states[N_STATES], "BAD_STATE", 0),
  ns(sock_orphans),
  ns(sock_wake_needed_rx),
  ns(sock_wake_needed_tx),
  ts(tcp_has_recvq),
  ts(tcp_recvq_bytes),
  ts(tcp_recvq_pkts),
  ts(tcp_has_recv_reorder),
  ts(tcp_recv_reorder_pkts),
  ts(tcp_has_sendq),
  ts(tcp_sendq_bytes),
  ts(tcp_sendq_pkts),
  ts(tcp_has_inflight),
  ts(tcp_inflight_bytes),
  ts(tcp_inflight_pkts),
  ts(tcp_n_in_listenq),
  ts(tcp_n_in_acceptq),
  us(udp_has_recvq),
  us(udp_recvq_bytes),
  us(udp_recvq_pkts),
  us(udp_has_sendq),
  us(udp_sendq_bytes),
  usa(udp_tot_recv_pkts_ul),
  usa(udp_tot_recv_drops_ul),
  usa(udp_tot_recv_pkts_os),
  usa(udp_tot_send_pkts_ul),
  usa(udp_tot_send_pkts_os),
  nsa(ef_vi_rx_ev_lost),
  nsa(ef_vi_rx_ev_bad_desc_i),
  nsa(ef_vi_rx_ev_bad_q_label),
  nsa(ef_vi_evq_gap),
#undef ns
#undef nsa
#undef ts
#undef us
#undef usa
};
#define N_MORE_STATS_FIELDS                                     \
  (sizeof(more_stats_fields) / sizeof(more_stats_fields[0]))


#if CI_CFG_SUPPORT_STATS_COLLECTION

static stat_desc_t ip_stats_fields[] = {
#define ns(x)  stat_desc(ci_ipv4_stats_count, x, STAT_COUNT)
  ns(in_recvs),
  ns(in_hdr_errs),
  ns(in_addr_errs),
  ns(forw_dgrams),
  ns(in_unknown_protos),
  ns(in_discards),
  ns(in_delivers),
  ns(out_requests),
  ns(out_discards),
  ns(out_no_routes),
  ns(reasm_timeout),
  ns(reasm_reqds),
  ns(reasm_oks),
  ns(reasm_fails),
  ns(frag_oks),
  ns(frag_fails),
  ns(frag_creates),
#undef ns
};
#define N_IP_STATS_FIELDS                                       \
  (sizeof(ip_stats_fields) / sizeof(ip_stats_fields[0]))


static stat_desc_t tcp_stats_fields[] = {
#define ns(x)  stat_desc(ci_tcp_stats_count, x, STAT_COUNT)
  ns(tcp_active_opens),
  ns(tcp_passive_opens),
  ns(tcp_attempt_fails),
  ns(tcp_estab_resets),
  ns(tcp_curr_estab),
  ns(tcp_in_segs),
  ns(tcp_out_segs),
  ns(tcp_retran_segs),
  ns(tcp_in_errs),
  ns(tcp_out_rsts),
#undef ns
};
#define N_TCP_STATS_FIELDS                                      \
  (sizeof(tcp_stats_fields) / sizeof(tcp_stats_fields[0]))


static stat_desc_t udp_stats_fields[] = {
#define ns(x)  stat_desc(ci_udp_stats_count, x, STAT_COUNT)
  ns(udp_in_dgrams),
  ns(udp_no_ports),
  ns(udp_in_errs),
  ns(udp_out_dgrams),
#undef ns
};
#define N_UDP_STATS_FIELDS                                      \
  (sizeof(udp_stats_fields) / sizeof(udp_stats_fields[0]))


static stat_desc_t tcp_ext_stats_fields[] = {
#define ns(x)  stat_desc(ci_tcp_ext_stats_count, x, STAT_COUNT)
  ns(syncookies_sent),
  ns(syncookies_recv),
  ns(syncookies_failed),
  ns(embrionic_rsts),
  ns(prune_called),
  ns(rcv_pruned),
  ns(ofo_pruned),
  ns(out_of_window_icmps),
  ns(lock_dropped_icmps),
  ns(arp_filter),
  ns(time_waited),
  ns(time_wait_recycled),
  ns(time_wait_killed),
  ns(paws_passive_rejected),
  ns(paws_active_rejected),
  ns(paws_estab_rejected),
  ns(delayed_ack),
  ns(delayed_ack_locked),
  ns(delayed_ack_lost),
  ns(listen_overflows),
  ns(listen_drops),
  ns(tcp_prequeued),
  ns(tcp_direct_copy_from_backlog),
  ns(tcp_direct_copy_from_prequeue),
  ns(tcp_prequeue_dropped),
  ns(tcp_hp_hits),
  ns(tcp_hp_hits_to_user),
  ns(tcp_pure_acks),
  ns(tcp_hp_acks),
  ns(tcp_reno_recovery),
  ns(tcp_sack_recovery),
  ns(tcp_sack_reneging),
  ns(tcp_fack_reorder),
  ns(tcp_sack_reorder),
  ns(tcp_reno_reorder),
  ns(tcp_ts_reorder),
  ns(tcp_full_undo),
  ns(tcp_partial_undo),
  ns(tcp_loss_undo),
  ns(tcp_sack_undo),
  ns(tcp_loss),
  ns(tcp_lost_retransmit),
  ns(tcp_reno_failures),
  ns(tcp_sack_failures),
  ns(tcp_loss_failures),
  ns(tcp_timeouts),
  ns(tcp_reno_recovery_fail),
  ns(tcp_sack_recovery_fail),
  ns(tcp_fast_retrans),
  ns(tcp_forward_retrans),
  ns(tcp_slow_start_retrans),
  ns(tcp_scheduler_failures),
  ns(tcp_rcv_collapsed),
  ns(tcp_dsack_old_sent),
  ns(tcp_dsack_ofo_sent),
  ns(tcp_dsack_recv),
  ns(tcp_dsack_ofo_recv),
  ns(tcp_abort_on_syn),
  ns(tcp_abort_on_data),
  ns(tcp_abort_on_close),
  ns(tcp_abort_on_memory),
  ns(tcp_abort_on_timeout),
  ns(tcp_abort_on_linger),
  ns(tcp_abort_failed),
  ns(tcp_memory_pressures),
#undef ns
};
#define N_TCP_EXT_STATS_FIELDS                                          \
  (sizeof(tcp_ext_stats_fields) / sizeof(tcp_ext_stats_fields[0]))

#endif  /* CI_CFG_SUPPORT_STATS_COLLECTION */


struct pid_mapping {
  struct pid_mapping* next;
  int*                stack_ids;
  int                 n_stack_ids;
  pid_t               pid;
};
static struct pid_mapping* pid_mappings;


struct stack_mapping {
  struct stack_mapping* next;
  pid_t*                pids;
  int                   n_pids;
  int                   stack_id;
};
static struct stack_mapping* stack_mappings;


static sa_sigaction_t*  libstack_signal_handlers;
static int              signal_fired;

static netif_t**	stacks;
static int		stacks_size;
static ci_dllist	stacks_list;
static socket_t*	sockets;
static int		sockets_n, sockets_size;

/* Config options -- may be modified by clients. */
int		cfg_lock;
int		cfg_nolock;
int             cfg_blocklock;
int		cfg_nosklock;
int		cfg_dump;
int		cfg_watch_msec = 1000;
unsigned	cfg_usec = 10000;
unsigned	cfg_samples = 1000;
int             cfg_notable;
int             cfg_zombie = 0;


ci_inline unsigned cycles64_to_usec(ci_uint64 cycles)
{
  static unsigned cpu_khz = -1;
  if( cpu_khz == (unsigned) -1 )
    CI_TRY(ci_get_cpu_khz(&cpu_khz));
  return (unsigned) (cycles * 1000 / cpu_khz);
}


ci_inline ci_uint64 usec_to_cycles64(unsigned usec)
{
  static unsigned cpu_khz = -1;
  if( usec == (unsigned) -1 )
    return (ci_uint64) -1;
  if( cpu_khz == (unsigned) -1 )
    CI_TRY(ci_get_cpu_khz(&cpu_khz));
  return (ci_uint64) usec * cpu_khz / 1000;
}


ci_inline void libstack_defer_signals(citp_signal_info* si)
{
  si->inside_lib = 1;
  ci_compiler_barrier();
}


ci_inline void libstack_process_signals(citp_signal_info* si)
{
  si->inside_lib = 0;
  ci_compiler_barrier();
  if( si->run_pending )
    citp_signal_run_pending(si);
}


static int __try_grab_stack_lock(ci_netif* ni, int* unlock,
                                 const char* caller)
{
  if( cfg_lock || cfg_nolock ) {
    *unlock = 0;
    return 1;
  }
  if( ! (*unlock = libstack_netif_trylock(ni)) )
    ci_log("%s: [%d] could not get lock", caller, NI_ID(ni));
  return *unlock;
}


#define try_grab_stack_lock(ni, unlock)                 \
  __try_grab_stack_lock((ni), (unlock), __FUNCTION__)


netif_t *stack_attached(int id)
{   if (id < 0 || id >= stacks_size)
        return NULL;
    else
        return stacks[id];
}

int libstack_init_signals(int fd)
{
  ci_tramp_reg_args_t args;
  int rc, i;

  CI_USER_PTR_SET (args.trampoline_entry, NULL);
  args.max_signum = NSIG;
  CI_USER_PTR_SET(args.signal_handler_postpone1, citp_signal_intercept_1);
  CI_USER_PTR_SET(args.signal_handler_postpone3, citp_signal_intercept_3);
  for( i = 0; i <= OO_SIGHANGLER_DFL_MAX; i++ )
    CI_USER_PTR_SET(args.signal_handlers[i], libstack_signal_handlers[i]);
  CI_USER_PTR_SET(args.signal_data, citp_signal_data);
  CI_USER_PTR_SET(args.signal_sarestorer, citp_signal_sarestorer_get());

  rc = ci_sys_ioctl (fd, OO_IOC_IOCTL_TRAMP_REG, &args);

  if(rc == -1)
    ci_log ("Error %d registering trampoline handler", errno);
  return rc;
}


static int is_pid(const char* name)
{
  int i;
  for( i = 0; i < strlen(name); ++i ) {
    if( name[i] < '0' || name[i] > '9' )
      return 0;
  }
  return 1;
}


/*
 * Walk /proc/<pid/fd/ to check if any fds refer to onload.  Returns
 * list of onload stacks or -1 on failure.
 */
static int is_onloaded(pid_t pid, int** ret_stacks_ids)
{
  int i;
  char fd_dir_path[256];
  snprintf(fd_dir_path, 256, "/proc/%d/fd", pid);
  DIR* fd_dir = opendir(fd_dir_path);
  if( ! fd_dir )
    return -1;

  int n_stacks = 0;
  int* stack_ids = NULL;
  struct dirent* ent;
  while( (ent = readdir(fd_dir)) ) {
    if( ent->d_name[0] == '.' )
      continue;
    char fd_path[256];
    snprintf(fd_path, 256, "%s/%s", fd_dir_path, ent->d_name);
    char sym_buf[256];
    ssize_t rc = readlink(fd_path, sym_buf, 256);
    if( rc == -1 ) {
      closedir(fd_dir);
      return rc;
    }
    sym_buf[rc] = '\0';
    if( ! strncmp(sym_buf, "onload", strlen("onload")) &&
        ! strstr(sym_buf, "stack") ) {
      char* ptr = strchr(sym_buf, '[');
      ptr = strchr(ptr, ':');
      ++ptr;
      int stack_id = atoi(ptr);
      int stack_seen = 0;
      for( i = 0; i < n_stacks; ++i ) {
        if( stack_ids[i] == stack_id )
          stack_seen = 1;
      }
      if( ! stack_seen ) {
        stack_ids = realloc(stack_ids, sizeof(*stack_ids) * (n_stacks + 1));
        stack_ids[n_stacks] = stack_id;
        ++n_stacks;
      }
    }
  }
  closedir(fd_dir);
  *ret_stacks_ids = stack_ids;
  return n_stacks;
}


static int libstack_mappings_init(void)
{
  int rc, i;
  pid_t my_pid = getpid();

  DIR* proc = opendir("/proc");
  if( ! proc )
    return -1;

  /* Walk over entire '/proc/' looking into '/proc/<pid>/fd/' to see
   * if there are any onloaded fds. Fill in pid_mappings accordingly.
   */
  struct dirent* ent;
  while( (ent = readdir(proc)) ) {
    if( ! is_pid(ent->d_name) )
      continue;

    pid_t pid = atoi(ent->d_name);
    if( pid == my_pid )
      continue;

    /* http://www.novell.com/support/kb/doc.php?id=3649220 some kernel
     * versions on SUSE have a pid=0 directory which is seen in "ls
     * /proc" but isn't accessible so don't try to read it.
     */
    if( pid == 0 )
      continue;

    int* stack_ids;
    rc = is_onloaded(pid, &stack_ids);
    if( rc == 0 )
      continue;
    if( rc == -1 ) {
      /* EACCES: do not have permissions for this process
       * ENOENT: process have died while we were running here */
      if( errno == EACCES || errno == ENOENT )
        continue;
      closedir(proc);
      return -1;
    }

    struct pid_mapping* pm = calloc(1, sizeof(*pm));
    pm->pid         = pid;
    pm->stack_ids   = stack_ids;
    pm->n_stack_ids = rc;
    pm->next        = pid_mappings;
    pid_mappings    = pm;
  }

  /* Set stack ids in stack_mappings using debug ioctl
   */
  ci_netif_info_t info;
  oo_fd fd;
  CI_TRY(oo_fd_open(&fd));
  info.mmap_bytes = 0;
  info.ni_exists = 0;
  i = 0;
  while( i >= 0 ) {
    info.ni_index = i;
    info.ni_orphan = cfg_zombie;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    CI_TRY(oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info));
    int stack_id = -1;
    if( info.ni_exists )
      stack_id = info.ni_index;
    else if( info.ni_no_perms_exists ) {
      stack_id = info.ni_no_perms_id;
      fprintf(stderr, "User %d:%d cannot access full details of stack %d(%s) "
             "owned by %d:%d share_with=%d\n", (int) getuid(), (int) geteuid(),
             info.ni_no_perms_id, info.ni_no_perms_name,
             (int) info.ni_no_perms_uid, (int) info.ni_no_perms_euid,
             info.ni_no_perms_share_with);
    }

    if( stack_id != -1 ) {
      struct stack_mapping* sm = calloc(1, sizeof(*sm));
      sm->stack_id = stack_id;
      sm->next = stack_mappings;
      stack_mappings = sm;
    }
    i = info.u.ni_next_ni.index;
  }
  CI_TRY(oo_fd_close(fd));

  /* Fill in pids in stack_mappings using pid_mappings
   */
  struct pid_mapping* pm = pid_mappings;
  while( pm ) {
    for( i = 0; i < pm->n_stack_ids; ++i ) {
      struct stack_mapping* sm = stack_mappings;
      int found_stack = 0;
      while( sm ) {
        if( pm->stack_ids[i] == sm->stack_id ) {
          sm->pids = realloc(sm->pids, sizeof(*sm->pids) * (sm->n_pids + 1));
          sm->pids[sm->n_pids] = pm->pid;
          ++sm->n_pids;
          found_stack = 1;
        }
        sm = sm->next;
      }
      if( ! found_stack )
        fprintf(stderr, "Warning: Traversing /proc found stack %d"
                " which debug ioctl did not\n", pm->stack_ids[i]);
    }
    pm = pm->next;
  }

  closedir(proc);
  return 0;
}


void libstack_stack_mapping_print_pids(int stack_id)
{
  const int buf_len = 1024;
  char buf[buf_len];
  int i, consumed = 0;
  struct stack_mapping* sm = stack_mappings;

  while( sm && sm->stack_id != stack_id )
    sm = sm->next;
  if( sm == NULL ) {
    ci_log("No stack_mapping for stack %d found", stack_id);
    return;
  }

  consumed += snprintf(&buf[consumed], buf_len - consumed, "pids: ");
  for( i = 0; i < sm->n_pids; ++i ) {
    if( i == sm->n_pids - 1 )
      consumed += snprintf(&buf[consumed], buf_len - consumed, "%d",
                           sm->pids[i]);
    else
      consumed += snprintf(&buf[consumed], buf_len - consumed, "%d,",
                           sm->pids[i]);
  }
  ci_log(buf);
}


void libstack_stack_mapping_print(void)
{
  int i;
  if( ! stack_mappings )
    return;
  printf("#stack-id stack-name      pids\n");
  struct stack_mapping* sm = stack_mappings;
  while( sm ) {
    if( sm->n_pids == 0 ) {
      printf("%-9d -               -\n", sm->stack_id);      
    }
    else {
      stack_attach(sm->stack_id);
      netif_t* netif = stack_attached(sm->stack_id);
      if( strlen(netif->ni.state->name) != 0 )
        printf("%-9d %-16s", sm->stack_id, netif->ni.state->name);
      else
        printf("%-9d -               ", sm->stack_id);

      for( i = 0; i < sm->n_pids; ++i ) {
        printf("%d", sm->pids[i]);
        if( i != sm->n_pids - 1 )
          printf(",");
      }
      printf("\n");
    }
    sm = sm->next;
  }
}


void libstack_pid_mapping_print(void)
{
  int i;
  struct pid_mapping* pm = pid_mappings;
  int max_spacing = 0;
  int cnt;

  if( ! pid_mappings )
    return;

  while( pm ) {
    if( max_spacing < pm->n_stack_ids * 2 + 1 )
      max_spacing = pm->n_stack_ids * 2 + 1;
    pm = pm->next;
  }

  printf("#pid      stack-id");
  if( max_spacing > strlen("stack-id") ) {
    for(i = 0; i < max_spacing - strlen("stack-id") - 1; ++i )
      printf(" ");
  }
  else
    printf(" ");
  printf("cmdline\n");

  pm = pid_mappings;
  while( pm ) {
    printf("%-10d", pm->pid);
    for( i = 0; i < pm->n_stack_ids; ++i ) {
      printf("%d", pm->stack_ids[i]);
      if( i != pm->n_stack_ids - 1 )
        printf(",");
    }
    if( max_spacing > strlen("stack-id") ) {
      for( i = 0; i < max_spacing - pm->n_stack_ids * 2; ++i )
        printf(" ");
    }
    else {
      for( i = 0; i < strlen("stack-id") - pm->n_stack_ids * 2 + 2; ++i )
        printf(" ");
    }

    char cmdline_path[256];
    snprintf(cmdline_path, 256, "/proc/%d/cmdline", pm->pid);
    int cmdline = open(cmdline_path, O_RDONLY);
    char buf[256];
    while( (cnt = read(cmdline, buf, 256)) > 0 ) {
      for( i = 0; i < cnt; ++i ) {
        if( buf[i] == '\0' )
          printf(" ");
        else
          printf("%c", buf[i]);
      }
    }
    printf("\n");

    pm = pm->next;
  }
}


static int get_file_size(const char* path)
{
  int fd = open(path, O_RDONLY);
  if( fd == -1 )
    return -1;
  char buf[128];
  int len = 0;
  while( 1 ) {
    ssize_t rc = read(fd, buf, 128);
    if( rc == -1 )
      return -1;
    len += rc;
    if( rc == 0 )
      return len;
  }
}


static void print_threads_info(pid_t pid)
{
  char task_path[256];
  snprintf(task_path, 256, "/proc/%d/task", pid);
  DIR* task_dir = opendir(task_path);

  struct dirent* ent;
  while( (ent = readdir(task_dir)) ) {
    if( ent->d_name[0] == '.' )
      continue;
    char status_path[256];
    snprintf(status_path, 256, "/proc/%d/task/%s/status", pid, ent->d_name);
    FILE* status = fopen(status_path, "r");
    char buf[256];
    while( fgets(buf, 256, status) ) {
      if( strncmp(buf, "Cpus_allowed:", strlen("Cpus_allowed:")) )
        continue;
      char* ptr = strchr(buf, ':');
      ++ptr;
      while( *ptr == '\t' )
        ++ptr;
      char* newline = strchr(ptr, '\n');
      *newline = '\0';
      printf("task%s: %s\n", ent->d_name, ptr);
    }
  }

  closedir(task_dir);
}


int libstack_affinities_print(void)
{
  int i, cnt;

  if( ! pid_mappings )
    return 0;

  struct pid_mapping* pm = pid_mappings;
  while( pm ) {
    printf("--------------------------------------------\n");
    printf("pid=%d\n", pm->pid);
    printf("cmdline=");
    char cmdline_path[256];
    snprintf(cmdline_path, 256, "/proc/%d/cmdline", pm->pid);
    int cmdline = open(cmdline_path, O_RDONLY);
    char cmdline_buf[256];
    while( (cnt = read(cmdline, cmdline_buf, 256)) > 0 ) {
      for( i = 0; i < cnt; ++i ) {
        if( cmdline_buf[i] == '\0' )
          printf(" ");
        else
          printf("%c", cmdline_buf[i]);
      }
    }
    printf("\n");
    print_threads_info(pm->pid);
    pm = pm->next;
  }
  printf("--------------------------------------------\n");
  return 0;
}


int libstack_env_print(void)
{
  if( ! pid_mappings )
    return 0;

  struct pid_mapping* pm = pid_mappings;
  while( pm ) {
    printf("--------------------------------------------\n");
    printf("pid: %d\n", pm->pid);
    printf("cmdline: ");
    char cmdline_path[256];
    snprintf(cmdline_path, 256, "/proc/%d/cmdline", pm->pid);
    int cmdline = open(cmdline_path, O_RDONLY);
    char cmdline_buf[256];
    while( read(cmdline, cmdline_buf, 256) )
      printf("%s", cmdline_buf);
    printf("\n");
    char env_path[256];
    snprintf(env_path, 256, "/proc/%d/environ", pm->pid);

    int file_len = get_file_size(env_path);
    if( file_len == -1 )
      return -1;

    char* buf = calloc(file_len, sizeof(*buf));
    int env = open(env_path, O_RDONLY);
    if( env == -1 )
      return -1;
    int rc = read(env, buf, file_len);
    if( rc == -1 )
      return rc;
    if( rc != file_len ) {
      fprintf(stderr, "%s: Read less than expected amount\n", __FUNCTION__);
      return -1;
    }

    char* var = buf;
    while( var ) {
      if( ! strncmp(var, "EF_", strlen("EF_")) )
        printf("env: %s\n", var);
      while( *var != '\0' )
        ++var;
      ++var;
      if( var - buf >= file_len )
        break;
    }
    free(buf);
    pm = pm->next;
  }
  printf("--------------------------------------------\n");
  return 0;
}


int stack_attach(unsigned id)
{
  netif_t* n;

  if( id < stacks_size && stacks[id] )  return 1;

  if( id >= stacks_size ) {
    int new_size = CI_MAX(stacks_size * 2, 8);
    new_size = CI_MAX(new_size, id + 1);
    stacks = realloc(stacks, new_size * sizeof(stacks[0]));
    CI_TEST(stacks);
    memset(stacks+stacks_size, 0, (new_size-stacks_size) * sizeof(stacks[0]));
    stacks_size = new_size;
  }
  CI_TEST(n = (netif_t*) malloc(sizeof(*n)));
  CI_ZERO(n);  /* bc: must zero-out UL netif */

  if( ! cfg_zombie ) {
    /* Possibly, this stack was already destroyed, so do not CI_TRY here. */
    int rc = ci_netif_restore_id(&n->ni, id);
    if( rc != 0 )
        return 0;
    if( ci_dllist_is_empty(&stacks_list) )
      libstack_init_signals(ci_netif_get_driver_handle(&n->ni));
  }
  stacks[id] = n;
  ci_dllist_push_tail(&stacks_list, &n->link);

  if( cfg_lock )  libstack_netif_lock(&n->ni);

  return 1;
}

void stack_detach(netif_t* n)
{
  IGNORE(ci_log("detaching netif %d at %p (given %p)\n",
		NI_ID(&n->ni), &n->ni, n););
  if( cfg_lock )  libstack_netif_unlock(&n->ni);
  ci_dllist_remove_safe(&n->link); /* take off stacks_list, if present */

  if( ! cfg_zombie ) {
    int fd = ci_netif_get_driver_handle(&n->ni);
    int id = NI_ID(&n->ni);

    /* Unmap. */
    ci_netif_dtor(&n->ni);
    CI_TRY(ef_onload_driver_close(fd));
    
    stacks[id] = 0;
  }
}


void list_all_stacks(int attach)
{
  ci_netif_info_t info;
  int i = 0;
  oo_fd fd;

  CI_TRY(oo_fd_open(&fd));
  info.mmap_bytes = 0;
  info.ni_exists = 0;

  while( i >= 0 ) {
    info.ni_index = i;
    info.ni_orphan = cfg_zombie;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    CI_TRY(oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info));
    if( info.ni_exists && (!cfg_zombie || info.ni_orphan) ) {
      if( attach )
	stack_attach(i);
      else
	ci_log("%3d: %u", info.ni_index, i);
    }
    i = info.u.ni_next_ni.index;
  }

  CI_TRY(oo_fd_close(fd));
}


void list_all_stacks2(stackfilter_t *filter,
                      stack_ni_fn_t *post_attach, stack_ni_fn_t *pre_detach,
                      oo_fd *p_fd)
{
  ci_netif_info_t info;
  int i = 0;
  oo_fd fd = (oo_fd) -1;

  if( p_fd )
    fd = *p_fd;
  if( fd == (oo_fd) -1 ) {
    CI_TRY(oo_fd_open(&fd));
    if( p_fd )
      *p_fd = fd;
  }

  info.mmap_bytes = 0;
  info.ni_exists = 0;

  while( i >= 0 ) {
    info.ni_index = i;
    info.ni_orphan = 0;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    CI_TRY(oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info));

    if( info.ni_exists ) {
      /* Are we already attached? */
      if( i < stacks_size && stacks[i] != NULL ) {
        ci_assert_ge(info.rs_ref_count, 2);
        //ci_log("known stack %d rs_ref_count=%d", i, info.rs_ref_count);
        /* Is the stack dead?  Should we detach? */
        if( info.rs_ref_count == 2 ) {
          IGNORE(ci_log("We are the only user of stack %d", i));
          if( pre_detach )
            pre_detach(&stacks[i]->ni);
          stack_detach(stacks[i]);
        }
      }
      else if( filter == NULL || filter(&info) ){
        /* New stack, let's attach */
        IGNORE(ci_log("new stack %3d: %u", info.ni_index, i));
        if( stack_attach(i) && post_attach )
          post_attach(&stacks[i]->ni);
      }
    } else if( info.ni_no_perms_exists )
      ci_log("User %d:%d can't share stack %d(%s) owned by %d:%d "
             "share_with=%d", (int) getuid(), (int) geteuid(),
             info.ni_no_perms_id, info.ni_no_perms_name,
             (int) info.ni_no_perms_uid, (int) info.ni_no_perms_euid,
             info.ni_no_perms_share_with);
    i = info.u.ni_next_ni.index;
  }

  if( p_fd == NULL )
    CI_TRY(oo_fd_close(fd));
}

void for_each_stack(void (*fn)(ci_netif* ni), int only_once)
{
  netif_t* n;
  CI_DLLIST_FOR_EACH2(netif_t, n, link, &stacks_list) {
    fn(&n->ni);
    if( only_once )
      break;
  }
}


void for_each_stack_id(void (*fn)(int id, void* arg), void* arg)
{
  int id;
  for (id=0; id<stacks_size; id++)
    if (stacks[id] != 0)
       (*fn)(id, arg);
}


void stacks_detach_all(void)
{
  netif_t* n;

  while (ci_dllist_not_empty(&stacks_list)) {
    n = CI_CONTAINER(netif_t, link, ci_dllist_start(&stacks_list));
    stack_detach(n);
  }
}


static void do_socket_op(const socket_op_t* op, socket_t* s)
{
  citp_waitable_obj* wo;
  netif_t* n = stacks[s->stack];
  int ni_unlock = 0;
  int s_unlock = 0;
  int ok;

  if( ! (op->flags & FL_NO_LOCK) &&
      ! __try_grab_stack_lock(&n->ni, &ni_unlock, op->name) )
    return;

  if( s->id < (int) n->ni.state->n_ep_bufs )
  if( oo_sock_id_is_waitable(&n->ni, s->id) )
  {
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);

    if( (op->flags & FL_LOCK_SOCK) && ! cfg_nosklock &&
        ! (s_unlock = ci_sock_trylock(&n->ni, &wo->waitable)) ) {
      ci_log("%s: [%d:%d] can't get sock lock (--nosocklock may help)",
             op->name, s->stack, s->id);
      return;
    }

    ok = 1;
    if( (op->flags & FL_TCPC) && ! (wo->waitable.state&CI_TCP_STATE_TCP_CONN) )
      ok = 0;
    if( (op->flags & FL_TCPA) && ! (wo->waitable.state & CI_TCP_STATE_TCP) )
      ok = 0;
    if( (op->flags & FL_UDP) && wo->waitable.state != CI_TCP_STATE_UDP )
      ok = 0;
    if( ! (wo->waitable.state & CI_TCP_STATE_SOCKET) )
      ok = 0;

    if( ok )
      op->fn(&n->ni, &wo->tcp);

    if( s_unlock )
      ci_sock_unlock(&n->ni, &wo->waitable);
  }

  if( ni_unlock )
    libstack_netif_unlock(&n->ni);
}


void for_each_socket(const socket_op_t* op)
{
  socket_t* s;
  for( s = sockets; s < sockets + sockets_n; ++s )
    do_socket_op(op, s);
}


static void* get_dstats(void* to, const void* from, size_t len)
{
  ci_netif_stats s = * (const ci_netif_stats*) from;
  dstats_t* d = (dstats_t*) to;
  int polls;

  ci_assert_equal(len, sizeof(dstats_t));

  polls = s.k_polls + s.u_polls;
  d->rx_evs_per_poll = s.rx_evs / polls;
  d->tx_evs_per_poll = s.tx_evs / polls;
  return NULL;
}


static void get_more_stats(ci_netif* ni, more_stats_t* s)
{
  unsigned i;
  memset(s, 0, sizeof(*s));
  for( i = 0; i < ni->state->n_ep_bufs; ++i )
  if( oo_sock_id_is_waitable(ni, i) )
  {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, i);
    citp_waitable* w = &wo->waitable;
    unsigned state = w->state;
    if( CI_TCP_STATE_NUM(state) >= N_STATES ) {
      ++s->states[N_STATES];
      continue;
    }
    ++s->states[CI_TCP_STATE_NUM(state)];
    if( state == CI_TCP_STATE_FREE )  continue;
    if( w->sb_aflags & CI_SB_AFLAG_ORPHAN       )  ++s->sock_orphans;
    if( w->wake_request & CI_SB_FLAG_WAKE_RX )  ++s->sock_wake_needed_rx;
    if( w->wake_request & CI_SB_FLAG_WAKE_TX )  ++s->sock_wake_needed_tx;
    if( state >= CI_TCP_SYN_SENT && state <= CI_TCP_TIME_WAIT ) {
      ci_tcp_state* ts = &wo->tcp;
      if( tcp_rcv_usr(ts) ) {
        ++s->tcp_has_recvq;
        s->tcp_recvq_bytes += tcp_rcv_usr(ts);
      }
      /* NB. Can have pkts even if no bytes... */
      s->tcp_recvq_pkts += ts->recv1.num + ts->recv2.num;
      if( ci_tcp_inflight(ts) ) {
        ++s->tcp_has_inflight;
        s->tcp_inflight_bytes += ci_tcp_inflight(ts);
        s->tcp_inflight_pkts += ts->retrans.num;
      }
      if( ts->rob.num ) {
        ++s->tcp_has_recv_reorder;
        s->tcp_recv_reorder_pkts += ts->rob.num;
      }
      if( SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)) ) {
        ++s->tcp_has_sendq;
        s->tcp_sendq_bytes += SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts));
        s->tcp_sendq_pkts += ci_tcp_sendq_n_pkts(ts);
      }
    }
    else if( state == CI_TCP_LISTEN ) {
      ci_tcp_socket_listen* tls = &wo->tcp_listen;
      s->tcp_n_in_listenq += tls->n_listenq;
      s->tcp_n_in_acceptq += ci_tcp_acceptq_n(tls);
    }
    else if( state == CI_TCP_STATE_UDP ) {
      ci_udp_state* us = &wo->udp;
      if( ci_udp_recv_q_not_empty(us) ) {
        ++s->udp_has_recvq;
        s->udp_recvq_bytes += ci_udp_recv_q_bytes(&us->recv_q);
        s->udp_recvq_pkts += ci_udp_recv_q_pkts(&us->recv_q);
      }
      if( us->tx_count ) {
        ++s->udp_has_sendq;
        s->udp_sendq_bytes += us->tx_count;
      }
      s->udp_tot_recv_pkts_ul += us->recv_q.pkts_added;
      s->udp_tot_recv_drops_ul += us->stats.n_rx_overflow;
      s->udp_tot_recv_pkts_os += us->stats.n_rx_os;
      s->udp_tot_send_pkts_ul += us->stats.n_tx_onload_uc;
      s->udp_tot_send_pkts_ul += us->stats.n_tx_onload_c;
      s->udp_tot_send_pkts_os += us->stats.n_tx_os;
    }
  }
#if CI_CFG_USERSPACE_PIPE
  else
    ++s->states[CI_TCP_STATE_PIPE_BUF_NUM];
#endif
  s->ef_vi_rx_ev_lost = ni->state->vi_stats.rx_ev_lost;
  s->ef_vi_rx_ev_bad_desc_i = ni->state->vi_stats.rx_ev_bad_desc_i;
  s->ef_vi_rx_ev_bad_q_label = ni->state->vi_stats.rx_ev_bad_q_label;
  s->ef_vi_evq_gap = ni->state->vi_stats.evq_gap;
}


static void* more_stats_getter(void* to, const void* from, size_t len)
{
  ci_assert_equal(len, sizeof(more_stats_t));
  get_more_stats((ci_netif*) from, (more_stats_t*) to);
  return to;
}


static void dump_stats(const stat_desc_t* stats_fields, int n_stats_fields,
                       const void* stats, int with_description)
{
  const stat_desc_t* s;
  for( s = stats_fields; s < stats_fields + n_stats_fields; ++s ) {
    ci_assert_equal(s->size, sizeof(ci_uint32));
    ci_log("%s: %u", s->name,
           *(const ci_uint32*) ((const char*) stats + s->offset));
    if( with_description && s->description )
      ci_log("  %s\n", s->description);
  }
}


static void clear_stats(const stat_desc_t* stats_fields, int n_stats_fields,
                        void* stats)
{
  const stat_desc_t* s;
  for( s = stats_fields; s < stats_fields + n_stats_fields; ++s ) {
    ci_assert_equal(s->size, sizeof(ci_uint32));
    *(ci_uint32*) ((char*) stats + s->offset) = 0u;
  }
}


ci_inline unsigned tv_delta(const struct timeval* a, const struct timeval* b)
{
  return (a->tv_sec - b->tv_sec) * 1000u + (a->tv_usec - b->tv_usec) / 1000u;
}


static void print_stats_header_line(const stat_desc_t* stats_fields,
                                    int n_stats_fields)
{
  const stat_desc_t* s;
  int j, i = 1;

  printf("#\ttime(%d)", i++);
  for( s = stats_fields; s < stats_fields + n_stats_fields; ++s )
    printf("\t%s(%d)", s->name, i++);
  printf("\n");
  printf("#");
  for( j = 1; j < i; ++j )  printf("\t(%d)", j);
  printf("\n");
}


static void watch_stats(const stat_desc_t* stats_fields, int n_stats_fields,
                        int stats_len_bytes, void* stats_src,
                        void* (*get_stats)(void* to, const void* from,
                                           size_t len))
{
  unsigned line_len = n_stats_fields * 20;
  char* line = malloc(line_len);
  unsigned time_msec = 0, target_msec = 0;
  struct timeval start, now;
  void* p = malloc(stats_len_bytes);
  void* c = malloc(stats_len_bytes);
  const stat_desc_t* s;
  int lo = 0, line_i;

  get_stats(c, stats_src, stats_len_bytes);
  gettimeofday(&start, 0);

  for( line_i = 0; ; ++line_i ) {
    memcpy(p, c, stats_len_bytes);
    target_msec += cfg_watch_msec;
    ci_sleep(target_msec - time_msec);
    get_stats(c, stats_src, stats_len_bytes);
    gettimeofday(&now, 0);
    time_msec = tv_delta(&now, &start);
    if( ! cfg_notable ) {
      if( (line_i & 0xf) == 0 )
        print_stats_header_line(stats_fields, n_stats_fields);
      lo = sprintf(line, "\t%.02f", (double) time_msec / 1000);
    }
    else
      ci_log("=====================================================");
    for( s = stats_fields; s < stats_fields + n_stats_fields; ++s ) {
      unsigned v = *(ci_uint32*) ((char*) c + s->offset);
      ci_assert_equal(s->size, sizeof(ci_uint32));
      if( s->flags & STAT_COUNT )
        v -= *(ci_uint32*) ((char*) p + s->offset);
      if( ! cfg_notable ) {
        lo += sprintf(line+lo, "\t%u", v);
        CI_TEST(lo < line_len * 3 / 4);
      }
      else
        ci_log("%30s: %u", s->name, v);
    }
    if( ! cfg_notable ) {
      printf("%s\n", line);
      fflush(stdout);
    }
  }
}

/**********************************************************************
**********************************************************************/

void socket_add(int stack_id, int sock_id)
{
  netif_t* n = stacks[stack_id];
  socket_t* s;

  if( ! n )  return;

  if( sockets_n == sockets_size ) {
    int new_size = CI_MAX(sockets_size * 2, 256);
    sockets = realloc(sockets, new_size * sizeof(sockets[0]));
    CI_TEST(sockets);
    sockets_size = new_size;
  }

  s = &sockets[sockets_n++];
  s->stack = stack_id;
  s->id = sock_id;
  s->s = 0;
}


void socket_add_all(int stack_id)
{
  netif_t* n = stacks[stack_id];
  int i;

  if( ! n )  return;

  for( i = 0; i < (int)n->ni.state->n_ep_bufs; ++i )
  if( oo_sock_id_is_waitable(&n->ni, i) )
  {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(&n->ni, i);
    if( ! (wo->waitable.state & CI_TCP_STATE_SOCKET) )  continue;
    socket_add(stack_id, i);
  }
}


void socket_add_all_all(void)
{
  netif_t* n;
  CI_DLLIST_FOR_EACH2(netif_t, n, link, &stacks_list)
    socket_add_all(NI_ID(&n->ni));
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void filter_dump(ci_netif* ni, oo_sp sock_id)
{
  int buf_len = 8192;
  char* buf;
  int rc;
  while( 1 ) {
    if( (buf = malloc(buf_len)) == NULL ) {
      ci_log("%s: Out of memory", __FUNCTION__);
      break;
    }
    rc = ci_tcp_helper_ep_filter_dump(ci_netif_get_driver_handle(ni),
                                      sock_id, buf, buf_len);
    if( rc >= 0 && rc <= buf_len )
      printf("%s", buf);
    free(buf);
    if( rc < 0 )
      ci_log("%s: failed (%d)", __FUNCTION__, -rc);
    if( rc <= buf_len )
      break;
    buf_len = rc;
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void dump_sock_qs(ci_netif* ni, ci_tcp_state* ts)
{ ci_tcp_state_dump_qs(ni, S_SP(ts), cfg_dump); }


static void for_each_tcp_socket(ci_netif* ni,
				void (*fn)(ci_netif*, ci_tcp_state*))
{
  int id;
  for( id = 0; id < (int)ni->state->n_ep_bufs; ++id )
  if( oo_sock_id_is_waitable(ni, id) )
  {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, id);
    if( ! (wo->waitable.state & CI_TCP_STATE_TCP_CONN) )  continue;
    fn(ni, &wo->tcp);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

unsigned arg_u[1];
const char* arg_s[1];


void zombie_stack_dump(int id, void *arg)
{
  int rc;
  oo_fd fd;
  
  CI_TRY(oo_fd_open(&fd));
  rc = oo_debug_dump_stack(fd, id, 1);
  CI_TRY(oo_fd_close(fd));
  
  if( rc == 0 )
    ci_log("Orphan stack %d state dumped to syslog", id);
  else
    ci_log("No such orphan stack %d\n", id);
}


void zombie_stack_kill(int id, void *arg)
{
  int rc;
  oo_fd fd;
  
  CI_TRY(oo_fd_open(&fd));
  rc = oo_debug_kill_stack(fd, id);
  CI_TRY(oo_fd_close(fd));
  
  if( rc == 0 )
    ci_log("Orphan stack %d state killed", id);
  else
    ci_log("No such orphan stack %d\n", id);
}


static void stack_dump(ci_netif* ni)
{
  ci_log("============================================================");
  ci_netif_dump(ni);
  ci_log("============================================================");
  ci_netif_dump_sockets(ni);
}

static void stack_netif(ci_netif* ni)
{
  ci_netif_dump(ni);
}

static void stack_netif_extra(ci_netif* ni)
{
  ci_netif_dump_extra(ni);
}

static void stack_dmaq(ci_netif* ni)
{
  ci_netif_dump_dmaq(ni, cfg_dump);
}

static void stack_timeoutq(ci_netif* ni)
{
  ci_netif_dump_timeoutq(ni);
}

static void stack_opts(ci_netif* ni)
{
  ci_log("ci_netif_config_opts_dump: %d", NI_ID(ni));
  ci_netif_config_opts_dump(&NI_OPTS(ni));
}

static void stack_stats(ci_netif* ni)
{
  ci_netif_stats stats = ni->state->stats;
  ci_log("==================== ci_netif_stats: %d ====================",
         NI_ID(ni));
  dump_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &stats, 0);
}

static void stack_describe_stats(ci_netif* ni)
{
  ci_netif_stats stats = ni->state->stats;
  ci_log("==================== ci_netif_stats: %d ====================",
         NI_ID(ni));
  dump_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &stats, 1);
}

static void stack_clear_stats(ci_netif* ni)
{
  clear_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &ni->state->stats);
}

static void stack_dstats(ci_netif* ni)
{
  dstats_t stats;
  get_dstats(&stats, &ni->state->stats, sizeof(stats));
  ci_log("==================== ci_netif_stats: %d ====================",
         NI_ID(ni));
  dump_stats(netif_dstats_fields, N_NETIF_DSTATS_FIELDS, &stats, 0);
}

static void stack_more_stats(ci_netif* ni)
{
  more_stats_t stats;
  get_more_stats(ni, &stats);
  ci_log("==================== more_stats: %d ====================",NI_ID(ni));
  dump_stats(more_stats_fields, N_MORE_STATS_FIELDS, &stats, 0);
}

#if CI_CFG_SUPPORT_STATS_COLLECTION

static void stack_ip_stats(ci_netif* ni)
{
  ci_ipv4_stats_count stats = ni->state->stats_snapshot.ipv4;
  ci_log("==================== ci_ipv4_stats_count: %d ====================",
         NI_ID(ni));
  dump_stats(ip_stats_fields, N_IP_STATS_FIELDS, &stats, 0);
}

static void stack_tcp_stats(ci_netif* ni)
{
  ci_tcp_stats_count stats = ni->state->stats_snapshot.tcp;
  ci_log("==================== ci_tcp_stats_count: %d ====================",
         NI_ID(ni));
  dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, &stats, 0);
}

static void stack_tcp_ext_stats(ci_netif* ni)
{
  ci_tcp_ext_stats_count stats = ni->state->stats_snapshot.tcp_ext;
  ci_log("=================== ci_tcp_ext_stats_count: %d ===================",
         NI_ID(ni));
  dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, &stats, 0);
}

static void stack_udp_stats(ci_netif* ni)
{
  ci_udp_stats_count stats = ni->state->stats_snapshot.udp;
  ci_log("==================== ci_udp_stats_count: %d ====================",
         NI_ID(ni));
  dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, &stats, 0);
}

static void stack_watch_ip_stats(ci_netif* ni)
{
  watch_stats(ip_stats_fields, N_IP_STATS_FIELDS, sizeof(ci_ipv4_stats_count),
              &ni->state->stats_snapshot.ipv4, memcpy);
}

static void stack_watch_tcp_stats(ci_netif* ni)
{
  watch_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, sizeof(ci_tcp_stats_count),
              &ni->state->stats_snapshot.tcp, memcpy);
}

static void stack_watch_tcp_ext_stats(ci_netif* ni)
{
  watch_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS,
              sizeof(ci_tcp_ext_stats_count),
              &ni->state->stats_snapshot.tcp_ext, memcpy);
}

#endif

static void stack_analyse(ci_netif* ni)
{
  int i, n_samples = 100000000;
  int locked = 0;
  int contended = 0;
  int deferred = 0;
  int primed_any = 0;
  int primed_all = 0;
  int spinner = 0;

  for( i = 0; i < n_samples; ++i ) {
    if( ci_netif_is_locked(ni) )
      ++locked;
    if( ni->state->lock.lock & CI_EPLOCK_FL_NEED_WAKE )
      ++contended;
    if( ni->state->lock.lock & CI_EPLOCK_NETIF_SOCKET_LIST )
      ++deferred;
    if( ci_netif_is_primed(ni) )
      ++primed_all;
    if( ni->state->evq_primed != 0 )
      ++primed_any;
    if( ni->state->is_spinner )
      ++spinner;
  }

#undef r
#define r(nm)  ci_log("%-20s: %5.01f%%", #nm, nm * 100.0 / n_samples)
  r(locked);
  r(contended);
  r(deferred);
  r(primed_any);
  r(primed_all);
  r(spinner);
#undef r
}

static void stack_packets(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) )
    ci_netif_pkt_dump_all(ni);
  if( unlock )
    libstack_netif_unlock(ni);
}

static void stack_time(ci_netif* ni)
{
  ci_ip_timer_state* its = IPTIMER_STATE(ni);
  ci_log("          sched_ticks: %x", its->sched_ticks);
  ci_log("ci_ip_time_real_ticks: %x", its->ci_ip_time_real_ticks);
  ci_log("                  frc: %"CI_PRIx64, its->frc);
  ci_log("  ci_ip_time_frc2tick: %u", (unsigned) its->ci_ip_time_frc2tick);
  ci_log("    ci_ip_time_frc2us: %u", (unsigned) its->ci_ip_time_frc2us);
  ci_log("   ci_ip_time_tick2ms: %f", ni->ci_ip_time_tick2ms);
  ci_log("                  khz: %u", (unsigned) its->khz);
}

static void stack_time_init(ci_netif* ni)
{
  ci_ip_timer_state* ipts = IPTIMER_STATE(ni);
  ni->ci_ip_time_tick2ms = 
    (double)(1u<<ipts->ci_ip_time_frc2tick)/((double)ipts->khz);
}

static void stack_timers(ci_netif* ni)
{
  ci_ip_timer_state_dump(ni);
}

static void stack_filter_table(ci_netif* ni)
{
  ci_netif_filter_dump(ni);
}

static void stack_filters(ci_netif* ni)
{
  filter_dump(ni, OO_SP_NULL);
}

static void stack_blacklist_intf_i(ci_netif* ni)
{
  int i;
  ci_log("blacklist_intf_i: stack=%d, bl_length=%u", NI_ID(ni), 
         ni->state->blacklist_length);
  for( i = 0; i < ni->state->blacklist_length; ++i )
    ci_log("  %d: %d", i, ni->state->blacklist_intf_i[i]);
}

static void stack_qs(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) )
    for_each_tcp_socket(ni, dump_sock_qs);
  if( unlock )
    libstack_netif_unlock(ni);
}

static void stack_lock(ci_netif* ni)
{
  if( cfg_lock )
    ci_log("%s: already locked due to --lock option", __FUNCTION__);
  else
    libstack_netif_lock(ni);
}

static void stack_trylock(ci_netif* ni)
{
  if( ! libstack_netif_trylock(ni) )
    ci_log("%s: [%d] failed", __FUNCTION__, NI_ID(ni));
}

static void stack_unlock(ci_netif* ni)
{
  if( cfg_lock )
    ci_log("%s: refusing due to --lock option", __FUNCTION__);
  else if( ! ef_eplock_is_locked(&ni->state->lock) )
    ci_log("%s: ERROR: stack %d not locked", __FUNCTION__, NI_ID(ni));
  else
    libstack_netif_unlock(ni);
}

static void stack_netif_unlock(ci_netif* ni)
{
  if( cfg_lock )
    ci_log("stupid");
  else {
    if( ! ci_netif_is_locked(ni) )
      ci_log("%d: not locked", NI_ID(ni));
    else
      libstack_netif_unlock(ni);
  }
}

static void stack_lock_force_wake(ci_netif* ni)
{
  unsigned v;
  if( ! cfg_lock )  libstack_netif_lock(ni);
  do
    v = ni->state->lock.lock;
  while( ci_cas32_fail(&ni->state->lock.lock,v,v|CI_EPLOCK_FL_NEED_WAKE) );
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_poll(ci_netif* ni)
{
  int unlock = 0;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int rc = ci_netif_poll(ni);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_poll: rc=%d", NI_ID(ni), rc);
  }
}

static void stack_poll_nolock(ci_netif* ni)
{
  int rc = ci_netif_poll(ni);
  ci_log("%s: [%d] ci_netif_poll: rc=%d", __FUNCTION__, NI_ID(ni), rc);
}

static void stack_spin_poll(ci_netif* ni)
{
  ci_uint64 now_frc;
  ci_log("%s: [%d]", __FUNCTION__, NI_ID(ni));
  while( 1 ) {
    ci_frc64(&now_frc);
    if( ci_netif_need_poll_spinning(ni, now_frc) ) {
      if( ci_netif_trylock(ni) ) {
        ci_netif_poll_n(ni, NI_OPTS(ni).evs_per_poll);
        libstack_netif_unlock(ni);
      }
    }
    else if( ! ni->state->is_spinner )
      ni->state->is_spinner = 1;
    ci_spinloop_pause();
  }
}

static void stack_prime(ci_netif* ni)
{
  int rc;
  citp_signal_info* si = citp_signal_get_specific_inited();
  libstack_defer_signals(si);
  rc = ef_eplock_lock_or_set_flag(&ni->state->lock,CI_EPLOCK_NETIF_NEED_PRIME);
  if( rc ) {
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_PRIME);
    libstack_netif_unlock(ni);
  }
  else
    libstack_process_signals(si);
}

static void stack_reset_primed(ci_netif* ni)
{
  stack_lock(ni);
  ni->state->evq_primed = 0;
  stack_unlock(ni);
}

static void stack_wake(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int rc_wake;
    rc_wake = ci_netif_force_wake(ni, 0);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_force_wake: rc=%d", NI_ID(ni), rc_wake);
  }
}

static void stack_wakeall(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int rc_wake;
    rc_wake = ci_netif_force_wake(ni, 1);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_force_wake: rc=%d", NI_ID(ni), rc_wake);
  }
}

static void stack_rxpost(ci_netif* ni)
{
  ci_uint32 nic_index = CI_DEFAULT_NIC; /* TODO: support multiple NICs */
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    ci_netif_rx_post(ni, nic_index);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_rx_post", NI_ID(ni));
  }
}


static void stack_sizeof(ci_netif* ni)
{
# define log_sizeof(x)  ci_log("%30s: %d", #x, (int) sizeof(x))
  log_sizeof(ci_netif);
  log_sizeof(ci_netif_state);
  log_sizeof(ci_netif_config);
  log_sizeof(ci_netif_config_opts);
  log_sizeof(ci_netif_ipid_cb_t);
  log_sizeof(ci_netif_filter_table_entry);
  log_sizeof(ci_netif_filter_table);
  log_sizeof(ci_ip_cached_hdrs);
  log_sizeof(ci_ip_timer);
  log_sizeof(ci_ip_timer_state);
  log_sizeof(citp_waitable);
  log_sizeof(citp_waitable_obj);
  log_sizeof(ci_sock_cmn);
  log_sizeof(ci_tcp_state);
  log_sizeof(ci_tcp_socket_cmn);
  log_sizeof(ci_tcp_state_synrecv);
  log_sizeof(ci_tcp_socket_listen);
  log_sizeof(ci_tcp_options);
  log_sizeof(ci_udp_state);
  log_sizeof(ci_netif_stats);
  log_sizeof(ci_udp_socket_stats);
  log_sizeof(ci_tcp_socket_listen_stats);
  log_sizeof(ci_ip_pkt_fmt);
  log_sizeof(ci_ip_pkt_fmt_prefix);
  log_sizeof(ci_ip_sock_stats);
  log_sizeof(ci_ip_sock_stats_count);
  log_sizeof(ci_ip_sock_stats_range);
}

static void stack_leak_pkts(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int i;
    for( i = 0; i < (int)arg_u[0]; ++i ) {
      ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni);
      if( ! pkt )  break;
      if( ci_cfg_verbose )
	ci_log("%d: leaked pkt %d", NI_ID(ni), OO_PKT_FMT(pkt));
    }
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: leaked %d packet buffers", NI_ID(ni), i);
  }
}

static void stack_alloc_pkts(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp = OO_PP_NULL;
  int i;
  if( ! cfg_lock )  libstack_netif_lock(ni);
  for( i = 0; i < (int) arg_u[0]; ++i ) {
    pkt = ci_netif_pkt_alloc(ni);
    if( pkt == NULL ) {
      ci_log("%d: allocated %d buffers", NI_ID(ni), i);
      break;
    }
    pkt->next = pp;
    pp = OO_PKT_P(pkt);
  }
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_alloc_pkts_hold(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp = OO_PP_NULL;
  int i;
  if( ! cfg_lock )  libstack_netif_lock(ni);
  for( i = 0; i < (int) arg_u[0]; ++i ) {
    pkt = ci_netif_pkt_alloc(ni);
    if( pkt == NULL ) {
      ci_log("%d: allocated %d buffers", NI_ID(ni), i);
      break;
    }
    pkt->next = pp;
    pp = OO_PKT_P(pkt);
  }
  if( 1 ) {
    libstack_netif_unlock(ni);
    while( ! signal_fired )
      sleep(1000);
    libstack_netif_lock(ni);
  }
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_alloc_pkts_block(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp = OO_PP_NULL;
  int i, locked = cfg_lock;
  for( i = 0; i < (int) arg_u[0]; ++i ) {
    pkt = ci_netif_pkt_alloc_block(ni, &locked);
    if( pkt == NULL ) {
      ci_log("%d: allocated %d buffers", NI_ID(ni), i);
      break;
    }
    pkt->next = pp;
    pp = OO_PKT_P(pkt);
  }
  if( ! locked ) {
    libstack_netif_lock(ni);
    locked = 1;
  }
  ni->state->n_async_pkts -= i;
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }
  if( ! cfg_lock )
    libstack_netif_unlock(ni);
}

#if ! CI_CFG_PP_IS_PTR
static void stack_nonb_pkt_pool_n(ci_netif* ni)
{
  volatile ci_uint64 *nonb_pkt_pool_ptr;
  ci_uint64 link;
  unsigned id, n, n_async_pkts;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp;

  nonb_pkt_pool_ptr = &(ni->state->nonb_pkt_pool);
 again:
  n_async_pkts = ni->state->n_async_pkts;
  link = *nonb_pkt_pool_ptr;
  id = link & 0xffffffff;
  if( id != 0xffffffff ) {
    if( ci_cas64u_fail(nonb_pkt_pool_ptr, link,
                       0x00000000ffffffffllu | (link & 0xffffffff00000000llu)) )
      goto again;
    OO_PP_INIT(ni, pp, id);
    pkt = PKT(ni, pp);
    n = 0;
    while( 1 ) {
      ++n;
      if( OO_PP_IS_NULL(pkt->next) )
        break;
      pkt = PKT(ni, pkt->next);
    }
    ci_netif_pkt_free_nonb_list(ni, id, pkt);
  }
  else {
    n = 0;
  }
  ci_log("%s: [%d] n_async_pkts=%d nonb_pkt_pool_n=%d", __FUNCTION__,
         NI_ID(ni), n_async_pkts, n);
}
#endif

static void stack_alloc_nonb_pkts(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  int n = 0, n_from_nonb;
  oo_pkt_p pp;
  oo_pkt_p* ppi = &pp;
  int n_to_alloc = arg_u[0];
  for( ; n < n_to_alloc; ++n ) {
    if( (pkt = ci_netif_pkt_alloc_nonb(ni)) == NULL )
      break;
    pkt->refcount = 0;
    __ci_netif_pkt_clean(pkt);
    *ppi = OO_PKT_P(pkt);
    ppi = &pkt->next;
  }
  n_from_nonb = n;
  if( n < n_to_alloc ) {
    if( ! cfg_lock )
      libstack_netif_lock(ni);
    for( ; n < n_to_alloc; ++n ) {
      if( (pkt = ci_netif_pkt_alloc(ni)) == NULL )
        break;
      pkt->refcount = 0;
      __ci_netif_pkt_clean(pkt);
      *ppi = OO_PKT_P(pkt);
      ppi = &pkt->next;
    }
    ni->state->n_async_pkts += n - n_from_nonb;
    if( ! cfg_lock )
      libstack_netif_unlock(ni);
  }
  if( n != 0 )
    ci_netif_pkt_free_nonb_list(ni, pp, CI_CONTAINER(ci_ip_pkt_fmt,next,ppi));
  ci_log("%s: [%d] put %d on nonb-pool (was %d)", __FUNCTION__, NI_ID(ni),
         n, n_from_nonb);
}

static void stack_nonb_thrash(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  int i, iter = arg_u[0];
  int n = 0;

  {
    ci_ip_pkt_fmt p;
    ci_uint64 link = 0;
    ci_uint64 u;
    p.next = (ci_int32) 0xffffffff;
    u = ((unsigned)OO_PP_ID(p.next)) | (link & 0xffffffff00000000llu);
    ci_log("u=%"CI_PRIx64, u);
    exit(1);
  }

  for( i = 0; i < iter; ++i ) {
    pkt = ci_netif_pkt_alloc_nonb(ni);
    if( pkt != NULL ) {
      pkt->refcount = 0;
      __ci_netif_pkt_clean(pkt);
      ci_netif_pkt_free_nonb_list(ni, OO_PKT_P(pkt), pkt);
      ++n;
    }
  }
  ci_log("%s: [%d] iter=%d n=%d", __FUNCTION__, NI_ID(ni), iter, n);
}

static void stack_txpkt(ci_netif* ni)
{
  int pkt_id = arg_u[0];
  if( IS_VALID_PKT_ID(ni, pkt_id) ) {
    ci_ip_pkt_fmt* pkt = __PKT(ni, pkt_id);
    ci_tcp_pkt_dump(ni, pkt, 0, 0);
  }
  else
    ci_log("%d: bad pkt=%d", NI_ID(ni), pkt_id);
}

static void stack_rxpkt(ci_netif* ni)
{
  int pkt_id = arg_u[0];
  if( IS_VALID_PKT_ID(ni, pkt_id) ) {
    ci_ip_pkt_fmt* pkt = __PKT(ni, pkt_id);
    ci_tcp_pkt_dump(ni, pkt, 1, 0);
  }
  else
    ci_log("%d: bad pkt=%d", NI_ID(ni), pkt_id);
}

static void stack_segments(ci_netif* ni)
{
  int i, pkt_id = arg_u[0];
  oo_pkt_p buf;
  if( IS_VALID_PKT_ID(ni, pkt_id) ) {
    ci_ip_pkt_fmt* pkt = __PKT(ni, pkt_id);
    ci_log("%d: pkt=%d n_buffers=%d", NI_ID(ni), pkt_id, pkt->n_buffers);
    buf = OO_PKT_P(pkt);
    for( i = 0; i < pkt->n_buffers; ++i ) {
      ci_ip_pkt_fmt* apkt = PKT_CHK(ni, buf);
      ci_log("  %d: "EF_ADDR_FMT":%d", i, apkt->base_addr[pkt->intf_i],
             apkt->buf_len);
      buf = apkt->frag_next;
    }
  }
  else
    ci_log("%d: bad pkt=%d", NI_ID(ni), pkt_id);
}

static void stack_ev(ci_netif* ni)
{
  int rc = ef_eventq_put(ef_vi_resource_id(&ni->nic_hw[0].vi), 
			 ci_netif_get_driver_handle(ni), 0xff);
  ci_log("%d: ef_eventq_put: rc=%d", NI_ID(ni), rc);
}

static void stack_ul_poll(ci_netif* ni)
{
  NI_OPTS(ni).spin_usec = arg_u[0];
  ni->state->spin_cycles = usec_to_cycles64(NI_OPTS(ni).spin_usec);
}

static void stack_timer_timeout(ci_netif* ni)
{
  NI_OPTS(ni).timer_usec = arg_u[0];
}

static void stack_timer_prime(ci_netif* ni)
{
  NI_OPTS(ni).timer_prime_usec = arg_u[0];
  ni->state->timer_prime_cycles =
    usec_to_cycles64(NI_OPTS(ni).timer_prime_usec);
}

#if CI_CFG_RANDOM_DROP
static void stack_rxdroprate(ci_netif* ni)
{
  NI_OPTS(ni).rx_drop_rate = arg_u[0]? RAND_MAX/arg_u[0] : 0;
}
#endif

static void stack_tcp_rx_checks(ci_netif* ni)
{
  NI_OPTS(ni).tcp_rx_checks = arg_u[0];
}

static void stack_tcp_rx_log_flags(ci_netif* ni)
{
  NI_OPTS(ni).tcp_rx_log_flags = arg_u[0];
}

static void stack_watch_stats(ci_netif* ni)
{
  watch_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, sizeof(ci_netif_stats),
              &ni->state->stats, memcpy);
}

static void stack_watch_more_stats(ci_netif* ni)
{
  watch_stats(more_stats_fields, N_MORE_STATS_FIELDS, sizeof(more_stats_t),
              ni, more_stats_getter);
}


static void stack_set_opt(ci_netif* ni)
{
  const char* opt_name = arg_s[0];
  unsigned opt_val = arg_u[0];

#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_OPTGROUP
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, pres)    \
    if( ! strcmp(opt_name, #name) ) {                                   \
      NI_OPTS(ni).name = opt_val;                                       \
      return;                                                           \
    }
#include <ci/internal/opts_netif_def.h>

  ci_log("unknown option: %s", opt_name);
}

static void stack_get_opt(ci_netif* ni)
{
  const char* opt_name = arg_s[0];

#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_OPTGROUP
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, pres) \
    if( ! strcmp(opt_name, #name) ) {                                     \
      ci_log("[%d] %s: %d", NI_ID(ni), opt_name, (int) NI_OPTS(ni).name); \
      return;                                                             \
    }
#include <ci/internal/opts_netif_def.h>

  ci_log("unknown option: %s", opt_name);
}

static void stack_set_rxq_limit(ci_netif* ni)
{
  ni->state->rxq_limit = arg_u[0];
}

static void stack_lots(ci_netif* ni)
{
  ci_netif_stats stats;
  more_stats_t more_stats;
  ci_tcp_stats_count t_stats;
  ci_tcp_ext_stats_count te_stats;
  ci_udp_stats_count u_stats;

  stats = ni->state->stats;
  get_more_stats(ni, &more_stats);
  t_stats = ni->state->stats_snapshot.tcp;
  te_stats = ni->state->stats_snapshot.tcp_ext;
  u_stats = ni->state->stats_snapshot.udp;

  ci_log("============================================================");
  ci_netif_dump(ni);
  ci_netif_dump_extra(ni);
  libstack_stack_mapping_print_pids(NI_ID(ni));
  ci_log("============================================================");
  ci_netif_dump_sockets(ni);
  dump_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &stats, 0);
  dump_stats(more_stats_fields, N_MORE_STATS_FIELDS, &more_stats, 0);
  dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, &t_stats, 0);
  dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, &te_stats, 0);
  dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, &u_stats, 0);
  ci_netif_config_opts_dump(&NI_OPTS(ni));
  stack_time(ni);
}


static void stack_reap_list(ci_netif* ni)
{
  if( ! cfg_lock )  libstack_netif_lock(ni);
  ci_netif_dump_reap_list(ni, 0);
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_reap_list_verbose(ci_netif* ni)
{
  if( ! cfg_lock )  libstack_netif_lock(ni);
  ci_netif_dump_reap_list(ni, 1);
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_pkt_reap(ci_netif* ni)
{
  if( ! cfg_lock )  libstack_netif_lock(ni);
  ci_netif_try_to_reap(ni, 1000000);
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_cicp_user_find_home(ci_netif* ni)
{
  const char* ip_str = arg_s[0];
  struct in_addr in_addr;
  ci_hwport_id_t hwport;
  ci_ip_addr_t laddr;
  cicp_encap_t encap;
  ci_ifid_t ifindex;
  ci_mac_addr_t mac;
  ci_mtu_t mtu;
  int rc;

  if( ! inet_aton(ip_str, &in_addr) ) {
    ci_log("%s: Bad IP address '%s'", __FUNCTION__, ip_str);
    return;
  }
  laddr = in_addr.s_addr;
  rc = cicp_user_find_home(CICP_HANDLE(ni), &laddr, &hwport, &ifindex,
                           &mac, &mtu, &encap);
  ci_log("cicp_user_find_home: rc=%d", rc);
  if( rc == 0 ) {
    ci_log("  hwport: %d", (int) hwport);
    ci_log(" ifindex: %d", (int) ifindex);
    ci_log("     mac: "CI_MAC_PRINTF_FORMAT, CI_MAC_PRINTF_ARGS(&mac));
    ci_log("     mtu: %d", (int) mtu);
    ci_log("   encap: %x,%d", (unsigned) encap.type, encap.vlan_id);
  }
}

static void stack_hwport_to_base_ifindex(ci_netif* ni)
{
  const cicp_ul_mibs_t* user = &CICP_MIBS(CICP_HANDLE(ni))->user;
  cicp_fwdinfo_t* fwdt = user->fwdinfo_utable;
  int i;
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    ci_log("hwport_to_base_ifindex[%d] = %d", i,
           (int) fwdt->hwport_to_base_ifindex[i]);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

#define STACK_OP_A(nm, help, args, fl)          \
  { (#nm), (stack_##nm), (NULL), (help), (args), (fl) }

#define STACK_OP_AU(nm, h, ah)    STACK_OP_A(nm, (h), (ah), FL_ARG_U)
#define STACK_OP_AX(nm, h, ah)    STACK_OP_A(nm, (h), (ah), FL_ARG_X)
#define STACK_OP_F(nm, help, fl)  STACK_OP_A(nm, (help), NULL, (fl))
#define STACK_OP(nm, help)        STACK_OP_A(nm, (help), NULL, 0)

#define ZOMBIE_STACK_OP(nm, help)           \
  { (#nm), (NULL), (zombie_stack_##nm), (help), (NULL), (FL_ID) }

static const stack_op_t zombie_stack_ops[] = {
  ZOMBIE_STACK_OP(dump, "[requires -z] show core state stack and sockets"),
  ZOMBIE_STACK_OP(kill, "[requires -z] terminate orphan/zombie stack"),
};

#define N_ZOMBIE_STACK_OPS                                     \
  (sizeof(zombie_stack_ops) / sizeof(zombie_stack_ops[0]))

static const stack_op_t stack_ops[] = {
  STACK_OP(dump,               "show core state of stack and sockets"),
  STACK_OP(netif,              "show core per-stack state"),
  STACK_OP(netif_extra,        "show extra per-stack state"),
  STACK_OP(dmaq,               "show state of DMA queue"),
  STACK_OP(timeoutq,           "show state of timeout queue"),
  STACK_OP(opts,               "show configuration options"),
  STACK_OP(stats,              "show stack statistics"),
  STACK_OP(describe_stats,     "show stack statistics with description"),
  STACK_OP(clear_stats,        "reset stack statistics"),
  STACK_OP(dstats,             "show derived statistics"),
  STACK_OP(more_stats,         "show more stack statistics"),
#if CI_CFG_SUPPORT_STATS_COLLECTION
  STACK_OP(ip_stats,           "show IP statistics"),
  STACK_OP(tcp_stats,          "show TCP statistics"),
  STACK_OP(tcp_ext_stats,      "show TCP extended stats"),
  STACK_OP(udp_stats,          "show UDP statistics"),
  STACK_OP(watch_ip_stats,     "show running IP stats"),
  STACK_OP(watch_tcp_stats,    "show running TCP stats"),
  STACK_OP(watch_tcp_ext_stats,"show running TCP-ext"),
#endif
  STACK_OP(analyse,            "analyse state over time"),
  STACK_OP(packets,            "show packets queued on netif"),
  STACK_OP(time,               "show stack timers"),
  STACK_OP(time_init,          "(re-)initialize stack timers"),
  STACK_OP(timers,             "dump state of stack timers"),
  STACK_OP(filter_table,       "show stack filter table"),
  STACK_OP_F(filters,          "show stack filters (syslog)", FL_ONCE),
  STACK_OP(blacklist_intf_i,   "dump blacklist_intf_i"),
  STACK_OP(qs,                 "show queues for each socket in stack"),
  STACK_OP(lock,               "lock the stack"),
  STACK_OP(trylock,            "try to lock the stack"),
  STACK_OP(unlock,             "unlock the stack"),
  STACK_OP(netif_unlock,       "unlock the netif"),
  STACK_OP(lock_force_wake,    "force a wake to test lock"),
  STACK_OP(poll,               "poll stack"),
  STACK_OP(poll_nolock,        "poll stack without locking"),
  STACK_OP(spin_poll,          "spin polling stack"),
  STACK_OP(prime,              "prime stack (enable interrupts)"),
  STACK_OP(reset_primed,       "reset evq_primed (should re-enable interrupts)"),
  STACK_OP(wake,               "force wakeup of sleepers"),
  STACK_OP(wakeall,            "force wakeup of everyone"),
  STACK_OP(rxpost,             "refill RX ring"),
  STACK_OP(sizeof,             "sizes of datastructures"),
  STACK_OP(ev,                 "post a h/w event to stack"),
  STACK_OP(watch_stats,        "show running statistics"),
  STACK_OP(watch_more_stats,   "show more statistics"),
  STACK_OP_AU(leak_pkts,       "drain allocation of packet buffers",
                                 "<pkt-id>"),
  STACK_OP_AU(alloc_pkts,      "allocate more pkt buffers", "<num>"),
  STACK_OP_AU(alloc_pkts_hold, "allocate and hold pkts 'till USR1", "<num>"),
  STACK_OP_AU(alloc_pkts_block,"allocate pkt buffers (blocking)", "<num>"),
#if ! CI_CFG_PP_IS_PTR
  STACK_OP(nonb_pkt_pool_n,    "count number of packets in non-blocking pool"),
#endif
  STACK_OP_AU(alloc_nonb_pkts, "allocate nonb pkt buffers", "<num>"),
  STACK_OP_AU(nonb_thrash,     "allocate and free nonb pkt buffers", "<num>"),
  STACK_OP_AU(txpkt,           "show content of transmit packet", "<pkt-id>"),
  STACK_OP_AU(rxpkt,           "show content of receive packet", "<pkt-id>"),
  STACK_OP_AU(segments,        "show segments in packet", "<pkt-id>"),
  STACK_OP_AU(ul_poll,         "set user level polling cycles option",
                                 "<cycles>"),
  STACK_OP_AU(timer_timeout,   "set timer timeout option", "<usec>"),
  STACK_OP_AU(timer_prime,     "set timer priming option", "<cycles>"),
#if CI_CFG_RANDOM_DROP
  STACK_OP_AU(rxdroprate,      "set reception drop rate option", "<1-in-n>"),
#endif
  STACK_OP_AX(tcp_rx_checks,   "set reception check bitmap option", "<mask>"),
  STACK_OP_AX(tcp_rx_log_flags,"set reception logging bitmap option","<mask>"),
  STACK_OP_A(set_opt,          "set stack option", "<name> <val>", FL_ARG_SU),
  STACK_OP_A(get_opt,          "get stack option", "<name>", FL_ARG_S),
  STACK_OP_AU(set_rxq_limit,   "set the rxq_limit", "<limit>"),
  STACK_OP(lots,               "dump state, opts, stats"),
  STACK_OP(reap_list,          "dump list of sockets on the reap_list"),
  STACK_OP(reap_list_verbose,  "dump sockets on the reap_list"),
  STACK_OP(pkt_reap,           "reap packet buffers from sockets"),
  STACK_OP_A(cicp_user_find_home,"invoke cicp_user_find_home", "<ip>",
             FL_ARG_S),
  STACK_OP(hwport_to_base_ifindex,"dump hwport_to_base_ifindex table"),
};
#define N_STACK_OPS	(sizeof(stack_ops) / sizeof(stack_ops[0]))


void for_each_stack_op(stackop_fn_t* fn, void* arg)
{
  const stack_op_t* op;
  for( op = stack_ops; op < stack_ops + N_STACK_OPS; ++op )
    (*fn)(op, arg);
  for( op = zombie_stack_ops; 
       op < zombie_stack_ops + N_ZOMBIE_STACK_OPS;
       ++op )
    (*fn)(op, arg);
}


const stack_op_t* get_stack_op(const char* name)
{
  const stack_op_t* op;
  const stack_op_t* ops;
  int n;
  if( cfg_zombie ) {
    n = N_ZOMBIE_STACK_OPS;
    ops = zombie_stack_ops;
  } 
  else {
    n = N_STACK_OPS;
    ops = stack_ops;
  }
  for( op = ops; op < ops + n || (op = NULL); ++op )
    if( ! strcmp(op->name, name) )
      break;
  return op;
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static void socket_dump(ci_netif* ni, ci_tcp_state* ts) {
  ci_log("------------------------------------------------------------");
  citp_waitable_dump(ni, &ts->s.b, "");
}

static void socket_qs(ci_netif* ni, ci_tcp_state* ts) {
  ci_log("------------------------------------------------------------");
  ci_tcp_state_dump_qs(ni, S_SP(ts), cfg_dump);
}

static void socket_lock(ci_netif* ni, ci_tcp_state* ts)
{ ci_sock_lock(ni, &ts->s.b); }

static void socket_unlock(ci_netif* ni, ci_tcp_state* ts)
{ ci_sock_unlock(ni, &ts->s.b); }

static void socket_trylock(ci_netif* ni, ci_tcp_state* ts) {
  if( ! ci_sock_trylock(ni, &ts->s.b) )
    ci_log("%d:%d trylock: failed", NI_ID(ni), S_SP(ts));
}

static void socket_filters(ci_netif* ni, ci_tcp_state* ts)
{ filter_dump(ni, S_SP(ts)); }

static void socket_nodelay(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT); }

static void socket_nagle(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT); }

static void socket_cork(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_CORK_BIT); }

static void socket_uncork(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_CORK_BIT); }

static void socket_advance(ci_netif* ni, ci_tcp_state* ts) {
  if( ! ci_ip_queue_is_empty(&ts->send) )
    ci_tcp_tx_advance(ts, ni);
}

static void socket_ack(ci_netif* ni, ci_tcp_state* ts) {
  ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni);
  if( pkt )
    ci_tcp_send_ack(ni, ts, pkt);
  else
    ci_log("%d:%d failed to allocate packet buffer", NI_ID(ni), S_SP(ts));
}

static void socket_rst(ci_netif* ni, ci_tcp_state* ts)
{ ci_tcp_send_rst(ni, ts); }

static void socket_set_mss(ci_netif* ni, ci_tcp_state* ts)
{
  ts->eff_mss = arg_u[0];
  ci_tcp_tx_change_mss(ni, ts); 
}

static void socket_set_pmtu(ci_netif* ni, ci_tcp_state* ts)
{
  ts->s.pkt.pmtus.pmtu = arg_u[0];
  ci_tcp_tx_change_mss(ni, ts); 
}

static void socket_set_sndbuf(ci_netif* ni, ci_tcp_state* ts)
{
  ts->s.so.sndbuf = arg_u[0];
  ci_tcp_set_sndbuf(ts);
}

static void socket_set_rcvbuf(ci_netif* ni, ci_tcp_state* ts)
{
  ts->s.so.rcvbuf = arg_u[0];
}

static void socket_set_cwnd(ci_netif* ni, ci_tcp_state* ts)
{ ts->cwnd = arg_u[0]; }

static void socket_send(ci_netif* ni, ci_tcp_state* ts) {
  ci_iovec iov;
  struct msghdr msg;
  int rc;

  CI_IOVEC_LEN(&iov) = arg_u[0];
  CI_TEST(CI_IOVEC_BASE(&iov) = malloc(arg_u[0]));

  CI_ZERO(&msg);
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* ?? NB. Blocking currently broken due to signal deferral stuff
  ** requiring us to have registered thread data.
  */
  rc = ci_tcp_sendmsg(ni, ts, &msg, MSG_DONTWAIT);
  ci_log("sendmsg(%d:%d, %d, 0) = %d",
	 NI_ID(ni), S_SP(ts), (int) CI_IOVEC_LEN(&iov), rc);
}

static void socket_recv(ci_netif* ni, ci_tcp_state* ts) {
  ci_tcp_recvmsg_args args;
  ci_iovec iov;
  struct msghdr msg;
  int rc;

  CI_IOVEC_LEN(&iov) = arg_u[0];
  CI_TEST(CI_IOVEC_BASE(&iov) = malloc(arg_u[0]));

  CI_ZERO(&msg);
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* ?? NB. Blocking currently broken due to signal deferral stuff
  ** requiring us to have registered thread data.
  */
  ci_tcp_recvmsg_args_init(&args, ni, ts, &msg, MSG_DONTWAIT, addr_spc_ign);
  rc = ci_tcp_recvmsg(&args);
  ci_log("recvmsg(%d:%d, %d, 0) = %d",
	 NI_ID(ni), S_SP(ts), (int) CI_IOVEC_LEN(&iov), rc);
}

static void socket_ppl_corrupt_loop(ci_netif* ni, ci_tcp_state* ts)
{
  /* Put this socket on the post-poll-list and corrupt the list by creating
   * a loop.
   */
  ci_netif_put_on_post_poll(ni, &ts->s.b);
  ts->s.b.post_poll_link.next = ts->s.b.post_poll_link.addr;
}

/**********************************************************************/

ci_inline unsigned t_usec(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (unsigned) ((ci_uint64) tv.tv_sec * 1000000 + tv.tv_usec);
}


/* Return true if arg is a TCP connection in a state that can pass data. */
ci_inline int is_tcp_stream(citp_waitable_obj* wo)
{
  return ( (wo->waitable.state
            & (CI_TCP_STATE_TCP_CONN | CI_TCP_STATE_NOT_CONNECTED
               | CI_TCP_STATE_SYNCHRONISED))
           == (CI_TCP_STATE_TCP_CONN | CI_TCP_STATE_SYNCHRONISED) );
}


typedef struct {
  unsigned	rx, tx;
} sockets_bw_sample_t;

static void sockets_bw_poll(int i)
{
  sockets_bw_sample_t* sam;
  citp_waitable_obj* wo;
  socket_t* s;

  for( s = sockets; s < sockets + sockets_n; ++s ) {
    netif_t* n = stacks[s->stack];
    if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
    if( ! is_tcp_stream(wo) )  continue;
    sam = (sockets_bw_sample_t*) s->s + i;
    sam->rx = tcp_rcv_nxt(&wo->tcp);
    sam->tx = tcp_snd_nxt(&wo->tcp);
  }
}

void sockets_watch_bw(void)
{
  sockets_bw_sample_t* sam;
  unsigned* times;
  citp_waitable_obj* wo;
  socket_t* s;
  unsigned i, boff;
  char* b;

  for( s = sockets; s < sockets + sockets_n; ++s )
    CI_TEST(s->s = malloc(cfg_samples * sizeof(sockets_bw_sample_t)));
  CI_TEST(times = malloc(cfg_samples * sizeof(times[0])));

  times[0] = t_usec();
  sockets_bw_poll(0);
  for( i = 1; i < cfg_samples; ++i ) {
    do times[i] = t_usec();
    while( (unsigned) (times[i] - times[i-1]) < cfg_usec );
    sockets_bw_poll(i);
  }

  printf("# usec delta");
  for( s = sockets; s < sockets + sockets_n; ++s ) {
    ci_uint32 be32;
    netif_t* n = stacks[s->stack];
    if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
    if( ! is_tcp_stream(wo) )  continue;
    be32 = tcp_raddr_be32(&wo->tcp);
    printf(" "CI_IP_PRINTF_FORMAT,CI_IP_PRINTF_ARGS(&be32));
  }
  printf("\n");
  CI_TEST(b = (char*) malloc(sockets_n * 2 * 10 + 20));

  for( i = 1; i < cfg_samples; ++i ) {
    boff = sprintf(b, "%u %u", times[i] - times[0], times[i] - times[i-1]);
    for( s = sockets; s < sockets + sockets_n; ++s ) {
      netif_t* n = stacks[s->stack];
      if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
      wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
      if( ! is_tcp_stream(wo) )  continue;
      sam = (sockets_bw_sample_t*) s->s;
      boff += sprintf(b+boff, " %u %u", SEQ_SUB(sam[i].rx, sam[i-1].rx),
                      SEQ_SUB(sam[i].tx, sam[i-1].tx));
    }
    printf("%s\n", b);
  }

  free(b);
  free(times);
  for( s = sockets; s < sockets + sockets_n; ++s )  free(s->s);
}

/**********************************************************************/

void sockets_bw(void)
{
  unsigned t_start, t_end, usec, txbw, rxbw;
  sockets_bw_sample_t* sam;
  citp_waitable_obj* wo;
  socket_t* s;

  for( s = sockets; s < sockets + sockets_n; ++s )
    CI_TEST(s->s = malloc(2 * sizeof(sockets_bw_sample_t)));

  t_start = t_usec();
  sockets_bw_poll(0);
  ci_sleep(cfg_watch_msec);
  t_end = t_usec();
  sockets_bw_poll(1);
  usec = t_end - t_start;

  for( s = sockets; s < sockets + sockets_n; ++s ) {
    netif_t* n = stacks[s->stack];
    if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
    if( ! is_tcp_stream(wo) )  continue;
    sam = (sockets_bw_sample_t*) s->s;
    txbw = (unsigned) ((ci_uint64) (sam[1].tx - sam[0].tx) * 8 / usec);
    rxbw = (unsigned) ((ci_uint64) (sam[1].rx - sam[0].rx) * 8 / usec);
    if( txbw || rxbw )
      printf("%d:%d  %d %d\n", NI_ID(&n->ni), s->id, txbw, rxbw);
  }

  for( s = sockets; s < sockets + sockets_n; ++s )  free(s->s);
}

/**********************************************************************/

static int sockets_watch_poll(socket_t* s, int first_time)
{
  citp_waitable_obj* wo;

  netif_t* n = stacks[s->stack];
  if( s->id >= (int)n->ni.state->n_ep_bufs )  return 0;
  wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
  if( ! (wo->waitable.state & CI_TCP_STATE_TCP_CONN) )  return 0;
  if( !first_time && ! memcmp(wo, s->s, sizeof(*wo)) )  return 0;
  memcpy(s->s, wo, sizeof(*wo));
  citp_waitable_dump(&n->ni, &wo->waitable, "");
  return 1;
}


void sockets_watch(void)
{
  socket_t* s;

  for( s = sockets; s < sockets + sockets_n; ++s ) {
    CI_TEST(s->s = malloc(sizeof(citp_waitable_obj)));
    sockets_watch_poll(s, 1);
  }

  while( 1 ) {
    int did_anything = 0;
    ci_sleep(cfg_watch_msec);
    for( s = sockets; s < sockets + sockets_n; ++s )
      did_anything += sockets_watch_poll(s, 0);
    if( did_anything )  ci_log(" ");
  }

  for( s = sockets; s < sockets + sockets_n; ++s )  free(s->s);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

#define SOCK_OP_A(nm, fl, help, args)  \
  { #nm, socket_##nm, help, args, (fl) }

#define SOCK_OP_F(nm, fl, help)        SOCK_OP_A(nm, fl, help, NULL)
#define SOCK_OP(nm, help)              SOCK_OP_A(nm, 0,  help, NULL)

#define TCPC_OP_A(nm, fl, help, args)  SOCK_OP_A(nm, (fl)|FL_TCPC, help, args)
#define TCPC_OP(nm, help)              SOCK_OP_A(nm, FL_TCPC, help, "")


static const socket_op_t socket_ops[] = {
  SOCK_OP_F (dump,    FL_NO_LOCK,
             "show socket content"),
  TCPC_OP   (qs,
             "show queues on socket"),
  SOCK_OP_F (lock,    FL_NO_LOCK,
             "lock socket"),
  SOCK_OP_F (unlock,  FL_NO_LOCK,
             "unlock socket"),
  SOCK_OP_F (trylock, FL_NO_LOCK,
             "try to lock socket"),
  SOCK_OP_F (filters, FL_NO_LOCK,
             "show socket's filter info"),
  TCPC_OP   (nodelay,
             "set socket option TCP_NODELAY"),
  TCPC_OP   (nagle,
             "unset socket option TCP_NODELAY"),
  TCPC_OP   (cork,
             "set socket option TCP_CORK"),
  TCPC_OP   (uncork,
             "unset socket option TCP_CORK"),
  TCPC_OP   (advance,
             "advance socket TCP transmission"),
  TCPC_OP   (ack,
             "send ACK"),
  TCPC_OP   (rst,	 "send RST"),
  TCPC_OP_A (set_mss, FL_ARG_U,
             "set TCP socket maximum segment size", "<mss>"),
  TCPC_OP_A (set_pmtu, FL_ARG_U,
             "set TCP path MTU state", "<pmtu>"),
  TCPC_OP_A (set_sndbuf, FL_ARG_U,
             "set socket SO_SNDBUF", "<sndbuf>"),
  TCPC_OP_A (set_rcvbuf, FL_ARG_U,
             "set socket SO_RCVBUF", "<rcvbuf>"),
  TCPC_OP_A (set_cwnd, FL_ARG_U,
             "set congestion window size", "<cwnd>"),
  TCPC_OP_A (send, FL_ARG_U,
             "transmit bytes on socket", "<bytes>"),
  TCPC_OP_A (recv, FL_ARG_U,
             "receive bytes on TCP socket", "<bytes>"),
  TCPC_OP   (ppl_corrupt_loop,
             "corrupt post-poll-list with a loop"),
};
#define N_SOCKET_OPTS	(sizeof(socket_ops) / sizeof(socket_ops[0]))


void for_each_socket_op(void(*fn)(const socket_op_t* op, void* arg), void *arg)
{
  const socket_op_t* op;
  for( op = socket_ops; op < socket_ops + N_SOCKET_OPTS; ++op )
    (*fn)(op, arg);
}


const socket_op_t *get_socket_op(const char* name)
{
  const socket_op_t* op;
  for( op = socket_ops; op < socket_ops + N_SOCKET_OPTS || (op = NULL); ++op )
    if( ! strcmp(op->name, name) )
      break;
  return op;
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static void signal_handler(int signum)
{
  signal_fired = 1;
}


int libstack_init(sa_sigaction_t* signal_handlers)
{
  ci_set_log_prefix("");
  ci_dllist_init(&stacks_list);
  if( libstack_mappings_init() )
    return -1;
  if( signal_handlers )
    libstack_signal_handlers = signal_handlers;
  else
    libstack_signal_handlers = citp_signal_handlers;
  CI_TEST(signal(SIGUSR1, signal_handler) != SIG_ERR);
  return 0;
}

void libstack_end(void)
{
  stacks_detach_all();
}

int libstack_netif_lock(ci_netif* ni)
{
  citp_signal_info* si = citp_signal_get_specific_inited();
  int rc;

  libstack_defer_signals(si);
  rc = ci_netif_lock(ni);
  if( rc != 0 )
    libstack_process_signals(si);
  return rc;
}
void libstack_netif_unlock(ci_netif* ni)
{
  ci_netif_unlock(ni);
  libstack_process_signals(citp_signal_get_specific_inited());
}
int libstack_netif_trylock(ci_netif* ni)
{
  citp_signal_info* si = citp_signal_get_specific_inited();
  int rc;

  libstack_defer_signals(si);
  rc = ci_netif_trylock(ni);
  if( rc )
    return rc;

  /* failed to get lock: process signals */
  libstack_process_signals(si);
  return rc;
}
