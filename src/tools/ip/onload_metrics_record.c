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
** \author  djr
**  \brief  Export metrics from Onload stacks
**   \date  2018/06/11
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */

#include <ci/internal/ip.h>
#include "libc_compat.h"

#if CI_CFG_TCP_METRICS
#if CI_HAVE_PCAP

#include <ci/app.h>
#include <onload/ioctl.h>
#include <onload/cplane_ops.h>
#include "libstack.h"
#include <pcap.h>
#include <net/if.h>
#include <fnmatch.h>


#define LOG_DUMP(x)


/* Data for dynamic update of the stack list */
static oo_fd onload_fd;
static pthread_t update_thread;
static pthread_t master_thread;
static int update_thread_started;
static volatile int stacklist_has_update = 0;

/* Filter stack names */
#define MAX_PATTERNS 10
static const char *filter_patterns[MAX_PATTERNS];
static int filter_patterns_n = 0;

/* NB. Signed value important for use in division below. */
static ci_int64 cpu_khz;

/* Signals we handle to give clean exit. */
static sigset_t sigset;

/* Set when we're killed by a signal. */
static volatile int killed;


static ci_cfg_desc cfg_opts[] = {
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

#define USAGE_STR  "[stack_id|stack_name ...]"


static void usage(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options] " USAGE_STR, ci_appname);

  ci_log(" ");
  ci_log("options:");
  ci_app_opt_usage(cfg_opts, N_CFG_OPTS);
  ci_log(" ");
  exit(-1);
}


struct frc_sync {
  uint64_t          sync_frc;
  uint64_t          sync_cost;
  int64_t           max_frc_diff;
  struct timespec   sync_ts;
};


static void frc_resync(struct frc_sync* fs)
{
  uint64_t after_frc, cost;

  if( fs->sync_cost == 0 ) {
    /* First time: Measure sync_cost and set other params. */
    int i;
    fs->max_frc_diff = cpu_khz * 1000 / 10;
    for( i = 0; i < 10; ++i ) {
      ci_frc64(&fs->sync_frc);
      clock_gettime(CLOCK_REALTIME, &fs->sync_ts);
      ci_frc64(&after_frc);
      cost = after_frc - fs->sync_frc;
      if( i == 0 )
        fs->sync_cost = cost;
      else
        fs->sync_cost = CI_MIN(fs->sync_cost, cost);
    }
    LOG_DUMP(ci_log("cpu_khz=%"PRId64" sync_cost=%"PRIu64"\n",
                    cpu_khz, fs->sync_cost));
  }

  /* Determine correspondence between frc and host clock. */
  do {
    ci_frc64(&fs->sync_frc);
    clock_gettime(CLOCK_REALTIME, &fs->sync_ts);
    ci_frc64(&after_frc);
  } while( after_frc - fs->sync_frc > fs->sync_cost * 3 );
}


static void frc2time(ci_uint64 frc, struct timespec* ts_out)
{
  static struct frc_sync fs;
  int64_t ns, frc_diff = frc - fs.sync_frc;

  /* This if() triggers on the first call. */
  if( frc_diff > fs.max_frc_diff ) {
    frc_resync(&fs);
    frc_diff = frc - fs.sync_frc;
  }

  *ts_out = fs.sync_ts;
  ns = frc_diff * 1000000 / cpu_khz;
  if( ns >= 0 ) {
    while( ns >= 1000000000 ) {  /* NB. This loop is much cheaper than div */
      ts_out->tv_sec += 1;
      ns -= 1000000000;
    }
    ts_out->tv_nsec += ns;
    if( ts_out->tv_nsec >= 1000000000 ) {
      ts_out->tv_nsec -= 1000000000;
      ts_out->tv_sec += 1;
    }
  }
  else {
    while( ns <= -1000000000 ) {  /* NB. This loop is much cheaper than div */
      ts_out->tv_sec -= 1;
      ns += 1000000000;
    }
    if( -ns <= ts_out->tv_nsec ) {
      ts_out->tv_nsec += ns;
    }
    else {
      ts_out->tv_nsec += 1000000000 + ns;
      ts_out->tv_sec -= 1;
    }
  }
}


static void stack_dump_on(ci_netif *ni)
{
  struct oo_metrics_ring* mr = &ni->state->metrics_ring;

  cpu_khz = IPTIMER_STATE(ni)->khz;

#ifdef NDEBUG
  if( mr->export_enabled ) {
    ci_log("[%d,%s] ERROR: this stack is already being dumped",
           ni->state->stack_id, ni->state->name);
    /* Detach just now, but if we are dumping every
     * stack, we will attach again and again. */
    stack_detach(stack_attached(ni->state->stack_id), 0);
    return;
  }
#endif

  /* No data from other tcpdump processes should be available. */
  ci_assert_equal(mr->metrics_read_i, mr->metrics_write_i);

  /* Set up dumping */
  ci_log("[%d,%s]: start dump", ni->state->stack_id, ni->state->name);
  mr->drops = 0;
  ci_mb();
  mr->export_enabled = 1;
}


static void stack_dump_off(ci_netif* ni)
{
  struct oo_metrics_ring* mr = &ni->state->metrics_ring;
  libstack_netif_lock(ni);
  mr->export_enabled = 0;
  mr->metrics_read_i = mr->metrics_write_i;
  ci_log("[%d,%s]: stop dump", ni->state->stack_id, ni->state->name);
  if( mr->drops )
    ci_log("[%d,%s]: WARNING: %u records dropped",
           ni->state->stack_id, ni->state->name, mr->drops);
  libstack_netif_unlock(ni);
}


static void stack_dump_off_in_sig(ci_netif* ni)
{
  struct oo_metrics_ring* mr = &ni->state->metrics_ring;
  mr->export_enabled = 0;
  ci_mb();
  mr->metrics_read_i = mr->metrics_write_i;
}


static void dump_flush(void)
{
  if( fflush(stdout) == EOF ) {
    ci_log("Failed to flush stdout");
    exit(1);
  }
}


static void stack_dump(ci_netif* ni)
{
  struct oo_metrics_ring* mr = &ni->state->metrics_ring;
  ci_uint16 read_i = mr->metrics_read_i;
  ci_uint16 i, fill_level = mr->metrics_write_i - read_i;
  struct timespec ts;

  if( fill_level == 0 )
    return;

  /* Dump a batch of records, then update metrics_read_i.  Avoid writing
   * metrics_read_i frequently since dirtying the cache line adds overhead
   * to the application we're monitoring.
   */
  if( fill_level > CI_CFG_METRICS_RING_SIZE / 4 )
    fill_level = CI_CFG_METRICS_RING_SIZE / 4;

  /* Barrier to ensure entries in dump ring are written. */
  ci_rmb();

  /* Prevent ^C from creating truncated dump file */
  CI_TEST( pthread_sigmask(SIG_BLOCK, &sigset, NULL) == 0 );

  for( i = 0; i < fill_level; ++i, ++read_i ) {
    const struct oo_metrics_record* rec;
    rec = &mr->entries[read_i % CI_CFG_METRICS_RING_SIZE];
    switch( rec->type ) {
    case MRT_TCP_OPEN:
      frc2time(rec->tcp_open.open_frc, &ts);
      printf("TO %d %u %d %d "OOF_IP4" "OOF_PORT" "OOF_IP4" "OOF_PORT
             " %ld.%06d %d %d\n",
             NI_ID(ni), rec->tcp_open.conn_id, rec->tcp_open.ep_id,
             rec->tcp_open.active_open,
             OOFA_IP4(rec->tcp_open.lcl_ip), OOFA_PORT(rec->tcp_open.lcl_port),
             OOFA_IP4(rec->tcp_open.rmt_ip), OOFA_PORT(rec->tcp_open.rmt_port),
             (long) ts.tv_sec, (int) ts.tv_nsec / 1000,
             oo_metrics_intvl2us(ni, rec->tcp_open.open_time),
             (int) rec->tcp_open.open_retries);
      break;
    case MRT_TCP_REQ:
      printf("TR %d %u %d %u %u %u %u %u %u %u\n",
             NI_ID(ni), rec->tcp_req.conn_id,
             (rec->tcp_req.flags & TSM_F_CLIENT) ? 1 : 0,
             rec->tcp_req.rx_bytes, rec->tcp_req.tx_bytes,
             rec->tcp_req.app_time, rec->tcp_req.tx_time,
             rec->tcp_req.idle_time, rec->tcp_req.rx_time,
             rec->tcp_req.retransmits);
      break;
    }
  }

  /* Ensure we've finished reading before we release. */
  ci_mb();
  mr->metrics_read_i = read_i;

  dump_flush();
  CI_TEST( pthread_sigmask(SIG_UNBLOCK, &sigset, NULL) == 0 );
}


/* Pre detach: almost the same as stack_dump_off, but dump records instead
 * of dropping them.
 */
static void stack_pre_detach(ci_netif *ni)
{
  struct oo_metrics_ring* mr = &ni->state->metrics_ring;
  mr->export_enabled = 0;
  ci_mb();
  stack_dump(ni);
  ci_log("[%d,%s]: now unused; stop dump",
         ni->state->stack_id, ni->state->name);
  if( mr->drops )
    ci_log("[%d,%s]: WARNING: %u records dropped",
           ni->state->stack_id, ni->state->name, mr->drops);
}


/* Used in stack_verify_used: help to check if there are any stacks */
static void stackid_check(int id, void *arg)
{
  int *set = arg;
  *set = 1;
}


/* Verify that the given stack is really used */
static void stack_verify_used(ci_netif *ni)
{
  ci_netif_info_t info;

  info.mmap_bytes = 0;
  info.ni_exists = 0;

  info.ni_index = ni->state->stack_id;
  info.ni_orphan = 0;
  info.ni_subop = CI_DBG_NETIF_INFO_NOOP;
  CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_GET_STACK_INFO, &info));

  ci_assert(info.ni_exists);

  if( info.rs_ref_count == 2 ) {
    int have_attached;
    LOG_DUMP(ci_log("We are the only user of stack %d", info.ni_index));
    stack_pre_detach(ni);
    stack_detach(stack_attached(info.ni_index), 0);

    /* Check that we have attached stacks */
    have_attached = 0;
    for_each_stack_id(stackid_check, &have_attached);
    if( !have_attached ) {
      ci_log("All stacks exited");
      exit(0);
    }
  }
}


static int stackfilter_match_name(ci_netif_info_t *info)
{
  int i;
  for( i = 0; i < filter_patterns_n; i++ ) {
    if( fnmatch(filter_patterns[i], info->ni_name, 0) == 0)
      return 1;
  }
  LOG_DUMP(ci_log("Onload stack [%d,%s]: not interested",
                  info->ni_index, info->ni_name));
  return 0; /* Not interested */
}


static void sighandler_fn(int sig, siginfo_t *info, void *context)
{
  if( ! killed ) {
    killed = 1;
    return;
  }
  /* Second signal. */
  for_each_stack(stack_dump_off_in_sig, 0);
  exit(0);
}


static sa_sigaction_t sighandlers[OO_SIGHANGLER_DFL_MAX+1] =
  { sighandler_fn, NULL, NULL };


/* Thread to catch stack list updates.  This thread should not call
 * list_all_stacks2(), since libstack is not thread-safe.  So, we just set
 * stacklist_has_update flag and main thread should call
 * list_all_stacks2(). */
static void *update_stack_list_thread(void *arg)
{
  struct oo_stacklist_update param;

  param.timeout = -1;
  param.seq = *(ci_uint32 *)arg;
  LOG_DUMP(ci_log("%s: inital seq=%d", __func__, param.seq));
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  while(1) {
    CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_WAIT_STACKLIST_UPDATE, &param));
    stacklist_has_update = 1;
    LOG_DUMP(ci_log("%s: new seq=%d", __func__, param.seq));
  }

  /* Unreachable */
  return NULL;
}


int main(int argc, char* argv[])
{
  int attach_new_stacks = 0;
  stackfilter_t *stackfilter = NULL;
  struct oo_stacklist_update param;

  ci_app_usage = usage;
  cfg_nopids = 1; /* pids are not needed, and can cause excessive delay */

  ci_app_getopt(USAGE_STR, &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  master_thread = pthread_self();
  CI_TRY(libstack_init(sighandlers));

  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGQUIT);
  sigaddset(&sigset, SIGPIPE);

  /* Get the initial seq no of stack list */
  CI_TRY(oo_fd_open(&onload_fd));
  param.timeout = 0;
  CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_WAIT_STACKLIST_UPDATE, &param));

  /* Attach to stacks: attach locks the stacks, stack_dump_on unlocks. */
  if( argc == 0 ) {
    attach_new_stacks = 1;
    list_all_stacks2(NULL, stack_dump_on, NULL, &onload_fd);
  }
  else {
    for( ; argc > 0 ; --argc, ++argv ) {
      unsigned stack_id;
      char dummy;

      if( sscanf(argv[0], " %u %c", &stack_id, &dummy) != 1 ) {
        if( filter_patterns_n == MAX_PATTERNS ) {
          ci_log("Too much stack name patterns: ignore '%s'", argv[0]);
          continue;
        }
        filter_patterns[filter_patterns_n++] = argv[0];
        attach_new_stacks = 1;
        continue;
      }
      if( ! stack_attach(stack_id) ) {
        ci_log("No such stack id: %d", stack_id);
        continue;
      }
      stack_dump_on(&stack_attached(stack_id)->ni);
    }
    if( attach_new_stacks ) {
      stackfilter = stackfilter_match_name;
      list_all_stacks2(stackfilter, stack_dump_on, NULL, &onload_fd);
    }
  }

  /* Create thread to notify us about stack list updates */
  pthread_create(&update_thread, NULL, update_stack_list_thread, &param.seq);
  update_thread_started = 1;

  printf("#TO s_id c_id ep_id active laddr lport raddr rport time open_us "
         "retries\n");
  printf("#TR s_id c_id cl rx_bytes tx_bytes app_us tx_us idle_us rx_us "
         "retrans\n");

  while( ! killed ) {
    for_each_stack(stack_dump, 0);

    if( stacklist_has_update ) {
       stacklist_has_update = 0; /* drop flag before updating the list */
       if( attach_new_stacks ) {
         list_all_stacks2(stackfilter, stack_dump_on, stack_pre_detach,
                          &onload_fd);
       }
       else {
         for_each_stack(stack_verify_used, 0);
       }
    }
  }

  for_each_stack(stack_dump_off, 0);
  return 0;
}

#else /* CI_HAVE_PCAP */

int main(int argc, char* argv[])
{
  ci_log("Onload was compiled without the libpcap development package.  "
         "You need to install the libpcap-devel or libpcap-dev package "
         "to run onload_metrics.");
  return 1;
}

#endif /* CI_HAVE_PCAP */
#else /* CI_CFG_TCP_METRICS */

int main(int argc, char* argv[])
{
  ci_log("Onload was compiled without TCP metrics support.  "
         "Please turn CI_CFG_TCP_METRICS on.");
  return 1;
}

#endif /* CI_CFG_TCP_METRICS */
