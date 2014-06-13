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
** <L5_PRIVATE L5_SOURCE>
** \author  sasha
**  \brief  tcpdump process for onload stack
**   \date  2011/05/17
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */
#define _GNU_SOURCE /* for strsignal */
#include <stdlib.h>
#include <ci/internal/ip.h>

#if CI_CFG_TCPDUMP
#if CI_HAVE_PCAP

#include <ci/app.h>
#include <onload/ioctl.h>
#include <ci/internal/cplane_handle.h>
#include <ci/internal/cplane_ops.h>
#include "libstack.h"
#include <pcap.h>
#include <net/if.h>
#include <fnmatch.h>

#define LOG_DUMP(x)

struct oo_pcap_pkthdr {
  struct oo_timeval ts;
  ci_uint32 caplen;
  ci_uint32 len;
};

#define MAXIMUM_SNAPLEN 65535
static int cfg_snaplen = MAXIMUM_SNAPLEN;
static int cfg_dump_os = 1;
static int cfg_if_is_loop = 0;
static struct timeval tv_now;

/* Interface to dump */
static const char *cfg_interface = "any";
static int cfg_ifindex = -1;
static cicp_encap_t cfg_encap;
#define CI_HWPORT_ID_LO CI_CFG_MAX_REGISTER_INTERFACES
ci_int8 dump_hwports[CI_CFG_MAX_REGISTER_INTERFACES+2];

/* Data for dynamic update of the stack list */
static oo_fd onload_fd = (oo_fd)-1;
static pthread_t update_thread;
static pthread_t master_thread;
static int update_thread_started = 0;
static volatile int stacklist_has_update = 0;

/* Filter stack names */
#define MAX_PATTERNS 10
static const char *filter_patterns[MAX_PATTERNS];
static int filter_patterns_n = 0;


static ci_cfg_desc cfg_opts[] = {
  {'s', "snaplen",   CI_CFG_UINT, &cfg_snaplen,
                "snarf snaplen bytes of data from each packet, man tcpdump"},
  {'i', "interface", CI_CFG_STR,  &cfg_interface,
                "interface to listen on, default to \"any\", man tcpdump"},
  {  1, "dump-os",   CI_CFG_FLAG, &cfg_dump_os, "dump packets sent via OS"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

#define USAGE_STR "[stack_id|stack_name ...] >pcap_file"

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

/* Using cicp_llap_retrieve(), convert cfg_ifindex to the interface bitmask
 * dump_hwports. */
static void ifindex_to_intf_i(ci_netif *ni)
{
  ci_hwport_id_t hwport;
  ci_ifid_t base_ifindex;
  int rc;

  memset(dump_hwports, 0, sizeof(dump_hwports));

  if( cfg_if_is_loop ) {
    dump_hwports[CI_HWPORT_ID_LO] = 1;
    LOG_DUMP(ci_log("dump on loopback"));
    return;
  }

  rc = cicp_llap_retrieve(CICP_HANDLE(ni), cfg_ifindex, NULL/*mtu*/,
                          &hwport, NULL/*mac*/, &cfg_encap,
                          &base_ifindex, NULL);

  if( rc != 0 ) {
    ci_log("unknown interface %d: %s", cfg_ifindex, cfg_interface);
    goto suicide;
  }
  if( cfg_encap.type == CICP_LLAP_TYPE_NONE ) {
    ci_log("non-onload interface %d: %s", cfg_ifindex, cfg_interface);
    goto suicide;
  }

#if CI_CFG_TEAMING
  /* Is it bond? */
  if( cfg_encap.type & CICP_LLAP_TYPE_BOND ) {
    rc = ci_bond_get_hwport_list(CICP_HANDLE(ni), base_ifindex, dump_hwports);
    if( rc == 0 ) {
      LOG_DUMP(
        int i;
        for(i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; i++)
          ci_log("dump_hwports[%d]=%d", i, dump_hwports[i]);
      )
      return;
    }
  }
#endif

  ci_assert_nequal(hwport, CI_HWPORT_ID_BAD);
  dump_hwports[hwport] = 1;
  LOG_DUMP(ci_log("dump on hwport=%d", hwport));

  return;

suicide:
  /* XXX Fixme:
   * for pcap plugin we should exit graciously without killing others */
  /* for onload_tcpdump we should exit */
  libstack_netif_unlock(ni);
  exit(1);
}

/* Turn dumping on */
static void stack_dump_on(ci_netif *ni)
{
  int i;
  ci_assert(ci_netif_is_locked(ni));

#ifdef NDEBUG
  {
    int i;
    /* Warn user if this is not the only tcpdump process running */
    for( i = 0;
         i < sizeof(ni->state->dump_intf) / sizeof(ni->state->dump_intf[0]);
         i++) {
      if( ni->state->dump_intf[i] != 0 ) {
        ci_log("ERROR: Onload stack [%d,%s] already has tcpdump process.  "
               "Multiple tcpdump processes for Onload do not work well.",
               ni->state->stack_id, ni->state->name);
        /* Detach just now, but if we are dumping every
         * stack, we will attach again and again. */
        stack_detach(stack_attached(ni->state->stack_id));
        return;
      }
    }
  }
#endif

  /* No data from other tcpdump processes should be available. */
  ci_assert_equal(ni->state->dump_read_i, ni->state->dump_write_i);

  /* Init dump queue */
  for( i = 0; i < CI_CFG_DUMPQUEUE_LEN; i++ )
    ni->state->dump_queue[i] = OO_PP_NULL;

  /* Find interface details if unknown */
  if( dump_hwports[0] == -1 )
    ifindex_to_intf_i(ni);

  /* Set up dumping */
  ci_log("Onload stack [%d,%s]: start packet dump",
         ni->state->stack_id, ni->state->name);
  {
    ci_hwport_id_t hwport_i;
    int intf_i;
    for( hwport_i = 0;
         hwport_i < CI_CFG_MAX_REGISTER_INTERFACES;
         hwport_i++ ) {
      intf_i = ci_netif_get_hwport_to_intf_i(ni)[hwport_i];
      if( intf_i >= 0 )
        ni->state->dump_intf[intf_i] = dump_hwports[hwport_i];
    }
    ni->state->dump_intf[OO_INTF_I_LOOPBACK] = dump_hwports[CI_HWPORT_ID_LO];
  }
  ni->state->dump_intf[OO_INTF_I_SEND_VIA_OS] = cfg_dump_os;
  libstack_netif_unlock(ni);
}

/* Turn dumping off */
static void stack_dump_off(ci_netif *ni)
{
  memset(ni->state->dump_intf, 0, sizeof(ni->state->dump_intf));
  libstack_netif_lock(ni);
  while( ni->state->dump_read_i != ni->state->dump_write_i ) {
    LOG_DUMP(ci_log("drop pkt %d", ni->state->dump_queue[
                    ni->state->dump_read_i % CI_CFG_DUMPQUEUE_LEN]));
    ci_netif_pkt_release(ni, PKT_CHK(ni,
                    ni->state->dump_queue[
                            ni->state->dump_read_i % CI_CFG_DUMPQUEUE_LEN]));
    ni->state->dump_read_i++;
  }
  ci_log("Onload stack [%d,%s]: stop packet dump",
         ni->state->stack_id, ni->state->name);
}

/* Dump and flush dumped data */
static void dump_data(const void *data, size_t size)
{
  if( fwrite(data, size, 1, stdout) != 1 ) {
    ci_log("Failed to dump packet data to stdout");
    exit(1);
  }
}
static void dump_flush(void)
{
  if( fflush(stdout) == EOF ) {
    ci_log("Failed to flush stdout");
    exit(1);
  }
}

/* Do dump */
static void stack_dump(ci_netif *ni)
{
  int strip_vlan = cfg_encap.type & CICP_LLAP_TYPE_VLAN;
  ci_uint8 max_i = ni->state->dump_write_i;
  sigset_t sigset;

  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);

  /* We store old value of max_i, so we can dump a limited number of
   * packets and go to the next stack even if this stack adds more and more
   * job for us. */
  for( ;
       ni->state->dump_read_i != max_i;
       ni->state->dump_read_i++ ) {
    struct oo_pcap_pkthdr hdr;
    int paylen;
    int fraglen;
    oo_pkt_p id;
    ci_ip_pkt_fmt *pkt;
    
    /* dump_read_i should be set BEFORE we use this packet */
    ci_wmb();
    id = ni->state->dump_queue[ni->state->dump_read_i % CI_CFG_DUMPQUEUE_LEN];
    if( id == OO_PP_NULL )
      continue;
    pkt = PKT_CHK(ni, id);

    ci_assert_gt(pkt->refcount, 0);

    paylen = CI_BSWAP_BE16(oo_ip_hdr(pkt)->ip_tot_len_be16);

    /* Check interface: since intf_i is already checked, we should
     * check VLAN id only (and strip it). */
    if( strip_vlan ) {
      if( cfg_dump_os && pkt->intf_i == OO_INTF_I_SEND_VIA_OS )
        paylen += ETH_HLEN;
      else if( pkt->vlan != cfg_encap.vlan_id )
        continue;
      else
        paylen += ETH_HLEN;
    }
    else
      paylen += oo_ether_hdr_size(pkt);

    hdr.caplen = CI_MIN(cfg_snaplen, paylen);
    fraglen = hdr.caplen;
    if( pkt->n_buffers > 1 )
      fraglen = CI_MIN(fraglen, pkt->buf_len);
    hdr.len = paylen;
    hdr.ts.tv_sec = tv_now.tv_sec;
    /* Avoid another gettimeofday().
     * Possibly, we should increment tv_now.tv_usec, but:
     * 10Gbit/sec=10Kbit/usec=1Kbyte/usec.
     * I.e., for one interface with 10Gbit/sec,
     * minimal packet of 64bytes takes less than usec.
     * For 2 full-duplex 10Gbit/s interfaces things are worse. */
    hdr.ts.tv_usec = tv_now.tv_usec;
    LOG_DUMP(ci_log("%u: got ni %d pkt %d len %d ref %d",
                    ni->state->dump_read_i, ni->state->stack_id,
                    OO_PKT_FMT(pkt), paylen, pkt->refcount));

    /* Prevent ^C from creating truncated dump file */
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    dump_data(&hdr, sizeof(hdr));
    if( strip_vlan && pkt->intf_i != OO_INTF_I_SEND_VIA_OS ) {
      dump_data(oo_ether_hdr(pkt), 2 * ETH_ALEN);
      dump_data((char *)oo_ether_hdr(pkt) + 2 * ETH_ALEN + ETH_VLAN_HLEN,
                fraglen - 2 * ETH_ALEN);
    }
    else
      dump_data(oo_ether_hdr(pkt), fraglen);

    /* Dump all scatter-gather chain */
    if( pkt->n_buffers  > 1 ) {
      ci_ip_pkt_fmt *frag = PKT_CHK(ni, pkt->frag_next);
      do {
        hdr.caplen -= fraglen;
        fraglen = CI_MIN(hdr.caplen, frag->buf_len);
        if( fraglen > 0 )
          dump_data(&pkt->ether_base, fraglen);
        if( OO_PP_IS_NULL(frag->frag_next) )
          break;
        frag = PKT_CHK(ni, frag->frag_next);
      } while( frag != NULL );
    }

    pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
  }
}

/* Pre detach: almost the same as stack_dump_off, but dump packets instead
 * of dropping them. */
static void stack_pre_detach(ci_netif *ni)
{
  memset(ni->state->dump_intf, 0, sizeof(ni->state->dump_intf));
  ci_wmb();
  stack_dump(ni);
  ci_log("Onload stack [%d,%s] is now unused: stop dumping",
         ni->state->stack_id, ni->state->name);
  /* we have cfg_lock=1, so stack_detach expects locked stack */
  libstack_netif_lock(ni);
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
  info.ni_subop = CI_DBG_NETIF_INFO_GET_ENDPOINT_STATE;
  CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_GET_STACK_INFO, &info));

  ci_assert(info.ni_exists);

  if( info.rs_ref_count == 2 ) {
    int have_attached;
    LOG_DUMP(ci_log("We are the only user of stack %d", info.ni_index));
    stack_pre_detach(ni);
    stack_detach(stack_attached(info.ni_index));

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
    if( fnmatch(filter_patterns[i], info->u.ni_next_ni.ni_name, 0) == 0)
      return 1;
  }
  LOG_DUMP(ci_log("Onload stack [%d,%s]: not interested",
                  info->ni_index, info->u.ni_next_ni.ni_name));
  return 0; /* Not interested */
}

static void atexit_fn(void)
{
  if( update_thread_started ) {
    pthread_cancel(update_thread);
    pthread_join(update_thread, NULL);
  }

  for_each_stack(stack_dump_off, 0);
  libstack_end();

  CI_TRY(oo_fd_close(onload_fd));

  /* Do not use fflush, sice we exit via signal.  All our threads are
   * cancelled, so we are safe here. */
  fflush_unlocked(stdout);
}
static void sighandler_fn(int sig, siginfo_t *info, void *context)
{
  if( update_thread == pthread_self() ) {
    /* We get here because master thread is blocking SIGINT.
     * So we re-send the signal to the master thread. */
    pthread_kill(master_thread, sig);
    return;
  }
  ci_log("Exit on signal %d %s", sig, strsignal(sig));
  exit(0);
}
sa_sigaction_t sighandlers[OO_SIGHANGLER_DFL_MAX+1] =
                                {sighandler_fn, NULL,NULL};

static void write_pcap_header(void)
{
  struct pcap_file_header hdr;

  hdr.magic = 0xa1b2c3d4;
  hdr.version_major = PCAP_VERSION_MAJOR;
  hdr.version_minor = PCAP_VERSION_MINOR;
  hdr.thiszone = 0;
  hdr.sigfigs = 0;
  hdr.snaplen = cfg_snaplen;
  hdr.linktype = DLT_EN10MB;

  dump_data(&hdr, sizeof(hdr));
  dump_flush();
}

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

/* Parse cfg_interface string and fill dump_hwports array.
 * We do exactly the same parsing as in tcpdump;
 * in case of error, we dump all interfaces, as with -iany */
static void parse_interface(void)
{
  int devnum;   /* pcap devnum */

  /* If cfg_interface is a number, we should parse it with
   * pcap_findalldevs(). */
  if( (devnum = atoi(cfg_interface)) != 0 ) {
    pcap_if_t *devpointer;
    char ebuf[PCAP_ERRBUF_SIZE];
    int i;

    if (devnum < 0) {
      ci_log("Error: infertace is negative number %d", devnum);
      goto error;
    }
    if( pcap_findalldevs(&devpointer, ebuf) < 0 ) {
      ci_log("Error: interface is a number %d, but pcap_findalldevs fails",
             devnum);
      goto error;
    }
    for( i = 0;
         i < devnum-1 && devpointer != NULL;
         i++, devpointer = devpointer->next );
    if( devpointer == NULL ) {
      ci_log("Error: no interface with pcap number %d", devnum);
      goto error;
    }
    cfg_interface = devpointer->name;
  }
  ci_log("Onload tcpdump on interface %s", cfg_interface);

  /* Now cfg_interface is an interface name.  Find the ifindex. */
  if( strcmp(cfg_interface, "any") == 0 ) {
    memset(dump_hwports, 1, sizeof(dump_hwports));
    return;
  }
  else
  {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if( fd < 0 ) {
      ci_log("ERROR: can not create socket");
      exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cfg_interface, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
      ci_log("Error: can not find ifindex for interface %s", cfg_interface);
      goto error;
    }
    cfg_ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
      ci_log("Error: can not find flags for interface %s", cfg_interface);
      goto error;
    }
    if( ifr.ifr_flags & IFF_LOOPBACK )
      cfg_if_is_loop = 1;
  }
  LOG_DUMP(ci_log("dump ifindex %d", cfg_ifindex));

  /* We can't use cicp_llap_retrieve() before we get any netif.  So, we set
   * a flag "fill me later" and return. */
  dump_hwports[0] = -1;
  return;

error:
  LOG_DUMP(ci_log("Error: dump all interfaces"));
  /* We do not exit in case of error: we just do our best and turn on
   * tcpdump on ALL interfaces.  If onload_tcpdump script is used,
   * tcpdump will report the proper error. */
  memset(dump_hwports, 1, CI_CFG_MAX_INTERFACES);
  dump_hwports[OO_INTF_I_LOOPBACK] = 1;
}

int main(int argc, char* argv[])
{
  int attach_new_stacks = 0;
  stackfilter_t *stackfilter = NULL;
  struct oo_stacklist_update param;

  ci_app_usage = usage;
  cfg_lock = 1; /* lock when attaching */

  ci_app_getopt(USAGE_STR, &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;
  master_thread = pthread_self();
  CI_TRY(libstack_init(sighandlers));

  /* Fix cfg_snaplen value. */
  if( cfg_snaplen == 0 )
    cfg_snaplen = MAXIMUM_SNAPLEN; /* tcpdump compatibility */
  cfg_snaplen = CI_MAX(cfg_snaplen, 80);
  cfg_snaplen = CI_MIN(cfg_snaplen, MAXIMUM_SNAPLEN);

  /* Parse interfaces */
  parse_interface();

  /* Pcap file header */
  write_pcap_header();

  /* Get the initial seq no of stack list */
  CI_TRY(oo_fd_open(&onload_fd));
  param.timeout = 0;
  CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_WAIT_STACKLIST_UPDATE, &param));

  /* Set up exit and signals before we attach to stacks */
  atexit(atexit_fn);

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

  while(1) {
    /* Wait for some stacks to be created if necessary. */
    if( dump_hwports[0] == -1 ) {
      if( !attach_new_stacks ) {
        ci_log("Failed to attach to any stacks, exit");
        exit(1);
      }
      while( ! stacklist_has_update )
        ci_spinloop_pause();
    }

    gettimeofday(&tv_now, NULL);
    for_each_stack(stack_dump, 0);
    /* Re-enable signals */

    if( stacklist_has_update ) {
       stacklist_has_update = 0; /* drop flag before updating the list */
       if( attach_new_stacks ) {
         list_all_stacks2(stackfilter, stack_dump_on, stack_pre_detach,
                          &onload_fd);
       }
       else
         for_each_stack(stack_verify_used, 0);
    }
    else
      dump_flush();
  }

  /* unreachable */
  return 0;
}
#else /* CI_HAVE_PCAP */
int
main(int argc, char* argv[])
{
  ci_log("Onload was compiled without libpcap development package installed.  "
         "You need to install libpcap-devel or libpcap-dev package "
         "to run onload_tcpdump.");
  return 1;
}
#endif /* CI_HAVE_PCAP */
#else /* CI_CFG_TCPDUMP */
int
main(int argc, char* argv[])
{
  ci_log("Onload was compiled without tcpdump support.  "
         "Please, turn CI_CFG_TCPDUMP on.");
  return 1;
}
#endif /* CI_CFG_TCPDUMP */
