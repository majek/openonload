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
*//*! \file linux_stats.c OS Interface for reporting network statistics
** <L5_PRIVATE L5_SOURCE>
** \author  Level 5
**  \brief  Package - driver/linux/net	Linux network driver support
**     $Id$
**   \date  2004/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */

 
/*--------------------------------------------------------------------
 *
 * Compile time assertions for this file
 *
 *--------------------------------------------------------------------*/

#define __ci_driver_shell__	/* implements driver to kernel interface */

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include "onload_internal.h"
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_fns.h>
#include <onload/tcp_driver.h>
#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>

#include <onload/cplane.h>
#include <ci/internal/ip.h>
#include <onload/efabcfg.h>
#include <onload/version.h>
#include <onload/driverlink_filter.h>

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/proc_fs.h>
#include <linux/module.h>



#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define PROC_NET proc_net
#else
#define PROC_NET current->nsproxy->net_ns->proc_net
#endif


/*--------------------------------------------------------------------
 *
 * Local constant declarations
 *
 *--------------------------------------------------------------------*/

/* Maximum time in jiffies for which stats from NIC structure is steel up
 * to date */
#define CI_LINUX_STATISTICS_UPDATE_FREQUENCY    1


/* /proc/net/tcp definitions */

/** line length for /proc/net/tcp file */
#define CI_TCP_SOCK_STAT_LINE_LENGTH            150

/** line length for /proc/net/udp file */
#define CI_UDP_SOCK_STAT_LINE_LENGTH            128

/** define line lingth by file_type */
#define CI_SOCK_STAT_LINE_LENGTH(file_type) \
  ((file_type) == CI_PROC_NET_TCP_ENTRY ? CI_TCP_SOCK_STAT_LINE_LENGTH : \
   CI_UDP_SOCK_STAT_LINE_LENGTH)

/** maximum line length to allocate */
#define CI_SOCK_STAT_LINE_LENGTH_MAX  (CI_TCP_SOCK_STAT_LINE_LENGTH + 1)

/** IPPROTO by file type */
#define CI_IPPROTO_BY_FILETYPE(file_type) \
    ((file_type) == CI_PROC_NET_TCP_ENTRY ? IPPROTO_TCP : IPPROTO_UDP)


/* /proc/net/snmp definitions */

/** number of parameters in IPv4 section of /proc/net/snmp file */
#define CI_IP_STATS_SNMP_IPV4_PARAM_COUNT       19

/** number of parameters in ICMP section of /proc/net/snmp file */
#define CI_IP_STATS_SNMP_ICMP_PARAM_COUNT       26

/** number of parameters in TCP section of /proc/net/snmp file */
#define CI_IP_STATS_SNMP_TCP_PARAM_COUNT        14

/** number of parameters in UDP section of /proc/net/snmp file */
#define CI_IP_STATS_SNMP_UDP_PARAM_COUNT        4

/** maximum length of word in /proc/net/snmp header line */
#define CI_IP_STATS_SNMP_HEADER_WORD_LENGTH     20

/** number of parameters in TcpExt section of /proc/net/netstat file */
#define CI_IP_STATS_NETSTAT_TCPEXT_PARAM_COUNT  65


/** Top level directory for sfc specific stats **/
struct proc_dir_entry *oo_proc_root = NULL;


/*--------------------------------------------------------------------
 *
 * Local function declarations
 *
 *--------------------------------------------------------------------*/

static void
get_tcp_sock(ci_netif *netif, ci_tcp_state *ts, char *tmpbuf, int num);

static int ci_tcp_seq_fop_open(struct inode *, struct file *);
static int ci_netstat_seq_open(struct inode *, struct file *);

static void *ci_tcp_seqop_start(struct seq_file *seq, loff_t *ppos);
static void *ci_tcp_seqop_next(struct seq_file *seq, void *v, loff_t *ppos);
static void ci_tcp_seqop_stop(struct seq_file *seq, void *v);
static int ci_tcp_seqop_show(struct seq_file *seq, void *v);


#if CI_CFG_STATS_NETIF
static int
efab_stacks_read_proc(char* buf, char** start, off_t offset, int count, 
		      int* eof, void* data);
#endif
static int
efab_version_read_proc(char* buf, char** start, off_t offset, int count, 
                       int* eof, void* data);
static int 
efabcfg_raw_read_proc(char *buf, char **start, off_t offset, int count, 
                      int *eof, void *data);
static int 
efab_workq_read_proc(char *buf, char **start, off_t offset, int count, 
		     int *eof, void *data);
static int
efab_dlfilters_read_proc(char* buf, char** start, off_t offset, int count, 
                         int* eof, void* data);

/*--------------------------------------------------------------------
 *
 * Private proc entry data structure
 *
 *--------------------------------------------------------------------*/
#define CI_PROC_NET_FLAG_KERNEL 1
#define CI_PROC_NET_FLAG_L5     2

/* Define standard linux open() and seq_show() methods */
typedef int (file_open_t)(struct inode *, struct file *);
typedef int (seq_show_t)(struct seq_file *, void *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define CI_TCP_SEQ_OPS_IN_AFINFO
#endif

typedef struct ci_netstat_seq_priv {
  ci_uint8      flag;
  ci_uint8      file_type;
  seq_show_t   *kern_show;
} ci_netstat_seq_priv;

typedef struct ci_tcp_seq_priv {
  union {
    struct tcp_iter_state tcp;
    struct udp_iter_state udp;
  } kern;

#ifdef CI_TCP_SEQ_OPS_IN_AFINFO
  struct seq_operations *seq_ops;
#endif

  /* Current status: remember which entries are already shown */
  int       l5;
  ci_netif *netif;
  int       ts_id;

  /* Permanent status: the file type */
  ci_uint8  flag;
  ci_uint8  file_type;
} ci_tcp_seq_priv;

#ifdef CI_TCP_SEQ_OPS_IN_AFINFO
#define CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, _field) ((st)->seq_ops->_field)
#else
#define CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, _field)        \
  ((st)->file_type == CI_PROC_NET_TCP_ENTRY ?                  \
   (st)->kern.tcp.seq_ops._field : (st)->kern.udp.seq_ops._field)
#endif
#define CI_TCP_SEQ_STATE_GET_NUM(st) \
  (*((st)->file_type == CI_PROC_NET_TCP_ENTRY ?                \
     &(st)->kern.tcp.num : &(st)->kern.udp.bucket))

/* Afinfo for files from /proc/driver/sfc/netstat/(snmp|netstat)-... */
typedef struct ci_netstat_seq_afinfo_s {
  ci_uint8  flag:2;
  ci_uint8  file_type:2;
} ci_netstat_seq_afinfo_t;

/* Afinfo for files from /proc/driver/sfc/netstat/(tcp|udp)-... */
typedef struct ci_tcp_seq_afinfo_s {
  struct tcp_seq_afinfo     kern;
  ci_netstat_seq_afinfo_t   sfc;
} ci_tcp_seq_afinfo_t;

typedef struct ci_proc_net_entry_s {
  char       *name;             /**< Entry name */
  file_open_t *kern_open;       /**< file open() method from kernel */
#ifdef CI_TCP_SEQ_OPS_IN_AFINFO
  struct seq_operations *kern_seq_ops;
#else
  seq_show_t *kern_seq_ops;
#endif
  struct file_operations *fops; /**< file operations for SF entries */
#define CI_INVALID ((void *)-1)
} ci_proc_net_entry_t;



/*--------------------------------------------------------------------
 *
 * Private proc entries table
 *
 *--------------------------------------------------------------------*/

static struct file_operations ci_tcp_seq_fops = {
  .owner    = THIS_MODULE,
  .open     = ci_tcp_seq_fop_open,
  .read     = seq_read,
  .llseek   = seq_lseek,
  .release  = seq_release_private,
};

static struct seq_operations ci_tcp_seq_ops = {
  .start    = ci_tcp_seqop_start,
  .stop     = ci_tcp_seqop_stop,
  .next     = ci_tcp_seqop_next,
  .show     = ci_tcp_seqop_show,
};

static struct file_operations ci_netstat_seq_fops = {
  .owner    = THIS_MODULE,
  .open     = ci_netstat_seq_open,
  .read     = seq_read,
  .llseek   = seq_lseek,
  .release  = single_release,
};

static ci_proc_net_entry_t ci_proc_net_table[] = {
    {"tcp", NULL, NULL, &ci_tcp_seq_fops},
    {"udp", NULL, NULL, &ci_tcp_seq_fops},
    {"snmp", NULL, CI_INVALID, &ci_netstat_seq_fops},
    {"netstat", NULL, CI_INVALID, &ci_netstat_seq_fops},
};

#define CI_PROC_NET_TABLE_SIZE \
    (sizeof(ci_proc_net_table) / sizeof(ci_proc_net_entry_t))

/* Should be sync'ed with ci_proc_net_table. */
enum {
    CI_PROC_NET_TCP_ENTRY = 0,
    CI_PROC_NET_UDP_ENTRY,
    CI_PROC_NET_SNMP_ENTRY,
    CI_PROC_NET_NETSTAT_ENTRY,
};


/* Entries under /proc/drivers/sfc */
typedef struct ci_proc_efab_entry_s {
  char        *name;             /**< Entry name */
  read_proc_t *read_proc;        /**< Entry read_proc handler */
} ci_proc_efab_entry_t;
static ci_proc_efab_entry_t ci_proc_efab_table[] = {
    {"cplane",         cicp_stat_read_proc}, 
    {"onloadcfg_raw",  efabcfg_raw_read_proc}, 
    {"workqueue",    efab_workq_read_proc},
//    {"efabcfg_opts", efabcfg_opts_read_proc}, 
#if CI_CFG_STATS_NETIF
    {"stacks",       efab_stacks_read_proc},
#endif
    {"version",      efab_version_read_proc},
    {"dlfilters",    efab_dlfilters_read_proc},
};

#define CI_PROC_EFAB_TABLE_SIZE \
    (sizeof(ci_proc_efab_table) / sizeof(ci_proc_efab_entry_t))


/** Global statististics store */
static ci_ip_stats ci_ip_stats_global;

/** /proc/net/tcp output format string */
static char *ci_ip_stats_tcp_fmt_string =
  "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %p "
  "%u %u %u %u %d";

static char *ci_ip_stats_snmp_ipv4_fmt_string =
  "Ip: %d %d %u %u %u %u "
  "%u %u %u %u %u %u "
  "%u %u %u %u %u %u %u";

static char *ci_ip_stats_snmp_icmp_fmt_string =
  "Icmp: %u %u %u %u %u %u "
  "%u %u %u %u %u %u "
  "%u %u %u %u %u %u "
  "%u %u %u %u %u "
  "%u %u %u";

#define CI_IP_STATS_SNMP_TCP_FMT_STRING1 "Tcp: %u %u %u "
#define CI_IP_STATS_SNMP_TCP_FMT_STRING2 \
  "%u %u " "%u %u %u %u %u %u " "%u %u"
static char *ci_ip_stats_snmp_tcp_fmt_string =
  CI_IP_STATS_SNMP_TCP_FMT_STRING1
  "%d "
  CI_IP_STATS_SNMP_TCP_FMT_STRING2;

static char *ci_ip_stats_snmp_udp_fmt_string =
  "Udp: %u %u %u %u";

static char *ci_ip_stats_netstat_tcpext_fmt_string =
  "TcpExt: %u %u %u "
  "%u %u %u %u "
  "%u %u %u "
  "%u %u %u "
  "%u %u %u "
  "%u %u %u "
  "%u %u "
  "%u %u "
  "%u %u "
  "%u %u "
  "%u %u "
  "%u %u "
  "%u "
  "%u %u %u %u "
  "%u %u %u %u "
  "%u %u "
  "%u %u %u "
  "%u %u %u "
  "%u "
  "%u %u "
  "%u %u "
  "%u %u %u %u "
  "%u %u %u "
  "%u %u %u "
  "%u %u";


/****************************************************************************
 *
 * Update global statistics
 *
 ****************************************************************************/
void
ci_ip_stats_update_global(ci_ip_stats *stats) {
  ci_assert(stats);
  ci_ip_stats_update(&ci_ip_stats_global, stats);
}
EXPORT_SYMBOL(ci_ip_stats_update_global);

/****************************************************************************
 *
 * stats for the proc/net/tcp
 *
 ****************************************************************************/
static void
get_tcp_sock(ci_netif *netif, ci_tcp_state  *ts, char *tmpbuf, int num)
{
    unsigned int    dest;
    unsigned int    src;
    unsigned short  destp;
    unsigned short  srcp;
    unsigned int    state;
    int             timer_active;
    unsigned long   timer_expires;
    unsigned int    tx_queue;
    unsigned int    rx_queue;
    unsigned int    refcount = 1;
    unsigned int    timeouts = 0;
    ci_ip_timer    *timer;

    dest  = tcp_raddr_be32(ts);
    src   = tcp_laddr_be32(ts);
    destp = ntohs(tcp_rport_be16(ts));
    srcp  = ntohs(tcp_lport_be16(ts));
    
    state = ci_sock_states_linux_map[CI_TCP_STATE_NUM(ts->s.b.state)];

    tx_queue = SEQ_SUB(tcp_snd_nxt(ts), tcp_snd_una(ts));
    rx_queue = tcp_rcv_usr(ts);

    /* How to get socket cleanup timer status ??? */
    if (ci_ip_timer_pending(netif, timer = &ts->rto_tid)) {
        timer_active	= 1;
        timer_expires	= timer->time;
    } else
    if (ci_ip_timer_pending(netif, timer = &ts->zwin_tid)) {
        timer_active	= 4;
        timer_expires	= timer->time;
    } else {
        timer_active	= 0;
        timer_expires = jiffies;
    }

    /* At least one of these values is 0. Let's show one of them. :-) */
    timeouts = ts->ka_probes + ts->zwin_probes;

	sprintf(tmpbuf, ci_ip_stats_tcp_fmt_string,
            /* record number */
            num,
            /* local address */
            src,
            /* local port */
            srcp,
            /* remote address */
            dest,
            /* remote port */
            destp,
            /* connection state */
            state,
            /* number of bytes in Tx queue */
            tx_queue,
            /* number of bytes in Rx queue */
            rx_queue,
            /* type of active timer */
            timer_active,
            /* time remaining before timeout */
            timer_expires - jiffies,
            /* current number of retransmits */
            ts->retransmits,
            /* socket owner user ID */
            ts->s.uid,                        
            /* number of zero window or keep alive probes sent */
            timeouts,
            /* inode associated with socket */
            ts->s.ino,
            /* connection refcount, not supported, always  */
            refcount,
            /* pointer to tcp_state structure */
            ts,
            /* retransmit timeout value */
            ts->rto,
            /* ACK timiout value */
            NI_CONF(netif).tconst_delack,
            /* L5 stack does not support quick ack */
            0,
            /* Sending congestion window */
            ts->cwnd,
            /* Slow start size threshold */
            ts->ssthresh >= 0xFFFF ? -1 : ts->ssthresh);
}

/****************************************************************************
 *
 * /proc/net/tcp substitution
 *
 ****************************************************************************/

ci_inline int
ci_netstat_efab_valid_state(ci_tcp_state *ts, ci_uint8 flag, ci_uint8 file_type)
{
  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  if (tcp_protocol(ts) != CI_IPPROTO_BY_FILETYPE(file_type))
    return 0;
  if (file_type == CI_PROC_NET_TCP_ENTRY) {
    if (ts->s.b.state == CI_TCP_CLOSED || ts->s.b.state == CI_TCP_STATE_FREE)
      return 0;
    if (ts->s.b.state == CI_TCP_LISTEN && (flag & CI_PROC_NET_FLAG_KERNEL))
      return 0;
    LOG_STATS(ci_log("Valid TCP state"));
    return 1;
  } else {
    ci_assert (file_type == CI_PROC_NET_UDP_ENTRY);
    if ((flag & CI_PROC_NET_FLAG_KERNEL))
      return 0;
    LOG_STATS(ci_log("Valid UDP state"));
    return 1;
  }
}

/****************************************************************************
 *
 * Rewrite Linux line from /proc/net/snmp with our data.
 *
 ****************************************************************************/
static int
ci_snmp_rewrite(char *buf, size_t *plen, ci_uint8 flag)
{
  ci_netif      *netif = NULL;

  int            len = *plen;
  char          *linux_buf = buf;
  int            rc;

  unsigned int   tcp_rto_algorithm;
  unsigned int   tcp_rto_min;
  unsigned int   tcp_rto_max;
  unsigned int   tcp_max_conn;

  unsigned int   forwarding;
  unsigned int   default_ttl;
  
  ci_ip_stats   *stats;

  char          *icmp_header;
  char          *tcp_header;
  char          *udp_header;
  char          *header;

  if ((stats = kmalloc(sizeof(*stats), GFP_KERNEL)) == NULL)
    return -ENOMEM;
  ci_ip_stats_clear(stats);

#define NEXT_LINE \
  do {                                                      \
    linux_buf = strchr(linux_buf, '\n');                    \
    if (linux_buf == NULL || linux_buf + 1 - buf >= len) {  \
      kfree(stats);                                    \
      return -EFAULT;                                       \
    }                                                       \
    linux_buf++;                                            \
  } while(0)

  /* Skip IPv4 header */
  NEXT_LINE;

  /* Read IPv4 counters */
  if ((rc = sscanf(linux_buf, ci_ip_stats_snmp_ipv4_fmt_string,
                   &forwarding,
                   &default_ttl,
                   &stats->ipv4.in_recvs,
                   &stats->ipv4.in_hdr_errs,
                   &stats->ipv4.in_addr_errs,
                   &stats->ipv4.forw_dgrams,
                   &stats->ipv4.in_unknown_protos,
                   &stats->ipv4.in_discards,
                   &stats->ipv4.in_delivers,
                   &stats->ipv4.out_requests,
                   &stats->ipv4.out_discards,
                   &stats->ipv4.out_no_routes,
                   &stats->ipv4.reasm_timeout,
                   &stats->ipv4.reasm_reqds,
                   &stats->ipv4.reasm_oks,
                   &stats->ipv4.reasm_fails,
                   &stats->ipv4.frag_oks,
                   &stats->ipv4.frag_fails,
                   &stats->ipv4.frag_creates)) !=
      CI_IP_STATS_SNMP_IPV4_PARAM_COUNT) {
    ci_log("Invalid /proc/net/snmp file format, "
           "failed on IPv4 statistics, rc=%d, expected %d", 
           rc, CI_IP_STATS_SNMP_IPV4_PARAM_COUNT);
    ci_log("%s", linux_buf);
    kfree(stats);
    return -EFAULT;
  }

  /* Skip IPv4 counters and ICMP header */
  NEXT_LINE; NEXT_LINE;

  /* Read ICMP counters */
  if ((flag & CI_PROC_NET_FLAG_KERNEL)) {
    if ((rc = sscanf(linux_buf, ci_ip_stats_snmp_icmp_fmt_string,
                     &stats->icmp.icmp_in_msgs,
                     &stats->icmp.icmp_in_errs,
                     &stats->icmp.icmp_in_dest_unreachs,
                     &stats->icmp.icmp_in_time_excds,
                     &stats->icmp.icmp_in_parm_probs,
                     &stats->icmp.icmp_in_src_quenchs,
                     &stats->icmp.icmp_in_redirects,
                     &stats->icmp.icmp_in_echos,
                     &stats->icmp.icmp_in_echo_reps,
                     &stats->icmp.icmp_in_timestamps,
                     &stats->icmp.icmp_in_timestamp_reps,
                     &stats->icmp.icmp_in_addr_masks,
                     &stats->icmp.icmp_in_addr_mask_reps,
                     &stats->icmp.icmp_out_msgs,
                     &stats->icmp.icmp_out_errs,
                     &stats->icmp.icmp_out_dest_unreachs,
                     &stats->icmp.icmp_out_time_excds,
                     &stats->icmp.icmp_out_parm_probs,
                     &stats->icmp.icmp_out_src_quenchs,
                     &stats->icmp.icmp_out_redirects,
                     &stats->icmp.icmp_out_echos,
                     &stats->icmp.icmp_out_echo_reps,
                     &stats->icmp.icmp_out_timestamps,
                     &stats->icmp.icmp_out_timestamp_reps,
                     &stats->icmp.icmp_out_addr_masks,
                     &stats->icmp.icmp_out_addr_mask_reps)) != 
        CI_IP_STATS_SNMP_ICMP_PARAM_COUNT) {
      ci_log("Invalid /proc/net/snmp file format, "
             "failed on ICMP statistics, rc=%d, expected %d", 
             rc, CI_IP_STATS_SNMP_ICMP_PARAM_COUNT);
      kfree(stats);
      return -EFAULT;
    }
  }

  /* Skip ICMP counters and TCP header */
  NEXT_LINE; NEXT_LINE;

  /* Read TCP counters */
  if ((rc = sscanf(linux_buf, ci_ip_stats_snmp_tcp_fmt_string,
                   &tcp_rto_algorithm,
                   &tcp_rto_min,
                   &tcp_rto_max,
                   (int *)&tcp_max_conn,
                   &stats->tcp.tcp_active_opens,
                   &stats->tcp.tcp_passive_opens,
                   &stats->tcp.tcp_attempt_fails,
                   &stats->tcp.tcp_estab_resets,
                   &stats->tcp.tcp_curr_estab,
                   &stats->tcp.tcp_in_segs,
                   &stats->tcp.tcp_out_segs,
                   &stats->tcp.tcp_retran_segs,
                   &stats->tcp.tcp_in_errs,
                   &stats->tcp.tcp_out_rsts)) !=
      CI_IP_STATS_SNMP_TCP_PARAM_COUNT) {
    ci_log("Invalid /proc/net/snmp file format, "
           "failed on TCP statistics, rc=%d, expected %d", 
           rc, CI_IP_STATS_SNMP_TCP_PARAM_COUNT);
    kfree(stats);
    return -EFAULT;
  }

    /* Skip TCP counters and UDP header */
  NEXT_LINE; NEXT_LINE;

  /* Read UDP counters */
  if ((flag & CI_PROC_NET_FLAG_KERNEL)) {
    if ((rc = sscanf(linux_buf, ci_ip_stats_snmp_udp_fmt_string,
                     &stats->udp.udp_in_dgrams,
                     &stats->udp.udp_no_ports,
                     &stats->udp.udp_in_errs,
                     &stats->udp.udp_out_dgrams)) !=
        CI_IP_STATS_SNMP_UDP_PARAM_COUNT) {
      ci_log("Invalid /proc/net/snmp file format, "
             "failed on UDP statistics, rc=%d, expected %d", 
             rc, CI_IP_STATS_SNMP_UDP_PARAM_COUNT);
      kfree(stats);
      return -EFAULT;
    }
    ci_ip_stats_update(stats, &ci_ip_stats_global);
  } else
    *stats = ci_ip_stats_global;

  /* Enumerate all netifs */
  while (iterate_netifs_unlocked(&netif) == 0) {
    /* Update global stats here */
#if CI_CFG_SUPPORT_STATS_COLLECTION
    ci_ip_stats_update(stats, &netif->state->stats_snapshot);
    ci_ip_stats_update(stats, &netif->state->stats_cumulative);
#endif
  } /* Enumerate all TCP helpers */


  /* Find all headers */
  linux_buf = strchr(buf, '\n');        /* linux_buf = "Ip: data" */
  linux_buf++;
  len = linux_buf - buf;
  linux_buf = strchr(linux_buf, '\n');  /* linux_buf = "Icmp: headers" */
  header = linux_buf++;
  linux_buf = strchr(linux_buf, '\n');  /* linux_buf = "Icmp: data" */
  linux_buf++;

  /* Allocate headers and fill them with Linux data. We should keep these
   * headers out of "buf" to avoid overwriting with our data. */
  icmp_header = kmalloc((CI_IP_STATS_SNMP_ICMP_PARAM_COUNT + 1) * 
                        CI_IP_STATS_SNMP_HEADER_WORD_LENGTH, GFP_KERNEL);
  tcp_header = kmalloc((CI_IP_STATS_SNMP_TCP_PARAM_COUNT + 1) * 
                       CI_IP_STATS_SNMP_HEADER_WORD_LENGTH, GFP_KERNEL);
  udp_header = kmalloc((CI_IP_STATS_SNMP_UDP_PARAM_COUNT + 1)* 
                       CI_IP_STATS_SNMP_HEADER_WORD_LENGTH, GFP_KERNEL);
  if (icmp_header == NULL || tcp_header == NULL || udp_header == NULL) {
    ci_log("%s: Out of memory", __FUNCTION__);
    if (icmp_header != NULL) kfree(icmp_header);
    if (tcp_header != NULL) kfree(tcp_header);
    if (udp_header != NULL) kfree(udp_header);
    kfree(stats);
    return -ENOMEM;
  }
  memcpy(icmp_header, header, linux_buf - header);
  icmp_header[linux_buf - header] = '\0';
  linux_buf = strchr(linux_buf, '\n');  /* linux_buf = "Tcp: headers" */
  header = linux_buf++;
  linux_buf = strchr(linux_buf, '\n');  /* linux_buf = "Tcp: data" */
  linux_buf++;
  memcpy(tcp_header, header, linux_buf - header);
  tcp_header[linux_buf - header] = '\0';
  linux_buf = strchr(linux_buf, '\n');  /* linux_buf = "Udp: headers" */
  header = linux_buf++;
  linux_buf = strchr(linux_buf, '\n');  /* linux_buf = "Udp: data" */
  linux_buf++;
  memcpy(udp_header, header, linux_buf - header);
  udp_header[linux_buf - header] = '\0';
  
  
  /* Print IPv4 counters */
  len += sprintf(buf + len, ci_ip_stats_snmp_ipv4_fmt_string,
                 forwarding,
                 default_ttl,
                 stats->ipv4.in_recvs,
                 stats->ipv4.in_hdr_errs,
                 stats->ipv4.in_addr_errs,
                 stats->ipv4.forw_dgrams,
                 stats->ipv4.in_unknown_protos,
                 stats->ipv4.in_discards,
                 stats->ipv4.in_delivers,
                 stats->ipv4.out_requests,
                 stats->ipv4.out_discards,
                 stats->ipv4.out_no_routes,
                 stats->ipv4.reasm_timeout,
                 stats->ipv4.reasm_reqds,
                 stats->ipv4.reasm_oks,
                 stats->ipv4.reasm_fails,
                 stats->ipv4.frag_oks,
                 stats->ipv4.frag_fails,
                 stats->ipv4.frag_creates);

  /* Print ICMP counters */
  len += sprintf(buf + len, icmp_header);
  kfree(icmp_header);
  len += sprintf(buf + len, ci_ip_stats_snmp_icmp_fmt_string,
                 stats->icmp.icmp_in_msgs,
                 stats->icmp.icmp_in_errs,
                 stats->icmp.icmp_in_dest_unreachs,
                 stats->icmp.icmp_in_time_excds,
                 stats->icmp.icmp_in_parm_probs,
                 stats->icmp.icmp_in_src_quenchs,
                 stats->icmp.icmp_in_redirects,
                 stats->icmp.icmp_in_echos,
                 stats->icmp.icmp_in_echo_reps,
                 stats->icmp.icmp_in_timestamps,
                 stats->icmp.icmp_in_timestamp_reps,
                 stats->icmp.icmp_in_addr_masks,
                 stats->icmp.icmp_in_addr_mask_reps,
                 stats->icmp.icmp_out_msgs,
                 stats->icmp.icmp_out_errs,
                 stats->icmp.icmp_out_dest_unreachs,
                 stats->icmp.icmp_out_time_excds,
                 stats->icmp.icmp_out_parm_probs,
                 stats->icmp.icmp_out_src_quenchs,
                 stats->icmp.icmp_out_redirects,
                 stats->icmp.icmp_out_echos,
                 stats->icmp.icmp_out_echo_reps,
                 stats->icmp.icmp_out_timestamps,
                 stats->icmp.icmp_out_timestamp_reps,
                 stats->icmp.icmp_out_addr_masks,
                 stats->icmp.icmp_out_addr_mask_reps);

  /* Print TCP counters */
  len += sprintf(buf + len, tcp_header);
  kfree(tcp_header);
  len += sprintf(buf + len, ci_ip_stats_snmp_tcp_fmt_string,
                 tcp_rto_algorithm,
                 tcp_rto_min,
                 tcp_rto_max,
                 tcp_max_conn,
                 stats->tcp.tcp_active_opens,
                 stats->tcp.tcp_passive_opens,
                 stats->tcp.tcp_attempt_fails,
                 stats->tcp.tcp_estab_resets,
                 stats->tcp.tcp_curr_estab,
                 stats->tcp.tcp_in_segs,
                 stats->tcp.tcp_out_segs,
                 stats->tcp.tcp_retran_segs,
                 stats->tcp.tcp_in_errs,
                 stats->tcp.tcp_out_rsts);

  /* Print UDP counters */
  len += sprintf(buf + len, udp_header);
  kfree(udp_header);
  len += sprintf(buf + len, ci_ip_stats_snmp_udp_fmt_string,
                 stats->udp.udp_in_dgrams,
                 stats->udp.udp_no_ports,
                 stats->udp.udp_in_errs,
                 stats->udp.udp_out_dgrams);
  kfree(stats);

  len += sprintf(buf + len, "\n");
  *plen = len;
  return 0;
}

/****************************************************************************
 *
 * Rewrite Linux line from /proc/net/netstat with our data.
 *
 ****************************************************************************/
static int
ci_netstat_rewrite(char *buf, size_t *plen, ci_uint8 flag)
{
  ci_netif      *netif = NULL;

  int            len = *plen;
  char          *linux_buf = buf;
  int            rc;

  ci_ip_stats   *stats;

  if ((stats = kmalloc(sizeof(*stats), GFP_KERNEL)) == NULL)
    return -ENOMEM;
  ci_ip_stats_clear(stats);

  /* Skip TcpExt header */
  NEXT_LINE;

  /* Read TcpExt counters */
  if ((flag & CI_PROC_NET_FLAG_KERNEL)) {
    if ((rc = sscanf(linux_buf, ci_ip_stats_netstat_tcpext_fmt_string,
                     &stats->tcp_ext.syncookies_sent, 
                     &stats->tcp_ext.syncookies_recv,
                     &stats->tcp_ext.syncookies_failed, 
                     &stats->tcp_ext.embrionic_rsts,
                     &stats->tcp_ext.prune_called,
                     &stats->tcp_ext.rcv_pruned,
                     &stats->tcp_ext.ofo_pruned,
                     &stats->tcp_ext.out_of_window_icmps,
                     &stats->tcp_ext.lock_dropped_icmps,
                     &stats->tcp_ext.arp_filter,
                     &stats->tcp_ext.time_waited,
                     &stats->tcp_ext.time_wait_recycled,
                     &stats->tcp_ext.time_wait_killed,
                     &stats->tcp_ext.paws_passive_rejected,
                     &stats->tcp_ext.paws_active_rejected,
                     &stats->tcp_ext.paws_estab_rejected,
                     &stats->tcp_ext.delayed_ack,
                     &stats->tcp_ext.delayed_ack_locked,
                     &stats->tcp_ext.delayed_ack_lost,
                     &stats->tcp_ext.listen_overflows,
                     &stats->tcp_ext.listen_drops,
                     &stats->tcp_ext.tcp_prequeued,
                     &stats->tcp_ext.tcp_direct_copy_from_backlog,
                     &stats->tcp_ext.tcp_direct_copy_from_prequeue,
                     &stats->tcp_ext.tcp_prequeue_dropped,
                     &stats->tcp_ext.tcp_hp_hits,
                     &stats->tcp_ext.tcp_hp_hits_to_user,
                     &stats->tcp_ext.tcp_pure_acks,
                     &stats->tcp_ext.tcp_hp_acks,
                     &stats->tcp_ext.tcp_reno_recovery,
                     &stats->tcp_ext.tcp_sack_recovery,
                     &stats->tcp_ext.tcp_sack_reneging,
                     &stats->tcp_ext.tcp_fack_reorder,
                     &stats->tcp_ext.tcp_sack_reorder,
                     &stats->tcp_ext.tcp_reno_reorder,
                     &stats->tcp_ext.tcp_ts_reorder,
                     &stats->tcp_ext.tcp_full_undo,
                     &stats->tcp_ext.tcp_partial_undo,
                     &stats->tcp_ext.tcp_loss_undo,
                     &stats->tcp_ext.tcp_sack_undo,
                     &stats->tcp_ext.tcp_loss,
                     &stats->tcp_ext.tcp_lost_retransmit,
                     &stats->tcp_ext.tcp_reno_failures,
                     &stats->tcp_ext.tcp_sack_failures,
                     &stats->tcp_ext.tcp_loss_failures,
                     &stats->tcp_ext.tcp_timeouts,
                     &stats->tcp_ext.tcp_reno_recovery_fail,
                     &stats->tcp_ext.tcp_sack_recovery_fail,
                     &stats->tcp_ext.tcp_fast_retrans,
                     &stats->tcp_ext.tcp_forward_retrans,
                     &stats->tcp_ext.tcp_slow_start_retrans,
                     &stats->tcp_ext.tcp_scheduler_failures,
                     &stats->tcp_ext.tcp_rcv_collapsed,
                     &stats->tcp_ext.tcp_dsack_old_sent,
                     &stats->tcp_ext.tcp_dsack_ofo_sent,
                     &stats->tcp_ext.tcp_dsack_recv,
                     &stats->tcp_ext.tcp_dsack_ofo_recv,
                     &stats->tcp_ext.tcp_abort_on_syn,
                     &stats->tcp_ext.tcp_abort_on_data,
                     &stats->tcp_ext.tcp_abort_on_close,
                     &stats->tcp_ext.tcp_abort_on_memory,
                     &stats->tcp_ext.tcp_abort_on_timeout,
                     &stats->tcp_ext.tcp_abort_on_linger,
                     &stats->tcp_ext.tcp_abort_failed,
                     &stats->tcp_ext.tcp_memory_pressures
        )) != CI_IP_STATS_NETSTAT_TCPEXT_PARAM_COUNT) {
      ci_log("Invalid /proc/net/netstat file format, rc=%d, expected %d", 
             rc, CI_IP_STATS_NETSTAT_TCPEXT_PARAM_COUNT);
      kfree(stats);
      return -EFAULT;
    }
    ci_ip_stats_update(stats, &ci_ip_stats_global);
  } else
    *stats = ci_ip_stats_global;

  /* Enumerate all netifs */
  while (iterate_netifs_unlocked(&netif) == 0) {
#if CI_CFG_SUPPORT_STATS_COLLECTION
    /* Update global stats here */
    ci_ip_stats_update(stats, &netif->state->stats_snapshot);
    ci_ip_stats_update(stats, &netif->state->stats_cumulative);
#endif
  } /* Enumerate all TCP helpers */

  /* Print TcpExt counters */
  linux_buf = strchr(buf, '\n');
  len = linux_buf - buf + 1;
  len += sprintf(buf + len, ci_ip_stats_netstat_tcpext_fmt_string,
                 stats->tcp_ext.syncookies_sent, 
                 stats->tcp_ext.syncookies_recv,
                 stats->tcp_ext.syncookies_failed, 
                 stats->tcp_ext.embrionic_rsts,
                 stats->tcp_ext.prune_called,
                 stats->tcp_ext.rcv_pruned,
                 stats->tcp_ext.ofo_pruned,
                 stats->tcp_ext.out_of_window_icmps,
                 stats->tcp_ext.lock_dropped_icmps,
                 stats->tcp_ext.arp_filter,
                 stats->tcp_ext.time_waited,
                 stats->tcp_ext.time_wait_recycled,
                 stats->tcp_ext.time_wait_killed,
                 stats->tcp_ext.paws_passive_rejected,
                 stats->tcp_ext.paws_estab_rejected,
                 stats->tcp_ext.paws_estab_rejected,
                 stats->tcp_ext.delayed_ack,
                 stats->tcp_ext.delayed_ack_locked,
                 stats->tcp_ext.delayed_ack_lost,
                 stats->tcp_ext.listen_overflows,
                 stats->tcp_ext.listen_drops,
                 stats->tcp_ext.tcp_prequeued,
                 stats->tcp_ext.tcp_direct_copy_from_backlog,
                 stats->tcp_ext.tcp_direct_copy_from_prequeue,
                 stats->tcp_ext.tcp_prequeue_dropped,
                 stats->tcp_ext.tcp_hp_hits,
                 stats->tcp_ext.tcp_hp_hits_to_user,
                 stats->tcp_ext.tcp_pure_acks,
                 stats->tcp_ext.tcp_hp_acks,
                 stats->tcp_ext.tcp_reno_recovery,
                 stats->tcp_ext.tcp_sack_recovery,
                 stats->tcp_ext.tcp_sack_reneging,
                 stats->tcp_ext.tcp_fack_reorder,
                 stats->tcp_ext.tcp_sack_reorder,
                 stats->tcp_ext.tcp_reno_reorder,
                 stats->tcp_ext.tcp_ts_reorder,
                 stats->tcp_ext.tcp_full_undo,
                 stats->tcp_ext.tcp_partial_undo,
                 stats->tcp_ext.tcp_loss_undo,
                 stats->tcp_ext.tcp_sack_undo,
                 stats->tcp_ext.tcp_loss,
                 stats->tcp_ext.tcp_lost_retransmit,
                 stats->tcp_ext.tcp_reno_failures,
                 stats->tcp_ext.tcp_sack_failures,
                 stats->tcp_ext.tcp_loss_failures,
                 stats->tcp_ext.tcp_timeouts,
                 stats->tcp_ext.tcp_reno_recovery_fail,
                 stats->tcp_ext.tcp_sack_recovery_fail,
                 stats->tcp_ext.tcp_fast_retrans,
                 stats->tcp_ext.tcp_forward_retrans,
                 stats->tcp_ext.tcp_slow_start_retrans,
                 stats->tcp_ext.tcp_scheduler_failures,
                 stats->tcp_ext.tcp_rcv_collapsed,
                 stats->tcp_ext.tcp_dsack_old_sent,
                 stats->tcp_ext.tcp_dsack_ofo_sent,
                 stats->tcp_ext.tcp_dsack_recv,
                 stats->tcp_ext.tcp_dsack_ofo_recv,
                 stats->tcp_ext.tcp_abort_on_syn,
                 stats->tcp_ext.tcp_abort_on_data,
                 stats->tcp_ext.tcp_abort_on_close,
                 stats->tcp_ext.tcp_abort_on_memory,
                 stats->tcp_ext.tcp_abort_on_timeout,
                 stats->tcp_ext.tcp_abort_on_linger,
                 stats->tcp_ext.tcp_abort_failed,
                 stats->tcp_ext.tcp_memory_pressures
                 );
  kfree(stats);
#undef NEXT_LINE

  len += sprintf(buf + len, "\n");
  *plen = len;
  return 0;
}

static char *
ci_netstat_name(const char *name, ci_uint8 flag)
{
  static char buf[128];
  ci_assert(flag & CI_PROC_NET_FLAG_L5);
  snprintf(buf, sizeof(buf), "%s-%s", name, 
           (flag & CI_PROC_NET_FLAG_KERNEL) ? "all" : "accel");
  return buf;
}

/****************************************************************************
 *
 * Functions to get next TCP state.
 *
 ****************************************************************************/
static ci_tcp_state *
ci_tcp_get_next_ts(ci_tcp_seq_priv  *st)
{
  ci_tcp_state     *ts;

  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  for (st->ts_id++;
       st->ts_id < st->netif->ep_tbl_n;
       st->ts_id++) {
    ts = ID_TO_TCP(st->netif, st->ts_id);
    ci_assert(ts);

    if (ci_netstat_efab_valid_state(ts, st->flag, st->file_type)) {
      LOG_STATS(ci_log("Found TCP State %d:%p, netif %d:%p", 
                       st->ts_id, ts, NI_ID(st->netif), st->netif));
      return ts;
    }
  }
  LOG_STATS(ci_log("No new TCP states in netif %d:%p", 
                   NI_ID(st->netif), st->netif));
  return NULL;
}

static ci_tcp_state *
ci_tcp_get_next_netif(ci_tcp_seq_priv  *st)
{
  ci_tcp_state     *ts;
  LOG_STATS(ci_log("Entered %s, netif %d:%p", __FUNCTION__,
                   st->netif ? NI_ID(st->netif) : -1, st->netif));
  while (iterate_netifs_unlocked(&st->netif) == 0) {
    LOG_STATS(ci_log("Found NETIF %d:%p", NI_ID(st->netif), st->netif));
    st->ts_id = -1;
    if ((ts = ci_tcp_get_next_ts(st)) != NULL)
      return ts;
  }
  LOG_STATS(ci_log("No new NETIFs"));
  return NULL;
}

static void *
ci_tcp_get_next(ci_tcp_seq_priv  *st)
{
  ci_tcp_state     *ts;

  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  CI_TCP_SEQ_STATE_GET_NUM(st)++;
  if (st->netif == NULL)
    return ci_tcp_get_next_netif(st);
  if ((ts = ci_tcp_get_next_ts(st)) != NULL || 
      (ts = ci_tcp_get_next_netif(st)) != NULL)
    return ts;

  return NULL;
}

/****************************************************************************
 *
 * seq_file interface functions
 *
 ****************************************************************************/

static int
ci_tcp_l5_start(ci_tcp_seq_priv  *st)
{
  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  st->l5 = 1;
  st->ts_id = -1;
  st->netif = NULL;
  CI_TCP_SEQ_STATE_GET_NUM(st)--;
  LOG_STATS(ci_log("Success in %s", __FUNCTION__));
  return 0;
}


static void*
ci_tcp_seqop_start(struct seq_file *seq, loff_t *ppos)
{
  ci_tcp_seq_priv *st = seq->private;
  void            *v;
  loff_t           count_pos = *ppos;

  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  /* 
   * Try to find Linux entry. We can't call linux ops.start(orig_param),
   * because if ppos is larger that linux have, linux will not tell us how
   * many entries it has.
   * As a result, we will call start(0) and next(),next(),next(),...
   */
  if ((st->flag & CI_PROC_NET_FLAG_KERNEL)) {
    loff_t  pos = 0, tmp_pos = 0;
    st->l5 = 0;
    ci_assert(CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, start));
    v = CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, start)(seq, &tmp_pos);
    do {
      if (count_pos-- == 0)
        return v;
      pos++;
      tmp_pos = pos;
      v = CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, next)(seq, v, &tmp_pos);
    } while (v != NULL);

    LOG_STATS(ci_log("all Linux TCP entries done"));
  } else {
    CI_TCP_SEQ_STATE_GET_NUM(st)++;
    if (*ppos == 0) {
      st->l5 = 0;
      LOG_STATS(ci_log("Success in %s: SEQ_START_TOKEN", __FUNCTION__));
      return SEQ_START_TOKEN;
    }
  }

  /* Find a good netif before calling ci_tcp_get_next() */
  if ((st->flag & CI_PROC_NET_FLAG_L5) && ci_tcp_l5_start(st) == 0) {
    LOG_STATS(ci_log("interating L5 TCP entries"));
    while ((v = ci_tcp_get_next(st)) != NULL) {
      LOG_STATS(ci_log("Success in %s: L5 state %p", __FUNCTION__, v));
      (*ppos)++;
      if (count_pos-- == 0) {
        return v;
      }
    }
  }
  LOG_STATS(ci_log("Success in %s", __FUNCTION__));
  return NULL;
}


static void *
ci_tcp_seqop_next(struct seq_file *seq, void *v, loff_t *ppos)
{
  ci_tcp_seq_priv   *st = seq->private;

  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  if (st->l5 == 0) {
    if ((st->flag & CI_PROC_NET_FLAG_KERNEL)) {
      v = CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, next)(seq, v, ppos);
      if (v != NULL) {
        LOG_STATS(ci_log("non-L5 next"));
        return v;
      }
      (*ppos)--;
    } 
    if (ci_tcp_l5_start(st) != 0) {
      LOG_STATS(ci_log("no next"));
      return NULL;
    }
  }
  (*ppos)++;
  LOG_STATS(ci_log("L5 next"););
  return ci_tcp_get_next(st);
}


static void
ci_tcp_seqop_stop(struct seq_file *seq, void *v)
{
  ci_tcp_seq_priv *st = seq->private;

  LOG_STATS(ci_log("Entered %s", __FUNCTION__));
  if ((st->flag & CI_PROC_NET_FLAG_KERNEL))
    CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, stop)(seq, v);
  if (st->l5 && st->netif != NULL)
    iterate_netifs_unlocked_dropref(st->netif);
  LOG_STATS(ci_log("Success in %s", __FUNCTION__));
}


static int
ci_tcp_seqop_show(struct seq_file *seq, void *v)
{
  ci_tcp_seq_priv *st = seq->private;
  char             tmpbuf[CI_SOCK_STAT_LINE_LENGTH_MAX];

  LOG_STATS(ci_log("Entered %s: st->l5 = %d, v = %p",
                   __FUNCTION__, st->l5, v));
  if (st->l5 && v != SEQ_START_TOKEN) {
    ci_assert(v);
    ci_assert(v == ID_TO_TCP(st->netif, st->ts_id));
    get_tcp_sock(st->netif, (ci_tcp_state *)v, tmpbuf, 
                 CI_TCP_SEQ_STATE_GET_NUM(st));
    LOG_STATS(ci_log("show: %s", tmpbuf));
    seq_printf(seq, "%-*s\n", CI_SOCK_STAT_LINE_LENGTH(st->file_type) - 1, 
               tmpbuf);
    LOG_STATS(ci_log("Success in %s", __FUNCTION__));
    return 0;
  }
  LOG_STATS(ci_log("Passthrough in %s", __FUNCTION__));
  return CI_TCP_SEQ_STATE_GET_KERNEL_OP(st, show)(seq, v);

}


/****************************************************************************
 *
 * /proc/net/tcp open() substitution
 *
 ****************************************************************************/

static int
ci_tcp_seq_fop_open(struct inode *inode, struct file *file)
{
  ci_tcp_seq_afinfo_t   *afinfo = PDE(inode)->data;
  int                    rc;
  struct seq_file       *seq;
  ci_tcp_seq_priv       *priv;
  ci_proc_net_entry_t   *entry;
  void                  *prev_priv;

  LOG_STATS(ci_log("Entered %s", __FUNCTION__));

  priv = kmalloc(sizeof(ci_tcp_seq_priv), GFP_KERNEL);
  if (priv == NULL) {
    ci_log("%s,%d: Out of memory!", __FUNCTION__, __LINE__);
    return -ENOMEM;
  }
  memset(priv, 0, sizeof(*priv));
  ci_assert((afinfo->sfc.flag & ~(CI_PROC_NET_FLAG_KERNEL | CI_PROC_NET_FLAG_L5)) 
            == 0);
  ci_assert(afinfo->sfc.file_type == CI_PROC_NET_TCP_ENTRY || 
            afinfo->sfc.file_type == CI_PROC_NET_UDP_ENTRY);
  priv->flag = afinfo->sfc.flag;
  priv->file_type = afinfo->sfc.file_type;
  LOG_STATS(ci_log("show kernel = %d, show l5 = %d, file_type = %d", 
                   (priv->flag & CI_PROC_NET_FLAG_KERNEL),
                   (priv->flag & CI_PROC_NET_FLAG_L5),
                   priv->file_type));

  entry = &ci_proc_net_table[afinfo->sfc.file_type];
  ci_assert_nequal(entry->kern_open, NULL);
  ci_assert_nequal(entry->kern_seq_ops, NULL);
  ci_assert_nequal(entry->kern_seq_ops, CI_INVALID);

  afinfo->kern.family = AF_INET;
#ifdef CI_TCP_SEQ_OPS_IN_AFINFO
  afinfo->kern.seq_ops = *entry->kern_seq_ops;
#else
  afinfo->kern.seq_show = entry->kern_seq_ops;
#endif
  LOG_STATS(ci_log("calling kern_open() = %p with kern_seq_ops = %p", 
                   entry->kern_open, entry->kern_seq_ops));

  /* We get header from the kernel, so we should open kernel file */
  rc = entry->kern_open(inode, file);
  if (rc != 0) {
    ci_log("%s,%d: system open() failed with rc = %d", 
           __FUNCTION__, __LINE__, rc);
    return rc;
  }

  seq = file->private_data;
  prev_priv = seq->private;
  if (priv->file_type == CI_PROC_NET_TCP_ENTRY) {
    priv->kern.tcp = *(struct tcp_iter_state *)prev_priv;
  } else {
    priv->kern.udp = *(struct udp_iter_state *)prev_priv;
  }
  kfree(prev_priv);

  seq->op = &ci_tcp_seq_ops;

  seq->private = priv;
  LOG_STATS(ci_log("Success in %s", __FUNCTION__));
  return 0;
}


static void ci_netstat_find_data(void)
{
  int entry_no;

  for (entry_no = 0; entry_no < CI_PROC_NET_TABLE_SIZE; entry_no++) {
    ci_proc_net_entry_t   *entry = &ci_proc_net_table[entry_no];
    struct proc_dir_entry *dir_entry;
    int                    entry_found;

    dir_entry = PROC_NET->subdir;

    entry_found = 0;
    while ((dir_entry != NULL) && (!entry_found)) {
      if (strcmp(dir_entry->name, entry->name) == 0) {
        OO_DEBUG_STATS(ci_log("Get kernel handlers for /proc/net/%s: %p",
                              entry->name, dir_entry->proc_fops->open));

        entry->kern_open = dir_entry->proc_fops->open;
        if (entry->kern_seq_ops != CI_INVALID) {
#ifdef CI_TCP_SEQ_OPS_IN_AFINFO
          entry->kern_seq_ops = 
              &((struct tcp_seq_afinfo *)dir_entry->data)->seq_ops;
#else
          entry->kern_seq_ops = 
              ((struct tcp_seq_afinfo *)dir_entry->data)->seq_show;
#endif
        }
        entry_found++;
      }

      dir_entry = dir_entry->next;
    }
    if (!entry_found)
      ci_log("Failed to get data for /proc/net/%s", entry->name);
  }
}


static struct proc_dir_entry*
ci_netstat_create_entries(struct proc_dir_entry* root)
{
  struct proc_dir_entry* netstat_root;
  ci_proc_net_entry_t       *entry;
  void                      *afinfo;
  ci_netstat_seq_afinfo_t   *afinfo_netstat;
  struct proc_dir_entry     *res;
  ci_uint8  flag;
  int       entry_no;

  ci_netstat_find_data();

  netstat_root = proc_mkdir("netstat", root);
  if( netstat_root == NULL ) {
    ci_log("%s: failed to create netstat subdirectory", __FUNCTION__);
    goto out;
  }

  for (entry_no = 0; entry_no < CI_PROC_NET_TABLE_SIZE; entry_no++)
  for (flag = CI_PROC_NET_FLAG_L5; 
       flag <= (CI_PROC_NET_FLAG_L5 | CI_PROC_NET_FLAG_KERNEL);
       flag++)
  {
    entry = &ci_proc_net_table[entry_no];
    if (entry_no == CI_PROC_NET_TCP_ENTRY || 
        entry_no == CI_PROC_NET_UDP_ENTRY)
    {
      afinfo = kmalloc(sizeof(ci_tcp_seq_afinfo_t), GFP_KERNEL);
      if (afinfo == NULL) {
        ci_log("%s,%d: Out of memory!", __FUNCTION__, __LINE__);
        goto out;
      }
      memset(afinfo, 0, sizeof(ci_tcp_seq_afinfo_t));
      afinfo_netstat = &((ci_tcp_seq_afinfo_t *)afinfo)->sfc;
    } else {
      afinfo = kmalloc(sizeof(ci_netstat_seq_afinfo_t), GFP_KERNEL);
      if (afinfo == NULL) {
        ci_log("%s,%d: Out of memory!", __FUNCTION__, __LINE__);
        goto out;
      }
      memset(afinfo, 0, sizeof(ci_netstat_seq_afinfo_t));
      afinfo_netstat = afinfo;

    }
    afinfo_netstat->flag = flag;
    afinfo_netstat->file_type = entry_no;

    res = create_proc_entry(ci_netstat_name(entry->name, flag), 
                            S_IRUGO, netstat_root);
    if( res == NULL ) {
      ci_log("%s: failed to create '%s'", __FUNCTION__, entry->name);
      goto out;
    }
    res->proc_fops = entry->fops;
    res->data = afinfo;
  }

 out:
  return netstat_root;
}


static void
ci_netstat_remove_entries(struct proc_dir_entry* netstat_root)
{
  int i;

  for( i = 0; i < CI_PROC_NET_TABLE_SIZE; i++ ) {
    remove_proc_entry(ci_netstat_name(ci_proc_net_table[i].name, 
                                      CI_PROC_NET_FLAG_L5), netstat_root);
    remove_proc_entry(ci_netstat_name(ci_proc_net_table[i].name, 
                                      CI_PROC_NET_FLAG_L5 | 
                                      CI_PROC_NET_FLAG_KERNEL), netstat_root);
  }
  remove_proc_entry(netstat_root->name,
                    netstat_root->parent);
}


static int
ci_netstat_seq_show(struct seq_file *seq, void *v)
{
  int   rc;
  ci_netstat_seq_priv *priv = (ci_netstat_seq_priv *)seq->private;

  /* Call Linux show() */
  rc = priv->kern_show(seq, v);
  if (rc != 0)
    return rc;

  /* Parse Linux output and replace it with L5 staff */
  if (priv->file_type == CI_PROC_NET_SNMP_ENTRY)
    return ci_snmp_rewrite(seq->buf + seq->from, &seq->count, priv->flag);
  else
    return ci_netstat_rewrite(seq->buf + seq->from, &seq->count, priv->flag);
}

/****************************************************************************
 *
 * /proc/drivers/sfc/netstat/(snmp|netstat) open() substitution
 *
 ****************************************************************************/
static int 
ci_netstat_seq_open(struct inode *inode, struct file *file)
{
  ci_netstat_seq_afinfo_t *afinfo = PDE(inode)->data;
  ci_proc_net_entry_t   *entry;
  int                    rc;
  struct seq_file       *seq;
  ci_netstat_seq_priv   *priv;

  priv = kmalloc(sizeof(ci_netstat_seq_priv), GFP_KERNEL);
  if (priv == NULL) {
    ci_log("%s,%d: Out of memory!", __FUNCTION__, __LINE__);
    return -ENOMEM;
  }
  memset(priv, 0, sizeof(*priv));
  ci_assert((afinfo->flag & ~(CI_PROC_NET_FLAG_KERNEL | CI_PROC_NET_FLAG_L5)) 
            == 0);
  ci_assert(afinfo->file_type == CI_PROC_NET_SNMP_ENTRY || 
            afinfo->file_type == CI_PROC_NET_NETSTAT_ENTRY);
  priv->flag = afinfo->flag;
  priv->file_type = afinfo->file_type;

  entry = &ci_proc_net_table[afinfo->file_type];
  ci_assert_nequal(entry->kern_open, NULL);
  ci_assert_equal(entry->kern_seq_ops, CI_INVALID);
  ci_assert(entry->kern_open != NULL);
  rc = entry->kern_open(inode, file);
  if (rc != 0)
    return rc;

  /* Rememver old show() function in private field. */
  seq = file->private_data;
  priv->kern_show = seq->op->show;
  seq->private = priv;

  /* 2.6.20 defines seq->op as const, but it is really safe to re-write it
   * here. */
  ((struct seq_operations *)seq->op)->show = ci_netstat_seq_show;
  return 0;
}


/****************************************************************************
 *
 * /proc/drivers/onload/onloadcfg_raw
 *
 ****************************************************************************/

static int 
efabcfg_raw_read_proc(char *buf, char **start, off_t offset, int count, 
                      int *eof, void *data)
{
  ci_cfg_hdr_t *hdr;
  int how_much, rc;

  while (ci_cfg_rd_trylock() != 0) {
    set_current_state(TASK_INTERRUPTIBLE);
    schedule_timeout(0);
  }
  
  hdr = ci_cfg_get();
 
  /* do we have a database installed? */
  if (hdr == 0) {
    rc = -ENODATA;
    goto error;
  }

  /* have we reached or exceeded the end? */
  if (offset >= hdr->len) {
    rc = -EINVAL;
    goto error;
  }

  /* number of bytes to copy */
  how_much = CI_MIN(count, hdr->len - offset);
  ci_assert_ge(how_much, 0);

  /* copy the data */
  memcpy(buf, (char*)hdr + offset, how_much);

  ci_cfg_rd_unlock();

  return how_much;

error:
  ci_cfg_rd_unlock();
  return rc;
}




/****************************************************************************
 *
 * /proc/drivers/onload/workqueue
 *
 ****************************************************************************/

#define PROC_PRINTF(fmt, ...)					\
  if( count - len > 0 )						\
    len += snprintf(buf+len, count-len, (fmt), __VA_ARGS__)
#define EFAB_WORKQ_READ_PROC_PRINT(v)			\
  PROC_PRINTF("%14s = %u\n", #v, wqueue->stats.v)
#define PROC_PUT(str)					\
  if( count - len > 0 )					\
    len += snprintf(buf+len, count-len, "%s", (str))

static int 
efab_workq_read_proc(char *buf, char **start, off_t offset, int count, 
		     int *eof, void *data)
{
  int len = 0;
#ifndef __USE_LINUX_WORKQUEUE
  ci_irqlock_state_t lock_flags;
  ci_workqueue_t *wqueue;
  wqueue = &CI_GLOBAL_WORKQUEUE;
  ci_irqlock_lock(&wqueue->lock, &lock_flags);
  if (wqueue->state == CI_WQ_ALIVE) {
      EFAB_WORKQ_READ_PROC_PRINT(working);
      EFAB_WORKQ_READ_PROC_PRINT(iter);
      EFAB_WORKQ_READ_PROC_PRINT(backlog);
      EFAB_WORKQ_READ_PROC_PRINT(started);
  }
  else {	
    PROC_PUT("The workqueue is not running.\n");
  }
  ci_irqlock_unlock(&wqueue->lock, &lock_flags);
#endif

  return count ? strlen(buf) : 0;
}


/****************************************************************************
 *
 * /proc/drivers/onload/stacks
 *
 ****************************************************************************/

#if CI_CFG_STATS_NETIF

static int 
efab_stacks_read_proc(char* buf, char** start, off_t offset, int count, 
		      int* eof, void* data)
{
  int len = 0; 
  ci_netif* ni = NULL;

  buf[0] = '\0'; /* let's care about no netifs */

  while(iterate_netifs_unlocked(&ni) == 0) {
    ci_netif_stats* s = &ni->state->stats;
    PROC_PRINTF("%d: %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u "
                "%u %u\n",
		NI_ID(ni), (int) ni->state->pid, (int) ni->state->uid,
		s->periodic_polls, s->periodic_evs,
		s->timeout_interrupts, s->interrupts, s->interrupt_polls,
		s->interrupt_wakes, s->interrupt_evs,
		s->interrupt_primes, s->select_primes, s->sock_wakes,
		s->pkt_wakes, s->unlock_slow,
		s->lock_wakes, s->deferred_work, s->sock_lock_sleeps,
                s->rx_evs, s->tx_evs);
  }

  return count ? strlen(buf) : 0;
}

#endif


/****************************************************************************
 *
 * /proc/driver/onload/version
 *
 ****************************************************************************/

static int 
efab_version_read_proc(char* buf, char** start, off_t offset, int count, 
                       int* eof, void* data)
{
  int len = 0; 
  PROC_PRINTF("onload_product: %s\n", ONLOAD_PRODUCT);
  PROC_PRINTF("onload_version: %s\n", ONLOAD_VERSION);
  PROC_PRINTF("uk_intf_ver: %s\n", oo_uk_intf_ver);
  return count ? strlen(buf) : 0;
}


/****************************************************************************
 *
 * /proc/driver/onload/dlfilters
 *
 ****************************************************************************/

static int 
efab_dlfilters_read_proc(char* buf, char** start, off_t offset, int count, 
                         int* eof, void* data)
{
  int len = 0; 
  int no_empty, no_tomb, no_used;

  efx_dlfilter_count_stats(efab_tcp_driver.dlfilter,
                           &no_empty, &no_tomb, &no_used);
  PROC_PRINTF("dlfilters: empty=%d, tomb=%d, used=%d\n",
              no_empty, no_tomb, no_used);
  return count ? strlen(buf) : 0;
}


/****************************************************************************
 *
 * Install new proc entries, substitute existing proc entries
 *
 ****************************************************************************/
/**
 * Install read-only files into /proc/drivers/sfc as requested by the table
 * in the argument.
 */
static void
ci_proc_files_install(struct proc_dir_entry *root, char *root_name,
                      ci_proc_efab_entry_t *entries, int num_entries)
{
  int entry_no;

  /* create new etherfabric specific proc entries */
  for (entry_no = 0; entry_no < num_entries; entry_no++) {
    ci_proc_efab_entry_t  *efab_entry = &entries[entry_no];

    OO_DEBUG_STATS(ci_log("Create %s/%s: read_proc=%p",
                      root_name, efab_entry->name, efab_entry->read_proc));

    if (create_proc_read_entry(efab_entry->name, 0, root, 
                               efab_entry->read_proc, 0) == NULL) {

      ci_log("Unable to create %s/%s: read_proc=%p",
             root_name, efab_entry->name, efab_entry->read_proc);

      /* we're not registering any methods off the proc entry so if we
         fail outcome is just that our entry doesn't get put into /proc
      */

    }
  }
}

/**
 * Install read-only files into /proc/drivers/sfc as requested by the table
 * in the argument.
 */
static void
ci_proc_files_uninstall(struct proc_dir_entry *root,
                        ci_proc_efab_entry_t *entries, int num_entries)
{
  int entry_no;

  /* create new etherfabric specific proc entries */
  for (entry_no = 0; entry_no < num_entries; entry_no++)
  {
    remove_proc_entry(entries[entry_no].name, root);
  }
}


static struct proc_dir_entry* netstat_root;


int
ci_install_proc_entries(void)
{
  oo_proc_root = proc_mkdir("driver/onload", NULL);
  if( ! oo_proc_root ) {
    ci_log("%s: failed to create driver/onload", __FUNCTION__);
    return -ENOMEM;
  }

  ci_proc_files_install(oo_proc_root, "/proc/driver/onload", 
                        ci_proc_efab_table, CI_PROC_EFAB_TABLE_SIZE);

  if( 0 )
    /* Disabled because (a) No-one is using this stuff and (b) we get a
     * crash if you "cat udp-all" with 2.6.24.7-65.el5rt.
     */
    netstat_root = ci_netstat_create_entries(oo_proc_root);

#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  /* create /proc/driver/sfc/mem */
  if( create_proc_read_entry("mem", 0, oo_proc_root,
                             ci_alloc_memleak_readproc, NULL) == NULL )
    ci_log("%s: failed to create 'mem'", __FUNCTION__);
#endif

  return 0;
}

/****************************************************************************
 *
 * Uninstall proc entries, return back old proc entries
 *
 ****************************************************************************/

void ci_uninstall_proc_entries(void)
{
  ci_ip_stats_clear(&ci_ip_stats_global);

  if( oo_proc_root == NULL )
    return;

  if( netstat_root ) {
    ci_netstat_remove_entries(netstat_root);
    netstat_root = NULL;
  }

  ci_proc_files_uninstall(oo_proc_root, ci_proc_efab_table,
                          CI_PROC_EFAB_TABLE_SIZE);
#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  remove_proc_entry("mem", oo_proc_root);
#endif
  remove_proc_entry(oo_proc_root->name, oo_proc_root->parent);
  oo_proc_root = NULL;
}
