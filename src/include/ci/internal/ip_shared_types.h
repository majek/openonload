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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Definition of the IP stack's shared state.
**   \date  2005/01/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_IP_SHARED_TYPES_H__
#define __CI_INTERNAL_IP_SHARED_TYPES_H__

/*
** READ ME FIRST please.
**
** This header contains the definition of the types that comprise the state
** of the Etherfabric TCP/IP stack.
**
** The only stuff that may appear here is types and data structures that
** are part of the shared state, constants associated with fields in those
** data structures and documentation.
**
** NO CODE IN THIS FILE PLEASE.
**
**
** - This state may be shared by multiple address spaces, so all data
** structures must be constructed in a way that is independent of the
** address space.  For the most part we use object IDs and offsets.
**
** - This state is shared between userlevel and kernel drivers, and
** potentially between 32-bit and 64-bit code.  The size and layout must
** therefore be unambiguous.
**
** - Where pointers are stored in this state, there must be some way to
** determine which address space the pointer exists in.  See
** ci_addr_spc_id_t.
*/



/*********************************************************************
***************************** Constants *****************************
*********************************************************************/

/* Maximum number of segments in a packet.  Please update TX_PKT_LEN(),
** ASSERT_VALID_PKT() if this changes.
**
** For 9000 byte jumbo frames i.e. 3 pages * 4k
** 3 segments are needed for send() as continues filling previous segment
** 5 segments are needed for iSCSI headers + 3 zero copy (ZC) data + digest
** 6 segments are needed for sendfile() this is the pathological case
**
** Note that this case only occurs because
** i)  Space in the dest pages (iobufset) are reserved even for ZC data
** ii) ZC segments might get copied if the pinned page limit is hit
** 
** segment num | len  | ZC   | src page | dest page   | notes 
** ----------------------------------------------------------------
**           0 | 66   | n    | -        | 0 (+158meta)| headers
**           1 | 1    | y    | 0        | 0           | offset=4095
**           2 | 3871 | n    | 1        | 0           | 4096-158-66-1
**           3 | 225  | ?    | 1        | 1           | 4096-3871
**           4 | 3871 | y    | 2        | 1/2         | 4096-225
**           5 | 1032 | ?    | 3        | 2           |
*/
#define CI_IP_PKT_SEGMENTS_MAX     6


/* See ci_netif_pkt_try_to_free(). */
#define CI_NETIF_PKT_TRY_TO_FREE_MAX_DESP  2


/* Timer wheels are used to schedule the timers. There are 4 level's on
** the wheel each of 256 buckets each bucket is a doubly linked list
** of timers
*/
#define CI_IPTIME_WHEELS      4
#define CI_IPTIME_BUCKETS     256
#define CI_IPTIME_BUCKETMASK  255
#define CI_IPTIME_BUCKETBITS  8
#define CI_IPTIME_WHEELSIZE   (CI_IPTIME_WHEELS*CI_IPTIME_BUCKETS)


/* ========= Field Protection ======== */
/* Where we know that a field of shared state is supposed to be written
** only by the kernel - and never by the user mode we use this pseudo-type
** to identify it.  Some fields can only be compiled as "const" if the compile
** time option to force initilaiztion to occur in the kernel is set.
*/

#ifdef __KERNEL__
#define CI_ULCONST 
#else
#define CI_ULCONST const
#endif

/* ========= UDP ========== */
/* Length of queue in each ep  ** MUST BE A POWER of 2 ** 
** ... finger in the air time again, but keep it small
*/
#define CI_ERRQ_UDP_ERR_MAX 4
#define CI_ERRQ_UDP_ERR_MASK (CI_ERRQ_UDP_ERR_MAX-1)

/* ========= TCP ========== */
/* Length of queue in each ep  ** MUST BE A POWER of 2 ** 
** ... finger in the air time again, but keep it small
*/
#define CI_ERRQ_TCP_ERR_MAX 4
#define CI_ERRQ_TCP_ERR_MASK (CI_ERRQ_TCP_ERR_MAX-1)





/* A linked list for things in the netif state. */
#define CI_MK_ID(x)             ci_ni_dllist##x
#define CI_ILL_ADDR_T           oo_p
#define CI_ILL_CTX_T            ci_netif*
#if CI_CFG_OOP_IS_PTR
# define CI_ILL_ADDR(ctx,lnk)	((oo_p) (lnk))
#endif
#define CI_ILL_NO_CODE
#include <ci/tools/idllist.h.tmpl>



/*********************************************************************
***************************** Primitives *****************************
*********************************************************************/

/*
** A fixed size representation of a pointer in the shared state.
*/
typedef struct {
  ci_uint64 ptr CI_ALIGN(8);
} ci_ss_ptr;




/*********************************************************************
*************************** Packet buffers ***************************
*********************************************************************/

/*!
** ci_ip_pkt_fmt_prefix
**
** Part of the meta-data in a packet buffer.
*/
typedef union {
  struct {
    oo_sp tx_sock;  /* sender of the loopback packet */
    oo_sp rx_sock;  /* receiver of the loopback packet */
  } lo CI_ALIGN(8);
  struct {
    ci_uint32         end_seq;  /* end sequence #, includes SYN/FIN flags */
    ci_uint32         window;   /* window advertised in the packet */

    union {
      struct {
       /* These fields are valid for the first packet in each block only */
        oo_pkt_p     next_block;   /* first packet of the next SACK block */
        oo_pkt_p     end_block;    /* last packet in current SACK block */
        ci_uint32    end_block_seq;/* end sequence number in the SACK block */
        ci_int32     num;          /* number of packets in this block */    
      } rob;        /* Re-order buffer lists support */
    } misc CI_ALIGN(8);
  } tcp_rx CI_ALIGN(8);
  struct {
    ci_uint32         end_seq;
    ci_uint32         start_seq;
    oo_pkt_p          block_end;     /* end of the current (un)sacked block */
    ci_user_ptr_t     next CI_ALIGN(8);   /* for ci_tcp_sendmsg() local use only! */
  } tcp_tx CI_ALIGN(8);
  struct {
    ci_uint64         rx_stamp CI_ALIGN(8); /*!< Time we arrived */

    /*! These flags can only be used by (i) netif lock holder, or (ii)
     *  in app context if they know the packet can't be touched by the
     *  netif lock holder (e.g. if it is a packet in the recv queue
     *  past the extract pointer).  Care needed as they are not atomic.
     */
#define CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED         0x1
#define CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED   0x2
#define CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_PASSED    0x4
#define CI_IP_PKT_FMT_PREFIX_UDP_RX_KEEP             0x8
    ci_uint32         rx_flags;

    ci_int32          tx_length;
    oo_sp             tx_sock_id; /* The socket this pkt is tx'd on:  
                                   * used for tx completion action */
  } udp;
} ci_ip_pkt_fmt_prefix;


#include <ci/net/ethernet.h>
/*!
** ci_ip_pkt_fmt:  IP packet representation.
**
** The packet may contain few segments. Three segments are supported
** not now. The first segment always refers to the packet internal
** buffer. The second and the third segments may refer to pages with
** data. Pair of segments for pages is required to cover cross page
** data in a packet.
*/
struct ci_ip_pkt_fmt_s {
  /* For use by transport layer to form linked lists. */
  oo_pkt_p              next;

  /* A linked list of buffers that are logically a single unit.  Each link
   * holds a reference, so that when a packet is freed, the reference it
   * holds to frag_next is dropped (if not null).  Used to chain IP
   * fragments, and to chain multiple buffers that comprise a single
   * packet.
   */
  oo_pkt_p              frag_next;

#if CI_CFG_PP_IS_PTR
  ci_int32              pkt_id;
#else
  oo_pkt_p              pp;
#endif

  ci_uint32             stack_id; /* Which stack was this pkt allocated for */

  /* payload length for passing between layers */
  ci_int32              pay_len;
  ci_int32              refcount;

  /* For receive packets, describes position of payload data.  For transmit
   * packets, identifies free space. 
   */
  oo_offbuf             buf;

  /* Interface to send packet out of (for TX), or interface packet was
   * received on (for RX). Indexes base_addr array for selecting
   * correct per-interface address of this buffer
   */
  ci_int16              intf_i;
  /* VLAN tag from packet header (RX). */
  ci_int16              vlan;

  union {
    struct {
      oo_pkt_p          dmaq_next; /**< Next packet in the overflow queue. */
#if CI_CFG_PORT_STRIPING
      ci_int32          intf_swap;
#endif
    } tx;
  } netif;

  ci_ip_pkt_fmt_prefix  pf CI_ALIGN(8);


#define CI_PKT_FLAG_TX_PENDING     0x0001  /* pkt is transmitting        */
#define CI_PKT_FLAG_RX_INDIRECT    0x0002  /* payload is elsewhere       */
#define CI_PKT_FLAG_RTQ_RETRANS    0x0004  /* pkt has been retransmitted */
#define CI_PKT_FLAG_RTQ_SACKED     0x0008  /* pkt has been SACKed        */
#define CI_PKT_FLAG_UDP            0x0010  /* UDP pkt                    */
                                /* 0x0020     currently unused */
#define CI_PKT_FLAG_MSG_CONFIRM    0x0040  /* request MSG_CONFIRM        */
#define CI_PKT_FLAG_TX_PSH         0x0800  /* needs PSH bit setting      */
#define CI_PKT_FLAG_TX_MORE        0x1000  /* Do not transmit the packet when
                                            * it is the last one, see
                                            * MSG_MORE */
                                /* 0x2000     currently unused */
#define CI_PKT_FLAG_NONB_POOL      0x4000  /* allocated from nonb-pool   */
#define CI_PKT_FLAG_RX             0x8000  /* pkt is on RX path          */
#define CI_PKT_FLAG_DEBUG          0xff000000u  /* reserved debug fields */
#define CI_PKT_FLAG_TX_MASK_ALLOWED                                     \
    (CI_PKT_FLAG_DEBUG | CI_PKT_FLAG_TX_MORE | CI_PKT_FLAG_TX_PSH |     \
     CI_PKT_FLAG_NONB_POOL)
  ci_uint32             flags;

  /*! Base address of this buffer for each NIC */
  ef_addr               base_addr[CI_CFG_MAX_INTERFACES] CI_ALIGN(8);
  /*! Current offset relative to base_addr */
  ci_int32              base_offset;

  /*! Length of data from base_addr used in this buffer. */
  ci_int32              buf_len;
  /*! Length of tx data in current IP packet (actually IP fragment).
   *  i.e. sum of tx_buf_len of some of the buffers linked by frag_next
   *  (not necessarily all as frag_next can link > 1 IP fragments
   *  together too)
   */
  ci_int32              tx_pkt_len;
  
  /*! Number of these buffers that are chained together using
   *  frag_next to form the packet
   */
  ci_int32              n_buffers;

  /* We have 4 variants of packet layout:
   * TX+simple, TX+vlan, RX+simple, RX+vlan.
   * On TX path, we create IP+TCP/UCP packet and, only after that, add
   * ethernet header.  We do not know about vlan tag when we create IP
   * packet, so we should use spare space to add it if necessary.
   * TX+simple: IP base = ip_base; Eth base = eth_base + 4
   * TX+vlan: IP base = ip_base; Eth base = eth_base
   * On RX path, we receive a packet and parse it later, so we can predict
   * the beginning of the ethernet header and can't predict the beginning of
   * IP header.
   * RX+simple: IP base = ip_base - 4; Eth base = eth_base
   * RX+vlan: IP base = ip_base; Eth base = eth_base
   * It is easy to see that TX+vlan and RX+vlan have equal layout, so there
   * are 3 possible layouts:
   *
   * TX+simple: IP base = ip_base; Eth base = eth_base + 4
   * RX+simple: IP base = ip_base - 4; Eth base = eth_base
   * vlan: IP base = ip_base; Eth base = eth_base
   */
  ci_uint8              pkt_layout;
#define CI_PKT_LAYOUT_INVALID   0
#define CI_PKT_LAYOUT_RX_SIMPLE 1
#define CI_PKT_LAYOUT_RX_VLAN   2
#define CI_PKT_LAYOUT_TX_SIMPLE 3
#define CI_PKT_LAYOUT_TX_VLAN   2 /* == CI_PKT_LAYOUT_RX_VLAN */

  /* In almost all cases, you DO NOT NEED to use the next fields directly!
   * Use oo_ether_*(), oo_ip_hdr(), oo_tx_ether_*() and oo_tx_ip_*()
   * accessors from ip_shared_ops.h.
   */
#if CI_CFG_RSS_HASH
  ci_uint8              dma_header[16]  CI_ALIGN(64);
  ci_uint8              ether_base[ETH_HLEN + ETH_VLAN_HLEN];
#else
  ci_uint8              ether_base[ETH_HLEN + ETH_VLAN_HLEN]  CI_ALIGN(64);
#endif
};

/*!
** ci_ip_pkt_queue
**
** General structure for a queue of packets.
*/
typedef struct {
  oo_pkt_p  head;     /**< Id of the first packet. */
  oo_pkt_p  tail;     /**< Id of the last packet. */
  ci_int32  num;      /**< Current number of packets in the queue. */
} ci_ip_pkt_queue;


typedef struct {
  oo_pkt_p  head;
  oo_pkt_p  tail;
  ci_int32  num;
} oo_pktq;
















/*!
** ci_netif_ipid_cb_t
**
** Control structure for the use of allocated IP ID ranges.
*/
typedef struct {
  /* Time at the last occasion that we visited the start
   * of record 0 in the range array */
  ci_iptime_t           loop_start_time;
  /* Time at the last occasion that we visited the start
   * or record 0 & that the delta from the previous visit
   * to record 0 was greater that the max hysterisis value
   */
  ci_iptime_t           low_use_start_time;
  /* Current index into range[] */
  ci_int32              current_index;
  /* First free entry in range[] */
  ci_int32              max_index;

#if CI_CFG_FULL_IP_ID_HANDLING==0
  /* for the "make it faster" version we just run around
   * one allocation. [ipid] ranges from 0 up & is masked by
   * CI_IPID_BLOCK_MASK.  The generated ID is (ipid | base)
   */
  ci_uint16             base;
  ci_uint16             next;
#endif

#if CI_CFG_NO_IP_ID_FAILURE
  /* flag to make sure we don't free if we fail the initial
   * ID block allocation */
  ci_int32              no_free;
#endif

#define CI_TP_IPID_RANGES 8
  struct { 
    ci_uint16 base;     /*! Base of this range of IDs */
    ci_uint16 next;     /*! Next ID to use in this range */
  }                     range[ CI_TP_IPID_RANGES ];
} ci_netif_ipid_cb_t;


/*!
** ci_netif_stats
**
** Statistics used to analyse behaviour of the stack.
*/
typedef struct {
#undef OO_STAT
#define OO_STAT(desc, type, name, kind)  type name;
#include <ci/internal/stats_def.h>
} ci_netif_stats;


/*!
** ci_netif_filter_table_entry  ci_netif_filter_table
**
** The filter table that demuxes packets to sockets.
*/
typedef struct {
  ci_int16  id;
  ci_int16  route_count;  /* how many lookups pass through this entry? */
  ci_uint32 laddr;
} ci_netif_filter_table_entry;


typedef struct {
  CI_ULCONST unsigned         table_size_mask;
  ci_netif_filter_table_entry table[1];
} ci_netif_filter_table;


/*!
** ci_netif_config
**
** 
*/
typedef struct {
  /* RTO time constants in local CPU time based ticks */
  ci_iptime_t tconst_rto_initial;  
  ci_iptime_t tconst_rto_min;     
  ci_iptime_t tconst_rto_max;

  /* default constants (in ms) for the above time constants */
# define CI_TCP_TCONST_RTO_INITIAL (1000)     /* The RTO constants are   */
# define CI_TCP_TCONST_RTO_MIN     (1000/5)   /* inspired by the choices */
# define CI_TCP_TCONST_RTO_MAX     (120*1000) /* of linux, not the RFCs! */


  /* Delayed acknowledgement configuration RFC1122: delay < 500ms typical
  ** delay for many stacks is about 200ms.  We set ours low because the
  ** periodic timer has fairly course granularity.  We still get most of
  ** the benefit. */
  ci_iptime_t tconst_delack;
#define CI_TCP_TCONST_DELACK      50    /* milliseconds                 */

  /* If there's a gap between packets we've received we'll re-enter
   * fast start to avoid conflict between other end's congestion
   * window validation and our delayed acknowledgements
   */
  ci_iptime_t tconst_idle;
#define CI_TCP_TCONST_IDLE        50    /* milliseconds                 */

  /* TCP keepalive configuration */
  ci_iptime_t tconst_keepalive_time;  /* time before probes */
  ci_iptime_t tconst_keepalive_time_in_secs;  /* time before probes */
  ci_iptime_t tconst_keepalive_intvl; /* interval between   */
  ci_iptime_t tconst_keepalive_intvl_in_secs; /* interval between   */
  ci_int32    keepalive_probes;  /* probes to try    */
  
  /* default constants (in ms) for the above time constants         */
  /* see Steven's TCP/IP Vol1 and RFC1122                           */
#define CI_TCP_TCONST_KEEPALIVE_TIME   7200000 /* 2 hours         */
#define CI_TCP_TCONST_KEEPALIVE_INTVL  75000   /* 75 seconds      */
#define CI_TCP_KEEPALIVE_PROBES 9              /* send 9 times    */
  
  /* zero window probe time */
  ci_iptime_t tconst_zwin_max; 
#define CI_TCP_TCONST_ZWIN_MAX    CI_TCP_TCONST_RTO_MAX
  
  /* listen polling timer for retransmission and synrecv timeout */
  ci_iptime_t tconst_listen_time;
  ci_int32    listen_synack_retries;
#define CI_TCP_TCONST_LISTEN_TIME 3000   /* every 3 seconds */
#define CI_TCP_LISTEN_SYNACK_RETRIES 5   /* send 5 synacks  */
  
  /* PAWs idle timeout (RFC1323 pg22) */
  ci_iptime_t tconst_paws_idle;
#define CI_TCP_TCONST_PAWS_IDLE (24*24*60*60*1000)  /* 24 days */

  /* 2MSL for TIMEWAIT timeout */
  ci_iptime_t tconst_2msl_time;
  /* timeout for closing orphaned states in FIN_WAIT[12] & CLOSING */
  ci_iptime_t tconst_fin_timeout;

  /* PMTU discovery timeout */
  ci_iptime_t tconst_pmtu_discover_slow;
# define CI_PMTU_TCONST_DISCOVER_SLOW (19*30*1000)  /*!< 10 mins (RFC1191) 
                                                     * reduced for ANVL -
                                                     * see bug 867 */
  ci_iptime_t tconst_pmtu_discover_fast;
# define CI_PMTU_TCONST_DISCOVER_FAST (2*60*1000)  /*!< 2 mins (RFC1191),
                                                   * also initial timeout  */
  /*! This value is not RFC1191-based.  It is used to increase the PMTU
   * value when (very unlikely, but possible) we hit the abs. min MTU. The
   * value is only used for the first timeout, and as we hit the bottom
   * rather than every time. This could at least help avoid a DoS attack.  */
  ci_iptime_t tconst_pmtu_discover_recover;
#define CI_PMTU_TCONST_DISCOVER_RECOVER (30*1000)

  /* Microseconds between resync of SO_TIMESTAMP clock to system time */
  ci_uint32 timestamp_resync_usec;

  /* Stack statistics timer */
  ci_iptime_t tconst_stats;
# define CI_TCONST_STATS 0    /*!< manual statistics collection = 0 */
} ci_netif_config;


typedef struct {
  /* These fields are defined in a separate file that is also used by the 
  ** configuration subsystem
  */
#define _CI_CFG_BITFIELD
#define _CI_CFG_BITFIELD1  :1
#define _CI_CFG_BITFIELD2  :2
#define _CI_CFG_BITFIELD3  :3
#define _CI_CFG_BITFIELD4  :4
#define _CI_CFG_BITFIELD8  :8
#define _CI_CFG_BITFIELD16 :16
#define _CI_CFG_BITFIELDA8 CI_ALIGN(8)
    
#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_OPTGROUP

#define CI_CFG_OPTFILE_VERSION(version)
#define CI_CFG_OPTGROUP(group, category, expertise)
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
        type name _CI_CFG_BITFIELD##bits;

#include <ci/internal/opts_netif_def.h>
    
    ci_boolean_t inited;
} ci_netif_config_opts;


/*!
** ci_ip_timer_state
**
** Management of timers and the timer wheels themselves.
**
** Ticks are calculated from the CPU cycle counter and converted based on a
** calibration of how fast the CPU runs during initialisation.
*/
typedef struct {
  ci_iptime_t sched_ticks;             /* scheduler's view of time     */
  ci_iptime_t ci_ip_time_real_ticks;   /* cache of real ticks   */
  ci_uint64   frc CI_ALIGN(8);
  ci_uint32   ci_ip_time_frc2tick;     /* bit shift to ticks    */
  ci_uint32   ci_ip_time_frc2us;       /* bit shift to us tick  */  

# define CI_IP_TIME_APP_GRANULARITY  1000u   /* approx tick in us     */
# define CI_IP_TIME_MAX_FRCSHIFT     31u     /* largest tick shift    */

  ci_uint32   khz;                     /* processor speed in khz */
  /*< precalculated min delay for ARP-confirming IP receipt */
  /* list of timers currently firing */
  ci_ni_dllist_t  fire_list;
  /* holds the timer wheels in a flat array */
  ci_ni_dllist_t  warray[CI_IPTIME_WHEELSIZE];  

} ci_ip_timer_state;


typedef ci_uint16  ci_iptime_callback_fn_t;
typedef ci_uint32  ci_iptime_callback_param_t;


/*!
** ci_ip_timer: An individual timer.
*/
typedef struct {
  ci_ni_dllist_link           link;
  ci_iptime_t                 time;         /* absolute time to expire  */  
  oo_sp                       param1;       /* first parameter for fn   */
  ci_iptime_callback_fn_t     fn;           /* function code for demux  */
# define CI_IP_TIMER_TCP_RTO         0x1    /* TCP RTO callback         */
# define CI_IP_TIMER_TCP_DELACK      0x2    /* TCP delack callback      */
# define CI_IP_TIMER_TCP_ZWIN        0x3    /* TCP zero window callback */
# define CI_IP_TIMER_TCP_KALIVE      0x4    /* TCP keep alive callback  */
# define CI_IP_TIMER_TCP_LISTEN      0x5    /* TCP listen callback      */
# define CI_IP_TIMER_NETIF_TIMEOUT   0x6    /* netif timeout state timer*/
# define CI_IP_TIMER_PMTU_DISCOVER   0x7    /* IP PMTU discovery        */ 
# define CI_IP_TIMER_PMTU_DISCOVER_2 0x8    /* IP PMTU discovery        */ 
# define CI_IP_TIMER_TCP_STATS       0x9    /* TCP statistics callback  */
# define CI_IP_TIMER_DEBUG_HOOK      0xa    /* Hook for timer debugging */
# define CI_IP_TIMER_NETIF_STATS     0xb    /* netif statistics timer   */
# define CI_IP_TIMER_UDP_TUNNEL      0xc    /* UDP tunnel frag discard  */
# define CI_IP_TIMER_TCP_TAIL_DROP   0xd    /* TCP tail drop timer      */
# define CI_IP_TIMER_TCP_CHIMNEY_PUSH 0xe   /* TCP offload push timer   */
# define CI_IP_TIMER_TCP_CORK        0xf    /* TCP_CORK timer   */
} ci_ip_timer;




/**********************************************************************
************************* Asynchronous IO *****************************
**********************************************************************/

typedef ci_uint32 ci_async_op_flags_t;





/*! Comment? */
typedef struct {
  volatile ci_int32  lock;
# define CI_EPLOCK_UNINITIALISED           0x00000000
# define CI_EPLOCK_UNLOCKED	           0x10000000
# define CI_EPLOCK_LOCKED	           0x20000000
# define CI_EPLOCK_FL_NEED_WAKE	           0x40000000

  /* Higher levels may use low-order bits as flags. */
# define CI_EPLOCK_CALLBACK_FLAGS          0x0fffffff

  /* stack needs to be primed (interrupt request) */
# define CI_EPLOCK_NETIF_NEED_PRIME        0x01000000
  /* stack needs to be polled */
# define CI_EPLOCK_NETIF_NEED_POLL         0x02000000
  /* a socket file descriptor is closed */
# define CI_EPLOCK_NETIF_CLOSE_ENDPOINT    0x04000000
  /* one or more sockets needs waking */
# define CI_EPLOCK_NETIF_NEED_WAKE         0x08000000
  /* need to wake someone waiting for free packet buffers */
# define CI_EPLOCK_NETIF_PKT_WAKE          0x00100000
  /* need to reinitialise VIs after NIC reset */
# define CI_EPLOCK_NETIF_RESET_STACK       0x00200000
  /* mask for the above flags */
# define CI_EPLOCK_NETIF_KERNEL_FLAGS      0x0f700000
  /* someone's waiting for free packet buffers */
# define CI_EPLOCK_NETIF_IS_PKT_WAITER     0x00800000
  /* these bits are the head of a linked list of sockets */
# define CI_EPLOCK_NETIF_SOCKET_LIST       0x000fffff
} ci_eplock_t;





/*********************************************************************
************************* Global netif state *************************
*********************************************************************/


typedef struct {
  ef_eventq_state       evq_state CI_ALIGN(8);
  ci_uint32             evq_timer_offset;  /* This is an offset into a page */
  ci_uint32             timer_quantum_ns;
  ci_uint32             vi_flags;
  CI_ULCONST ci_uint32  vi_mem_mmap_bytes;
  CI_ULCONST ci_uint32  vi_io_mmap_bytes;
  CI_ULCONST ci_uint32  vi_evq_bytes;
  CI_ULCONST ci_uint16  vi_instance;
  CI_ULCONST ci_uint16  vi_rxq_size;
  CI_ULCONST ci_uint16  vi_txq_size;
  CI_ULCONST ci_uint8   vi_arch;
  CI_ULCONST ci_uint8   vi_variant;
  CI_ULCONST ci_uint8   vi_revision;
  CI_ULCONST char       pci_dev[20];
  /* Transmit overflow queue.  Packets here are ready to send. */
  oo_pktq               dmaq;
  /* Counts bytes of packet payload into and out of the TX descriptor ring. */
  ci_uint32             tx_bytes_added;
  ci_uint32             tx_bytes_removed;
  /* Incremented when a packet is placed into the TX descriptor ring or
   * overflow queue. */
  ci_uint32             tx_dmaq_insert_seq;
  ci_uint32             tx_dmaq_insert_seq_last_poll;
  /* Incremented when transmission of a packet completes. */
  ci_uint32             tx_dmaq_done_seq;
  /* Linked list of TCP sockets waiting for space to send. */
  ci_ni_dllist_t        tx_ready_list;
  /* Holds partially received RX packet fragments. */
  oo_pkt_p              rx_frags;
} ci_netif_state_nic_t;


struct ci_netif_state_s {

  ci_netif_state_nic_t  nic[CI_CFG_MAX_INTERFACES];
  CI_ULCONST ci_int32   nic_n;

  ci_uint64             evq_last_prime CI_ALIGN(8);

  CI_ULCONST cicp_ns_mmap_info_t control_mmap CI_ALIGN(8);

  CI_ULCONST ci_uint32  stack_id; /* FIXME equal to thr->id */
  CI_ULCONST char       pretty_name[CI_CFG_STACK_NAME_LEN + 8];
  CI_ULCONST ci_uint32  netif_mmap_bytes;
  CI_ULCONST ci_uint32  vi_mem_mmap_offset;
  CI_ULCONST ci_uint32  vi_io_mmap_offset;
  CI_ULCONST ci_uint32  vi_state_bytes;

  CI_ULCONST ci_uint32  flags;
# define CI_NETIF_FLAG_DEBUG              0x1 /* driver is debug build   */
# define CI_NETIF_FLAG_ONLOAD_UNSUPPORTED 0x2 /* OOL unsupported on this h/w */

  /* To give insight into runtime errors detected.  See also copy in
   * ci_netif.
   */
  ci_uint32             error_flags;
# define CI_NETIF_ERROR_POST_POLL_LIST    0x1
# define CI_NETIF_ERROR_LOOP_PKTS_LIST    0x2

  /* The bits of this field are used for eventq-primed flags. */

  ci_uint32             evq_primed;

  ci_int8               hwport_to_intf_i[CI_CFG_MAX_REGISTER_INTERFACES];
  ci_int8               intf_i_to_hwport[CI_CFG_MAX_INTERFACES];
  ci_int8               blacklist_intf_i[CI_CFG_MAX_BLACKLIST_INTERFACES];
  ci_uint32             blacklist_length;

  /* Set to true by a thread that is "spinning" waiting for network events
   * and leared when no longer spinning.  May be set/cleared by multiple
   * threads without synchronisation.
   */
  ci_int8               is_spinner;

  /* Set when some work (normally done by ci_netif_poll()) has been left
   * outstanding, and should be done at a convenient moment.
   */
  ci_int8               poll_work_outstanding;

  /* Set by thread that is spinning just after it polls for network events. */
  ci_uint64             last_spin_poll_frc CI_ALIGN(8);

  /* Set by a thread just before it goes to sleep. */
  ci_uint64             last_sleep_frc CI_ALIGN(8);

  /** The global lock.  Protects access to most netif state. */
  ci_eplock_t           lock;

  oo_pkt_p              freepkts;   /**< List of free packet buffers */
  ci_int32              n_freepkts; /**< Number of buffers in freepkts list */

  /** List of packets sent via loopback in order of transmit;
   * it should be reverted when delivering to receiver. */
  oo_pkt_p              looppkts;

  /* Number of packets that are in use by the RX path.  This includes
  ** packets posted as RX descriptors, and those queued in socket
  ** buffers 
  */
  ci_int32              n_rx_pkts;

  /* Set if one or more descriptor rings is getting low on buffers. */
  ci_int32              rxq_low;

  /* The currently enforced RXQ limit.  Usually this is the same as the
   * rxq_limit config option, but can be reduced when suffering memory
   * pressure.
   */
  ci_int32              rxq_limit;

  /* Set when we're short of packet buffers in the RX rings. */
  ci_uint32             mem_pressure;
# define OO_MEM_PRESSURE_LOW       0x1
# define OO_MEM_PRESSURE_CRITICAL  0x2

  /* Pool of packet buffers used only when suffering mem_pressure. */
  oo_pkt_p              mem_pressure_pkt_pool;
  ci_int32              mem_pressure_pkt_pool_n;

  /* Number of packets that are in use by or available to threads not
  ** holding the netif lock.  This includes packets in the nonb_pkt_pool,
  ** and ones allocated from that pool and not yet returned to data
  ** structures controlled by the netif lock.  (e.g. Packets on TCP
  ** sockets' [send_prequeue]s).  This value is protected by the netif
  ** lock.
  */
  ci_int32              n_async_pkts;

#if ! CI_CFG_PP_IS_PTR
  /* [nonb_pkt_pool] is a pool of free packet buffers that can be allocated
  ** without holding the netif lock.
  */
  ci_uint64             nonb_pkt_pool CI_ALIGN(8);
#endif

  ci_netif_ipid_cb_t    ipid;

  /* Offset to the DMAQ descriptors Falcon only. */
  CI_ULCONST ci_uint32  vi_ofs;

  CI_ULCONST ci_uint32  table_ofs;       /**< offset of s/w filter table */
#if CI_CFG_PKTS_AS_HUGE_PAGES
  CI_ULCONST ci_uint32  buf_ofs;         /**< offset of packet buffers */
#endif
  CI_ULCONST ci_uint32  pkt_sets_n;      /**< number of pkt sets allocated */
  CI_ULCONST ci_uint32  pkt_sets_max;    /**< max number of iobufsets */

  /* Packet buffers allocated.  This is [pkt_sets_n * PKTS_PER_SET]. */
  CI_ULCONST ci_int32   n_pkts_allocated;

  ci_ip_timer_state     iptimer_state CI_ALIGN(8);

  ci_ip_timer           timeout_tid CI_ALIGN(8); /**< time-out timer */
  ci_ni_dllist_t        timeout_q;       /**< time-out queue */

  /* List of sockets that may have reapable buffers. */
  ci_ni_dllist_t        reap_list;

#if CI_CFG_SUPPORT_STATS_COLLECTION
  ci_int32              stats_fmt; /**< Output format */
  ci_ip_timer           stats_tid CI_ALIGN(8); /**< NETIF statistics timer id */
  ci_ip_stats           stats_snapshot CI_ALIGN(8);        
  ci_ip_stats           stats_cumulative CI_ALIGN(8);
#endif

 /* Info about endpoints. */


  oo_sp                 free_eps_head;   /**< Endpoints free list */
  ci_uint32             deferred_free_eps_head; /**< Endpoints that could be 
                                                   freed (atomic) */

#if CI_CFG_USERSPACE_PIPE
  oo_sp                 free_pipe_bufs;  /**< Free pipe buffer blocks */
#endif

  /* Max number of ep bufs is 1 << CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX */
  ci_uint32  max_ep_bufs;                /**< Upper limit of end points */
  CI_ULCONST ci_uint32  n_ep_bufs;       /**< Number of available endpoints */
#if CI_CFG_USERSPACE_PIPE
  /*< Bit array: ep_buf is endpoint?
   * 1 << CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX bits ==
   * (1 << CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX) / 32 ci_uint32 ==
   * 1 << (CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX - 5) ci_uint32 ==
   * 1024 ci_uint32 for CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX=15 == 4K
   */
  ci_uint32  ep_buf_is_ep[1 << (CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX - 5)];
#endif

  CI_ULCONST ci_uint32  ep_ofs;          /**< Offset to endpoints array */
  CI_ULCONST ci_uint32  synrecv_ofs;     /**< Offset to listenq array */
  
  oo_p                  free_synrecvs;    /**< Free list of synrecv bufs. */

#if CI_CFG_FD_CACHING
  ci_int32              epcache_n;       /**< Num entries avail on ep-cache */
#endif

  ci_netif_config       conf CI_ALIGN(8);
  ci_netif_config_opts  opts CI_ALIGN(8);

  /* Some config values derived from opts. */
  ci_uint64             spin_cycles         CI_ALIGN(8);
  ci_uint64             buzz_cycles         CI_ALIGN(8);
  ci_uint64             timer_prime_cycles  CI_ALIGN(8);
  ci_uint64             timestamp_resync_cycles CI_ALIGN(8);

  CI_ULCONST ci_uint32  io_mmap_bytes;
  CI_ULCONST ci_uint32  buf_mmap_bytes;

  /* Set to true when endpoints are woken. */
  CI_ULCONST
  ci_int32 poll_did_wake;

  /* are we in the poll loop? */
  ci_int32              in_poll;
  ci_ni_dllist_t        post_poll_list;

  oo_pkt_p              rx_defrag_head;       /*  rx buffers re-assembly */
  oo_pkt_p              rx_defrag_tail;

  ci_int32              send_may_poll;

  char                  name[CI_CFG_STACK_NAME_LEN + 1];
  ci_int32              pid;
  CI_ULCONST uid_t      uid;
  
  ci_uint32             defer_work_count;

#if CI_CFG_STATS_NETIF
  ci_netif_stats        stats;
#endif

#define OO_INTF_I_SEND_VIA_OS   CI_CFG_MAX_INTERFACES
#define OO_INTF_I_LOOPBACK      (CI_CFG_MAX_INTERFACES+1)
#define OO_INTF_I_NUM           (CI_CFG_MAX_INTERFACES+2)
#if CI_CFG_TCPDUMP
  oo_pkt_p              dump_queue[CI_CFG_DUMPQUEUE_LEN];
  ci_uint8              dump_intf[OO_INTF_I_NUM];
  volatile ci_uint8     dump_read_i;
  volatile ci_uint8     dump_write_i;
#endif

  ef_vi_stats           vi_stats CI_ALIGN(8);

  /* Followed by:
  **
  **   vi_state  (for each nic)
  */
};



/*********************************************************************
*************************** Per-socket lock **************************
*********************************************************************/

struct oo_waitable_lock {
  volatile ci_uint32 wl_val;
# define OO_WAITABLE_LK_LOCKED           0x10000000
# define OO_WAITABLE_LK_NEED_WAKE        0x20000000
#if CI_CFG_USERSPACE_PIPE
# define OO_WAITABLE_LK_PIPE_RX          0x4000000
# define OO_WAITABLE_LK_PIPE_TX          0x8000000
#endif
};


/*********************************************************************
**************************** Sockets etc. ****************************
*********************************************************************/

typedef ci_uint32 op_state_id_32bits_t;


typedef union {
  volatile ci_uint64 all;
  struct {
    volatile ci_uint32 rx;
    volatile ci_uint32 tx;
  } rw;
} ci_sleep_seq_t;
#define CI_SLEEP_SEQ_NEVER ((ci_uint32)(-1))

/*!
** citp_waitable
**
** This is a base type that underlies all sockets, and in future
** potentially other stuff too.  The idea is it represents
** application-level resources that are being accelerated, and are
** identified by a handle (file descriptor) in an application.
**
** Examples of intended future uses include acceleration for I/O Completion
** Ports for windows, and epoll() on Linux.
*/
typedef struct {
  /* Used to implement race-free sleeping / wakeup.  Incremented
  ** whenever anything interesting happens. This is defined at start of
  ** struct to ensure consistent alignement and padding on 64 and 32 bit
  */
  ci_sleep_seq_t sleep_seq CI_ALIGN(8);

#if CI_CFG_SOCKP_IS_PTR
  ci_int32              bufid;
#else
  oo_sp                 bufid;
#endif
  ci_uint32             state;

  /* These bits are set when someone wants to be woken (or other action
  ** associated with things happening). */
  ci_uint32             wake_request;
# define CI_SB_FLAG_WAKE_TX_B  0
# define CI_SB_FLAG_WAKE_RX_B  1

  /* These flags are set to indicate that something has happened, that
  ** should maybe lead to someone being woken (if they're interested...see
  ** above).
  */
  ci_uint32             sb_flags;
# define CI_SB_FLAG_WAKE_TX      (1u << CI_SB_FLAG_WAKE_TX_B)      /* 0x1 */
# define CI_SB_FLAG_WAKE_RX      (1u << CI_SB_FLAG_WAKE_RX_B)      /* 0x2 */
# define CI_SB_FLAG_TCP_POST_POLL 0x4
# define CI_SB_FLAG_RX_DELIVERED  0x8

  /* Atomic flags.  Manipulate only with atomic ops. */
  ci_uint32             sb_aflags;
  /* Set when not connected to a file descriptor. */
#define CI_SB_AFLAG_ORPHAN              0x1
#define CI_SB_AFLAG_ORPHAN_BIT          0u
  /* Socket is in an accept queue. */
#define CI_SB_AFLAG_TCP_IN_ACCEPTQ      0x2
#define CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT  1u
  /* Object is queued for deferred work by netif lock holder. */
#define CI_SB_AFLAG_DEFERRED            0x4
#define CI_SB_AFLAG_DEFERRED_BIT        2u
  /* Do not enable onload interrupts from fop->poll */
#define CI_SB_AFLAG_AVOID_INTERRUPTS    0x8
#define CI_SB_AFLAG_AVOID_INTERRUPTS_BIT  3u
  /* Closed with SO_LINGER: waiting for real close */
#define CI_SB_AFLAG_IN_SO_LINGER        0x10
#define CI_SB_AFLAG_IN_SO_LINGER_BIT    4u
  /* O_ASYNC */
#define CI_SB_AFLAG_O_ASYNC             0x20
#define CI_SB_AFLAG_O_ASYNC_BIT         5u
  /* O_NONBLOCK -- must be equal to MSG_DONTWAIT */
#define CI_SB_AFLAG_O_NONBLOCK          0x40
#define CI_SB_AFLAG_O_NONBLOCK_BIT      6u
  /* O_APPEND */
#define CI_SB_AFLAG_O_APPEND            0x80
#define CI_SB_AFLAG_O_APPEND_BIT        7u
  /* O_NDELAY */
# define CI_SB_AFLAG_O_NDELAY           CI_SB_AFLAG_O_NONBLOCK
# define CI_SB_AFLAG_O_NDELAY_BIT       CI_SB_AFLAG_O_NONBLOCK_BIT

  /* Link field for [ci_netif_state::post_poll_list]. */
  ci_ni_dllist_link     post_poll_link;

  /* Per-socket lock. */
  struct oo_waitable_lock lock;

  /* Argument for the callback in tcp_helper_resource */
  ci_user_ptr_t callback_arg;
  ci_boolean_t  callback_armed;

  oo_sp                 wt_next;
  /* Linked list.  Used for:
  **   - ci_tcp_socket_listen::acceptq
  **   - ci_netif_state::free_eps_head
  */

  ci_int32              next_id;
  /* Linked list.  Used when an integer id is needed:
  **   - deferred socket list
  **   - ci_netif_state::deferred_free_eps_head
  **   - ci_netif_state::async_signal_q
  **   - ci_netif_state::async_completion_q
  */

  ci_int32              sigown;  /** pid that receives signals from this */
  ci_uint8              sigsig;  /** signal to send fcntl(F_SETSIG) */

} citp_waitable;






/*********************************************************************
******************************* Sockets ******************************
*********************************************************************/

typedef struct {
  ci_ip_timer           tid;            /* adjustment timer */
  ci_uint16             pmtu;           /* current PMTU */
  ci_uint8              state;
  /* State of discovery mechanism.  When disabled, IP:DF bit is clear. */
# define CI_PMTU_DISCOVER_DISABLE                 0
# define CI_PMTU_DISCOVER_ENABLE                  1
# define CI_PMTU_DISCOVER_ENABLE_AND_CHECK_SENDS  2
  ci_uint8              plateau_id;     /* index in plateau table */
  ci_uint32             traffic;        /* used to keep track of tx traffic
                                           between successive plateau climbs */
} ci_pmtu_state_t;

typedef struct {
  cicp_mac_verinfo_t  mac_integrity; /*!< MAC table version number handle   */

  /* This field receives the source address that should be used.
   *
   * Why not just use [ip.ip_saddr_be32] ?  Because that field is
   * overloaded (when used in [ci_sock_cmn::pkt]) to be the bound local IP
   * of the socket, so we can't write it.  TODO: Change that!!
   */
  ci_ip_addr_t    ip_saddr_be32;

  ci_uint16       dport_be16;  /* Dest port: This is an input. */

  /* [status] is either >= 0, in which case it takes one of the values of
   * cicpos_retrieve_rc_t, or -ve, in which case the mac lookup failed and
   * [-status] gives the OS error code.
   */
  ci_int8         status;

  ci_uint8        flags;
  /* retrrc_localroute, and we really CAN handle it */
#define CI_IP_CACHE_IS_LOCALROUTE       1
  /* we should reconfirm ARP entry - it is STALE or will go STALE soon */
#define CI_IP_CACHE_NEED_UPDATE_SOON    2
  /* we should update ARP entry - it is usable, but STALE */
#define CI_IP_CACHE_NEED_UPDATE_STALE   4

  ci_pmtu_state_t pmtus;
  ci_ip_addr_t    nexthop;
  ci_mtu_t        mtu;
  ci_ifid_t       ifindex;
  cicp_encap_t    encap;
  ci_int32        intf_i;
  ci_hwport_id_t  hwport CI_ALIGN(4); /* ip hdr to start at 4-byte boundary */
  ci_uint8        ether_offset;
  /* Here we are aligned+2 and have 2 cases:
   * - 4 bytes padding, 12 bytes dmac/smac, 2 bytes type/len
   * - 12 bytes dmac/smac, 4 bytes IEEE 802.1Q tag, 2 bytes type/len
   * ether_offset field shows where the real ethernet header begins.
   * I.e. ether_offset=4 in the first case and ether_offset=0 in the second.
   *
   * To access to the ethernet header field, use ci_ip_cache_ether_*()
   * accessors from ip_shared_ops.h.
   */
  ci_uint8        ether_header[2 * ETH_ALEN + ETH_VLAN_HLEN];
  ci_uint16       ether_type;
  ci_ip4_hdr      ip;
} ci_ip_cached_hdrs;


typedef ci_int32 ci_pkt_priority_t;




/* Per-socket state that affect control plane lookup.  ie. These fields
 * influence routing decisions etc.
 */
struct oo_sock_cplane {
  /* IP to be used as source address.  If zero then source address is
   * selected by the control plane lookup.  Usually set when a socket is
   * bound to a local IP.  Must not be set to a multicast IP -- should be
   * left at zero if socket is bound to a multicast IP.
   */
  ci_uint32  ip_laddr_be32;
  ci_uint16  lport_be16;
  ci_ifid_t  so_bindtodevice;
  ci_ifid_t  ip_multicast_if;
  ci_uint32  ip_multicast_if_laddr_be32;
  ci_uint8   ip_ttl;
  ci_uint8   ip_mcast_ttl;
  ci_uint8   sock_cp_flags;
# define OO_SCP_NO_MULTICAST        0x1   /* do not accelerate multicast */
# define OO_SCP_CONNECTED           0x2   /* socket is connected (UDP)   */
# define OO_SCP_LADDR_BOUND         0x4   /* local IP bound (UDP)        */
};


struct ci_sock_cmn_s {
  citp_waitable         b;

  oo_sp                 local_peer; /**< Id of the local peer socket
                                         in case of loopback connection */


  ci_uint32             s_flags CI_ALIGN(8);
#define CI_SOCK_FLAG_REUSEADDR    0x00000001   /* socket SO_REUSEADDR option */
#define CI_SOCK_FLAG_KALIVE       0x00000002   /* socket SO_KEEPALIVE option */
#define CI_SOCK_FLAG_BROADCAST    0x00000004   /* socket SO_BROADCAST option */
#define CI_SOCK_FLAG_OOBINLINE    0x00000008   /* socket SO_OOBINLINE option */
#define CI_SOCK_FLAG_LINGER       0x00000010   /* socket SO_LINGER option    */
#define CI_SOCK_FLAG_DONTROUTE    0x00000020   /* socket SO_DONTROUTE option */
#define CI_SOCK_FLAG_FILTER       0x00000040   /* socket has h/w filter      */
/* bind() has been successfully called on this socket. */
#define CI_SOCK_FLAG_BOUND        0x00000080 
/* The address portion of the local address has been bound (i.e. not
 * INADDR_ANY). This flag is only valid when CI_SOCK_FLAG_BOUND has been
 * set and is used by Windows LSP to determine whether to reset the local
 * address when/if a socket is disconnected (at successful completion of
 * disconnectex).
 */
#define CI_SOCK_FLAG_ADDR_BOUND   0x00000100
/* Socket was bound to explicit port number. It is used by Linux stack to
 * determaine if the socket should be re-bound by connect()/listen() after 
 * shutdown().
 */
#define CI_SOCK_FLAG_PORT_BOUND   0x00000200
#define CI_SOCK_FLAG_SET_SNDBUF   0x00000400   /* app as set SO_SNDBUF */
#define CI_SOCK_FLAG_SET_RCVBUF   0x00000800   /* app as set SO_RCVBUF */
#define CI_SOCK_FLAG_SW_FILTER_FULL 0x00001000 /* s/w filter insert failed */
#define CI_SOCK_FLAG_BOUND_ALIEN  0x00002000   /* bound to non-SFC address */
#define CI_SOCK_FLAG_CONNECT_MUST_BIND 0x00004000 /* Call bind in connect() */


  ci_uint32             s_aflags;
#define CI_SOCK_AFLAG_CORK              0x01          /* TCP_CORK     */
#define CI_SOCK_AFLAG_CORK_BIT          0u
#define CI_SOCK_AFLAG_NODELAY           0x200        /* TCP_NODELAY  */
#define CI_SOCK_AFLAG_NODELAY_BIT       9u

  /* Some TCP-specific flags, but we don't want another flags field. */
#define CI_SOCK_AFLAG_NEED_ACK          0x400
#define CI_SOCK_AFLAG_NEED_ACK_BIT      10u



  /*! Which socket flags should be inherited by accepted connections? */
#define CI_SOCK_FLAG_TCP_INHERITED                                          \
  (CI_SOCK_FLAG_KALIVE | CI_SOCK_FLAG_OOBINLINE | CI_SOCK_FLAG_LINGER |     \
   CI_SOCK_FLAG_BROADCAST | CI_SOCK_FLAG_SET_SNDBUF | CI_SOCK_FLAG_SET_RCVBUF)
#define CI_SOCK_AFLAG_TCP_INHERITED CI_SOCK_AFLAG_CORK

  struct oo_sock_cplane cp;

  ci_ip_cached_hdrs     pkt;
  union {
    ci_tcp_hdr          space_for_tcp_hdr;
    ci_udp_hdr          space_for_udp_hdr;
  } space_for_hdrs;
  /* Headers.  Used as a template for outgoing packets, and also to match
  ** addresses in the netif filter table.  NB. Not all fields are stored in
  ** network byte-order.
  */

  ci_int32             tx_errno;
  /* Zero if transmits permitted by user, else error code to return to 'em. */

  ci_int32             rx_errno;
  /* Zero if data can still arrive.  Otherwise low-order bits give error
  ** code to return to user (which may be zero).
  */

  ci_uint32 os_sock_status; /*!< seq<<2 + (RX and TX bits) */
#define OO_OS_STATUS_RX 1
#define OO_OS_STATUS_TX 2
#define OO_OS_STATUS_SEQ_SHIFT 2

  struct {
    /* This contains only sockopts that are inherited from the listening
    ** socket by newly accepted TCP sockets.
    */
    ci_int32            sndbuf;
    ci_int32            rcvbuf;

    /* In Linux, scheduler does not work with units less than jiffies,
     * and it is larger that millisecond (at least with HZ <= 1000).
     * So, there is no reason to keep user-supplied usec value
     * for SO_(RCV|SND)_TIMEO.  And Linux itself keeps jiffies only. */
    ci_uint32           rcvtimeo_msec;
    ci_uint32           sndtimeo_msec;

    ci_uint32           linger;
    ci_int32            rcvlowat;
    ci_int32            so_debug; /* Flags for dummy options */
# define CI_SOCKOPT_FLAG_SO_DEBUG    0x1
# define CI_SOCKOPT_FLAG_IP_RECVERR  0x2
  } so;

  /* Socket options that are not inherited on accept from listening socket.
  ** (NB. I'm not confident about there: some of them should maybe be in
  ** [so] above.
  */
  ci_pkt_priority_t     so_priority;
  ci_int32              so_error;

  /* When set, these limit the RX path to only accept packets from the
   * given interface.  Used by SO_BINDTODEVICE and also the
   * EF_MCAST_JOIN_BINDTODEVICE option.  The base_ifindex and vlan are
   * needed to make the RX-side check efficient.
   */
  ci_ifid_t             rx_bind2dev_ifindex;
  ci_ifid_t             rx_bind2dev_base_ifindex;
  ci_int16              rx_bind2dev_vlan;

  ci_uint8              cmsg_flags;
# define CI_IP_CMSG_PKTINFO     0x01
# define CI_IP_CMSG_TTL         0x02
# define CI_IP_CMSG_TOS         0x04
# define CI_IP_CMSG_RECVOPTS    0x08
# define CI_IP_CMSG_RETOPTS     0x10
# define CI_IP_CMSG_TIMESTAMP   0x20
# define CI_IP_CMSG_TIMESTAMPNS 0x40

  ci_uint64             ino CI_ALIGN(8);  /**< Inode of the O/S socket */
  ci_uint32             uid;              /**< who made this socket    */
  ci_int32		pid;


  ci_uint8              domain;           /*!<  PF_INET or PF_INET6 */

  ci_ni_dllist_link     reap_link;
};



/*********************************************************************
***************************** UDP sockets ****************************
*********************************************************************/

typedef  struct {
  ci_uint32 err;

# define CI_SOCK_ERR_ORIGIN_NONE  0
# define CI_SOCK_ERR_ORIGIN_LOCAL 1
# define CI_SOCK_ERR_ORIGIN_ICMP  2
# define CI_SOCK_ERR_ORIGIN_ICMP6 3
  ci_uint8 origin;  

  ci_uint8 type;
  ci_uint8 code;
  ci_uint8 pad;
  ci_uint32 info;
  ci_uint32 data;
  ci_uint32 sa_addr;
  ci_uint16 sa_port;
} ci_sock_ee;


typedef struct {
  /* These fields are protected by the netif lock. */
  oo_pkt_p      head;
  oo_pkt_p      tail;
  ci_uint32     pkts_added;
  ci_uint32     pkts_reaped;
  ci_uint32     bytes_added;

  /* These fields are protected by the sock lock. */

  /* Extract points to the next packet to be consumed, or the packet
   * before the one to be consumed (if consumed bit is set in
   * pkt_fmt_prefix udp rx flags). This allows it to point at the tail
   * when we've extracted everything.
   */
  oo_pkt_p      extract;
  ci_uint32     pkts_delivered;
  ci_uint32     bytes_delivered;

#if CI_CFG_ZC_RECV_FILTER
  /* Similar rules apply to filter as to extract */
  oo_pkt_p      filter;
  ci_uint32     pkts_filter_dropped;
  ci_uint32     bytes_filter_dropped;
  ci_uint32     pkts_filter_passed;
  ci_uint32     bytes_filter_passed;
#endif
} ci_udp_recv_q;


typedef struct {
  ci_uint32 n_rx_os;          /* datagrams received via O/S sock       */
  ci_uint32 n_rx_os_slow;     /* datagrams received via O/S sock (slow)*/
  ci_uint32 n_rx_os_error;    /* recv via O/S returned error           */
  ci_uint32 n_rx_eagain;      /* recv returned EAGAIN                  */
  ci_uint32 n_rx_overflow;    /* datagrams dropped due to overflow     */
  ci_uint32 n_rx_mem_drop;    /* datagrams dropped due to out-of-mem   */
  ci_uint32 n_rx_pktinfo;     /* n times IP_PKTINFO retrieved          */
  ci_uint32 max_recvq_depth;  /* maximum bytes queued for recv         */

  ci_uint32 n_tx_os;          /* datagrams send via OS socket          */
  ci_uint32 n_tx_os_slow;     /* datagrams send via OS socket (slower) */
  ci_uint32 n_tx_onload_c;    /* datagrams sent via onload (connected) */
  ci_uint32 n_tx_onload_uc;   /* datagrams sent via onload (uncon)     */
  ci_uint32 n_tx_cp_match;    /* unconnected, matched cache            */
  ci_uint32 n_tx_cp_uc_lookup;/* unconnected, control plane lookup     */
  ci_uint32 n_tx_cp_c_lookup; /* connected, control plane lookup       */
  ci_uint32 n_tx_cp_a_lookup; /* unconnected, unlocked lookup          */
  ci_uint32 n_tx_cp_no_mac;   /* datagrams delayed due to no mac       */
  ci_uint32 n_tx_lock_poll;   /* locked to poll stack                  */
  ci_uint32 n_tx_lock_pkt;    /* locked to get packet buf              */
  ci_uint32 n_tx_lock_snd;    /* locked to send                        */
  ci_uint32 n_tx_lock_cp;     /* locked to update control plane        */
  ci_uint32 n_tx_lock_defer;  /* deferred to lock holder               */
  ci_uint32 n_tx_eagain;      /* send queue was full, returned EAGAIN  */
  ci_uint32 n_tx_spin;        /* send queue was full, did spin         */
  ci_uint32 n_tx_block;       /* send queue was full, did block        */
  ci_uint32 n_tx_poll_avoids_full; /* polling made space in sendq      */
  ci_uint32 n_tx_fragments;   /* number of (non-first) fragments       */
  ci_uint32 n_tx_msg_confirm; /* onload send with MSG_CONFIRM          */
  ci_uint32 n_tx_os_late;     /* sent via OS, after copying            */
  ci_uint32 n_tx_unconnect_late; /* concurrent send and unconnect      */
} ci_udp_socket_stats;


struct  ci_udp_state_s {
  ci_sock_cmn           s;

  /*! Cache used for "unconnected" destinations - i.e. where a dest. addr
   * has been provided by the caller.  We use this cache regardless of 
   * whether we are connected */
  ci_ip_cached_hdrs     ephemeral_pkt CI_ALIGN(8);

  ci_uint32 udpflags;
#define CI_UDPF_FILTERED        0x00000001  /*!< filter inserted         */
#define CI_UDPF_MCAST_LOOP      0x00000002  /*!< IP_MULTICAST_LOOP       */
#define CI_UDPF_IMPLICIT_BIND   0x00000004  /*!< did implicit bind       */
#define CI_UDPF_EF_SEND         0x00000010  /*!< Last send via onload    */
#define CI_UDPF_LAST_RECV_ON    0x00000020  /*!< Last recv via onload    */
#define CI_UDPF_EF_BIND         0x00000040  /*!< Bound to onloaded intf  */
#define CI_UDPF_MCAST_B2D       0x00000080  /*!< done bind2dev on mcast add */
#define CI_UDPF_NO_MCAST_B2D    0x00000100  /*!< don't bind2dev on mcast add */
#define CI_UDPF_PEEK_FROM_OS    0x00000200  /*!< Datagram peeked from OS */
#define CI_UDPF_SO_TIMESTAMP    0x00004000  /*!< SO_TIMESTAMP */
#define CI_UDPF_MCAST_JOIN      0x00008000  /*!< done IP_ADD_MEMBERSHIP */
#define CI_UDPF_MCAST_FILTER    0x00010000  /*!< mcast filter added */

#if CI_CFG_ZC_RECV_FILTER
  /* Only safe to use these at user-level in context of caller who set them */
  ci_uint64     recv_q_filter CI_ALIGN(8);
  ci_uint64     recv_q_filter_arg CI_ALIGN(8);
#endif
  ci_udp_recv_q recv_q;

  /*! A list of buffers to support receiving datagrams via kernel in zc API */ 
  oo_pkt_p zc_kernel_datagram;
  /*! Number of buffers present in zc_kernel_datagram list */
  ci_uint32 zc_kernel_datagram_count;

  /* Coversion from FRC stamp -> timeval is inaccurate, we cache the
   * result to ensure we return the same value to subsequent
   * SIOCGSTAMP calls for the same packet
   */
  struct oo_timespec stamp_cache;
  /*! Receive timestamp (FRC) of last packet passed to the user */
  ci_uint64 stamp CI_ALIGN(8); 
  /*! Value of stamp before SO_TIMESTAMP enabled */
  ci_uint64 stamp_pre_sots CI_ALIGN(8); 

  /* Linked list of UDP datagrams.  Datagrams to be sent are queued here
   * (in reverse order) when the netif lock is contended in sendmsg().
   * Manipulated atomically.  Link field is [pkt->netif.tx.dmaq_next].
   */
  ci_int32  tx_async_q;
  oo_atomic_t tx_async_q_level;
  /* Number of bytes "inflight".  i.e. Sent to interface (including
   * overflow queue) and not yet had TX event.
   */
  ci_uint32 tx_count;

  ci_udp_socket_stats stats;

};


#if CI_CFG_USERSPACE_PIPE
/*********************************************************************
***************************** PIPEs  ********************************
*********************************************************************/

/* Structure represents pipe buffer when it's attached to free_pipe_bufs
 * list in netif state. Pipe buffers are allocated from the same memory as
 * socket buffers. They are allocated and freed in groups, so when free buffers
 * are added to the list only first buffer and it's id - all others go in
 * sequence of a given length. */
struct oo_pipe_buf {
  oo_sp id;              /*!< Id of the first buffer in free sequence */
  oo_sp next;            /*!< Next sequence head (not next buffer
                          * in this one!) */
  ci_uint32  length;     /*!< Number of socket buffers in this chunk of
                          * pipe buffers */
};

struct oo_pipe {
  citp_waitable         b;

  struct {
    ci_uint32 bufid;
    ci_uint32 offset;
  } read_ptr;

  struct {
    ci_uint32 bufid;
    ci_uint32 offset;
  } write_ptr;

  /* These flags should be modified with atomic operations */
  volatile ci_uint32 aflags;

  /* values are same as fd flags set with fcntrl */
#define CI_PFD_AFLAG_NONBLOCK              0x01
  /* Indicates that end of the pipe is closed. Used to store this
   * information  till the second one is also closed. */
#define CI_PFD_AFLAG_CLOSED                0x02

#define CI_PFD_AFLAG_READER_SHIFT   0
#define CI_PFD_AFLAG_READER_MASK    0x07
#define CI_PFD_AFLAG_WRITER_SHIFT   4
#define CI_PFD_AFLAG_WRITER_MASK    0x70


  /* Initial number of pipe buffers to be allocated */
#define OO_PIPE_INITIAL_BUFS 8
  /* Amount of buffers by which total number of pipe buffers will
   * be incremented in case of buffers shortage */
#define OO_PIPE_BURST_BUFS   40
  /* Maximum number of pipe buffers which can be allocated for
   * a pipe */
#define OO_PIPE_MAX_BUFS     128
#define OO_PIPE_BUF_SIZE EP_BUF_SIZE
  ci_int32 buffer_idxs [OO_PIPE_MAX_BUFS]; /*!< List of id's of buffers shared
                                            * between userspace and kernel*/
  ci_uint32 bufs_num;  /*!< Number of buffers in the pipe */

  /* in future pipe capacity may be up to 1048576 - define from linux kernel,
   * so 32-bits are enough, rolling over 0 is not a problem. */
  volatile ci_uint32 bytes_added;           /*!< Total number of bytes written to the pipe */
  volatile ci_uint32 bytes_removed;         /*!< Total number of bytes removed
                                             * from the pipe */
};
#endif


/*********************************************************************
***************************** TCP sockets ****************************
*********************************************************************/

/* structure to parse TCP options in SYN */
typedef struct {
  ci_int32              smss;           /* Max segment size */
  ci_uint32             wscl_shft;      /* Window scale shift */
  ci_uint32             flags;          /* Other options enabled (only those
                                           we support) */
} ci_tcp_options;


/*
** connections that we have sent a SYN-ACK due to a SYN arriving on a
** listen socket but are awaiting the final ACK to promote it onto the
** accept queue.
*/
typedef struct {
  ci_ni_dllist_link    link;      /* Link into listenq[] or free_synrecvs */

  ci_uint16            r_port;    /* remote port                         */
  ci_uint32            l_addr;    /* local address                       */
  ci_uint32            r_addr;    /* remote address                      */

  ci_uint32            rcv_nxt;   /* sequence number one beyond SYN      */

  ci_uint32            snd_isn;   /* initial sequence number for SYN-ACK */
  ci_uint8             rcv_wscl;  /* advertised window scale in SYN-ACK  */
  ci_int8              retries;   /* number of times SYN-ACK sent        */

  ci_tcp_options       tcpopts;   /* TCP options specific for SYN        */
  ci_uint32            tspeer;    /* Timestamp from peer                 */
  ci_uint32            timest;    /* Timestamp                           */
  
  ci_iptime_t          timeout;   /* timeout for resending SYN-ACK       */

  oo_sp                local_peer;/* id of the peer for lo connection    */
} ci_tcp_state_synrecv;



/* TCP options which must survive when CLOSED endpoint (i.e. ci_tcp_state)
 * is transformed into LISTEN (i.e. ci_tcp_socket_listen). */
typedef struct {
  /* TCP_KEEP* socket options: */
  ci_uint32            ka_probe_th;         /* probe threshold                  */
  ci_iptime_t          t_ka_time;           /* time before probes sent in ticks */
  ci_iptime_t          t_ka_time_in_secs;   /* time before probes sent in secs  */
  ci_iptime_t          t_ka_intvl;          /* time between probes in tick      */
  ci_iptime_t          t_ka_intvl_in_secs;  /* time between probes in secs      */

  ci_uint32            user_mss;            /* user-provided maximum MSS */
  ci_uint8             tcp_defer_accept;    /* TCP_DEFER_ACCEPT sockopt  */
#define OO_TCP_DEFER_ACCEPT_OFF 0xff

} ci_tcp_socket_cmn;




struct oo_tcp_socket_stats {
  ci_uint32  tx_stop_rwnd;    /* TX stopped by receive window      */
  ci_uint32  tx_stop_cwnd;    /* TX stopped by congestion window   */
  ci_uint32  tx_stop_more;    /* TX stopped by CORK, MSG_MORE etc. */
  ci_uint32  tx_stop_nagle;   /* TX stopped by nagle's algorithm   */
  ci_uint32  tx_stop_app;     /* TX stopped because TXQ empty      */
  ci_uint32  tx_nomac_defer;  /* Deferred send waiting for ARP     */
#if CI_CFG_BURST_CONTROL
  ci_uint32  tx_stop_burst;   /* TX stopped by burst control       */
#endif
  ci_uint32  rtos;            /* RTO timeouts                      */
  ci_uint32  fast_recovers;   /* times entered fast-recovery       */
  ci_uint32  rx_seq_errs;     /* out-of-seq pkts w payload dropped */
  ci_uint32  rx_ack_seq_errs; /* out-of-seq ACKs dropped           */
  ci_uint32  rx_ooo_pkts;     /* out-of-order pkts recvd           */
  ci_uint32  rx_ooo_fill;     /* out-of-order events               */
};


struct ci_tcp_state_s {
  ci_sock_cmn         s;
  ci_tcp_socket_cmn   c;

  ci_uint32            tcpflags;
  /* Options negotiated with SYN options. */
# define CI_TCPT_FLAG_TSO               0x01  /* Timestamp RFC1323    */
# define CI_TCPT_FLAG_WSCL              0x02  /* Window scale RFC1323 */
# define CI_TCPT_FLAG_SACK              0x04  /* SACK RFC2018         */
# define CI_TCPT_FLAG_ECN               0x08  /* ECN RFC3168          */
# define CI_TCPT_FLAG_STRIPE            0x10  /* Striping             */
# define CI_TCPT_FLAG_OPT_MASK          0x1f
  /* TCP socket state flags */
# define CI_TCPT_FLAG_ADVANCE_NEEDED    0x80  /* used for sendfile   */
# define CI_TCPT_FLAG_WAS_ESTAB         0x100
  /* Has socket ever been ESTABLISHED?  Simulates SS_CONNECTED state in
   * Linux (more or less). */
# define CI_TCPT_FLAG_NONBLOCK_CONNECT  0x200

  /* Using temporary source IP addr. */
#define CI_TCPT_FLAG_PASSIVE_OPENED     0x80000  /* was passively opened */
#define CI_TCPT_FLAG_NO_ARP             0x100000 /* there was a failed ARP */
#define CI_TCPT_FLAG_NO_TX_ADVANCE      0x200000 /* don't tx_advance */
#define CI_TCPT_FLAG_LOOP_DEFERRED      0x400000 /* deferred loopback conn */

  /* flags advertised on SYN */
# define CI_TCPT_SYN_FLAGS \
        (CI_TCPT_FLAG_WSCL | CI_TCPT_FLAG_TSO | CI_TCPT_FLAG_SACK)
# define CI_TCPT_NEG_FLAGS \
        (CI_TCPT_FLAG_TSO | CI_TCPT_FLAG_WSCL | CI_TCPT_FLAG_SACK | \
         CI_TCPT_FLAG_ECN)

  ci_int32            send_max;
  ci_uint32           send_in;    /**< Packets added directly to send queue */
  ci_uint32           send_out;   /**< Packets removed from send queue */
  ci_ip_pkt_queue     send;       /**< Send queue. */

  ci_ip_pkt_queue     retrans;    /**< Retransmit queue. */

  ci_ip_pkt_queue     recv1;      /**< Receive queue. */
  ci_ip_pkt_queue     recv2;      /**< Aux receive queue for urgent data */
  ci_uint32           recv_off;   /**< Offset to current recv queue
                                       from base of [ci_tcp_state] */
  oo_pkt_p            recv1_extract; 
                                  /**< Next id in main receive queue to be 
                                       extracted by recvmsg */

  ci_ip_pkt_queue     rob;        /**< Re-order buffer. */
  oo_pkt_p            last_sack[CI_TCP_SACK_MAX_BLOCKS + 1];  
                                  /**< First packets of last-received
                                   * block (in [0]) and last-sent 
                                   * SACKed blocks */
  ci_uint32           dsack_start;/**< Start SEQ of DSACK option */
  ci_uint32           dsack_end;  /**< End SEQ of DSACK option */
  oo_pkt_p            dsack_block;/**< Second block packet id: 
                                   * CI_ILL_END used for no second block;
                                   * CI_ILL_UNUSED when no DSACK present */

  /* Next field is needed to support PathMTU discovery functionality */
  ci_uint32            snd_check;   /* equal to snd_nxt at beginning of
                                       tested interval */

  ci_uint32            snd_nxt;     /* next sequence number to send       */
  ci_uint32            snd_max;     /* maximum sequence number advertised */
  ci_uint32            snd_una;     /* oldest unacknowledged byte         */
#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
  ci_uint32            snd_wl1;     /* sequence number of received
                                     * segment that updated snd_max */
#endif

  ci_uint32            fast_path_check;
  /* If in a state in which we can execute the TCP receive fast path, then
  ** this reflects the expected TCP header length and flags.  Otherwise it
  ** is set to an invalid value that should never match a TCP packet.
  */

  ci_uint32            outgoing_hdrs_len;
  /* Length of IP + TCP headers (inc TSO if any).
   * Does not include Ethernet header len any more! */

  ci_uint16            amss;        /* advertised mss to the sending side */
  ci_uint32            smss;        /* sending MSS (excl IP & TCP hdrs)   */
  ci_uint32            eff_mss;     /* PMTU-based mss, excl TCP options   */
  ci_uint32            snd_up;      /* send urgent pointer, holds the seq 
                                       num of byte following the OOB byte */

  ci_uint32            rcv_wnd_advertised; /* receive window to advertise in
                                              outgoing packets            */
  ci_uint32            rcv_wnd_right_edge_sent; /* the edge of the receive
                                                   window sent in an 
                                                   outgoing packet        */
  ci_uint32            rcv_added;   /* amount added to rx queue           */
  ci_uint32            rcv_delivered; /* amount removed from rx queue     */
  ci_uint32            ack_trigger; /* rcv_delivered value which triggers
                                       next receive window update         */
#if CI_CFG_BURST_CONTROL
  ci_uint32            burst_window; /* bytes after snd_una that we
                                        can burst to before receiving
                                        any packets from other side,
                                        or zero if unlimited */
#endif
  ci_uint32            rcv_up;      /* receive urgent pointer, holds the
                                       seq num of the OOB byte            */

  ci_uint32            rcv_wscl;    /* receive window scaling             */
  ci_uint32            snd_wscl;    /* send window scaling                */

  ci_uint32            congstate;   /* congestion status flag             */
# define CI_TCP_CONG_OPEN       0x0 /* opening congestion window          */
# define CI_TCP_CONG_RTO        0x1 /* RTO timer has fired                */
# define CI_TCP_CONG_RTO_RECOV  0x2 /* Recovery after RTO                 */
# define CI_TCP_CONG_FAST_RECOV 0x4 /* NewReno or SACK fast recovery      */
# define CI_TCP_CONG_COOLING    0x8 /* waiting for recovery or SACKs      */
# define CI_TCP_CONG_NOTIFIED   0x12 /* congestion has been notified somehow */

  ci_uint32            congrecover; /* snd_nxt when loss detected         */
  oo_pkt_p             retrans_ptr; /* next packet to retransmit          */
  ci_uint32            retrans_seq; /* seq of next packet to retransmit   */

  ci_uint32            cwnd;        /* congestion window                  */
  ci_uint32            cwnd_extra;  /* adjustments when congested         */
  ci_uint32            ssthresh;    /* slow-start threshold               */
  ci_uint32            bytes_acked; /* bytes acked but not yet added to cwnd */
  
  ci_uint32            dup_acks;    /* number of dup-acks received        */
  ci_uint32            dup_thresh;  /* dupack threshold -- constant for now */

#if CI_CFG_TCP_FASTSTART  
  ci_uint32            faststart_acks; /* Bytes to ack before leaving faststart */
#endif

#if CI_CFG_TAIL_DROP_PROBE
  ci_uint32            taildrop_state;
  ci_uint32            taildrop_mark; /* Sequence number of tail of retransmit queue */
#define CI_TCP_TAIL_DROP_INACTIVE 0x0
#define CI_TCP_TAIL_DROP_ACTIVE   0x1
#define CI_TCP_TAIL_DROP_WAITING  0x2
#define CI_TCP_TAIL_DROP_PRIMED   0x4
#define CI_TCP_TAIL_DROP_PROBED   0x8
#endif

  /* Keep alive probes, and sending ACKs after gaps that may cause
   * other end to validated its congetion window 
   */
  ci_iptime_t          t_prev_recv_payload; /* timestamp of prev in-seq 
                                             * burst with payload */
  ci_iptime_t          t_last_recv_payload; /* timestamp of last in-seq 
                                             * packet with payload */
  ci_iptime_t          t_last_recv_ack;     /* timestamp of last in-seq 
                                             * packet without payload */

  /* congestion window validation RFC2861; 
   * also used for time-wait state timeout
   */
  ci_iptime_t          t_last_sent; /* timestamp of last segment          */

#if CI_CFG_CONGESTION_WINDOW_VALIDATION
  ci_iptime_t          t_last_full; /* timestamp when window last full    */
  ci_uint32            cwnd_used;   /* congestion window used             */
  /* NB: [t_last_sent] is only set on datapath when
   * CI_CFG_CONGESTION_WINDOW_VALIDATION is enabled.  But it is overloaded
   * for 2MSL timeout in TIME_WAIT state, which is why it is not
   * conditionally compiled.
   */
#endif

  /* sa and sv are scaled by 8 and 4 respectively to minimize roundoff
  ** error when time has a large granularity See the appendix of
  ** Jacobson's SIGCOMM 88  */
  ci_iptime_t          sa;          /* smoothed round trip time           */
  ci_iptime_t          sv;          /* round trip time variance estimate  */
  ci_iptime_t          rto;         /* retransmit timeout value           */
  ci_uint32            retransmits; /* number of retransmissions */


  /* these fields for RTT measurement are valid when:
  **   (i) not using TCP timestamps
  **   (ii) not in a congested state (Karn's algo)
  **   (iii) SEQ_LE(snd_una, timed_seq) (tail of bursts unmeasured)
  */
  ci_uint32            timed_seq;   /* first byte of timed packet         */
  ci_iptime_t          timed_ts;    /* timestamp for timed packet         */

  /* timestamp option fields see RFC1323 */
  ci_uint32            tsrecent;    /* TS.Recent RFC1323                  */
  ci_uint32            tslastack;   /* Last.ACK.sent RFC1323              */ 
#ifndef NDEBUG
  ci_uint32            tslastseq;   /* Sequence no of packet that updated tsrecent
                                       Just being used for debugging - purge at will */
#endif
  ci_iptime_t          tspaws;      /* last active timestamp for tsrecent */
#define CI_TCP_TSO_WORD (CI_BSWAPC_BE32((CI_TCP_OPT_NOP       << 24u)  | \
                                        (CI_TCP_OPT_NOP       << 16u)  | \
                                        (CI_TCP_OPT_TIMESTAMP <<  8u)  | \
                                        (0xa                        )))

  /* delayed acknowledgements */
  ci_uint32            acks_pending;/* number of packets needing ack      */
/* These bits are ORed into acks_pending */
#define CI_TCP_DELACK_SOON_FLAG 0x80000000
#define CI_TCP_ACK_FORCED_FLAG  0x40000000
/* Mask to get the number of acks pending (includes ACK_FORCED but not
 * DELACK_SOON bit)
 */
#define CI_TCP_ACKS_PENDING_MASK 0x7fffffff

  /* keepalive vailables */
  ci_uint32            ka_probes;   /* number of probes sent              */

  ci_uint32            zwin_probes; /* zero window probes counter         */
  ci_uint32            zwin_acks;   /* zero window acks counter           */
  ci_int32             incoming_tcp_hdr_len; /* expected TCP header length */

  /* timer ids for timers */
  ci_ip_timer          rto_tid;     /* retransmit timer                   */
  ci_ip_timer          delack_tid;  /* delayed acknowledgement timer      */
  ci_ip_timer          zwin_tid;    /* zero window probe timer            */
  ci_ip_timer          kalive_tid;  /* keep alive timer                   */
#if CI_CFG_TCP_SOCK_STATS
  ci_ip_timer          stats_tid;   /* Statistics report timer            */
#endif
#if CI_CFG_TAIL_DROP_PROBE
  ci_ip_timer          taildrop_tid;/* Tail drop probe timer              */
#endif
  ci_ip_timer          cork_tid;    /* TCP timer for TCP_CORK/MSG_MORE   */


  ci_uint16 urg_data; /** out-of-band byte store & relevant flags */
#define CI_TCP_URG_DATA_MASK    0x00ff
#define CI_TCP_URG_COMING       0x0100  /* oob byte here or coming */
#define CI_TCP_URG_IS_HERE      0x0200  /* oob byte is valid (got it) */
#define CI_TCP_URG_PTR_VALID    0x0400  /* tcp_rcv_up is valid */

#if CI_CFG_TCP_SOCK_STATS
  ci_ip_sock_stats     stats_snapshot CI_ALIGN(8);   /**< statistics snapshot */
  ci_ip_sock_stats     stats_cumulative CI_ALIGN(8); /**< cummulative statistics */
  ci_int32             stats_fmt;        /**< Output format */
#endif
 
#if CI_CFG_FD_CACHING
  /* Used to cache TCP-state and associated fds to improve accept performance */
  ci_int32             cached_on_fd;
  ci_int32             cached_on_pid;
  /* Link into either the epcache_pending, the epcache_cache, the
     epcache_acceptex, or none */
  ci_ni_dllist_link    epcache_link;
#endif

  /* An extension of the send queue.  Packets are put here when the netif
  ** lock is contended, and are later transferred to the sendq.  This is a
  ** linked list of packets in reverse order. */
  ci_int32             send_prequeue;
  oo_atomic_t          send_prequeue_in;

  ci_ni_dllist_link    timeout_q_link;
  ci_ni_dllist_link    tx_ready_link;


  struct oo_tcp_socket_stats  stats;
};


typedef struct {
  ci_uint32            n_listenq_overflow;
  ci_uint32            n_listenq_no_synrecv;
  ci_uint32            n_acks_reset;
  ci_uint32            n_acceptq_overflow;
  ci_uint32            n_acceptq_no_sock;
  ci_uint32            n_accept_loop2_closed;
  ci_uint32            n_accept_os;
} ci_tcp_socket_listen_stats;


struct ci_tcp_socket_listen_s {
  ci_sock_cmn          s;
  ci_tcp_socket_cmn    c;

  /* Accept queue of established connections.  This is a concurrent fifo
  ** (ie. reader and writer need not synchronise).
  */
  ci_uint32            acceptq_max;
  ci_int32             acceptq_put;
  ci_uint32            acceptq_n_in;
  oo_sp                acceptq_get;
  ci_uint32            acceptq_n_out;

  /* For each listening socket we have a list of SYNRECV buffs, one for each
   * SYN we've received for which there hasn't yet been an ACK.  i.e. on
   * receipt of SYN we make a synrecv buf, then send the SYNACK.  The on
   * receipt of the ACK of the SYNACK, we 'promote' the synrecv buffer to a
   * fully fledged end-point.  We call this list the listenq
   */
  ci_int32             n_listenq;
  ci_int32             n_listenq_new;
  ci_ni_dllist_t       listenq[CI_CFG_TCP_LISTENQ_BUCKETS];

#if CI_CFG_FD_CACHING
  /* We cache EPs between close and accept to speed up passive opens.  See
   * comment in defintion of ci_netif_state_s::epcache_free for details.
   */
  ci_ni_dllist_t       epcache_cache;   /**< List of cache entries in use */

  /* Actually, cached EPs go through an intermediate state - cache pending.
   * This is needed to cope with close-wait.  If the EP is in close-wait and
   * the app has closed it, EP can't be reused yet.  Hence for this period it
   * goes on the epcache_pending list.  Hence at citp_tcp_close, EPs go onto
   * the pending list, and at citp_tcp_drop, they move from pending to cache
   * list (ready to be reused by the next accept).  The only reason we need a
   * list of pending EPs is that we want to be able to find all a listening
   * socket's cached EPs, both ready for reuse and pending (so that we can
   * uncache them easily when the listening socket closes).  Note that we
   * don't want a single list with each entry having a bit "is_in_close_wait",
   * because this would mean walking a potentially long way down the list on
   * accept finding one not in close-wait, and the whole point of this is to
   * make accept nice and quick.
   */
  ci_ni_dllist_t       epcache_pending;
#endif

  /* timer to poll the listen queue for retransmits */
  ci_ip_timer          listenq_tid;

#if CI_CFG_STATS_TCP_LISTEN
  ci_tcp_socket_listen_stats  stats;
#endif
};



/*********************************************************************
***************************** Alien  ********************************
*********************************************************************/

struct oo_alien_ep {
  citp_waitable b;
  ci_uint32 stack_id;
  oo_sp     sock_id;
};

/*!
** citp_waitable_obj
**
** This type is a union that holds all the specialisations of
** citp_waitable.  It is needed so that we know how much space these things
** occupy, and also provides a convenient way to get from one to another
** without casting.
*/
union citp_waitable_obj_u {
  citp_waitable         waitable;
  ci_sock_cmn           sock;
  ci_tcp_state          tcp;
  ci_tcp_socket_listen  tcp_listen;
  ci_udp_state          udp;
#if CI_CFG_USERSPACE_PIPE
  struct oo_pipe        pipe;
#endif
  struct oo_alien_ep    alien;
};


struct oo_eth_hdr {
  ci_uint8  ether_dhost[6];
  ci_uint8  ether_shost[6];
  ci_uint16 ether_type;
};



#endif  /* __CI_INTERNAL_IP_SHARED_TYPES_H__ */
/*! \cidoxg_end */
