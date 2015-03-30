/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Virtual Interface definitions for EtherFabric Virtual
**            Interface HAL.
** \date      2015/02/16
** \copyright Copyright &copy; 2015 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_EF_VI_H__
#define __EFAB_EF_VI_H__


/**********************************************************************
 * Primitive types ****************************************************
 **********************************************************************/

/* We standardise on the types from stdint.h and synthesise these types
 * for compilers/platforms that don't provide them */

#if defined(__GNUC__)
# if defined(__linux__) && defined(__KERNEL__)
#  include <linux/types.h>
#  include <linux/time.h>
# else
#  include <stdint.h>
#  include <inttypes.h>
#  include <time.h>
#   include <sys/types.h>
# endif
# define EF_VI_ALIGN(x) __attribute__ ((aligned (x)))
# define ef_vi_inline static inline

#elif defined(_MSC_VER)

typedef unsigned char       uint8_t;
typedef char                int8_t;

typedef unsigned short      uint16_t;
typedef short               int16_t;

typedef unsigned int        uint32_t;
typedef int                 int32_t;

typedef unsigned long long  uint64_t;
typedef long long           int64_t;

# define ef_vi_inline static __inline

# define EF_VI_ALIGN(x)
#else
# error Unknown compiler
#endif


/*! \brief Cache line sizes for alignment purposes */
#if defined(__powerpc64__) || defined(__powerpc__)
# define EF_VI_DMA_ALIGN  128
#else
# define EF_VI_DMA_ALIGN  64
#endif


#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * Types **************************************************************
 **********************************************************************/

/*! \brief A pointer to an event queue */
typedef uint32_t                ef_eventq_ptr;

/*! \brief An address */
typedef uint64_t                ef_addr;
/*! \brief An address of an I/O area for a virtual interface */
typedef char*                   ef_vi_ioaddr_t;


/**********************************************************************
 * Dimensions *********************************************************
 **********************************************************************/

/*! \brief The maximum number of queues per virtual interface */
#define EF_VI_MAX_QS              32
/*! \brief The minimum size of array to pass when polling the event queue */
#define EF_VI_EVENT_POLL_MIN_EVS  2


/**********************************************************************
 * ef_event ***********************************************************
 **********************************************************************/

/*! \brief A DMA request identifier.
**
** This is an integer token specified by the transport and associated
** with a DMA request.  It is returned to the VI user with DMA completion
** events.  It is typically used to identify the buffer associated with
** the transfer.
*/
typedef int			ef_request_id;


/*! \brief Mask to use with an ef_request_id. */
#define EF_REQUEST_ID_MASK      0xffffffff


/*! \brief A token that identifies something that has happened.
**
** Examples include packets received, packets transmitted, and errors.
**
** Users should not access this structure, but should instead use the
** macros provided.
*/
typedef union {
  /** A generic event, to query the type when it is unknown */
  struct {
    unsigned       type       :16;
  } generic;
  /** An event of type EF_EVENT_TYPE_RX */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :16;
    unsigned       rq_id      :32;
    unsigned       len        :16;
    unsigned       flags      :16;
  } rx;
  /** An event of type EF_EVENT_TYPE_RX_DISCARD */
  struct {  /* This *must* have same initial layout as [rx]. */
    unsigned       type       :16;
    unsigned       q_id       :16;
    unsigned       rq_id      :32;
    unsigned       len        :16;
    unsigned       flags      :16;
    unsigned       subtype    :16;
  } rx_discard;
  /** An event of type EF_EVENT_TYPE_TX */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :16;
    unsigned       desc_id    :16;
  } tx;
  /** An event of type EF_EVENT_TYPE_TX_ERROR */
  struct {  /* This *must* have same layout as [tx]. */
    unsigned       type       :16;
    unsigned       q_id       :16;
    unsigned       desc_id    :16;
    unsigned       subtype    :16;
  } tx_error;
  /** An event of type EF_EVENT_TYPE_TX_WITH_TIMESTAMP */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :16;
    unsigned       rq_id      :32;
    unsigned       ts_sec     :32;
    unsigned       ts_nsec    :32;
  } tx_timestamp;
  /** An event of type EF_EVENT_TYPE_RX_NO_DESC_TRUNC */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :16;
  } rx_no_desc_trunc;
  /** An event of type EF_EVENT_TYPE_RX_PACKED_STREAM */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :16;
    unsigned       flags      :16;
    unsigned       n_pkts     :16;
    unsigned       ps_flags   :8;
  } rx_packed_stream;
  /** An event of type EF_EVENT_TYPE_SW */
  struct {
    unsigned       type       :16;
    unsigned       data;
  } sw;
} ef_event;


/*! \brief Type of event in an ef_event e */
#define EF_EVENT_TYPE(e)        ((e).generic.type)


/*! \brief Possible types of events */
enum {
  /** Good data was received. */
  EF_EVENT_TYPE_RX,
  /** Packets have been sent. */
  EF_EVENT_TYPE_TX,
  /** Data received and buffer consumed, but something is wrong. */
  EF_EVENT_TYPE_RX_DISCARD,
  /** Transmit of packet failed. */
  EF_EVENT_TYPE_TX_ERROR,
  /** Received packet was truncated due to a lack of descriptors. */
  EF_EVENT_TYPE_RX_NO_DESC_TRUNC,
  /** Software generated event. */
  EF_EVENT_TYPE_SW,
  /** Event queue overflow. */
  EF_EVENT_TYPE_OFLOW,
  /** TX timestamp event. */
  EF_EVENT_TYPE_TX_WITH_TIMESTAMP,
  /** A batch of packets was received in a packed stream. */
  EF_EVENT_TYPE_RX_PACKED_STREAM,
};


/* Macros to look up various information per event */

/*! \brief Get the number of bytes received */
#define EF_EVENT_RX_BYTES(e)            ((e).rx.len)
/*! \brief Get the RX descriptor ring ID used for a received packet. */
#define EF_EVENT_RX_Q_ID(e)             ((e).rx.q_id)
/*! \brief Get the dma_id used for a received packet. */
#define EF_EVENT_RX_RQ_ID(e)            ((e).rx.rq_id)
/*! \brief True if the CONTinuation Of Packet flag is set for an RX event */
#define EF_EVENT_RX_CONT(e)             ((e).rx.flags & EF_EVENT_FLAG_CONT)
/*! \brief True if the Start Of Packet flag is set for an RX event */
#define EF_EVENT_RX_SOP(e)              ((e).rx.flags & EF_EVENT_FLAG_SOP)
/*! \brief True if the next buffer flag is set for a packed stream event */
#define EF_EVENT_RX_PS_NEXT_BUFFER(e)   ((e).rx_packed_stream.flags &	\
                                         EF_EVENT_FLAG_PS_NEXT_BUFFER)
/*! \brief True if the iSCSIOK flag is set for an RX event */
#define EF_EVENT_RX_ISCSI_OKAY(e)       ((e).rx.flags & EF_EVENT_FLAG_ISCSI_OK)

/*! \brief Start Of Packet flag. */
#define EF_EVENT_FLAG_SOP             0x1
/*! \brief CONTinuation Of Packet flag. */
#define EF_EVENT_FLAG_CONT            0x2
/*! \brief iSCSI CRC validated OK flag. */
#define EF_EVENT_FLAG_ISCSI_OK        0x4
/*! \brief Multicast flag. */
#define EF_EVENT_FLAG_MULTICAST       0x8
/*! \brief Packed Stream Next Buffer flag. */
#define EF_EVENT_FLAG_PS_NEXT_BUFFER  0x10

/*! \brief Get the TX descriptor ring ID used for a transmitted packet. */
#define EF_EVENT_TX_Q_ID(e)     ((e).tx.q_id)

/*! \brief Get the RX descriptor ring ID used for a discarded packet. */
#define EF_EVENT_RX_DISCARD_Q_ID(e)  ((e).rx_discard.q_id)
/*! \brief Get the dma_id used for a discarded packet. */
#define EF_EVENT_RX_DISCARD_RQ_ID(e) ((e).rx_discard.rq_id)
/*! \brief True if the CONTinuation Of Packet flag is set for an RX_DISCARD
** event */
#define EF_EVENT_RX_DISCARD_CONT(e)  ((e).rx_discard.flags&EF_EVENT_FLAG_CONT)
/*! \brief True if the Start Of Packet flag is set for an RX_DISCARD event */
#define EF_EVENT_RX_DISCARD_SOP(e)   ((e).rx_discard.flags&EF_EVENT_FLAG_SOP)
/*! \brief Get the reason for an EF_EVENT_TYPE_RX_DISCARD event */
#define EF_EVENT_RX_DISCARD_TYPE(e)  ((e).rx_discard.subtype)
/*! \brief Get the length of a discarded packet */
#define EF_EVENT_RX_DISCARD_BYTES(e) ((e).rx_discard.len)

/*! \brief The reason for an EF_EVENT_TYPE_RX_DISCARD event */
enum {
  /** IP header or TCP/UDP checksum error */
  EF_EVENT_RX_DISCARD_CSUM_BAD,
  /** Hash mismatch in a multicast packet */
  EF_EVENT_RX_DISCARD_MCAST_MISMATCH,
  /** Ethernet CRC error */
  EF_EVENT_RX_DISCARD_CRC_BAD,
  /** Frame was truncated */
  EF_EVENT_RX_DISCARD_TRUNC,
  /** No ownership rights for the packet */
  EF_EVENT_RX_DISCARD_RIGHTS,
  /** Event queue error, previous RX event has been lost */
  EF_EVENT_RX_DISCARD_EV_ERROR,
  /** Other unspecified reason */
  EF_EVENT_RX_DISCARD_OTHER,
};

/*! \brief Get the TX descriptor ring ID used for a transmit error */
#define EF_EVENT_TX_ERROR_Q_ID(e)              ((e).tx_error.q_id)
/*! \brief Get the reason for a TX_ERROR event */
#define EF_EVENT_TX_ERROR_TYPE(e)              ((e).tx_error.subtype)

/*! \brief Get the TX descriptor ring ID used for a timestamped packet. */
#define EF_EVENT_TX_WITH_TIMESTAMP_Q_ID(e)     ((e).tx_timestamp.q_id)
/*! \brief Get the dma_id used for a timetsamped packet. */
#define EF_EVENT_TX_WITH_TIMESTAMP_RQ_ID(e)    ((e).tx_timestamp.rq_id)
/*! \brief Get the number of seconds from the timestamp of a transmitted
** packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_SEC(e)      ((e).tx_timestamp.ts_sec)
/*! \brief Get the number of nanoseconds from the timestamp of a transmitted
** packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_NSEC(e)     ((e).tx_timestamp.ts_nsec)
/*! \brief Get the sync flags from the timestamp of a transmitted packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(e) ((e).tx_timestamp.ts_nsec & 3)

/*! \brief The adapter clock has previously been set in sync with the
** system */
#define EF_VI_SYNC_FLAG_CLOCK_SET 1
/*! \brief The adapter clock is in sync with the external clock (PTP) */
#define EF_VI_SYNC_FLAG_CLOCK_IN_SYNC 2

/*!\brief The reason for an EF_EVENT_TYPE_TX_ERROR event */
enum {
  /** No ownership rights for the packet */
  EF_EVENT_TX_ERROR_RIGHTS,
  /** TX pacing engine work queue was full */
  EF_EVENT_TX_ERROR_OFLOW,
  /** Oversized transfer has been indicated by the descriptor */
  EF_EVENT_TX_ERROR_2BIG,
  /** Bus or descriptor protocol error occurred when attempting to read the
  ** memory referenced by the descriptor */
  EF_EVENT_TX_ERROR_BUS,
};

/*! \brief Get the RX descriptor ring ID used for a received packet that
** was truncated due to a lack of descriptors. */
#define EF_EVENT_RX_NO_DESC_TRUNC_Q_ID(e)  ((e).rx_no_desc_trunc.q_id)

/*! \brief Mask for the data in a software generated event */
#define EF_EVENT_SW_DATA_MASK   0xffff
/*! \brief  Get the data for an EF_EVENT_TYPE_SW event */
#define EF_EVENT_SW_DATA(e)     ((e).sw.data)

/*! \brief Output format for an ef_event */
#define EF_EVENT_FMT            "[ev:%x]"
/*! \brief Get the type of an event */
#define EF_EVENT_PRI_ARG(e)     (unsigned) (e).generic.type


/* ***************** */


/*! \brief ef_iovec is similar to the standard struct iovec.  An array of
** these is used to designate a scatter/gather list of I/O buffers.
*/
typedef struct {
  /** base address of the buffer */
  ef_addr  iov_base EF_VI_ALIGN(8);
  /** length of the buffer */
  unsigned iov_len;
} ef_iovec;


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

/*! \brief Flags that can be requested when allocating an ef_vi */
enum ef_vi_flags {
  /** Default setting */
  EF_VI_FLAGS_DEFAULT     = 0x0,
  /** Receive iSCSI header digest enable: hardware verifies header digest
  ** (CRC) when packet is iSCSI. */
  EF_VI_ISCSI_RX_HDIG     = 0x2,
  /** Transmit iSCSI header digest enable: hardware calculates and inserts
  ** header digest (CRC) when packet is iSCSI. */
  EF_VI_ISCSI_TX_HDIG     = 0x4,
  /** Receive iSCSI data digest enable: hardware verifies data digest (CRC)
  ** when packet is iSCSI. */
  EF_VI_ISCSI_RX_DDIG     = 0x8,
  /** Transmit iSCSI data digest enable: hardware calculates and inserts
  ** data digest (CRC) when packet is iSCSI. */
  EF_VI_ISCSI_TX_DDIG     = 0x10,
  /** Use physically addressed TX descriptor ring */
  EF_VI_TX_PHYS_ADDR      = 0x20,
  /** Use physically addressed RX descriptor ring */
  EF_VI_RX_PHYS_ADDR      = 0x40,
  /** IP checksum calculation and replacement is disabled */
  EF_VI_TX_IP_CSUM_DIS    = 0x80,
  /** TCP/UDP checksum calculation and replacement is disabled */
  EF_VI_TX_TCPUDP_CSUM_DIS= 0x100,
  /** Drop transmit packets that are not TCP or UDP */
  EF_VI_TX_TCPUDP_ONLY    = 0x200,
  /** Drop packets with a mismatched IP source address
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_IP      = 0x400,              /* Siena only */
  /** Drop packets with a mismatched MAC source address
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MAC     = 0x800,              /* Siena only */
  /** Set lowest bit of queue ID to 0 when matching within filter block
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MASK_1  = 0x1000,             /* Siena only */
  /** Set lowest 2 bits of queue ID to 0 when matching within filter block
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MASK_2  = 0x2000,             /* Siena only */
  /** Set lowest 3 bits of queue ID to 0 when matching within filter block
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MASK_3  = (0x1000 | 0x2000),  /* Siena only */
  /** Disable using TX descriptor push, so always use doorbell for transmit */
  EF_VI_TX_PUSH_DISABLE   = 0x4000,
  /** Always use TX descriptor push, so never use doorbell for transmit
  ** (7000 series only) */
  EF_VI_TX_PUSH_ALWAYS    = 0x8000,             /* ef10 only */
  /** Add timestamp to received packets (7000 series only) */
  EF_VI_RX_TIMESTAMPS     = 0x10000,            /* ef10 only */
  /** Add timestamp to transmitted packets (7000 series only) */
  EF_VI_TX_TIMESTAMPS     = 0x20000,            /* ef10 only */
  /** Enable loopback of transmitted packets (7000 series only) */
  EF_VI_TX_LOOPBACK       = 0x40000,            /* ef10 only */
  /** Enable packed stream mode for received packets (7000 series only) */
  EF_VI_RX_PACKED_STREAM  = 0x80000,            /* ef10 only */
  /** Use 64KB packe3d stream buffers, instead of the 1024KB default
  ** (7000 series only) */
  EF_VI_RX_PS_BUF_SIZE_64K = 0x100000,          /* ef10 only */
};


/*! \brief Flags that can be returned when an ef_vi has been allocated */
enum ef_vi_out_flags {
  /** Clock sync status */
  EF_VI_OUT_CLOCK_SYNC_STATUS = 0x1,            /* ef10 only */
};

/**********************************************************************
 * ef_vi data structure ***********************************************
 **********************************************************************/

/*! \brief NIC architectures that are supported */
enum ef_vi_arch {
  /** 5000 and 6000-series NICs */
  EF_VI_ARCH_FALCON,
  /** 7000-series NICs */
  EF_VI_ARCH_EF10,
};

/*! \brief State of TX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Previous slot that has been handled */
  uint32_t  previous;
  /** Descriptors added to the ring */
  uint32_t  added;
  /** Descriptors removed from the ring */
  uint32_t  removed;
  /** Timestamp in nanoseconds */
  uint32_t  ts_nsec;
} ef_vi_txq_state;

/*! \brief State of RX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Descriptors previously added to the ring, but unhandled */
  uint32_t  prev_added;
  /** Descriptors added to the ring */
  uint32_t  added;
  /** Descriptors removed from the ring */
  uint32_t  removed;
  /** Packets received as part of a jumbo (7000-series only) */
  uint32_t  in_jumbo;                           /* ef10 only */
  /** Bytes received as part of a jumbo (7000-series only) */
  uint32_t  bytes_acc;                          /* ef10 only */
  /** Count of packets received in packed stream (7000-series only) */
  uint16_t  rx_ps_pkt_count;                    /* ef10 only */
  /** Credit for packed stream handling (7000-series only) */
  uint16_t  rx_ps_credit_avail;                 /* ef10 only */
} ef_vi_rxq_state;

/*! \brief State of event queue
**
** Users should not access this structure.
*/
typedef struct {
  /** Event queue pointer */
  ef_eventq_ptr evq_ptr;
  /** Timestamp (major part) */
  unsigned      sync_timestamp_major;
  /** Timestamp (minor part) */
  unsigned      sync_timestamp_minor;
  /** Timestamp synchronised with adapter */
  unsigned      sync_timestamp_synchronised; /* with adapter */
  /** Time synchronisation flags */
  unsigned      sync_flags;
} ef_eventq_state;

/*! \brief TX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Mask for indexes within ring, to wrap around */
  uint32_t         mask;
  /** Pointer to descriptors */
  void*            descriptors;
  /** Pointer to IDs */
  uint32_t*        ids;
} ef_vi_txq;

/*! \brief RX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Mask for indexes within ring, to wrap around */
  uint32_t         mask;
  /** Pointer to descriptors */
  void*            descriptors;
  /** Pointer to IDs */
  uint32_t*        ids;
} ef_vi_rxq;

/*! \brief State of a virtual interface
**
** Users should not access this structure.
*/
typedef struct {
  /** Event queue state */
  ef_eventq_state evq;
  /** TX descriptor ring state */
  ef_vi_txq_state txq;
  /** RX descriptor ring state */
  ef_vi_rxq_state rxq;
  /* Followed by request id fifos. */
} ef_vi_state;

/*! \brief Statistics for a virtual interface
**
** Users should not access this structure.
*/
typedef struct {
  /** RX events lost */
  uint32_t rx_ev_lost;
  /** RX events with a bad descriptor */
  uint32_t rx_ev_bad_desc_i;
  /** RX events with a bad queue label */
  uint32_t rx_ev_bad_q_label;
  /** Gaps in the event queue (empty slot followed by event) */
  uint32_t evq_gap;
} ef_vi_stats;

/*! \brief The type of NIC in use
**
** Users should not access this structure.
*/
struct ef_vi_nic_type {
  /** Architecture of the NIC */
  unsigned char  arch;
  /** Variant of the NIC */
  char           variant;
  /** Revision of the NIC */
  unsigned char  revision;
};

struct ef_pio;


/*! \brief A virtual interface.
**
** An ef_vi represents a virtual interface on a specific NIC.  A virtual
** interface is a collection of an event queue and two DMA queues used to
** pass Ethernet frames between the transport implementation and the
** network.
**
** Users should not access this structure.
*/
typedef struct ef_vi {
  /** True if the virtual interface has been initialized */
  unsigned                      inited;
  /** The resource ID of the virtual interface */
  unsigned                      vi_resource_id;
  /** The instance ID of the virtual interface */
  unsigned                      vi_i;

  /** The length of a receive buffer */
  unsigned                      rx_buffer_len;
  /** The length of the prefix at the start of a received packet */
  unsigned                      rx_prefix_len;
  /** The timestamp correction for received packets */
  int                           rx_ts_correction;
  /** Pointer to virtual interface memory */
  char*                         vi_mem_mmap_ptr;
  /** Length of virtual interface memory */
  int                           vi_mem_mmap_bytes;
  /** Pointer to virtual interface I/O region */
  char*                         vi_io_mmap_ptr;
  /** Length of virtual interface I/O region */
  int                           vi_io_mmap_bytes;
  /** True if the virtual interface is in a cluster */
  int                           vi_clustered;
  /** True if packed stream mode is enabled for the virtual interface */
  int                           vi_is_packed_stream;
  /** The packed stream buffer size for the virtual interface */
  unsigned                      vi_ps_buf_size;

  /** I/O address for the virtual interface */
  ef_vi_ioaddr_t                io;

  /** Programmed I/O region linked to the virtual interface */
  struct ef_pio*                linked_pio;

  /** Base of the event queue for the virtual interface */
  char*                         evq_base;
  /** Mask for offsets within the event queue for the virtual interface */
  unsigned                      evq_mask;
  /** The timer quantum for the virtual interface, in nanoseconds */
  unsigned                      timer_quantum_ns;

  /** The threshold at which to switch from using TX descriptor push to
  ** using a doorbell */
  unsigned                      tx_push_thresh;

  /** The TX descriptor ring for the virtual interface */
  ef_vi_txq                     vi_txq;
  /** The RX descriptor ring for the virtual interface */
  ef_vi_rxq                     vi_rxq;
  /** The state of the virtual interface */
  ef_vi_state*                  ep_state;
  /** The flags for the virtual interface */
  enum ef_vi_flags              vi_flags;
  /** Flags returned when the virtual interface is allocated */
  enum ef_vi_out_flags          vi_out_flags;
  /** Statistics for the virtual interface */
  ef_vi_stats*                  vi_stats;

  /** Virtual queues for the virtual interface */
  struct ef_vi*                 vi_qs[EF_VI_MAX_QS];
  /** Number of virtual queues for the virtual interface */
  int                           vi_qs_n;

  /** The type of NIC hosting the virtual interface */
  struct ef_vi_nic_type	        nic_type;

  /*! \brief Driver-dependent operations. */
  /* Doxygen comment above is the detailed description of ef_vi::ops */
  struct ops {
    /** Transmit a packet from a single packet buffer */
    int (*transmit)(struct ef_vi*, ef_addr base, int len,
                    ef_request_id);
    /** Transmit a packet from a vector of packet buffers */
    int (*transmitv)(struct ef_vi*, const ef_iovec*, int iov_len,
                     ef_request_id);
    /** Initialize TX descriptors on the TX descriptor ring, for a vector
    **  of packet buffers */
    int (*transmitv_init)(struct ef_vi*, const ef_iovec*,
                          int iov_len, ef_request_id);
    /** Submit newly initialized TX descriptors to the NIC */
    void (*transmit_push)(struct ef_vi*);
    /** Transmit a packet already resident in Programmed I/O */
    int (*transmit_pio)(struct ef_vi*, int offset, int len,
                        ef_request_id dma_id);
    /** Transmit a packet already resident in Programmed I/O */
    int (*transmit_copy_pio)(struct ef_vi*, int pio_offset,
                             const void* src_buf, int len,
                             ef_request_id dma_id);
    /** Initialize an RX descriptor on the RX descriptor ring */
    int (*receive_init)(struct ef_vi*, ef_addr, ef_request_id);
    /** Submit newly initialized RX descriptors to the NIC */
    void (*receive_push)(struct ef_vi*);
    /** Poll an event queue */
    int (*eventq_poll)(struct ef_vi*, ef_event*, int evs_len);
    /** Prime a virtual interface allowing you to go to sleep blocking on it */
    void (*eventq_prime)(struct ef_vi*);
    /** Prime an event queue timer with a new timeout */
    void (*eventq_timer_prime)(struct ef_vi*, unsigned v);
    /** Start an event queue timer running */
    void (*eventq_timer_run)(struct ef_vi*, unsigned v);
    /** Stop an event-queue timer */
    void (*eventq_timer_clear)(struct ef_vi*);
    /** Prime an event queue timer to expire immediately */
    void (*eventq_timer_zero)(struct ef_vi*);
  } ops;  /**< Driver-dependent operations. */
  /* Doxygen comment above is documentation for the ops member of ef_vi */
} ef_vi;


/*! \brief Return the resource ID of the virtual interface
**
** \param vi The virtual interface to query.
**
** \return The resource ID of the virtual interface.
**
** Return the resource ID of the virtual interface.
*/
ef_vi_inline unsigned ef_vi_resource_id(ef_vi* vi)
{
  return vi->vi_resource_id;
}


/*! \brief Return the flags of the virtual interface
**
** \param vi The virtual interface to query.
**
** \return The flags of the virtual interface.
**
** Return the flags of the virtual interface.
*/
ef_vi_inline enum ef_vi_flags ef_vi_flags(ef_vi* vi)
{
  return vi->vi_flags;
}



/*! \brief Return the instance ID of the virtual interface
**
** \param vi The virtual interface to query.
**
** \return The instance ID of the virtual interface.
**
** Return the instance ID of the virtual interface.
*/
ef_vi_inline unsigned ef_vi_instance(ef_vi* vi)
{
  return vi->vi_i;
}


/*! \brief Return a string that identifies the version of ef_vi
**
** \return A string that identifies the version of ef_vi.
**
** Return a string that identifies the version of ef_vi. This should be
** treated as an unstructured string. At time of writing it is the version
** of OpenOnload or EnterpriseOnload in which ef_vi is distributed.
**
** Note that Onload will check this is a version that it recognizes. It
** recognizes the version strings generated by itself, and those generated
** by older official releases of Onload (when the API hasn't changed), but
** not those generated by older patched releases of Onload. Consequently,
** ef_vi applications built against patched versions of Onload will not be
** supported by future versions of Onload.
*/
extern const char* ef_vi_version_str(void);


/*! \brief Returns a string that identifies the char driver interface
**         required
**
** \return A string that identifies the char driver interface required by
**         this build of ef_vi.
**
** Returns a string that identifies the char driver interface required by
** this build of ef_vi.
**
** Returns the current version of the drivers that are running - useful to
** check that it is new enough.
*/
extern const char* ef_vi_driver_interface_str(void);


/**********************************************************************
 * Receive interface **************************************************
 **********************************************************************/

/*! \brief Returns the length of the prefix at the start of a received
**         packet
**
** \param vi The virtual interface to query.
**
** \return The length of the prefix at the start of a received packet.
**
** Returns the length of the prefix at the start of a received packet.
**
** The NIC may be configured to deliver meta-data in a prefix before the
** packet payload data. This call returns the size of the prefix.
**
** When a large packet is received that is scattered over multiple packet
** buffers, the prefix is only present in the first buffer.
*/ef_vi_inline int ef_vi_receive_prefix_len(ef_vi* vi)
{
  return vi->rx_prefix_len;
}


/*! \brief Returns the length of a receive buffer
**
** \param vi The virtual interface to query.
**
** \return The length of a receive buffer.
**
** Returns the length of a receive buffer.
**
** When a packet arrives that does not fit within a single receive buffer,
** it is spread over multiple buffers.
**
** The application must ensure that receive buffers are at least as large
** as the value returned by this function, else there is a risk that a DMA
** may overrun the buffer.
*/
ef_vi_inline int ef_vi_receive_buffer_len(ef_vi* vi)
{
  return vi->rx_buffer_len;
}


/*! \i_ef_vi Set the length of receive buffers.
 *
 * Set the length of receive buffers for this VI.  The new length is used
 * for subsequent calls to ef_vi_receive_init() and ef_vi_receive_post().
 *
 * This call has no effect for 5000 and 6000-series (Falcon) adapters.
 */
ef_vi_inline void ef_vi_receive_set_buffer_len(ef_vi* vi, unsigned buf_len)
{
  vi->rx_buffer_len = buf_len;
}


/*! \brief Returns the amount of free space in the RX descriptor ring.
**
** \param vi The virtual interface to query.
**
** \return The amount of free space in the RX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the amount of free space in the RX descriptor ring. This is the
** number of slots that are available for pushing a new descriptor (and an
** associated unfilled packet buffer).
*/
ef_vi_inline int ef_vi_receive_space(ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  return vi->vi_rxq.mask - (qs->added - qs->removed);
}


/*! \brief Returns the fill level of the RX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The fill level of the RX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the fill level of the RX descriptor ring. This is the number of
** slots that hold a descriptor (and an associated unfilled packet buffer).
** The fill level should be kept as high as possible, so there are enough
** slots available to handle a burst of incoming packets.
*/
ef_vi_inline int ef_vi_receive_fill_level(ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  return qs->added - qs->removed;
}


/*! \brief Returns the total capacity of the RX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The total capacity of the RX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the total capacity of the RX descriptor ring.
*/
ef_vi_inline int ef_vi_receive_capacity(ef_vi* vi)
{
  return vi->vi_rxq.mask;
}


/*! \brief Initialize an RX descriptor on the RX descriptor ring
**
** \param vi     The virtual interface for which to initialize an RX
**               descriptor.
** \param addr   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code.
**
** Initialize an RX descriptor on the RX descriptor ring, and prepare the
** associated packet buffer (identified by its DMA address) to receive
** packets. This function only writes a few bytes into host memory, and is
** very fast.
*/
#define ef_vi_receive_init(vi, addr, dma_id)            \
  (vi)->ops.receive_init((vi), (addr), (dma_id))


/*! \brief Submit newly initialized RX descriptors to the NIC
**
** \param vi The virtual interface for which to push descriptors.
**
** \return None.
**
** Submit newly initialized RX descriptors to the NIC. The NIC can then
** receive packets into the associated packet buffers.
**
** For Solarflare 7000-series NICs, this function submits RX descriptors
** only in multiples of 8. This is to conform with hardware requirements.
** If the number of newly initialized RX descriptors is not exactly
** divisible by 8, this function does not submit any remaining descriptors
** (up to 7 of them).
*/
#define ef_vi_receive_push(vi) (vi)->ops.receive_push((vi))


/*! \brief Initialize an RX descriptor on the RX descriptor ring, and
**         submit it to the NIC
**
** \param vi     The virtual interface for which to initialize and push an
**               RX descriptor.
** \param addr   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code.
**
** Initialize an RX descriptor on the RX descriptor ring, and submit it to
** the NIC. The NIC can then receive a packet into the associated packet
** buffer.
**
** This function simply wraps ef_vi_receive_init() and
** ef_vi_receive_push(). It is provided as a convenience, but is less
** efficient than submitting the descriptors in batches by calling the
** functions separately.
**
** Note that for Solarflare 7000-series NICs, this function submits RX
** descriptors only in multiples of 8. This is to conform with hardware
** requirements. If the number of newly initialized RX descriptors is not
** exactly divisible by 8, this function does not submit any remaining
** descriptors (including, potentially, the RX descriptor initialized in
** this call).
*/
extern int ef_vi_receive_post(ef_vi* vi, ef_addr addr, ef_request_id dma_id);


/*! \brief _Deprecated:_ use ef_vi_receive_get_timestamp_with_sync_flags()
** instead.
**
** \param vi     The virtual interface that received the packet.
** \param pkt    The received packet.
** \param ts_out Pointer to a timespec, that is updated on return with the
**               UTC timestamp for the packet.
**
** \return 0 on success, or a negative error code.
**
** _This function is now deprecated._ Use
** ef_vi_receive_get_timestamp_with_sync_flags() instead.
**
** Retrieve the UTC timestamp associated with a received packet.
**
** This function must be called after retrieving the associated RX event
** via ef_eventq_poll(), and before calling ef_eventq_poll() again.
**
** If the virtual interface does not have RX timestamps enabled, the
** behavior of this function is undefined.
*/
extern int ef_vi_receive_get_timestamp(ef_vi* vi, const void* pkt,
                                       struct timespec* ts_out);


/*! \brief Retrieve the UTC timestamp associated with a received packet,
**         and the clock sync status flags
**
** \param vi        The virtual interface that received the packet.
** \param pkt       The first packet buffer for the received packet.
** \param ts_out    Pointer to a timepsec, that is updated on return with
**                  the UTC timestamp for the packet.
** \param flags_out Pointer to an unsigned, that is updated on return with
**                  the sync flags for the packet.
**
** \return 0 on success, or a negative error code:\n
**         - ENOMSG - Synchronisation with adapter has not yet been
**           achieved.\n
**           This only happens with old firmware.\n
**         - ENODATA - Packet does not have a timestamp.\n
**           On current Solarflare adapters, packets that are switched from
**           TX to RX do not get timestamped.\n
**         - EL2NSYNC - Synchronisation with adapter has been lost.\n
**           This should never happen!
**
** Retrieve the UTC timestamp associated with a received packet, and the
** clock sync status flags.
**
** This function:
** - must be called after retrieving the associated RX event via
**   ef_eventq_poll(), and before calling ef_eventq_poll() again
** - must only be called for the first segment of a jumbo packet
** - must not be called for any events other than RX.
**
** If the virtual interface does not have RX timestamps enabled, the
** behavior of this function is undefined.
**
** This function will also fail if the virtual interface has not yet
** synchronized with the adapter clock. This can take from a few hundred
** milliseconds up to several seconds from when the virtual interface is
** allocated.
**
** On success the ts_out and flags_out fields are updated, and a value of
** zero is returned. The flags_out field contains the following flags:
** - EF_VI_SYNC_FLAG_CLOCK_SET is set if the adapter clock has ever been
**   set (in sync with system)
** - EF_VI_SYNC_FLAG_CLOCK_IN_SYNC is set if the adapter clock is in sync
**   with the external clock (PTP).
**
** In case of error the timestamp result (*ts_out) is set to zero, and a
** non-zero error code is returned (see Return value above).
*/
extern int
ef_vi_receive_get_timestamp_with_sync_flags(ef_vi* vi, const void* pkt,
                                            struct timespec* ts_out,
                                            unsigned* flags_out);


/**********************************************************************
 * Transmit interface *************************************************
 **********************************************************************/

/*! \brief Returns the amount of free space in the TX descriptor ring.
**
** \param vi The virtual interface to query.
**
** \return The amount of free space in the TX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the amount of free space in the TX descriptor ring. This is the
** number of slots that are available for pushing a new descriptor (and an
** associated filled packet buffer).
*/
ef_vi_inline int ef_vi_transmit_space(ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return vi->vi_txq.mask - (qs->added - qs->removed);
}


/*! \brief Returns the fill level of the TX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The fill level of the TX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the fill level of the TX descriptor ring. This is the number of
** slots that hold a descriptor (and an associated filled packet buffer).
** The fill level should be low or 0, unless a large number of packets have
** recently been posted for transmission. A consistently high fill level
** should be investigated.
*/
ef_vi_inline int ef_vi_transmit_fill_level(ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return qs->added - qs->removed;
}


/*! \brief Returns the total capacity of the TX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The total capacity of the TX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the total capacity of the TX descriptor ring.
*/
ef_vi_inline int ef_vi_transmit_capacity(ef_vi* vi)
{
  return vi->vi_txq.mask;
}


/*! \brief Initialize a TX descriptor on the TX descriptor ring, for a
**         single packet buffer
**
** \param vi     The virtual interface for which to initialize a TX
**               descriptor.
** \param addr   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param bytes  The size of the packet to transmit.
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Initialize a TX descriptor on the TX descriptor ring, for a single
** packet buffer. The associated packet buffer (identified by its DMA
** address) must contain the packet to transmit. This function only writes
** a few bytes into host memory, and is very fast.
*/
extern int ef_vi_transmit_init(ef_vi* vi, ef_addr addr, int bytes,
                               ef_request_id dma_id);


/*! \brief Initialize TX descriptors on the TX descriptor ring, for a
**         vector of packet buffers
**
** \param vi      The virtual interface for which to initialize a TX
**                descriptor.
** \param iov     Start of the iovec array describing the packet buffers.
** \param iov_len Length of the iovec array.
** \param dma_id  DMA id to associate with the descriptor. This is
**                completely arbitrary, and can be used for subsequent
**                tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Initialize TX descriptors on the TX descriptor ring, for a vector of
** packet buffers. The associated packet buffers (identified in the iov
** vector) must contain the packet to transmit. This function only writes a
** few bytes into host memory, and is very fast.
**
** Building a packet by concatenating a vector of buffers allows:
** - sending a packet that is larger than a packet buffer
**   - the packet is split across multiple buffers in a vector
** - optimizing sending packets with only small differences:
**   - the packet is split into those parts that are constant, and those
**     that vary between transmits
**   - each part is written into its own buffer
**   - after each transmit, the buffers containing varying data must be
**     updated, but the buffers containing constant data are re-used
**   - this minimizes the amount of data written between transmits.
*/
#define ef_vi_transmitv_init(vi, iov, iov_len, dma_id)          \
  (vi)->ops.transmitv_init((vi), (iov), (iov_len), (dma_id))


/*! \brief Submit newly initialized TX descriptors to the NIC
**
** \param vi The virtual interface for which to push descriptors.
**
** \return None.
**
** Submit newly initialized TX descriptors to the NIC. The NIC can then
** transmit packets from the associated packet buffers.
**
** This may be called at most once after TX descriptors have been
** initialized using ef_vi_transmit_init() or ef_vi_transmitv_init().
*/
#define ef_vi_transmit_push(vi) (vi)->ops.transmit_push((vi))


/*! \brief Transmit a packet from a single packet buffer
**
** \param vi     The virtual interface for which to initialize and push a
**               TX descriptor.
** \param base   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param len    The size of the packet to transmit.
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet from a single packet buffer. This Initializes a TX
** descriptor on the TX descriptor ring, and submits it to the NIC. The NIC
** can then transmit a packet from the associated packet buffer.
**
** This function simply wraps ef_vi_transmit_init() and
** ef_vi_transmit_push(). It is provided as a convenience. It is less
** efficient than submitting the descriptors in batches by calling the
** functions separately, but unless there is a batch of packets to
** transmit, calling this function is often the right thing to do.
*/
#define ef_vi_transmit(vi, base, len, dma_id)           \
  (vi)->ops.transmit((vi), (base), (len), (dma_id))


/*! \brief Transmit a packet from a vector of packet buffers
**
** \param vi      The virtual interface for which to initialize a TX
**                descriptor.
** \param iov     Start of the iovec array describing the packet buffers.
** \param iov_len Length of the iovec array.
** \param dma_id  DMA id to associate with the descriptor. This is
**                completely arbitrary, and can be used for subsequent
**                tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet from a vector of packet buffers. This initializes a TX
** descriptor on the TX descriptor ring, and submits it to the NIC. The NIC
** can then transmit a packet from the associated packet buffers.
**
** This function simply wraps ef_vi_transmitv_init() and
** ef_vi_transmit_push(). It is provided as a convenience. It is less
** efficient than submitting the descriptors in batches by calling the
** functions separately, but unless there is a batch of packets to
** transmit, calling this function is often the right thing to do.
**
** Building a packet by concatenating a vector of buffers allows:
** - sending a packet that is larger than a packet buffer
**   - the packet is split across multiple buffers in a vector
** - optimizing sending packets with only small differences:
**   - the packet is split into those parts that are constant, and those
**     that vary between transmits
**   - each part is written into its own buffer
**   - after each transmit, the buffers containing varying data must be
**     updated, but the buffers containing constant data are re-used
**   - this minimizes the amount of data written between transmits.
*/
#define ef_vi_transmitv(vi, iov, iov_len, dma_id)       \
  (vi)->ops.transmitv((vi), (iov), (iov_len), (dma_id))


/*! \brief Transmit a packet already resident in Programmed I/O
**
** \param vi     The virtual interface from which to transmit.
** \param offset The offset within its Programmed I/O region to the start
**               of the packet. This must be aligned to at least a 16-byte
**               boundary.
** \param len    Length of the packet to transmit. This must be at a
**               multiple of 16 bytes.
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet already resident in Programmed I/O.
**
** The Programmed I/O region used by this call must not be reused until an
** event indicating TX completion is handled (see \ref using_transmit), thus
** completing the transmit operation for the packet. Failure to do so might
** corrupt an ongoing transmit.
**
** The Programmed I/O region can hold multiple packets, referenced by
** different offset parameters. All other constraints must still be
** observed, including:
** - alignment
** - minimum size
** - maximum size
** - avoiding reuse until transmission is complete.
*/
#define ef_vi_transmit_pio(vi, offset, len, dma_id)             \
  (vi)->ops.transmit_pio((vi), (offset), (len), (dma_id))


/*! \brief Transmit a packet by copying it into the Programmed I/O region
**
** \param vi         The virtual interface from which to transmit.
** \param pio_offset The offset within its Programmed I/O region to the
**                   start of the packet. This must be aligned to at least
**                   a 16-byte boundary.
** \param src_buf    The source buffer from which to read the packet.
** \param len        Length of the packet to transmit. This must be at
**                   least 16 bytes.
** \param dma_id     DMA id to associate with the descriptor. This is
**                   completely arbitrary, and can be used for subsequent
**                   tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet by copying it into the Programmed I/O region.
**
** The src_buf parameter must point at a complete packet that is copied to
** the adapter and transmitted. The source buffer need not be registered,
** and is available for re-use immediately after this call returns.
**
** This call does not copy the packet data into the local copy of the
** adapter's Programmed I/O buffer. As a result it is slightly faster than
** calling ef_pio_memcpy() followed by ef_vi_transmit_pio().
**
** The Programmed I/O region used by this call must not be reused until an
** event indicating TX completion is handled (see \ref using_transmit), thus
** completing the transmit operation for the packet. Failure to do so might
** corrupt an ongoing transmit.
**
** The Programmed I/O region can hold multiple smaller packets, referenced
** by different offset parameters. All other constraints must still be
** observed, including:
** - alignment
** - minimum size
** - maximum size
** - avoiding reuse until transmission is complete.
*/
#define ef_vi_transmit_copy_pio(vi, pio_offset, src_buf, len, dma_id)	\
  (vi)->ops.transmit_copy_pio((vi), (pio_offset), (src_buf),            \
                              (len), (dma_id))


/*! \brief Maximum number of transmit completions per transmit event. */
#define EF_VI_TRANSMIT_BATCH  64


/*! \brief Unbundle an event of type of type EF_EVENT_TYPE_TX or
**         EF_EVENT_TYPE_TX_ERROR
**
** \param ep    The virtual interface that has raised the event.
** \param event The event, of type EF_EVENT_TYPE_TX or
**              EF_EVENT_TYPE_TX_ERROR
** \param ids   Array of size EF_VI_TRANSMIT_BATCH, that is updated on
**              return with the DMA ids that were used in the originating
**              ef_vi_transmit_*() calls.
**
** \return The number of valid ef_request_ids (can be zero).
**
** Unbundle an event of type of type EF_EVENT_TYPE_TX or
** EF_EVENT_TYPE_TX_ERROR.
**
** The NIC might coalesce multiple packet transmissions into a single TX
** event in the event queue. This function returns the number of descriptors
** whose transmission has completed, and updates the ids array with the
** ef_request_ids for each completed DMA request.
**
** After calling this function, the TX descriptors for the completed TX
** event are ready to be re-initialized. The associated packet buffers are
** no longer in use by ef_vi. Each buffer can then be freed, or can be
** re-used (for example as a packet buffer for a descriptor on the TX ring,
** or on the RX ring).
*/
extern int ef_vi_transmit_unbundle(ef_vi* ep, const ef_event* event,
                                   ef_request_id* ids);


/*! \brief Set the threshold at which to switch from using TX descriptor
**         push to using a doorbell
**
** \param vi        The virtual interface for which to set the threshold.
** \param threshold The threshold to set, as the number of outstanding
**                  transmits at which to switch.
**
** \return 0 on success, or a negative error code.
**
** Set the threshold at which to switch from using TX descriptor push to
** using a doorbell. TX descriptor push has better latency, but a doorbell
** is more efficient.
**
** The default value for this is controlled using the EF_VI_TX_PUSH_DISABLE
** and EF_VI_TX_PUSH_ALWAYS flags to ef_vi_init().
**
** This is not supported by all Solarflare NICs. At the time of writing,
** 7000-series NICs support this, but it is ignored by earlier NICs.
*/
extern void ef_vi_set_tx_push_threshold(ef_vi* vi, unsigned threshold);


/**********************************************************************
 * Eventq interface ***************************************************
 **********************************************************************/

/*! \brief Returns true if ef_eventq_poll() will return event(s)
**
** \param vi The virtual interface to query.
**
** \return True if ef_eventq_poll() will return event(s).
**
** Returns true if ef_eventq_poll() will return event(s).
*/
extern int ef_eventq_has_event(ef_vi* vi);


/*! \brief Returns true if there are a given number of events in the event
**         queue.
**
** \param evq      The event queue to query.
** \param n_events Number of events to check.
**
** \return True if the event queue contains at least `n_events` events.
**
** Returns true if there are a given number of events in the event queue.
**
** This looks ahead in the event queue, so has the property that it will
** not ping-pong a cache-line when it is called concurrently with events
** being delivered.
**
** This function returns quickly. It is useful for an application to
** determine whether it is falling behind in its event processing.
*/
extern int ef_eventq_has_many_events(ef_vi* evq, int n_events);


/*! \brief Prime a virtual interface allowing you to go to sleep blocking
**         on it
**
** \param vi The virtual interface to prime.
**
** \return None.
**
** Prime a virtual interface allowing you to go to sleep blocking on it.
*/
#define ef_eventq_prime(vi) (vi)->ops.eventq_prime((vi))


/*! \brief Poll an event queue
**
** \param evq     The event queue to poll.
** \param evs     Array in which to return polled events.
** \param evs_len Length of the evs array, must be >=
**                EF_VI_EVENT_POLL_MIN_EVS.
**
** \return The number of events retrieved.
**
** Poll an event queue. Any events that have been raised are added to the
** given array. Most events correspond to packets arriving, or packet
** transmission completing. This function is critical to latency, and must
** be called as often as possible.
**
** This function returns immediately, even if there are no outstanding
** events. The array might not be full on return.
*/
#define ef_eventq_poll(evq, evs, evs_len)               \
  (evq)->ops.eventq_poll((evq), (evs), (evs_len))


/*! \brief Returns the capacity of an event queue
**
** \param vi The event queue to query.
**
** \return The capacity of an event queue.
**
** Returns the capacity of an event queue.
*/
ef_vi_inline int ef_eventq_capacity(ef_vi* vi)
{
  return (vi->evq_mask + 1u) / 8;
}


/*! \brief Get the current offset into the event queue.
**
** \param evq The event queue to query.
**
** \return The current offset into the eventq.
**
** Get the current offset into the event queue.
*/
ef_vi_inline unsigned ef_eventq_current(ef_vi* evq)
{
  return (unsigned) evq->ep_state->evq.evq_ptr;
}


/**********************************************************************
 * ef_vi layout *******************************************************
 **********************************************************************/

/*! \brief Types of layout that are used for receive buffers. */
enum ef_vi_layout_type {
  /** An Ethernet frameo */
  EF_VI_LAYOUT_FRAME,
  /** Hardware timestamp (minor ticks) */
  EF_VI_LAYOUT_MINOR_TICKS,
};


/*! \brief Layout of the data that is delivered into receive buffers. */
typedef struct {
  /** The type of layout */
  enum ef_vi_layout_type   evle_type;
  /** Offset to the data */
  int                      evle_offset;
  /** Description of the layout */
  const char*              evle_description;
} ef_vi_layout_entry;


/*! \brief Gets the layout of the data that the adapter delivers into
**         receive buffers
**
** \param vi             The virtual interface to query.
** \param layout_out     Pointer to an ef_vi_layout_entry*, that is updated
**                       on return with a reference to the layout table.
** \param layout_len_out Pointer to an int, that is updated on return with
**                       the length of the layout table.
**
** \return 0 on success, or a negative error code.
**
** Gets the layout of the data that the adapter delivers into receive
** buffers. Depending on the adapter type and options selected, there can
** be a meta-data prefix in front of each packet delivered into memory.
**
** The first entry is always of type EF_VI_LAYOUT_FRAME, and the offset is
** the same as the value returned by ef_vi_receive_prefix_len().
*/
extern int
ef_vi_receive_query_layout(ef_vi* vi,
                           const ef_vi_layout_entry**const layout_out,
                           int* layout_len_out);

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_EF_VI_H__ */
