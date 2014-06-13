/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
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

/*
 *  \brief  Virtual Interface
 *   \date  2007/05/16
 */
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
# else
#  include <stdint.h>
#  include <inttypes.h>
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

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * Types **************************************************************
 **********************************************************************/

typedef uint32_t                ef_eventq_ptr;

typedef uint64_t                ef_addr;
typedef char*                   ef_vi_ioaddr_t;


/**********************************************************************
 * Dimensions *********************************************************
 **********************************************************************/

#define EF_VI_MAX_QS              32
#define EF_VI_EVENT_POLL_MIN_EVS  2


/**********************************************************************
 * ef_event ***********************************************************
 **********************************************************************/

/*! \i_ef_vi A DMA request identifier.
**
** This is an integer token specified by the transport and associated
** with a DMA request.  It is returned to the VI user with DMA completion
** events.  It is typically used to identify the buffer associated with
** the transfer.
*/
typedef int			ef_request_id;

typedef union {
	uint64_t  u64[1];
	uint32_t  u32[2];
	uint16_t  u16[4];
} ef_vi_qword;


#define EF_REQUEST_ID_MASK      0xffffffff


/*! \i_ef_event An [ef_event] is a token that identifies something that
** has happened.  Examples include packets received, packets transmitted
** and errors.
*/
typedef union {
	struct {
		unsigned       type       :16;
	} generic;
	struct {
		unsigned       type       :16;
		unsigned       q_id       :16;
		unsigned       rq_id      :32;
		unsigned       len        :16;
		unsigned       flags      :16;
	} rx;
	struct {  /* This *must* have same initial layout as [rx]. */
		unsigned       type       :16;
		unsigned       q_id       :16;
		unsigned       rq_id      :32;
		unsigned       len        :16;
		unsigned       flags      :16;
		unsigned       subtype    :16;
	} rx_discard;
	struct {
		unsigned       type       :16;
		unsigned       q_id       :16;
		unsigned       desc_id    :16;
	} tx;
	struct {  /* This *must* have same layout as [tx]. */
		unsigned       type       :16;
		unsigned       q_id       :16;
		unsigned       desc_id    :16;
		unsigned       subtype    :16;
	} tx_error;
	struct {
		unsigned       type       :16;
		unsigned       q_id       :16;
	} rx_no_desc_trunc;
	struct {
		unsigned       type       :16;
		unsigned       data;
	} sw;
} ef_event;


#define EF_EVENT_TYPE(e)        ((e).generic.type)
enum {
	/** Good data was received. */
	EF_EVENT_TYPE_RX,
	/** Packets have been sent. */
	EF_EVENT_TYPE_TX,
	/** Data received and buffer consumed, but something is wrong. */
	EF_EVENT_TYPE_RX_DISCARD,
	/** Transmit of packet failed. */
	EF_EVENT_TYPE_TX_ERROR,
	/** Received packet was truncated due to lack of descriptors. */
	EF_EVENT_TYPE_RX_NO_DESC_TRUNC,
	/** Software generated event. */
	EF_EVENT_TYPE_SW,
	/** Event queue overflow. */
	EF_EVENT_TYPE_OFLOW,
};

#define EF_EVENT_RX_BYTES(e)    ((e).rx.len)
#define EF_EVENT_RX_Q_ID(e)     ((e).rx.q_id)
#define EF_EVENT_RX_RQ_ID(e)    ((e).rx.rq_id)
#define EF_EVENT_RX_CONT(e)     ((e).rx.flags & EF_EVENT_FLAG_CONT)
#define EF_EVENT_RX_SOP(e)      ((e).rx.flags & EF_EVENT_FLAG_SOP)
#define EF_EVENT_RX_ISCSI_OKAY(e) ((e).rx.flags & EF_EVENT_FLAG_ISCSI_OK)
#define EF_EVENT_FLAG_SOP       0x1
#define EF_EVENT_FLAG_CONT      0x2
#define EF_EVENT_FLAG_ISCSI_OK  0x4
#define EF_EVENT_FLAG_MULTICAST 0x8

#define EF_EVENT_TX_Q_ID(e)     ((e).tx.q_id)

#define EF_EVENT_RX_DISCARD_Q_ID(e)  ((e).rx_discard.q_id)
#define EF_EVENT_RX_DISCARD_RQ_ID(e) ((e).rx_discard.rq_id)
#define EF_EVENT_RX_DISCARD_CONT(e)  ((e).rx_discard.flags&EF_EVENT_FLAG_CONT)
#define EF_EVENT_RX_DISCARD_SOP(e)   ((e).rx_discard.flags&EF_EVENT_FLAG_SOP)
#define EF_EVENT_RX_DISCARD_TYPE(e)  ((e).rx_discard.subtype)
#define EF_EVENT_RX_DISCARD_BYTES(e) ((e).rx_discard.len)
enum {
	EF_EVENT_RX_DISCARD_CSUM_BAD,
	EF_EVENT_RX_DISCARD_MCAST_MISMATCH,
	EF_EVENT_RX_DISCARD_CRC_BAD,
	EF_EVENT_RX_DISCARD_TRUNC,
	EF_EVENT_RX_DISCARD_RIGHTS,
	EF_EVENT_RX_DISCARD_EV_ERROR,
	EF_EVENT_RX_DISCARD_OTHER,
};

#define EF_EVENT_TX_ERROR_Q_ID(e)    ((e).tx_error.q_id)
#define EF_EVENT_TX_ERROR_TYPE(e)    ((e).tx_error.subtype)
enum {
	EF_EVENT_TX_ERROR_RIGHTS,
	EF_EVENT_TX_ERROR_OFLOW,
	EF_EVENT_TX_ERROR_2BIG,
	EF_EVENT_TX_ERROR_BUS,
};

#define EF_EVENT_RX_NO_DESC_TRUNC_Q_ID(e)  ((e).rx_no_desc_trunc.q_id)

#define EF_EVENT_SW_DATA_MASK   0xffff
#define EF_EVENT_SW_DATA(e)     ((e).sw.data)

#define EF_EVENT_FMT            "[ev:%x]"
#define EF_EVENT_PRI_ARG(e)     (unsigned) (e).generic.type


/* ***************** */

typedef struct {
	ef_eventq_ptr	   evq_ptr;
} ef_eventq_state;


/*! \i_ef_base [ef_iovec] is similar the standard [struct iovec].  An
** array of these is used to designate a scatter/gather list of I/O
** buffers.
*/
typedef struct {
	ef_addr                       iov_base EF_VI_ALIGN(8);
	unsigned                      iov_len;
} ef_iovec;

/* Falcon constants */
#define TX_EV_DESC_PTR_LBN 0


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

enum ef_vi_flags {
	EF_VI_FLAGS_DEFAULT     = 0x0,
	EF_VI_ISCSI_RX_HDIG     = 0x2,
	EF_VI_ISCSI_TX_HDIG     = 0x4,
	EF_VI_ISCSI_RX_DDIG     = 0x8,
	EF_VI_ISCSI_TX_DDIG     = 0x10,
	EF_VI_TX_PHYS_ADDR      = 0x20,
	EF_VI_RX_PHYS_ADDR      = 0x40,
	EF_VI_TX_IP_CSUM_DIS    = 0x80,
	EF_VI_TX_TCPUDP_CSUM_DIS= 0x100,
	EF_VI_TX_TCPUDP_ONLY    = 0x200,
	EF_VI_TX_FILTER_IP      = 0x400,              /* Siena only */
	EF_VI_TX_FILTER_MAC     = 0x800,              /* Siena only */
	EF_VI_TX_FILTER_MASK_1  = 0x1000,             /* Siena only */
	EF_VI_TX_FILTER_MASK_2  = 0x2000,             /* Siena only */
	EF_VI_TX_FILTER_MASK_3  = (0x1000 | 0x2000),  /* Siena only */
	EF_VI_TX_PUSH_DISABLE   = 0x4000,
};

typedef struct {
	uint32_t  added;
	uint32_t  removed;
} ef_vi_txq_state;

typedef struct {
	uint32_t  added;
	uint32_t  removed;
} ef_vi_rxq_state;

typedef struct {
	uint32_t         mask;
	void*            doorbell;
	void*            descriptors;
	uint32_t*        ids;
} ef_vi_txq;

typedef struct {
	uint32_t         mask;
	void*            doorbell;
	void*            descriptors;
	uint32_t*        ids;
} ef_vi_rxq;

typedef struct {
	ef_eventq_state  evq;
	ef_vi_txq_state  txq;
	ef_vi_rxq_state  rxq;
	/* Followed by request id fifos. */
} ef_vi_state;

typedef struct {
	uint32_t	rx_ev_lost;
	uint32_t	rx_ev_bad_desc_i;
	uint32_t	rx_ev_bad_q_label;
	uint32_t	evq_gap;
} ef_vi_stats;

enum ef_vi_arch {
	EF_VI_ARCH_FALCON,
};

struct ef_vi_nic_type {
	unsigned char  arch;
	char           variant;
	unsigned char  revision;
};

/*! \i_ef_vi  A virtual interface.
**
** An [ef_vi] represents a virtual interface on a specific NIC.  A
** virtual interface is a collection of an event queue and two DMA queues
** used to pass Ethernet frames between the transport implementation and
** the network.
*/
typedef struct ef_vi {
	unsigned                      vi_resource_id;
	unsigned                      vi_i;

	char*				vi_mem_mmap_ptr;
	int                           vi_mem_mmap_bytes;
	char*				vi_io_mmap_ptr;
	int                           vi_io_mmap_bytes;

	ef_eventq_state*              evq_state;
	char*                         evq_base;
	unsigned                      evq_mask;
	ef_vi_ioaddr_t                evq_timer_reg;
	unsigned                      timer_quantum_ns;
	ef_vi_ioaddr_t                evq_prime;

	ef_vi_txq                     vi_txq;
	ef_vi_rxq                     vi_rxq;
	ef_vi_state*                  ep_state;
	enum ef_vi_flags              vi_flags;
	ef_vi_stats*		      vi_stats;

	struct ef_vi*		      vi_qs[EF_VI_MAX_QS];
	int                           vi_qs_n;

	struct ef_vi_nic_type	      nic_type;
} ef_vi;


/* This structure is opaque to the client & used to pass mapping data
 * from the resource manager to the ef_vi lib. for ef_vi_init().
 */
struct vi_mappings {
	uint32_t         signature;
# define VI_MAPPING_VERSION   0x02  /*Byte: Increment me if struct altered*/
# define VI_MAPPING_SIGNATURE (0xBA1150 + VI_MAPPING_VERSION)

	struct ef_vi_nic_type nic_type;

	int              vi_instance;

	unsigned         evq_bytes;
	char*            evq_base;
	ef_vi_ioaddr_t   evq_timer_reg;
	unsigned         timer_quantum_ns;

	unsigned         rx_queue_capacity;
	ef_vi_ioaddr_t   rx_dma_ef1;
	char*            rx_dma_falcon;
	ef_vi_ioaddr_t   rx_bell;

	unsigned         tx_queue_capacity;
	ef_vi_ioaddr_t   tx_dma_ef1;
	char*            tx_dma_falcon;
	ef_vi_ioaddr_t   tx_bell;

	ef_vi_ioaddr_t   evq_prime;
};
/* This is used by clients to allocate a suitably sized buffer for the 
 * resource manager to fill & ef_vi_init() to use. */
#define VI_MAPPINGS_SIZE (sizeof(struct vi_mappings))


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

/* Initialise [data_area] with information required to initialise an ef_vi.
 * In the following, an unused param should be set to NULL. Note the case
 * marked (*) of [iobuf_mmap] for falcon/driver; for normal driver this
 * must be NULL.
 *
 * \param  data_area     [in,out] required, must ref at least VI_MAPPINGS_SIZE 
 *                                bytes
 * \param  evq_capacity  [in] number of events in event queue.  Specify 0 for
 *                            no event queue.
 * \param  rxq_capacity  [in] number of descriptors in RX DMA queue.  Specify
 *                            0 for no RX queue.
 * \param  txq_capacity  [in] number of descriptors in TX DMA queue.  Specify
 *                            0 for no TX queue.
 * \param  mmap_info     [in] mem-map info for resource
 * \param  io_mmap       [in] ef1,    required
 *                            falcon, required
 * \param  iobuf_mmap    [in] ef1,    UL: unused
 *                            falcon, UL: required
 */
extern void ef_vi_init_mapping_vi(void* data_area, struct ef_vi_nic_type,
                                  unsigned rxq_capacity,
                                  unsigned txq_capacity, int instance,
                                  void* io_mmap, void* iobuf_mmap_rx,
                                  void* iobuf_mmap_tx, enum ef_vi_flags);


extern void ef_vi_init_mapping_evq(void* data_area, struct ef_vi_nic_type,
                                   int instance, void* io_mmap,
				   unsigned evq_bytes, void* base,
				   void* timer_reg, unsigned timer_quantum_ns);

ef_vi_inline unsigned ef_vi_resource_id(ef_vi* vi)
{ 
	return vi->vi_resource_id; 
}

ef_vi_inline enum ef_vi_flags ef_vi_flags(ef_vi* vi)
{ 
	return vi->vi_flags; 
}


/**********************************************************************
 * Receive interface **************************************************
 **********************************************************************/

/*! \i_ef_vi Returns the length of the prefix at the start of a received
** packet.
**
** The NIC may be configured to deliver meta-data in a prefix before the
** packet payload data.  This call returns the size of the prefix.
**
** When a large packet is received that is scattered over multiple packet
** buffers, the prefix is only present in the first buffer.
*/
extern int ef_vi_receive_prefix_len(ef_vi* vi);


/*! \i_ef_vi Returns the amount of space in the RX descriptor ring.
**
** \return the amount of space in the queue.
*/
ef_vi_inline int ef_vi_receive_space(ef_vi* vi) 
{
	ef_vi_rxq_state* qs = &vi->ep_state->rxq;
	return vi->vi_rxq.mask - (qs->added - qs->removed);
}


/*! \i_ef_vi Returns the fill level of the RX descriptor ring.
**
** \return the fill level of the queue.
*/
ef_vi_inline int ef_vi_receive_fill_level(ef_vi* vi) 
{
	ef_vi_rxq_state* qs = &vi->ep_state->rxq;
	return qs->added - qs->removed;
}


ef_vi_inline int ef_vi_receive_capacity(ef_vi* vi)
{ 
	return vi->vi_rxq.mask;
}


/*! \i_ef_vi  Form a receive descriptor. */
extern int ef_vi_receive_init(ef_vi* vi, ef_addr addr, ef_request_id dma_id);

/*! \i_ef_vi  Submit initialised receive descriptors to the NIC. */
extern void ef_vi_receive_push(ef_vi* vi);

/*! \i_ef_vi  Post a buffer on the receive queue.
**
**   \return 0 on success, or -EAGAIN if the receive queue is full
*/
extern int ef_vi_receive_post(ef_vi*, ef_addr addr,
			      ef_request_id dma_id);

/**********************************************************************
 * Transmit interface *************************************************
 **********************************************************************/

/*! \i_ef_vi Return the amount of space (in descriptors) in the transmit
**           queue.
**
** \return the amount of space in the queue (in descriptors)
*/
ef_vi_inline int ef_vi_transmit_space(ef_vi* vi) 
{
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	return vi->vi_txq.mask - (qs->added - qs->removed);
}


/*! \i_ef_vi Returns the fill level of the TX descriptor ring.
**
** \return the fill level of the queue.
*/
ef_vi_inline int ef_vi_transmit_fill_level(ef_vi* vi)
{
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	return qs->added - qs->removed;
}


/*! \i_ef_vi Returns the total capacity of the TX descriptor ring.
**
** \return the capacity of the queue.
*/
ef_vi_inline int ef_vi_transmit_capacity(ef_vi* vi)
{ 
	return vi->vi_txq.mask;
}


/*! \i_ef_vi  Transmit a packet.
**
**   \return -EAGAIN if the transmit queue is full, or 0 on success
*/
extern int ef_vi_transmit(ef_vi*, ef_addr, int bytes, ef_request_id dma_id);

/*! \i_ef_vi  Transmit a packet using a gather list.
**
**   \param iov_len must be greater than zero
**   \param iov the first must be non-zero in length (but others need not)
**
**   \return -EAGAIN if the queue is full, or 0 on success
*/
extern int ef_vi_transmitv(ef_vi*, const ef_iovec* iov, int iov_len,
                           ef_request_id dma_id);

/*! \i_ef_vi  Initialise a DMA request.
**
** \return -EAGAIN if the queue is full, or 0 on success
*/
extern int ef_vi_transmit_init(ef_vi*, ef_addr, int bytes,
                               ef_request_id dma_id);

/*! \i_ef_vi  Initialise a DMA request.
**
** \return -EAGAIN if the queue is full, or 0 on success
*/
extern int ef_vi_transmitv_init(ef_vi*, const ef_iovec*, int iov_len,
                                ef_request_id dma_id);

/*! \i_ef_vi  Submit DMA requests to the NIC.
**
** The DMA requests must have been initialised using
** ef_vi_transmit_init() or ef_vi_transmitv_init().
*/
extern void ef_vi_transmit_push(ef_vi*);


/*! \i_ef_vi Maximum number of transmit completions per transmit event. */
#define EF_VI_TRANSMIT_BATCH  64

/*! \i_ef_vi Determine the set of [ef_request_id]s for each DMA request
**           which has been completed by a given transmit completion
**           event.
**
** \param ids must point to an array of length EF_VI_TRANSMIT_BATCH
** \return the number of valid [ef_request_id]s (can be zero)
*/
extern int ef_vi_transmit_unbundle(ef_vi* ep, const ef_event*,
                                   ef_request_id* ids);


/*! \i_ef_event Returns true if ef_eventq_poll() will return event(s). */
extern int ef_eventq_has_event(ef_vi* vi);

/*! \i_ef_event Returns true if there are quite a few events in the event
** queue.
**
** This looks ahead in the event queue, so has the property that it will
** not ping-pong a cache-line when it is called concurrently with events
** being delivered.
*/
extern int ef_eventq_has_many_events(ef_vi* evq, int look_ahead);

extern void ef_eventq_prime(ef_vi* vi);

/*! \i_ef_event Retrieve event notifications from the event queue.
**
** \return The number of events retrieved.
**
** [evs_len] must be >= EF_VI_EVENT_POLL_MIN_EVS.
*/
extern int ef_eventq_poll(ef_vi* evq, ef_event* evs, int evs_len);

/*! \i_ef_event Returns the capacity of an event queue. */
ef_vi_inline int ef_eventq_capacity(ef_vi* vi) 
{
	return (vi->evq_mask + 1u) / 8;
}

ef_vi_inline unsigned ef_eventq_current(ef_vi* evq)
{
	return (unsigned) evq->evq_state->evq_ptr;
}

/* Returns the instance ID of [vi] */
ef_vi_inline unsigned ef_vi_instance(ef_vi* vi)
{ return vi->vi_i; }


/**********************************************************************
 * Initialisation *****************************************************
 **********************************************************************/

/*! Return size of state buffer of an initialised VI. */
extern int ef_vi_state_bytes(ef_vi*);

/*! Return size of buffer needed for VI state given sizes of RX and TX
** DMA queues.  Queue sizes must be legal sizes (power of 2), or 0 (no
** queue).
*/
extern int ef_vi_calc_state_bytes(int rxq_size, int txq_size);

/*! Initialise [ef_vi] from the provided resources. [vvis] must have been
** created by ef_make_vi_data() & remains owned by the caller.
*/
extern void ef_vi_init(ef_vi*, void* vi_info, ef_vi_state* state,
                       ef_eventq_state* evq_state, enum ef_vi_flags);

extern void ef_vi_state_init(ef_vi*);
extern void ef_eventq_state_init(ef_vi*);

/*! Convert an efhw device arch to ef_vi_arch, or returns -1 if not
** recognised.
*/
extern int  ef_vi_arch_from_efhw_arch(int efhw_arch);

/* Add a VI into the set managed by a VI with an event queue.  Only needed
 * when a VI is constructed manually.
 *
 * Returns the Q label (>= 0) on success, or -EBUSY if [evq_vi] already has
 * a full complement of slaved VIs.
 */
extern int ef_vi_add_queue(ef_vi* evq_vi, ef_vi* add_vi);

/* Place statistics relating to errors in the nominated buffer.
 *
 * This call does not populate [s] immediately; stats are updated by other
 * calls, so the lifetime of [s] must be as long as the vi.
 */
extern void ef_vi_set_stats_buf(ef_vi* vi, ef_vi_stats* s);


/* Returns a string that identifies the version of ef_vi.  This should be
 * treated as an unstructured string.  At time of writing it is the version
 * of OpenOnload or EnterpriseOnload that ef_vi is distributed in.
 */
extern const char* ef_vi_version_str(void);

/* Returns a string that identifies the char driver interface required by
 * this build of ef_vi.
 */
extern const char* ef_vi_driver_interface_str(void);


/**********************************************************************
 * Re-Initialisation **************************************************
 **********************************************************************/

/* This set of functions will reinitialise the software rings and deal
 * with any buffers that they contain by calling the supplied callback
 * for each one to allow it to be freed.
 */

typedef void (*ef_vi_reinit_callback)(ef_request_id id, void* arg);

extern int ef_vi_rxq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg);
extern int ef_vi_txq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg);
extern int ef_vi_evq_reinit(ef_vi* vi);

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_EF_VI_H__ */
