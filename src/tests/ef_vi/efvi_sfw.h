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

#ifndef __EFVI_SFW_H__
#define __EFVI_SFW_H__

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>


#define ROUND_UP(p, align)   (((p)+(align)-1u) & ~((align)-1u))


/* Maximum number of network interfaces. */
#define MAX_NET_IFS          8


/* Hardware delivers at most 1824 bytes to each buffer, and for best
 * performance buffers should be aligned on a 64-byte boundary.  Also, RX
 * DMA will not cross a 4K boundary.  And if using physical addressing
 * (including VFs) the I/O address space may be discontiguous at 4K
 * boundaries.  So best thing to do is to make buffers always be 2K in
 * size.
 */
#define PKT_BUF_SIZE         2048


struct pkt_buf;


struct net_if {
  const char*      name;
  int              id;
  int              ifindex;
  /* Handle for accessing the driver. */
  ef_driver_handle dh;
  /* Protection domain. */
  ef_pd            pd;
  /* vi_set is only used for receive-side scaling (RSS). */
  ef_vi_set        vi_set;
  int              vi_set_size;
};


struct vi {
  /* ID of this VI. */
  int              id;
  /* The network interface this VI is associated with. */
  struct net_if*   net_if;
  /* Handle for accessing the driver. */
  ef_driver_handle dh;
  /* Virtual interface (hardware send/recv interface). */
  ef_vi            vi;
  /* Registered memory. */
  void*            pkt_bufs;
  int              pkt_bufs_n;
  ef_memreg        memreg;
  /* Length of prefix pre-pended to packet by NIC. */
  int              rx_prefix_len;
  /* Pool of free packet buffers (LIFO to minimise working set). */
  struct pkt_buf*  free_pkt_bufs;
  int              free_pkt_bufs_n;
};


struct pkt_buf {
  struct vi*       vi_owner;
  /* Linked list of [pkt_buf]s. */
  struct pkt_buf*  next;
  /* The I/O address of this buffer in each net_if.  Indexed by [net_if->id] */
  ef_addr          addr[MAX_NET_IFS];
  /* The ID of this buffer within [vi_owner]s pool. */
  int              id;
  /* Reference count.  No concurrency control, so we assume packet buffers
   * are only used in a single thread.
   */
  int              n_refs;
};


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


/* Align address where data is delivered onto a 64-byte boundary, because
 * that gives best performance.
 */
#define RX_DMA_OFF     ROUND_UP(sizeof(struct pkt_buf), 64)

/* Where does a received packet start?  The hardware usually puts a
 * meta-data prefix in front of the packet data.
 */
#define RX_PKT_OFF(vi)   (RX_DMA_OFF + (vi)->rx_prefix_len)

/* Get pointer to the received packet payload. */
#define RX_PKT_PTR(pb)   ((char*) (pb) + RX_PKT_OFF((pb)->vi_owner))

/* Pack VI that owns the packet buffer, and the buffer-id into TX request
 * ID.  NB. We only have 16-bits to play with.
 */
#define MK_TX_RQ_ID(vi_i, pb_i)  (((vi_i) << 12) | (pb_i))
#define TX_RQ_ID_VI(rq_id)       ((rq_id) >> 12)
#define TX_RQ_ID_PB(rq_id)       ((rq_id) & 0xfff)


struct net_if*
net_if_alloc(int net_if_id, const char* name, int rss_set_size);

extern void
net_if_map_vi_pool(struct net_if*, struct vi*);

extern struct pkt_buf*
pkt_buf_from_id(struct vi* vi, int pkt_buf_i);

extern void
pkt_buf_free(struct pkt_buf* pkt_buf);

extern void
pkt_buf_release(struct pkt_buf* pkt_buf);

extern void
vi_refill_rx_ring(struct vi* vi);

extern struct vi*
vi_alloc(int id, struct net_if*);

extern struct vi*
vi_alloc_from_set(int id, struct net_if*, int vi_set_instance);

extern int
vi_send(struct vi* vi, struct pkt_buf* pkt_buf, int off, int len);


#endif  /* __EFVI_SFW_H__ */
