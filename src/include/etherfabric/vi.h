/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  Virtual packet / DMA interface.
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_etherfabric */
#ifndef __EFAB_VI_H__
#define __EFAB_VI_H__

#include <etherfabric/ef_vi.h>
#include <etherfabric/base.h>


struct ef_pd;


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

#define EF_VI_DEFAULT_INTERFACE  -1


  /*! \i_ef_vi  Allocate a virtual interface.
  **
  ** Allocate a virtual interface for a single NIC.
  **
  **   \param vi        area of memory that will be initialzied
  **   \param nic       handle identifying the NIC to be used
  **   \param ifindex   interface ifindex, or EF_VI_DEFAULT_INTERFACE
  **   \param evq_capacity number of events in event queue.  Specify 0 for
  **                    no event queue or -1 for the default size.
  **   \param rxq_capacity number of descriptors in RX DMA queue.  Specify
  **                    0 for no RX queue or -1 for the default size.
  **   \param txq_capacity number of descriptors in TX DMA queue.  Specify
  **                    0 for no TX queue or -1 for the default size.
  **   \param evq_opt   VI where events will arrive
  **   \param evq_dh
  **   \param flags     EF_VI_ flags to select hardware attributes of the DMA q
  **
  **   \return          >= 0 iff successful otherwise a negative error code
  **                    On success value is Q_ID.
  */
extern int ef_vi_alloc(ef_vi* vi, ef_driver_handle nic,
                       int ifindex, int evq_capacity,
                       int rxq_capacity, int txq_capacity,
		       ef_vi* evq_opt, ef_driver_handle evq_dh,
		       enum ef_vi_flags flags);

extern int ef_vi_alloc_from_pd(ef_vi* vi, ef_driver_handle vi_dh,
			       struct ef_pd* pd, ef_driver_handle pd_dh,
			       int evq_capacity, int rxq_capacity,
			       int txq_capacity,
			       ef_vi* evq_opt, ef_driver_handle evq_dh,
			       enum ef_vi_flags flags);



  /*! \i_ef_vi Release and free a virtual interface.
  **
  **   \param vi        reference to the virtual interface
  **   \param nic       handle identifying the NIC the interface is on
  **
  **   \return          0 iff successful otherwise a negative error code
  **
  ** If successful the memory for state provided for this virtual interface
  ** is no longer required following this call and no further events from
  ** this virtual interface will be delivered to its event queue.
  */
extern int ef_vi_free(ef_vi* vi, ef_driver_handle nic);

  /*! i_ef_vi Flush the interface.
  **
  **   \param vi        reference to the virtual interface
  **   \param nic       handle identifying the NIC the interface is on
  **
  **   \return          0 iff successful otherwise a negative error code
  ** 
  ** After this function returns, it is safe to reuse all buffers which
  ** have been pushed onto the NIC
  */
extern int ef_vi_flush(ef_vi* vi, ef_driver_handle nic);

  /*! i_ef_vi Pace the interface.
  **
  ** Sets a minimum inter-packet gap for the TXQ.  Gap is (2^val)*100ns.
  ** If [val] is -1 then the TXQ is put into the "pacing" bin, but no gap
  ** is enforced.  This can be used to give priority to latency sensitive
  ** traffic over bulk traffic.
  */
extern int ef_vi_pace(ef_vi* vi, ef_driver_handle nic, int val);

  /*! i_ef_vi Return the interface MTU.
  **
  **   \param vi        reference to the virtual interface
  **   \return          the Maximum Transmission Unit
  **
  ** The maximum size of ethernet frames that can be transmitted through,
  ** and received by the interface.  This value is the total frame size,
  ** including all headers, but not including the Ethernet frame check.
  */
extern unsigned ef_vi_mtu(ef_vi* vi, ef_driver_handle);

  /*! \i_ef_vi  Get the Ethernet MAC address.
  **
  ** This is not a cheap call, so cache the result if you care about
  ** performance.
  */
extern int ef_vi_get_mac(ef_vi*, ef_driver_handle, void* mac_out);


/**********************************************************************
 * ef_vi_set **********************************************************
 **********************************************************************/

typedef struct {
	unsigned vis_res_id;
} ef_vi_set;


  /*
  ** Allocate a set of virtual interfaces.
  **
  ** A VI set is usually used for the purposes of spreading the load of
  ** handling received packets.  This sometimes called "receive-side
  ** scaling" or RSS.
  */
extern int ef_vi_set_alloc(ef_vi_set*, ef_driver_handle, int ifindex,
			   int n_vis);

  /*
  ** Allocate a set of virtual interfaces in a PD.
  **
  ** A VI set is usually used for the purposes of spreading the load of
  ** handling received packets.  This sometimes called "receive-side
  ** scaling" or RSS.
  */
extern int ef_vi_set_alloc_from_pd(ef_vi_set*, ef_driver_handle,
				   struct ef_pd* pd, ef_driver_handle pd_dh,
				   int n_vis);

  /*
  ** Initialise a VI that forms part of a set of VIs.  This is analogous to
  ** ef_vi_alloc().
  */
extern int ef_vi_alloc_from_set(ef_vi* vi, ef_driver_handle vi_dh,
				ef_vi_set* vi_set, ef_driver_handle vi_set_dh,
				int index_in_vi_set, int evq_capacity,
				int rxq_capacity, int txq_capacity,
				ef_vi* evq_opt, ef_driver_handle evq_dh,
				enum ef_vi_flags flags);


/**********************************************************************
 * ef_filter **********************************************************
 **********************************************************************/

enum ef_filter_flags {
	EF_FILTER_FLAG_NONE           = 0x0,
	EF_FILTER_FLAG_REPLACE        = 0x1,
};

typedef struct {
	unsigned type;
	unsigned flags;
	unsigned data[5];
} ef_filter_spec;

enum {
	EF_FILTER_VLAN_ID_ANY = -1,
};

typedef struct {
	int filter_id;
} ef_filter_cookie;


extern void ef_filter_spec_init(ef_filter_spec *, enum ef_filter_flags);
extern int ef_filter_spec_set_ip4_local(ef_filter_spec *, int protocol,
					unsigned host_be32, int port_be16);
extern int ef_filter_spec_set_ip4_full(ef_filter_spec *, int protocol,
				       unsigned host_be32, int port_be16,
				       unsigned rhost_be32, int rport_be16);
extern int ef_filter_spec_set_eth_local(ef_filter_spec *, int vlan_id,
					const void *mac);
extern int ef_filter_spec_set_unicast_all(ef_filter_spec *);
extern int ef_filter_spec_set_multicast_all(ef_filter_spec *);

extern int ef_vi_filter_add(ef_vi*, ef_driver_handle, const ef_filter_spec*,
			    ef_filter_cookie *filter_cookie_out);
extern int ef_vi_filter_del(ef_vi*, ef_driver_handle, ef_filter_cookie *);

extern int ef_vi_set_filter_add(ef_vi_set*, ef_driver_handle,
				const ef_filter_spec*,
				ef_filter_cookie *filter_cookie_out);
extern int ef_vi_set_filter_del(ef_vi_set*, ef_driver_handle,
				ef_filter_cookie *);


#endif  /* __EFAB_VI_H__ */
/*! \cidoxg_end */
