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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Interface between sfc_char driver and userland.
**   \date  2010/09/01
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*
** README!!!!
**
** This header defines a stable interface between userlevel code and the
** sfc_char driver.  DO NOT make any changes that break backwards
** compatibility.
*/

#ifndef __CI_EFCH_OP_TYPES_H__
#define __CI_EFCH_OP_TYPES_H__

#include <ci/efch/resource_id.h>


/* We use an md5sum over certain headers to check that userland and kernel
 * drivers are built against a compatible interface.
 */
enum { EFCH_INTF_VER_LEN = 32 };


struct efch_timeval {
  int32_t tv_sec;
  int32_t tv_usec;
};


/**********************************************************************
 *
 * Allocating resources.
 *
 */

struct efch_vi_alloc_in {
  int32_t             ifindex;            /* only used if no pd or vi_set */
  int32_t             pd_or_vi_set_fd;    /* -1 if not specified */
  efch_resource_id_t  pd_or_vi_set_rs_id;
  int32_t             vi_set_instance;
  int32_t             evq_fd;
  efch_resource_id_t  evq_rs_id;
  int32_t             evq_capacity;
  int32_t             txq_capacity;
  int32_t             rxq_capacity;
  uint32_t            flags;  /* EFAB_VI_* flags */
  uint8_t             tx_q_tag;
  uint8_t             rx_q_tag;
};


struct efch_vi_alloc_out {
  int32_t             evq_capacity;
  int32_t             txq_capacity;
  int32_t             rxq_capacity;
  uint8_t             nic_arch;
  uint8_t             nic_variant;
  uint8_t             nic_revision;
  uint8_t             nic_flags;
  uint32_t            mem_mmap_bytes;
  uint32_t            io_mmap_bytes;
  int32_t             instance;
  uint32_t            rx_prefix_len;
};


struct efch_vi_set_alloc {
  int32_t             in_ifindex;         /* only used if pd_fd < 0 */
  int32_t             in_min_n_vis;
  uint32_t            in_flags;
  int32_t             in_pd_fd;           /* -1 if not specified */
  efch_resource_id_t  in_pd_rs_id;
};


struct efch_memreg_alloc {
  int32_t             in_vi_or_pd_fd;
  efch_resource_id_t  in_vi_or_pd_id;
  uint64_t            in_mem_ptr;
  uint64_t            in_mem_bytes;
  uint64_t            in_addrs_out_ptr;
  int                 in_addrs_out_stride;
};


struct efch_pio_alloc {
  int32_t             in_pd_fd;
  efch_resource_id_t  in_pd_id;
};


#define EFCH_PD_FLAG_VF               0x1
#define EFCH_PD_FLAG_VF_OPTIONAL      0x2
#define EFCH_PD_FLAG_PHYS_ADDR        0x4


struct efch_pd_alloc {
  int32_t             in_ifindex;
  uint32_t            in_flags;
};


typedef struct ci_resource_alloc_s {
  char               intf_ver[EFCH_INTF_VER_LEN];
  uint32_t           ra_type;
  efch_resource_id_t out_id;
  union {
    struct efch_vi_alloc_in    vi_in;
    struct efch_vi_alloc_out   vi_out;
    struct efch_vi_set_alloc   vi_set;
    struct efch_memreg_alloc   memreg;
    struct efch_pd_alloc       pd;
    struct efch_pio_alloc      pio;
  } u;
} ci_resource_alloc_t;


/**********************************************************************
 *
 * Resource OPs.
 *
 */

typedef struct ci_resource_op_s {
  efch_resource_id_t    id;
  uint32_t              op;
# define                CI_RSOP_VI_GET_MAC              0x49
# define                CI_RSOP_EVENTQ_PUT              0x51
# define                CI_RSOP_EVENTQ_WAIT             0x54
# define                CI_RSOP_VI_GET_MTU              0x55
# define                CI_RSOP_DUMP                    0x58
# define                CI_RSOP_EVQ_REGISTER_POLL       0x59
# define                CI_RSOP_PT_ENDPOINT_FLUSH       0x5a
# define                CI_RSOP_PT_ENDPOINT_PACE        0x62
# define                CI_RSOP_FILTER_ADD_IP4          0x63
# define                CI_RSOP_FILTER_ADD_MAC          0x64
# define                CI_RSOP_FILTER_ADD_ALL_UNICAST  0x65
# define                CI_RSOP_FILTER_ADD_ALL_MULTICAST 0x66
# define                CI_RSOP_FILTER_DEL              0x67
# define                CI_RSOP_PIO_LINK_VI             0x68
# define                CI_RSOP_PIO_UNLINK_VI           0x69
# define                CI_RSOP_FILTER_ADD_IP4_VLAN     0x70
# define                CI_RSOP_FILTER_ADD_ALL_UNICAST_VLAN   0x71
# define                CI_RSOP_FILTER_ADD_ALL_MULTICAST_VLAN 0x72

  union {
    struct {
      uint32_t          current_ptr;
      struct efch_timeval timeout;
      uint32_t          nic_index;
    } evq_wait;
    struct {
      uint64_t          ev;
    } evq_put;
    struct {
      ci_uint16         out_mtu;
    } vi_get_mtu;
    struct {
      uint8_t           out_mac[6];
    } vi_get_mac;
    struct {
      int32_t           pace;
    } pt;
    struct {
      int32_t            in_vi_fd;
      efch_resource_id_t in_vi_id;
    } pio_link_vi;
    struct {
      int32_t            in_vi_fd;
      efch_resource_id_t in_vi_id;
    } pio_unlink_vi;
    struct {
      struct {
        uint8_t         protocol;
        ci_int16        port_be16;
        ci_int16        rport_be16;
        uint32_t        host_be32;
        uint32_t        rhost_be32;
        /* On NICs that require VLAN field as well, we use the field
         * from struct mac below. */
      } ip4;
      struct {
        ci_int16        vlan_id;
        uint8_t         mac[6];
      } mac;
      int               replace;
      int32_t           out_filter_id;
    } filter_add;
    struct {
      int32_t           filter_id;
    } filter_del;
  } u CI_ALIGN(8);
} ci_resource_op_t;


#define CI_IOC_CHAR_BASE       81

#define CI_RESOURCE_OP      (CI_IOC_CHAR_BASE+ 0)  /* ioctls for resources */
#define CI_RESOURCE_ALLOC   (CI_IOC_CHAR_BASE+ 1)  /* allocate resources   */
#define CI_IOC_CHAR_MAX     (CI_IOC_CHAR_BASE+ 2)


/**********************************************************************
 *
 * Memory mappings.
 *
 */

/* mmap offsets must be page aligned, hence the bottom PAGE_SHIFT bits must
** be zero.  To be conservative we should assume 8k pages and 32-bit
** offset.  That leaves is with 19 bits to play with.  We current use 5 for
** the resource id, and 12 for the map_id (total 17).
*/
#define EFAB_MMAP_OFFSET_MAP_ID_BITS  (19u - EFRM_RESOURCE_MAX_PER_FD_BITS)
#define EFAB_MMAP_OFFSET_MAP_ID_MASK  ((1u << EFAB_MMAP_OFFSET_MAP_ID_BITS)-1u)
#define EFAB_MMAP_OFFSET_ID_MASK      (EFRM_RESOURCE_MAX_PER_FD - 1u)

static inline off_t
EFAB_MMAP_OFFSET_MAKE(efch_resource_id_t id, unsigned map_id) {
  return (id.index | (map_id << EFRM_RESOURCE_MAX_PER_FD_BITS))
         << CI_PAGE_SHIFT;
}

static inline efch_resource_id_t
EFAB_MMAP_OFFSET_TO_RESOURCE_ID(off_t offset) {
  efch_resource_id_t id;
  id.index = (offset >> CI_PAGE_SHIFT) & EFAB_MMAP_OFFSET_ID_MASK;
  return id;
}

static inline unsigned
EFAB_MMAP_OFFSET_TO_MAP_ID(off_t offset)
{ return offset >> (CI_PAGE_SHIFT + EFRM_RESOURCE_MAX_PER_FD_BITS); }


#endif  /* __CI_EFCH_OP_TYPES_H__ */
