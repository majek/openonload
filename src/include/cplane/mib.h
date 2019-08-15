/*
** Copyright 2005-2019  Solarflare Communications Inc.
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

/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

/* Public API for UL Control plane.  This header is:
 * (a) sourceful for the customers;
 * (b) compilable in both UL and kernel.
 */
#ifndef __TOOLS_CPLANE_PUBLIC_H__
#define __TOOLS_CPLANE_PUBLIC_H__

#include <ci/compat.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/byteorder.h>
#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>
#include <linux/neighbour.h>

/* At user level, net/if.h and linux/if.h cannot both be #included.  However,
 * there are files that #include this one requiring each of those.  As a
 * workaround, do the #include only if neither has yet been included. */
#if ! defined(IFNAMSIZ)
# ifndef __KERNEL__
#  include <sys/socket.h>
#  include <net/if.h> /* for IFNAMSIZ */
# else
#  include <linux/if.h> /* for IFNAMSIZ */
# endif
#endif



/*
 *** Primary data types ***
 */

typedef ci_int16 cicp_rowid_t;
#define CICP_ROWID_BAD ((cicp_rowid_t)(-1))
#define CICP_ROWID_IS_VALID(id) ((cicp_rowid_t)(id) >= 0)
#define CICP_ROWID_MAX 0x7fff

/* Row id for MAC and FWD cache tables. */
typedef ci_int32 cicp_mac_rowid_t;
#define CICP_MAC_ROWID_BAD ((cicp_mac_rowid_t)(-1))
#define CICP_MAC_ROWID_IS_VALID(id) ((cicp_mac_rowid_t)(id) >= 0)
#define CICP_MAC_ROWID_MAX 0x7fffffff

typedef ci_uint8 ci_hwport_id_t;
#define CI_HWPORT_ID_BAD          ((ci_hwport_id_t) -1)
#define CI_HWPORT_ID_BAD_LICENSED ((ci_hwport_id_t) -2)
typedef ci_uint16 ci_ifid_t;
#define CI_IFID_BAD  0
#define CI_IFID_LOOP 1

typedef ci_uint8 cicp_prefixlen_t;
#define CI_IP_PREFIXLEN_BAD 0xff

typedef ci_uint8 ci_mac_addr_t[6];
typedef ci_uint16 ci_mtu_t;


/*! flags for types of encapsulation supported by the NIC */
enum {
  CICP_LLAP_TYPE_NONE   = 0,
  CICP_LLAP_TYPE_VLAN   = 1,
  CICP_LLAP_TYPE_BOND   = 2,
  CICP_LLAP_TYPE_SLAVE = 4,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER2 = 8,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER34 = 0x10,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER23 = 0x20,
  CICP_LLAP_TYPE_LOOP = 0x40,
  CICP_LLAP_TYPE_MACVLAN = 0x80,
};
#define CICP_LLAP_TYPE_USES_HASH \
  (CICP_LLAP_TYPE_XMIT_HASH_LAYER34 | \
   CICP_LLAP_TYPE_XMIT_HASH_LAYER2 | \
   CICP_LLAP_TYPE_XMIT_HASH_LAYER23 )
#define CICP_LLAP_TYPE_XMIT_HASH_LAYER4 CICP_LLAP_TYPE_XMIT_HASH_LAYER34

/* enum is always int, so no typedef for enum */
typedef ci_uint8 cicp_llap_type_t;


/*
 *** Local Link Access Point table ***
 */

typedef struct {
  cicp_llap_type_t type;
  ci_uint16 vlan_id;
} cicp_encap_t;


#define CICP_ENCAP_NAME_FMT "%s%s%s%s%s%s%s%s"
#define cicp_encap_name(encap)                                  \
    (encap & CICP_LLAP_TYPE_VLAN ? "VLAN " : ""),               \
    (encap & CICP_LLAP_TYPE_MACVLAN ? "MACVLAN " : ""),         \
    (encap & CICP_LLAP_TYPE_LOOP ? "LOOP " : ""),               \
    (encap & CICP_LLAP_TYPE_BOND ? "BOND " : ""),               \
    (encap & CICP_LLAP_TYPE_USES_HASH ? "HASH " : ""),          \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER34 ? "L34 " : ""),   \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER2 ? "L2 " : ""),     \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER23 ? "L23 " : "")    \


typedef ci_uint16 cicp_hwport_mask_t;
static inline ci_hwport_id_t cp_hwport_mask_first(cicp_hwport_mask_t mask)
{
  /* if mask == 0 then it results in CI_HWPORT_ID_BAD */
  return ffs(mask) - 1;
}
static inline cicp_hwport_mask_t cp_hwport_make_mask(ci_hwport_id_t hwport)
{
  /* Address potential shif overflow when:
   *  * hwport == dim->hwports_max == bits(ci_hwport_id_t)
   *  * CI_HWPORT_ID_BAD is passed*/
  if( hwport >= sizeof(cicp_hwport_mask_t) * 8 )
    return 0;
  return ((cicp_hwport_mask_t) 1) << hwport;
}

typedef struct cicp_llap_row_s {
  ci_ifid_t ifindex;

  ci_mtu_t mtu;               /*< IP Maximum Transmit Unit for this i/f */
  ci_uint8 flags;             /*< various flags */
#define CP_LLAP_UP                     1
#define CP_LLAP_ALIEN                  2
#define CP_LLAP_LICENSED_ONLOAD        4
#define CP_LLAP_LICENSED_TCP_DIRECT    8
#define CP_LLAP_LICENSED_SCALEOUT     16
/* lower interface not yet discoverd */
#define CP_LLAP_LICENSE_POSTPONED     32
/* lower iface is in some other (main) namespace */
#define CP_LLAP_IMPORTED              64
  char name[IFNAMSIZ+1];
  ci_mac_addr_t mac;          /*< MAC address of access point */
  cicp_encap_t encap;         /*< encapsulation used on this i/f */

  /* the following fields are only valid in SFC interfaces */
  ci_ifid_t vlan_ifindex;     /*< ifindex for VLAN master */

  /* Hardware ports under this interface.
   *
   * tx_hwports are used for transmit.  Everything except LACP team/bond
   * (+vlan/macvlan over LACP) has one bit set tx_hwports mask only.
   *
   * rx_hwports are used for receive.  For all team/bond types, all ports
   * in aggregation must be included into rx_hwports mask, to ensure that
   * appropriate TCP filters are inserted for any TCP connection, and OS
   * will not receive any TCP packets with Onload destination.  Otherwise
   * OS may reply with RST. */
  cicp_hwport_mask_t tx_hwports;
  cicp_hwport_mask_t rx_hwports;
} cicp_llap_row_t;

/* Bitmask including all licences that allow the use of Onload. */
#define CP_LLAP_ALL_ONLOAD_LICENCES (CP_LLAP_LICENSED_ONLOAD | \
                                     CP_LLAP_LICENSED_SCALEOUT)

/* Bitmask including all licences that allow Onload to accelerate UDP. */
#define CP_LLAP_ONLOAD_UDP_ACCEL_LICENCES  CP_LLAP_LICENSED_ONLOAD


typedef ci_uint8 cp_hwport_flags_t;

struct cp_hwport_row {
/* we reuse CP_LLAP flags here */
#define CP_HWPORT_ROW_IN_USE 128
  cp_hwport_flags_t flags;
  ci_uint32 oo_vi_flags_mask;
  ci_uint32 efhw_flags_extra;
  ci_uint8  pio_len_shift;
  ci_uint32 ctpio_start_offset;
};


static inline int
cicp_llap_row_is_free(cicp_llap_row_t *row)
{
  return row->ifindex == CI_IFID_BAD;
}


static inline int
cicp_hwport_row_is_free(struct cp_hwport_row* row)
{
  return (row->flags & CP_HWPORT_ROW_IN_USE) == 0;
}

/*
 *** IP address on network InterFace table ***
 */

typedef struct
{
  /* keys: */
  ci_ip_addr_t     net_ip;    /*< network own address */
  cicp_prefixlen_t net_ipset; /*< network IP address set specification */
  ci_ifid_t        ifindex;   /*< O/S index of link layer interface */

  /* data: */
  ci_ip_addr_t     bcast_ip;  /*< broadcast IP address, 0 if not set */
  ci_uint8         scope;     /*< RT_SCOPE_UNIVERSE=0, more is worse */
  /* XXX store flag: primary or secondary (see IFA_F_SECONDARY) */
} cicp_ipif_row_t;

typedef struct
{
  /* keys: */
  ci_ip6_addr_t    net_ip6;
  cicp_prefixlen_t net_ipset;
  ci_ifid_t        ifindex;

  /* data: */
  ci_uint8         scope;
} cicp_ip6if_row_t;

static inline int
cicp_ipif_row_is_free(cicp_ipif_row_t *row)
{
  return row->net_ipset == CI_IP_PREFIXLEN_BAD;
}

static inline int
cicp_ip6if_row_is_free(cicp_ip6if_row_t *row)
{
  return row->net_ipset == CI_IP_PREFIXLEN_BAD;
}

/*
 *** Route Cache table ***
 */
typedef ci_uint8 cicp_ip_tos_t;

/* Keys for forward cache table. */
struct cp_fwd_key {
  ci_ip_addr_t  src;
  ci_ip_addr_t  dst;
  ci_ifid_t     ifindex;
  cicp_ip_tos_t tos;

  ci_uint8      flag;
#define CP_FWD_KEY_REQ_REFRESH  0x80
#define CP_FWD_KEY_REQ_WAIT     0x40
#define CP_FWD_KEY_TRANSPARENT  0x20
#define CP_FWD_KEY_UDP          0x10
#define CP_FWD_KEY_SOURCELESS   0x08
};
#define CP_FWD_KEY_FMT \
  "from "CI_IP_PRINTF_FORMAT" to "CI_IP_PRINTF_FORMAT" via %d tos %d"
#define CP_FWD_KEY_ARGS(key) \
  CI_IP_PRINTF_ARGS(&(key)->src), CI_IP_PRINTF_ARGS(&(key)->dst), \
  (key)->ifindex, (key)->tos

struct cp_fwd_key_ext {
  /* This is part of "key", but only ever stored in fwd_row */
  cicp_prefixlen_t src_prefix;
  cicp_prefixlen_t dst_prefix;
};

/* Routing info in the forward cache table. */
struct cp_fwd_data {
  ci_ip_addr_t      src;
  ci_ip_addr_t      next_hop;
  ci_mtu_t          mtu;
  ci_ifid_t         ifindex;

  ci_uint8          arp_valid;
  ci_mac_addr_t     src_mac;
  cicp_hwport_mask_t hwports;
  ci_mac_addr_t     dst_mac;
  cicp_encap_t      encap;
};

static inline ci_ip_addr_t cp_prefixlen2bitmask(cicp_prefixlen_t len)
{
  return CI_BSWAP_BE32(~(len == 0 ? 0xffffffff : (1 << (32 - len)) - 1));
}

static inline int /*bool*/
cp_ip_prefix_match(ci_ip_addr_t ip1, ci_ip_addr_t ip2, cicp_prefixlen_t len)
{
  return ((ip1 ^ ip2) & cp_prefixlen2bitmask(len)) == 0;
}

typedef uint32_t cp_version_t;

/* fwd table has the following properties:
 *
 * 1. Each fwd entry has prefix sizes associated allowing the entry to match
 *    requests ignoring the respective least significant bits of both
 *    src and dst ip addresses
 * 2. There is only one entry that can handle any given ip address.
 *  * if there is an entry for 1.1.1.0/24 then there is no entry 1.1.0.0/16
 *  * if with existing route 1.1.0.0/16, a new route 1.1.1.0/24 is added
 *    then the fwd table entry 1.1.0.0/16 gets deleted and entries
 *    1.1.1.0/24 1.1.2/24 etc are added as needed
 * 3. best effort tendency to adding the widest fwd table entries
 *    (entries are created as widest but after route change widening occurs
 *     when needed)
 *
 * Following (2) for a given request with full fwd table scan of given table
 * would produce at most single result.
 * In practice, full scan is avoided by using hash probing.
 * It may take several probes though to find the matching row. Each probe uses
 * key modified to address increase of prefix. e.g. for address 1.1.1.1
 * the search could be 1.1.1.1, then 1.1.1.0, and 1.1.0.0.
 * (It is possible for probe of 1.1.1.1 to return 1.1.0.0 if the probe sequence
 *  went over it by chance).
 *
 * Note: examples above used one dimension of ip address prefix range for
 * simplicity.
 */
struct cp_fwd_row {
  /* the key and data fields are 0 padded */
  struct cp_fwd_key     key;
  struct cp_fwd_key_ext key_ext;
  struct cp_fwd_data    data[2]; /* two snapshots of data */

  /* Version is the "data" version. Even version means that snapshot of data
   * at index 0 is to be read by clients, odd that the data under index 1.
   *
   * When data changes, both copies are updated, one-after another.
   * The version may be updated without any data change, for example for
   * CICP_FWD_FLAG_STALE flag.
   */
  cp_version_t version;
  uint32_t use; /* in how many probe sequences record is used */
  uint8_t flags;

/* flags used by server */
/* fwd row is at least half ttl old and frc_used needs refreshing */
#define CICP_FWD_FLAG_STALE           0x1
/* changes have been started */
#define CICP_FWD_FLAG_CHANGES_STARTED 0x2
/* row contains modification of MTU */
#define CICP_FWD_FLAG_MTU             0x4
/* MTU is a result of Path MTU discovery and will expire */
#define CICP_FWD_FLAG_MTU_EXPIRES     0x8
/* This route has a gateway */
#define CICP_FWD_FLAG_HAS_GATEWAY     0x10

/* flags used by client: */
/* row is used and the key is valid */
#define CICP_FWD_FLAG_OCCUPIED        0x80
/* data field has been filled once */
#define CICP_FWD_FLAG_DATA_VALID      0x40
};

static inline int/*bool*/
cp_fwd_key_match(struct cp_fwd_row* fwd, struct cp_fwd_key* key)
{
  ci_ip_addr_t src_prefix;
  ci_ip_addr_t dst_prefix;
  src_prefix = cp_prefixlen2bitmask(fwd->key_ext.src_prefix);
  dst_prefix = cp_prefixlen2bitmask(fwd->key_ext.dst_prefix);

  return (fwd->flags & CICP_FWD_FLAG_OCCUPIED) != 0 &&
         (fwd->key.dst & dst_prefix) == (key->dst & dst_prefix) &&
         (fwd->key.src & src_prefix) == (key->src & src_prefix) &&
         fwd->key.ifindex == key->ifindex && fwd->key.tos == key->tos &&
         ((fwd->key.flag ^ key->flag) & CP_FWD_KEY_TRANSPARENT) == 0;
}


/*
 *** Read-only cplane memory ***
 */

/* Read-only cplane memory is structured as following:
 * struct cp_tables_dim dim;
 * struct cp_hwport_row hwport[hwport_max];
 * cicp_llap_row_t llap[llap_max];
 * cicp_bond_row_t bond[bond_max];
 * cicp_ipif_row_t ipif[ipif_max];
 * struct cp_fwd_row fwd[fwd_max+1];
 */

struct cp_tables_dim {
  /* Number of hwport rows */
  cicp_rowid_t hwport_max;

  /* Number of llap rows */
  cicp_rowid_t llap_max;

  /* Number of ipif rows */
  cicp_rowid_t ipif_max;
  cicp_rowid_t ip6if_max;

  /* Number of fwd cache rows, must be 2^n */
  ci_uint8 fwd_ln2;
  cicp_mac_rowid_t fwd_mask; /* 2^fwd_ln2 - 1 */

  /* RT signal used to notify about new oof instances */
  ci_int32 oof_req_sig;
  /* signal used to notify about update of main cp server */
  ci_int32 llap_update_sig;
  /* signal to request sync with OS */
  ci_int32 os_sync_sig;

  /* PID of the server process */
  ci_uint32 server_pid;

#ifdef CP_SYSUNIT
  ci_uint32 sub_server_pid;
#endif
};

enum {
  CP_FWD_PREFIX_SRC,
  CP_FWD_PREFIX_DST,
  CP_FWD_PREFIX_NUM
};

/*
 *** Read-write cplane memory ***
 */

/* This structure is writable for all Onloaded processes.
 * It allows to say:
 * - "I'm using this route, don't move it out of the cache and resolve ARP"
 */
struct cp_fwd_rw_row {
  /* Last time this row was used. */
  ci_uint64 frc_used CI_ALIGN(8);

  /* Use ci_atomic32_* operations to modify flags: */
  ci_uint32 flags;
/* ARP entry is almost-stale and should be confirmed when possible */
#define CICP_FWD_RW_FLAG_ARP_NEED_REFRESH 0x1
};


/* The main cplane object, used by both Cplane Process and Cplane users */

struct cp_mibs {
  /* Read-only data: */
  struct cp_tables_dim* dim;

  /* Version of the hwport, ipif, llap tables */
  cp_version_t* version;

  /* Version of the llap tables. Not used in selecting which table to index,
   * but rather a finer heuristic to detect stale llap rows. */
  cp_version_t* llap_version;

  /* Version of "dump from OS" point of view: odd means "dump in progress".
   * It is increased when dump is started and when it finishes
   * successfully. */
  cp_version_t* dump_version;

  /* Number of times when the cplane server have nothing to do (blocked in
   * epoll) multiplied by 2.  As with dump_version, an odd value means that
   * cplane is updating something right now.
   */
  cp_version_t* idle_version;

  /* Version exposed to oof subsystem. */
  cp_version_t* oof_version;

  struct cp_hwport_row* hwport;
  cicp_llap_row_t* llap;
  cicp_ipif_row_t* ipif;
  cicp_ip6if_row_t* ip6if;

  /* See CP_FWD_PREFIX_*.  There is a single copy of each fwd_prefix bitmap
   * shared between both MIB frames.  It is not protected by any lock, as each
   * bit is independent of each other bit, and the only consistency requirement
   * is that the presence of a prefix-length in the fwd table implies that the
   * corresponding bit in the appopriate fwd_prefix entry is set.  As such,
   * normal non-atomic writes are sufficient for updating fwd_prefix.  Barriers
   * are not even required between changes to fwd_prefix and the table itself,
   * as there is no harm in the race between look-ups by clients and changes to
   * the table. */
  ci_uint64 *fwd_prefix;
  struct cp_fwd_row* fwd;

  /* Read-write data, array size fwd_max */
  struct cp_fwd_rw_row* fwd_rw;
};

static inline ci_uint8 cp_get_largest_prefix(ci_uint64 prefix_bitmask)
{
  return 63 - __builtin_clzll(prefix_bitmask);
}


typedef struct
{
  cicp_mac_rowid_t id;
  cp_version_t     version;
} cicp_verinfo_t;


static inline struct cp_fwd_row*
cp_get_fwd_by_id(struct cp_mibs* mib, cicp_mac_rowid_t id)
{
  ci_assert_nequal(id, CICP_ROWID_BAD);
  ci_assert(CICP_ROWID_IS_VALID(id));
  ci_assert_le(id, mib->dim->fwd_mask);
  return &mib->fwd[id];
}


static inline struct cp_fwd_row*
cp_get_fwd(struct cp_mibs* mib, cicp_verinfo_t* ver)
{
  return cp_get_fwd_by_id(mib, ver->id);
}

static inline struct cp_fwd_data*
cp_get_fwd_data(struct cp_mibs* mib, cicp_verinfo_t* ver)
{
  return &cp_get_fwd(mib, ver)->data[ver->version & 1];
}

static inline cp_version_t*
cp_fwd_version(struct cp_fwd_row* r)
{
  return &r->version;
}

static inline struct cp_fwd_data*
cp_get_fwd_data_current(struct cp_fwd_row* r)
{
  return &r->data[*cp_fwd_version(r) & 1];
}

static inline int
cp_fwd_version_matches(struct cp_mibs* mib, cicp_verinfo_t* ver)
{
  ci_assert_nequal(ver->id, CICP_ROWID_BAD);
  ci_assert(CICP_ROWID_IS_VALID(ver->id));
  return ver->version == *cp_fwd_version(cp_get_fwd(mib, ver));
}


static inline struct cp_fwd_rw_row*
cp_get_fwd_rw(struct cp_mibs* mib, cicp_verinfo_t* ver)
{
  ci_assert_nequal(ver->id, CICP_ROWID_BAD);
  ci_assert(CICP_ROWID_IS_VALID(ver->id));
  ci_assert_le(ver->id, mib->dim->fwd_mask);
  return &mib->fwd_rw[ver->id];
}


/* Set up cp_mibs structure from the mmaped memory;
 * caller must set mibs->dim before.
 * Return the size of memory used by MIBs. */
size_t cp_init_mibs(void* mem, struct cp_mibs* mibs);

/* The caller is responsible for version check before and after this
 * function is called. */
static inline cicp_rowid_t
cp_llap_find_row(struct cp_mibs* mib, ci_ifid_t ifindex)
{
  cicp_rowid_t i;

  ci_assert_nequal(ifindex, CI_IFID_BAD);

  for( i = 0; i < mib->dim->llap_max; i++ ) {
    if( mib->llap[i].ifindex == ifindex )
      return i;
    if( cicp_llap_row_is_free(&mib->llap[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}

/* The caller is responsible for version check before and after this
 * function is called. */
static inline cicp_rowid_t
cp_llap_by_ifname(struct cp_mibs* mib, const char* ifname)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->llap_max; i++ ) {
    if( strcmp(mib->llap[i].name, ifname) == 0 )
      return i;
    if( cicp_llap_row_is_free(&mib->llap[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}

/* The caller is responsible for version check before and after this
 * function is called. */
static inline cicp_rowid_t
cp_ipif_any_row_by_ifindex(struct cp_mibs* mib, ci_ifid_t ifindex)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->ipif_max; i++ ) {
    if( mib->ipif[i].ifindex == ifindex )
      return i;
    if( cicp_ipif_row_is_free(&mib->ipif[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}


static inline cicp_hwport_mask_t
cp_get_licensed_hwports(struct cp_mibs* mib, cicp_hwport_mask_t hwports, int flags)
{
  cicp_hwport_mask_t licensed_hwports = 0;

  for( ; hwports; hwports &= (hwports - 1) ) {
    ci_hwport_id_t id = cp_hwport_mask_first(hwports);
    if( cicp_hwport_row_is_free(&mib->hwport[id]) )
      continue;
    if( mib->hwport[id].flags & flags )
      licensed_hwports |= cp_hwport_make_mask(id);
  }

  return licensed_hwports;
}


extern int cp_get_acceleratable_llap_count(struct cp_mibs*);
extern int cp_get_acceleratable_ifindices(struct cp_mibs*,
                                          ci_ifid_t* ifindices, int max_count);
extern ci_ifid_t cp_get_hwport_ifindex(struct cp_mibs*, ci_hwport_id_t);


/* This is an arbitrary limit of re-hashing when searching or adding
 * destination in MAC or FWD tables. */
#define CP_REHASH_LIMIT(mask) ((mask) >> 2)

extern cicp_mac_rowid_t
cp_fwd_find_row(struct cp_mibs* mib, struct cp_fwd_key* key);
extern cicp_mac_rowid_t
__cp_fwd_find_match(struct cp_mibs* mib, struct cp_fwd_key* key,
                    ci_uint64 src_prefs, ci_uint64 dst_prefs);
static inline cicp_mac_rowid_t
cp_fwd_find_match(struct cp_mibs* mib, struct cp_fwd_key* key)
{
  ci_uint64 src_prefs = mib->fwd_prefix[CP_FWD_PREFIX_SRC];
  ci_uint64 dst_prefs = mib->fwd_prefix[CP_FWD_PREFIX_DST];
  return __cp_fwd_find_match(mib, key, src_prefs, dst_prefs);
}

static inline int ci_frc64_after(uint64_t old_frc, uint64_t new_frc)
{
  return (int64_t)(new_frc - old_frc) > 0;
}

/* If a fwd-table entry is marked UDP-only, but the query is not UDP-only, the
 * table entry should be promoted to a protocol-generic entry. */
static inline int /*bool*/
cp_fwd_udp_route_needs_promotion(struct cp_mibs* mib, cicp_mac_rowid_t id,
                                 struct cp_fwd_key* key)
{
  ci_assert_nequal(id, CICP_MAC_ROWID_BAD);
  /* "The row is a UDP-only entry for a non-UDP request." */
  return cp_get_fwd_by_id(mib, id)->key.flag & ~key->flag & CP_FWD_KEY_UDP;
}

/* Some route properties (currently, whether the request was originated by a
 * UDP socket) are not significant for lookup but should be checked when
 * deciding whether to issue a new request for the route.  This function
 * further checks the result of cp_fwd_find_row() for satisfaction of these
 * properties. */
static inline int /*bool*/
cp_fwd_find_row_found_perfect_match(struct cp_mibs* mib, cicp_mac_rowid_t id,
                                    struct cp_fwd_key* key)
{
  return id != CICP_MAC_ROWID_BAD &&
         ! cp_fwd_udp_route_needs_promotion(mib, id, key);
}


/* Bits for AF_UNIX message when asking to print the sp_server internal
 * state:
 * (1 << CP_SERVER_PRINT_STATE_FOO) | (1 << CP_SERVER_PRINT_STATE_BAR) | ...
 * 0 is considered to be equal to all-ones except STAT_DOC.
 */
#define CP_SERVER_PRINT_STATE_BASE  0
#define CP_SERVER_PRINT_STATE_DST   1
#define CP_SERVER_PRINT_STATE_SRC   2
#define CP_SERVER_PRINT_STATE_LLAP  3
#define CP_SERVER_PRINT_STATE_TEAM  4
#define CP_SERVER_PRINT_STATE_MAC   5
#define CP_SERVER_PRINT_STATE_FWD   6
#define CP_SERVER_PRINT_STATE_STAT  7
#define CP_SERVER_PRINT_STATE_MAC6  8
#define CP_SERVER_PRINT_STATE_DST6  9
#define CP_SERVER_PRINT_STATE_SRC6  10
#define CP_SERVER_PRINT_STATE_STAT_DOC 11 /* This one MUST be the last */


#endif /* __TOOLS_CPLANE_PUBLIC_H__ */
