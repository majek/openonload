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
** \author  cgg
**  \brief  Control Plane O/S Synchronization definitions
**   \date  2005/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_cplane_sync */

#ifndef __CI_DRIVER_EFAB_CPLANE_SYNC_H__
#define __CI_DRIVER_EFAB_CPLANE_SYNC_H__

/*! This file provides definitions are specific to given Operating System MIB
 *  synchronization scenario.  For example two versions of this header may be
 *  used to deal with Linux synchronization and with Windows synchronization
 *
 *  The prefix cicpos is used for definitions in this header:
 *       ci - our main prefix
 *       cp - control plane
 *       os - operating system synchronization
 */

/*----------------------------------------------------------------------------
 * Configuration
 *---------------------------------------------------------------------------*/

#define CICPOS_LLAP_NAMELEN_MAX 16

/*----------------------------------------------------------------------------
 * Address Resolution MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use the functions defined in
   <onload/cplane.h>
*/



typedef struct {
    ci_uint32 nl_msg_reject;     /*< # of rejected netlink neighbor msgs   */
    ci_uint32 poller_last_start; /*< last time poller was started          */
    ci_uint32 poller_last_end;   /*< last time poller ended                */
    ci_uint32 reinforcements;    /*< # of reinforcements                   */
} cicpos_mac_stat_t;


/*! Address Resolution table information used for synchonization that is
 *  O/S specific
 */
typedef struct
{   int                delete_unused; /* do our own purging of MAC entries */
    cicpos_mac_stat_t  stats;
} cicpos_mac_mib_t;


#define _cicpos_sys_ticks() (jiffies)

#define _CICPOS_MAC_STAT_SET_SYS_TICKS(_cplane, _fldname) \
        (_cplane)->mac_table->sync.stats._fldname = _cicpos_sys_ticks()

#define _CICPOS_MAC_STAT_INC(_cplane, _fldname) \
        ++((_cplane)->mac_table->sync.stats._fldname)

/* statistics access macros */

#define CICPOS_MAC_STAT_INC_NL_MSG_REJECT(_cplane) \
        _CICPOS_MAC_STAT_INC(_cplane, nl_msg_reject)
  
#define CICPOS_MAC_STAT_INC_REINFORCEMENTS(_cplane) \
        _CICPOS_MAC_STAT_INC(_cplane, reinforcements)
  
#define CICPOS_MAC_STAT_SET_POLLER_LAST_START(_cplane) \
        _CICPOS_MAC_STAT_SET_SYS_TICKS(_cplane, poller_last_start)

#define CICPOS_MAC_STAT_SET_POLLER_LAST_END(_cplane) \
       _CICPOS_MAC_STAT_SET_SYS_TICKS(_cplane, poller_last_end)


/*
 * Neighbor Cache Entry States
 * These values match those in the host os.
 * WARNING: if the host os values change then these need changing.
 * TODO: Introduce proper conversion functions for CICPOS_STATE_* constants.
 */
#define CICPOS_IPMAC_INCOMPLETE 0x01
#define CICPOS_IPMAC_REACHABLE  0x02
#define CICPOS_IPMAC_STALE      0x04
#define CICPOS_IPMAC_DELAY      0x08
#define CICPOS_IPMAC_PROBE      0x10
#define CICPOS_IPMAC_FAILED     0x20
#define CICPOS_IPMAC_NOARP      0x40
#define CICPOS_IPMAC_PERMANENT  0x80
#define CICPOS_IPMAC_NONE       0x00

#define CICPOS_IPMAC_CONNECTED \
       (CICPOS_IPMAC_NOARP | \
        CICPOS_IPMAC_PERMANENT | \
        CICPOS_IPMAC_REACHABLE)

#define CICPOS_IPMAC_VALID \
       (CICPOS_IPMAC_CONNECTED | \
        CICPOS_IPMAC_STALE | \
        CICPOS_IPMAC_DELAY | \
        CICPOS_IPMAC_PROBE)

struct cicpos_mac_row_sync_s
{   ci_iptime_t confirmed; /*< from nda_cacheinfo(rtnetlink.h) */
    ci_uint32   used;      /*< from nda_cacheinfo(rtnetlink.h) */
    ci_uint32   updated;   /*< from nda_cacheinfo(rtnetlink.h) */
    ci_uint32   refcnt;    /*< from nda_cacheinfo(rtnetlink.h) */
    
    ci_uint16   state;     /*< from Neighbor Cache Entry State(rtnetlink.h) */
    ci_uint8    flags;     /*< from Neighbor Cache Entry Flags(rtnetlink.h) */
    ci_uint8    family;    /*< address family (socket.h) */
} /* cicpos_mac_row_sync_t*/;




/*! Address Resolution entry information used for synchronization that is
    O/S-specific */
typedef struct
{   cicpos_mac_row_sync_t os;
    unsigned mapping_set; /*< time (jiffies) mapping last established */
    /* after each poll, if this flag is not set, the entry is deleted */
    unsigned    source_sync:1,  /*< os field only valid if this is 1 */
	        source_prot:1,  /*< entry has been set by protocol   */
		recent_sync:1;  /*< entry has been seen recently */
} cicpos_mac_row_t;



/*! Indicate that this entry has just been synchronized with the O/S
 */
extern void cicpos_mac_row_synced(cicpos_mac_row_t *row);



/*! Check whether this row has been synced since this function was last
 *  called
 */
extern int /* bool */ cicpos_mac_row_recent(cicpos_mac_row_t *sync);
    



/*----------------------------------------------------------------------------
 * kernel routing MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use the functions defined in
   <onload/cplane.h>
*/

/*! Synchronization-support module-specific per-entry information */
typedef struct
{   /* after each poll, if this flag is not set, the entry is deleted */
    ci_uint8 confirmed_on_last_poll;
} cicpos_route_row_t;



/*----------------------------------------------------------------------------
 * kernel access point MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use the functions defined in
   <onload/cplane.h>
*/

typedef struct
{   char name[CICPOS_LLAP_NAMELEN_MAX+1]; /*< interface name e.g. eth0 */
    /*! after each poll, if this flag is not set, the entry is deleted */
    ci_uint8 confirmed_on_last_poll;
} cicpos_llap_row_t;


/*----------------------------------------------------------------------------
 * /proc statistics
 *---------------------------------------------------------------------------*/

extern const struct file_operations cicp_stat_fops;


/*----------------------------------------------------------------------------
 * overall control plane
 *---------------------------------------------------------------------------*/


extern int cicpos_running;


#endif /* __CI_DRIVER_EFAB_CPLANE_SYNC_H__ */
/*! \cidoxg_end */
