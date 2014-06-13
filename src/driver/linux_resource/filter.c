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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains /proc/driver/sfc_resource/ implementation.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
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
#include <linux/device.h>
#include "linux_resource_internal.h"
#include "kernel_compat.h"
#include <ci/driver/internal.h>
#include <ci/tools/byteorder.h>
#include <ci/net/ipv4.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/kernel_proc.h>

/* ************************************* */
/* Types, not needed outside this module */
/* ************************************* */

struct efrm_filter_rule_s;
struct efrm_filter_table_s;

typedef enum efrm_protocol_e {
	ep_tcp        = 0,
	ep_udp        = 1,
	ep_ip         = 2,
	ep_eth        = 3
} efrm_protocol_t; 

typedef struct efrm_filter_table_s
{
	struct efrm_filter_rule_s*    efrm_ft_first_rule;
	struct efrm_filter_rule_s*    efrm_ft_last_rule;
	struct efrm_filter_table_s*   efrm_ft_prev;
	struct efrm_filter_table_s*   efrm_ft_next;
	char*                         efrm_ft_interface_name;
	char*                         efrm_ft_pcidev_name;
	efrm_pd_handle                efrm_ft_directory;
	efrm_pd_handle                efrm_ft_rules_file;
} efrm_filter_table_t;

typedef enum efrm_filter_ruletype_e
{
	EFRM_FR_PORTRANGE,
	EFRM_FR_MACADDRESS
} efrm_filter_ruletype_t;

typedef enum efrm_filter_action_e {
	EFRM_FR_ACTION_UNSUPPORTED  = 0,
	EFRM_FR_ACTION_ACCEPT,
	EFRM_FR_ACTION_DROP
} efrm_filter_action_t;

typedef struct efrm_filter_rule_portrange_s {
	unsigned short        efrp_lcl_min;
	unsigned short        efrp_lcl_max;
	unsigned short        efrp_rmt_min;
	unsigned short        efrp_rmt_max;
	__be32                efrp_lcl_ip;
	__be32                efrp_rmt_ip;
	__be32                efrp_lcl_mask;
	__be32                efrprmtl_mask;
} efrm_filter_rule_portrange_t;

typedef struct efrm_filter_rule_macaddress_s {
	char                  efrm_lcl_mac     [6];
	char                  efrm_lcl_mask    [6];
	unsigned short        efrm_vlan_id;
} efrm_filter_rule_macaddress_t;

typedef struct efrm_filter_rule_s
{
	efrm_filter_ruletype_t                eit_ruletype;
	union {
		efrm_filter_rule_portrange_t  efr_range;
		efrm_filter_rule_macaddress_t efr_macaddess;
	}                                     efrm_rule;
	unsigned char                         efr_protocol;
	efrm_filter_action_t                  efr_action;

	struct efrm_filter_rule_s*            efrm_fr_next;
}  efrm_filter_rule_t;

/* ******* */
/* Globals */
/* ******* */

static DEFINE_SPINLOCK(efrm_ft_lock);
static DEFINE_MUTEX(efrm_ft_mutex);
static efrm_filter_table_t* efrm_ft_root_table = NULL;
static char const* efrm_protocol_names[5] = {
	"tcp",
	"udp",
	"ip",
	"eth",
	"???"
};
static char const* efrm_action_names[3] = { "???" , "ACCEPT", "DECELERATE" };
static efrm_pd_handle efrm_pd_add_rule = NULL;
static efrm_pd_handle efrm_pd_del_rule = NULL;

/* ************************************************************ */
/* String parsing code.  sscanf() isn't available in the kernel */
/* ************************************************************ */

static int efrm_atoi( const char** src, size_t* length )
{
	/* This function works much like atoi, but modifies its inputs to make
	   progress through the data stream. */
	int rval = 0;
	int multiplier = 1;
	if ( !*length ) return -1;

	if ( **src == '-' ) {
		*src = *src + 1;
		*length = *length - 1;
		multiplier = -1;
	}

	while ( *length ) {
		char c = **src;
		if ( c >= '0' && c <= '9' ) {
			rval *= 10;
			rval += ( c - '0' );
		}
		else {
			break;
		}
		*src = *src + 1;
		*length = *length - 1;
	}
	return rval * multiplier;
}

static int efrm_hextoi( const char** src, size_t* length )
{
	/* This function works much like atoi, but modifies its inputs to make
	   progress through the data stream. */
	int rval = 0;
	while ( length ) {
		char c = **src;
		if ( c >= '0' && c <= '9' ) {
			rval *= 16;
			rval += ( c - '0' );
		}
		else if ( c >= 'a' && c <= 'f' ) {
			rval *= 16;
			rval += 10 + ( c - 'a' );
		}
		else if ( c >= 'A' && c <= 'F' ) {
			rval *= 16;
			rval += 10 + ( c - 'A' );
		}
		else {
			break;
		}
		*src = *src + 1;
		*length = *length - 1;
	}
	return rval;
}


static void efrm_skip_num( const char** src, size_t* length, int num )
{
	/* Skip forward num characetrs */
	if ( *length < num )
		num = *length;
	*length = *length - num;
	*src = *src + num;
}

static void efrm_skip_whitespace( const char** src, size_t* length )
{
	/* Skip past arbitary whitespace */
	while ( length ) {
		char c = **src;
		if ( c != ' ' && c != '\t' && c != '\r' && c != '\0' )
			break;
		*src = *src + 1;
		*length = *length - 1;
	}
}

static int efrm_consume_next_word( const char** src, size_t* length,
                                   char* dest, size_t destlen )
{
	/* Read non-whitespace until you run out of buffer, or reach
	   whitespace.*/
	int rval = 0;
	
	if ( !src || !*src || !length || !dest )
		return -EINVAL;
	
	while ( length && destlen ) {
		char c = **src;
		if ( c == ' ' || c == '\t' || c == '\r'
		  || c == '\n' || c == '\0' ) {
			*dest = '\0';
			break;
		}
		*dest++ = c;
		*src = *src + 1;
		*length = *length - 1;
		destlen--;
		rval++;
	}
	return rval;
}

static int efrm_compare_and_skip( const char** src, size_t* length,
                                  char const* compare )
{
	/* Returns strncmp() and moves on if it matches. */
	size_t compare_length;
	int mismatch;
	
	compare_length = strlen(compare);
	mismatch = strncmp( *src, compare, compare_length );
	if ( compare_length > *length ) {
		return -1;
	}
	
	if ( !mismatch ) {
		efrm_skip_num( src, length, compare_length );
	}
	return mismatch;
}

static int efrm_consume_portrange( const char** src, size_t* length,
                                   unsigned short* low, unsigned short* high )
{
	/* Matches (\d+)[:(\d+)] outputting the matches.  Returns 0 if ok. */
	*low = efrm_atoi( src, length );
	*high = *low;
	if ( efrm_compare_and_skip( src, length, ":" ) == 0
			 || efrm_compare_and_skip( src, length, "-" ) == 0 ) {
		*high = efrm_atoi( src, length );
	}
	if ( *low > *high ) return -EINVAL;
	return 0;
}

static int efrm_fill_top_bits( int n, unsigned char* out, int length )
{
	/* Used for making masks, sets the top n bits of a buffer.
	   Does not cleasr the other bits. */
	int w;
	if ( n < 0 || (n > length * 8) )
		return 0;
	
	w = 0;
	while ( n > 0 ) {
		unsigned char c = 0;
		if ( n >= 8 ) {
			c = 0xff;
			n -= 8;
		}
		else {
			for ( ; n>0; --n )
			{
				c >>= 1;
				c |= 0x80;
			}
		}
		out[w++] = c;
	}
	return 1;
}

static int efrm_get_ip_trit( const char** src, size_t* length, ci_uint8* ip )
{
	/* Reads "0" to "255" and returns 0 if the value was in range. */
	int v = efrm_atoi( src, length );
	if ( v < 0 || v > 255 ) return -EINVAL;
	*ip = (ci_uint8) ( v&255 );
	return 0;
}

static int efrm_consume_ip_mask( const char** src, size_t* length,
                                 __be32* ip, __be32* mask )
{
	/* Reads a standard IPv4 address and mask, in either form.
	   Expect to consume a.b.c.d, possibly with suffix of /e.f.g.h or /n */
	ci_uint8* ip_ptr = (ci_uint8*) ip;
	ci_uint8* mask_ptr = (ci_uint8*) mask;
	if ( efrm_get_ip_trit( src, length, ip_ptr + 0 ) < 0 )	return 0;
	if ( efrm_compare_and_skip( src, length, "." ) != 0 )	 return 0;
	if ( efrm_get_ip_trit( src, length, ip_ptr + 1 ) < 0 )	return 0;
	if ( efrm_compare_and_skip( src, length, "." ) != 0 )	 return 0;
	if ( efrm_get_ip_trit( src, length, ip_ptr + 2 ) < 0 )	return 0;
	if ( efrm_compare_and_skip( src, length, "." ) != 0 )	 return 0;
	if ( efrm_get_ip_trit( src, length, ip_ptr + 3 ) < 0 )	return 0;
	
	if ( efrm_compare_and_skip( src, length, "/" ) != 0 ) {
		*mask = 0;
	}
	else {
		if ( efrm_get_ip_trit( src, length, mask_ptr + 0 ) < 0 )
			return 0;
		if ( efrm_compare_and_skip( src, length, "." ) != 0 )
			return efrm_fill_top_bits( mask_ptr[0], mask_ptr, 4 );
		if ( efrm_get_ip_trit( src, length, mask_ptr + 1 ) < 0 )
			return 0;
		if ( efrm_compare_and_skip( src, length, "." ) != 0 )
			return 0;
		if ( efrm_get_ip_trit( src, length, mask_ptr + 2 ) < 0 )
			return 0;
		if ( efrm_compare_and_skip( src, length, "." ) != 0 )
			return 0;
		if ( efrm_get_ip_trit( src, length, mask_ptr + 3 ) < 0 )
			return 0;
	}
	return 1;
}

static int efrm_consume_mac( const char** src, size_t* length,
                             unsigned char* mac, unsigned char* mask )
{
	/* Consumes a mac address, with mask.  Colon separated. */
	memset( mac, 0, 6 );
	memset( mask, 0xff, 6 );
	
	mac[0] = efrm_hextoi( src, length );
	if ( efrm_compare_and_skip( src, length, ":" ) != 0
		&& efrm_compare_and_skip( src, length, "-" ) != 0 )
		return 0;
	mac[1] = efrm_hextoi( src, length );
	if ( efrm_compare_and_skip( src, length, ":" ) != 0
		&& efrm_compare_and_skip( src, length, "-" ) != 0 )
		return 0;
	mac[2] = efrm_hextoi( src, length );
	if ( efrm_compare_and_skip( src, length, ":" ) != 0
		&& efrm_compare_and_skip( src, length, "-" ) != 0 )
		return 0;
	mac[3] = efrm_hextoi( src, length );
	if ( efrm_compare_and_skip( src, length, ":" ) != 0
		&& efrm_compare_and_skip( src, length, "-" ) != 0 )
		return 0;
	mac[4] = efrm_hextoi( src, length );
	if ( efrm_compare_and_skip( src, length, ":" ) != 0
		&& efrm_compare_and_skip( src, length, "-" ) != 0 )
		return 0;
	mac[5] = efrm_hextoi( src, length );
	
	if ( efrm_compare_and_skip( src, length, "/" ) == 0 ) {
		mask[0] = efrm_hextoi( src, length );
		if ( efrm_compare_and_skip( src, length, ":" ) != 0
			&& efrm_compare_and_skip( src, length, "-" ) != 0 ) {
			return efrm_fill_top_bits(
				efrm_atoi(src, length), mask, 6 );
			}
		mask[1] = efrm_hextoi( src, length );
		if ( efrm_compare_and_skip( src, length, ":" ) != 0
			&& efrm_compare_and_skip( src, length, "-" ) != 0 )
			return 0;
		mask[2] = efrm_hextoi( src, length );
		if ( efrm_compare_and_skip( src, length, ":" ) != 0
			&& efrm_compare_and_skip( src, length, "-" ) != 0 )
			return 0;
		mask[3] = efrm_hextoi( src, length );
		if ( efrm_compare_and_skip( src, length, ":" ) != 0
			&& efrm_compare_and_skip( src, length, "-" ) != 0 )
			return 0;
		mask[4] = efrm_hextoi( src, length );
		if ( efrm_compare_and_skip( src, length, ":" ) != 0
			&& efrm_compare_and_skip( src, length, "-" ) != 0 )
			return 0;
		mask[5] = efrm_hextoi( src, length );
	}
	
	return 1;
}

static char const* efrm_get_protocol_name( efrm_protocol_t proto )
{
	/* Turns a protocol into a printable name */
	if ( proto < 0 || proto > 3 ) 
		return efrm_protocol_names[4];

	return efrm_protocol_names[proto];
}

static int
efrm_protocol_matches( struct efx_filter_spec *spec, efrm_protocol_t proto )
{
	/* Returns a truth value - does the spec match the protocol? */
	switch (spec->type) {
	case EFX_FILTER_TCP_FULL:
	case EFX_FILTER_TCP_WILD:
		return (proto == ep_tcp) || (proto==ep_ip);
	case EFX_FILTER_UDP_FULL:
	case EFX_FILTER_UDP_WILD:
		return (proto == ep_udp) || (proto==ep_ip);
	case EFX_FILTER_MAC_FULL:
	case EFX_FILTER_MAC_WILD:
		return proto == ep_eth;
	}
	return 0;
}


static char const* efrm_get_action_name( efrm_filter_action_t action )
{
	/* Turn an action into a printable string. */
	if ( action < 1 || action > 2 )
		return efrm_action_names[0];
	return efrm_action_names[action];
}

static inline char const* efrm_get_pciname_from_device( struct device* dev )
{
	/* This returns something of the form 0000:13:00.0
	   This matches the PHYSICAL port, but is unique */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	return dev ? dev->bus_id : NULL;
#else
	return dev_name(dev);
#endif
}

static char const*
efrm_get_interefacename_from_index( int ifindex, struct net_device** ndev )
{
	/* This returns something of the form eth4, but can only be found when
	   driver is initialised.
	   You MUST call dev_put(ndev) when you're done with it. */
	char const* dev_name = NULL;
	*ndev = dev_get_by_index(&init_net, ifindex);
	if (*ndev) {
		dev_name = (*ndev)->name;
	}
	return dev_name;
}

static int
efrm_correct_table_ifname( efrm_filter_table_t* table, char const* ifname )
{
	/* Returns a truth value, is this table for the given interface? */
	if ( !table )
		return 0;
	return strcmp( ifname, table->efrm_ft_interface_name ) == 0;
}

static int
efrm_correct_table_pciname( efrm_filter_table_t* table, char const* pciname )
{
	/* Returns a truth value, is this table for the given port? */
	if ( !table || !pciname || !table->efrm_ft_pcidev_name ) {
		EFRM_ERR("%s: Internal err %p %p", __func__, table, pciname );
		return 0;
	}
	return strcmp( pciname, table->efrm_ft_pcidev_name ) == 0;
}

/* ******************************************************************** */
/* Table/Rule manipulation functions - these spinlock and the only ones */
/* ******************************************************************** */
static void ethrm_link_table( efrm_filter_table_t* table )
{
	/* Add the table to the root list of tables. */
	spin_lock_bh(&efrm_ft_lock);
	table->efrm_ft_prev = NULL;
	table->efrm_ft_next = efrm_ft_root_table;
	if ( efrm_ft_root_table ) {
		efrm_ft_root_table->efrm_ft_prev = table;
	}
	efrm_ft_root_table = table;

	spin_unlock_bh(&efrm_ft_lock);
}
static void ethrm_unlink_table( efrm_filter_table_t* table )
{
	/* Remove the table from the list of tables. */
	if ( !table ) return;

	spin_lock_bh(&efrm_ft_lock);

	/* Update links to other tables */
	if ( table->efrm_ft_prev )
		table->efrm_ft_prev->efrm_ft_next = table->efrm_ft_next;
	if ( table->efrm_ft_next )
		table->efrm_ft_next->efrm_ft_prev = table->efrm_ft_prev;
	
	/* Update the root of the table, if needed. */
	if ( efrm_ft_root_table == table ) {
		efrm_ft_root_table = table->efrm_ft_next;
	}
	
	/* Added safety; make sure this table won't be matched in future */
	*table->efrm_ft_interface_name = '\0';
	*table->efrm_ft_pcidev_name = '\0';

	spin_unlock_bh(&efrm_ft_lock);
}


static void
ethrm_link_rule( efrm_filter_rule_t* rule, efrm_filter_table_t* table,
                 efrm_filter_rule_t* prev, efrm_filter_rule_t* next )
{
	/* Add the rule into the table, between prev and next. */
	spin_lock_bh(&efrm_ft_lock);

	/* Insert it in place. */
	if ( prev ) {
		rule->efrm_fr_next = next;
		prev->efrm_fr_next = rule;
	}
	else {
		/* Was the previous NULL?  Then we're start of table. */
		rule->efrm_fr_next = table->efrm_ft_first_rule;
		table->efrm_ft_first_rule = rule;
	}
	
	/* Was the previous the end of the table?  Update that. */
	if ( prev == table->efrm_ft_last_rule ) {
		table->efrm_ft_last_rule = rule;
	}

	spin_unlock_bh(&efrm_ft_lock);
}

static void
ethrm_unlink_rule( efrm_filter_rule_t* rule, efrm_filter_table_t* table,
                   efrm_filter_rule_t* prev )
{
	/* Remove the rule from the table, pulling up prev into its place. */
	spin_lock_bh(&efrm_ft_lock);

	/* Special handling for first rule */
	if ( !prev ) {
		table->efrm_ft_first_rule = rule->efrm_fr_next;
	}
	else {
		prev->efrm_fr_next = rule->efrm_fr_next; 
	}

	/* Special handling for last rule */
	if ( rule == table->efrm_ft_last_rule ) {
		table->efrm_ft_last_rule = prev;
	}

	spin_unlock_bh(&efrm_ft_lock);
}


/* ***************************************************************** */
/* Allocation/Removal functions, must be mutexed, but not spinlocked */
/* ***************************************************************** */

static void efrm_remove_files( efrm_filter_table_t* table )
{
	/* Remove the /proc/ files associated with this table. */
	if ( table && table->efrm_ft_rules_file ) {
		efrm_proc_remove_file( table->efrm_ft_rules_file );
		table->efrm_ft_rules_file = NULL;
	}
	if ( table && table->efrm_ft_directory ) {
		efrm_proc_dir_put(table->efrm_ft_directory);
		table->efrm_ft_directory = NULL;
	}
}

static void efrm_add_files( efrm_filter_table_t* table )
{
	/* Create the /proc/ files for this table. */
	if ( !table || !table->efrm_ft_first_rule )
		return;
	if ( !table->efrm_ft_directory ) {
		char const* ifname = table->efrm_ft_interface_name;
		table->efrm_ft_directory = efrm_proc_dir_get( ifname );
	}
	if ( table->efrm_ft_directory && !table->efrm_ft_rules_file ) {
		table->efrm_ft_rules_file = efrm_proc_create_file(
				"firewall_rules", 0444,
				table->efrm_ft_directory,
				efrm_read_rules, NULL, table
				);
	}
}

static int
find_table_by_ifname( char const* ifname, efrm_filter_table_t** table )
{
	/* Find a table matching this interface name.
	   Returns a truth value, outputs the table. */
	efrm_filter_table_t* cur_table = efrm_ft_root_table;
	while ( cur_table ) {
		if ( efrm_correct_table_ifname( cur_table, ifname ) ) {
			*table = cur_table;
			return 1;
		}
		cur_table = cur_table->efrm_ft_next;
	}
	return 0;
}

static int
find_table_by_pcidevice( char const* pciname, efrm_filter_table_t** table )
{
	/* Find a table matching this pci device name.
	   Returns a truth value, outputs the table. */
	efrm_filter_table_t* cur_table = efrm_ft_root_table;
	
	if ( !pciname || !table ) {
		EFRM_ERR("%s:Internal error %p %p", __func__, pciname, table );
		return 0;
	}
	
	
	while ( cur_table ) {
		if ( efrm_correct_table_pciname( cur_table, pciname ) ) {
			*table = cur_table;
			return 1;
		}
		cur_table = cur_table->efrm_ft_next;
	}
	return 0;
}

static int
interface_has_rules( char const* ifname )
{
	efrm_filter_table_t* table;
	int got_table = find_table_by_ifname( ifname, &table );
	if ( got_table ) {
		return table->efrm_ft_first_rule != NULL;
	}
	return 0;
}

static efrm_filter_table_t*
efrm_allocate_new_table( char const* pci_name, char const* if_name )
{
	/* Allocates a new, efrm_filter_table_t structure, fills in the name,
	   and plugs it into the table list.
	   Returns the table, or NULL if kmalloc() fails.
	   MUST NOT BE IN THE SPINLOCK */
	static const size_t size = sizeof(efrm_filter_table_t)
	                           + IFNAMSIZ + IFNAMSIZ;
	char* buf = (char*) kmalloc( size, GFP_KERNEL );
	efrm_filter_table_t* table = (efrm_filter_table_t*) buf;
	if ( table ) {
		char* interface_name = buf + sizeof(efrm_filter_table_t);
		char* pcidev_name = buf
		                     + sizeof(efrm_filter_table_t) + IFNAMSIZ;
		
		interface_name[0] = '\0';
		pcidev_name[0] = '\0';
		
		table->efrm_ft_first_rule = NULL;
		table->efrm_ft_last_rule = NULL;
		table->efrm_ft_prev = NULL;
		table->efrm_ft_next = NULL;
		table->efrm_ft_pcidev_name = pcidev_name;
		table->efrm_ft_interface_name = interface_name;
		if ( pci_name ) {
			strlcpy( pcidev_name, pci_name, IFNAMSIZ );
		}
		if ( if_name ) {
			strlcpy( interface_name, if_name, IFNAMSIZ );
		}
		table->efrm_ft_directory = NULL;
		table->efrm_ft_rules_file = NULL;
	}
	return table;
}

static efrm_filter_table_t*
efrm_insert_new_table( char const* pci_name, char const* if_name )
{
	/* Create and link a table with these names. */
	efrm_filter_table_t* table = efrm_allocate_new_table(pci_name,
	                                                     if_name );
	if ( table ) {
		ethrm_link_table( table );
	}
	return table;
}

static int
add_rule_to_table( efrm_filter_table_t* table, efrm_filter_rule_t* rule,
                   int position )
{
	/* Insert the given rule at the assigned position -
	   negative positions mean "At end"
	   Returns 0 (no errors are currently possible). */

	efrm_filter_rule_t* next;
	efrm_filter_rule_t* prev;
	
	if ( !table || !rule ) {
		return -EINVAL;
	}

	 /* Find the entry previous to this in the table. */
	if ( position < 0 ) {
		prev = table->efrm_ft_last_rule;
		next = NULL;
		position = 0;
	} else {
		prev = NULL;
		next = table->efrm_ft_first_rule;
		while ( position > 0 && next ) {
			prev = next;
			next = next->efrm_fr_next;
			position -= 1;
		}
	}
	
	if ( position ) {
		EFRM_ERR( "%s: Rule is %d beyond the end, adding instead.",
				__func__, position );
		prev = table->efrm_ft_last_rule;
		next = NULL;
	}
	/* And put the new rule into the table */
	ethrm_link_rule( rule, table, prev, next );
	/* In case this was the first rule, create the access files */
	efrm_add_files( table );
	
	return 0;
}

static int
remove_rule_from_table( efrm_filter_table_t* table, int position )
{
	/* Remove the nth rule from a table. */

	efrm_filter_rule_t* prev_rule = NULL;
	efrm_filter_rule_t* rule = NULL;
	int rc = 0;

	rule = table->efrm_ft_first_rule;
	
	/* Walk to the correct rule. */
	while ( rule && position ) {
		prev_rule = rule;
		rule = rule->efrm_fr_next;
		position -= 1;
	}
	if ( rule ) {
		ethrm_unlink_rule( rule, table, prev_rule );
		kfree( rule );
		/* If there are no rules, remove the associated files */
		if ( !table->efrm_ft_first_rule ) {
			efrm_remove_files( table );
		}
	} else {
		/* Insufficient rules in table. */
		rc = -EINVAL;
	}
	
	return rc;
}

static void remove_all_rules_from_table( efrm_filter_table_t* table )
{
	/* Remove all the rules from the table */

	efrm_filter_rule_t* rule = table->efrm_ft_first_rule;
	while ( rule ) {
		efrm_filter_rule_t* next = rule->efrm_fr_next;
		kfree( rule );
		rule = next;
	}
	table->efrm_ft_first_rule = NULL;
	table->efrm_ft_last_rule = NULL;
	efrm_remove_files( table );
}

static int remove_table( efrm_filter_table_t* table )
{
	/* Free up a table, maintaining the table of tables.
	   Returns zero or a negative value on failure */
	if ( !table )
		return -EINVAL;
	ethrm_unlink_table(table);
	remove_all_rules_from_table(table);
	kfree( table );
	return 0;
}


static int remove_all_rules( char const* ifname )
{
	/* Remove all rules associated with a device.
	   Returns 0 on success, or a negative failure value. */
	efrm_filter_table_t* table;
	int rc = -EINVAL;
	int found;
	
	found = find_table_by_ifname( ifname, &table );
	if ( found ) {
		remove_all_rules_from_table(table);
		rc = 0;
	}
	return rc;
}


static int remove_rule( char const* ifname, int position )
{
	/* Remove the the rule at position from the table associated with
	   this device.
	   Returns 0 or a negative error code. */
	efrm_filter_table_t* table;
	int found = find_table_by_ifname( ifname, &table );
	if ( !found )
		return -EINVAL;
	return remove_rule_from_table( table, position );
}

static ssize_t
print_rule ( char* buf, char const* iface, int max_num,
             efrm_filter_rule_t* rule, int number )
{
	/* Print a rule in a human readable form (that the parser can read
	   back in) to the specified buffer.
	   Returns the number of characters printed. */

	/* TODO: Really should indicate a desire to print past the end of the
	   buffer, and handle the user reading further. */
	char const* action_name = efrm_get_action_name( rule->efr_action );
	if ( rule->efr_protocol == ep_eth ) {
		return scnprintf( buf, max_num, "if=%s rule=%d protocol=eth "
			"mac=%02x:%02x:%02x:%02x:%02x:%02x"
			"/%02x:%02x:%02x:%02x:%02x:%02x action=%s\n",
			iface ? iface : "?", number,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mac[0] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mac[1] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mac[2] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mac[3] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mac[4] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mac[5] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mask[0] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mask[1] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mask[2] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mask[3] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mask[4] & 0xff,
			(unsigned char) rule->efrm_rule.efr_macaddess.efrm_lcl_mask[5] & 0xff,
			action_name );
	} else {
		return scnprintf( buf, max_num, "if=%s rule=%d protocol=%s"
			" local_ip=" CI_IP_PRINTF_FORMAT "/" CI_IP_PRINTF_FORMAT
			" remote_ip=" CI_IP_PRINTF_FORMAT "/" CI_IP_PRINTF_FORMAT
			" local_port=%d-%d remote_port=%d-%d action=%s\n",
			iface ? iface : "?", number,
			efrm_get_protocol_name( rule->efr_protocol ),
			CI_IP_PRINTF_ARGS( &rule->efrm_rule.efr_range.efrp_lcl_ip ),
			CI_IP_PRINTF_ARGS( &rule->efrm_rule.efr_range.efrp_lcl_mask ),
			CI_IP_PRINTF_ARGS( &rule->efrm_rule.efr_range.efrp_rmt_ip ),
			CI_IP_PRINTF_ARGS( &rule->efrm_rule.efr_range.efrprmtl_mask ),
			rule->efrm_rule.efr_range.efrp_lcl_min,
			rule->efrm_rule.efr_range.efrp_lcl_max,
			rule->efrm_rule.efr_range.efrp_rmt_min,
			rule->efrm_rule.efr_range.efrp_rmt_max,
			action_name );
	}
}

static ssize_t
efrm_print_all_rules( efrm_filter_table_t* table, char* buf, int max_bytes )
{
	/* Print all the rules from a table into the given buffer. */
	efrm_filter_rule_t* rule;
	int rule_number = 0;
	char* next_buf = buf;
	int bytes_remaining = max_bytes;
	ssize_t total_bytes_used = 0;

	if ( !table || !buf || !max_bytes )
		return 0;

	rule = table->efrm_ft_first_rule;
	while ( rule && total_bytes_used < bytes_remaining ) {
		int bytes_used = print_rule(next_buf,
				    table->efrm_ft_interface_name,
				    bytes_remaining-total_bytes_used,
				    rule, rule_number++ );
		next_buf += bytes_used;
		total_bytes_used += bytes_used;
		rule = rule->efrm_fr_next;
	}
	return total_bytes_used;
}

/* TODO: I think these can be included now, rather than copied here */
static inline int __efx_filter_get_ipv4(const struct efx_filter_spec *spec,
					 __be32 *host1, __be16 *port1,
					 __be32 *host2, __be16 *port2)
{
	*host1 = htonl(spec->data[0] >> 16 | spec->data[1] << 16);
	*port1 = htons(spec->data[0]);
	*host2 = htonl(spec->data[2]);
	*port2 = htons(spec->data[1] >> 16);
	return 0;
}

/* As __efx_filter_get_ipv4 is ONLY correct in some circumstances -
	use this which checks the ->type field first */
static inline int efx_filter_get_ipv4(const struct efx_filter_spec *spec,
					 __be32 *host1, __be16 *port1,
					 __be32 *host2, __be16 *port2)
{
	__be32 ignored_host;
	__be16 ignored_port;
	switch (spec->type) {
	case EFX_FILTER_TCP_FULL:
	case EFX_FILTER_UDP_FULL:
		return __efx_filter_get_ipv4( spec, host1, port1,
						host2, port2 );
	case EFX_FILTER_TCP_WILD:
		*host1 = 0;
		*port1 = 0;
		return __efx_filter_get_ipv4(spec, &ignored_host,
						&ignored_port, host2, port2);
	case EFX_FILTER_UDP_WILD:
		*host1 = 0;
		*port1 = 0;
		return __efx_filter_get_ipv4(spec, &ignored_host, port2,
						host2, &ignored_port);
	default:
		return -EINVAL;
	}
}

static inline int
efx_filter_get_mac(const struct efx_filter_spec *spec, u8 *addr, u16* vid )
{
	switch (spec->type) {
	case EFX_FILTER_MAC_WILD:
		*vid = EFX_FILTER_VID_UNSPEC;
		break;
	case EFX_FILTER_MAC_FULL:
		*vid = spec->data[0];
		break;
	default:
		return -EINVAL;
	}

	addr[0] = spec->data[2] >> 8;
	addr[1] = spec->data[2];
	addr[2] = spec->data[1] >> 24;
	addr[3] = spec->data[1] >> 16;
	addr[4] = spec->data[1] >> 8;
	addr[5] = spec->data[1];
	return 0;
}

static inline int efrm_filter_check (struct efx_dl_device *dl_dev,
                                     struct efx_filter_spec *spec)
{
	/* This is the function that actually checks whether a filter spec
	   matches one of the rules for this interface.
	  Returns -EACCES if the filter should be dropped, zero otherwise
	   (including if it matches an ACCEPT rule)
	   As it runs at driver level, it cannot grab the mutex; so it must
	   take the spinlock instead.
	*/
	__be32 host1 = 0, host2 = 0;
	__be16 port1 = 0, port2 = 0;
	int local_port, remote_port;
	int is_udp;
	int found;
	efrm_filter_action_t rc = EFRM_FR_ACTION_UNSUPPORTED;
	efrm_filter_rule_t* rule = NULL;
	efrm_filter_table_t* table = NULL;
	char const* pciname = efrm_get_pciname_from_device(
	                                &dl_dev->pci_dev->dev);
	int unsupported = 0;

	spin_lock_bh(&efrm_ft_lock);
	
	found = find_table_by_pcidevice( pciname, &table );
	if ( !found ) {
		/* No rules for this interface, so accept. */
		goto check_filter_complete;
	}
	rule = table->efrm_ft_first_rule;
	is_udp = (spec->type == EFX_FILTER_UDP_FULL
	        || spec->type == EFX_FILTER_UDP_WILD);
	
	efx_filter_get_ipv4(spec, &host1, &port1, &host2, &port2);
	/* TODO: Ensure endianness of ef_iptble in a nicer way that this. */
	remote_port = CI_BSWAP_BE16(port1);
	local_port = CI_BSWAP_BE16(port2);
	
	while ( rule )
	{
		if ( rule->eit_ruletype == EFRM_FR_PORTRANGE ) {
		  /* TODO: Make this block of code more readable */
		  int protocol_matches = efrm_protocol_matches(spec,
		                                         rule->efr_protocol );
		  int local_port_matches =
		        (rule->efrm_rule.efr_range.efrp_lcl_min <= local_port )
		   && ( rule->efrm_rule.efr_range.efrp_lcl_max >= local_port );
		  int remote_port_matches =
		        ( rule->efrm_rule.efr_range.efrp_rmt_min<=remote_port )
		   &&	( rule->efrm_rule.efr_range.efrp_rmt_max>=remote_port );
		  int remote_ip_matches = !host1 ||
		    ( ( host1 & rule->efrm_rule.efr_range.efrprmtl_mask )
		    == ( rule->efrm_rule.efr_range.efrp_rmt_ip
		         & rule->efrm_rule.efr_range.efrprmtl_mask ) );
		  int local_ip_matches = !host2 ||
		    ( ( host2 & rule->efrm_rule.efr_range.efrp_lcl_mask )
		    == ( rule->efrm_rule.efr_range.efrp_lcl_ip
		         & rule->efrm_rule.efr_range.efrp_lcl_mask ) );

		  if (   protocol_matches
		      && local_port_matches
		      && remote_port_matches
		      && local_ip_matches
		      && remote_ip_matches
		  ) {
			/* Matched rule, take its action and stop */
			/* TODO: Is that correct with a wildcard accept? */
			rc = rule->efr_action;
			break;
		  }
		}
		else if ( rule->eit_ruletype == EFRM_FR_MACADDRESS ) {
		  int is_mac = (   spec->type == EFX_FILTER_MAC_FULL
		                || spec->type == EFX_FILTER_MAC_WILD);
		  if ( is_mac ) {
		    u16 vlan_id = 0;
		    char addr[6];
		    int i;
		    int match;
		    
		    efx_filter_get_mac(spec, addr, &vlan_id );
		    match = (vlan_id == rule->efrm_rule.efr_macaddess.efrm_vlan_id)
		         || (vlan_id == EFX_FILTER_VID_UNSPEC);
		    
		    for ( i=0; match && i<6; ++i ) {
		        match &= (rule->efrm_rule.efr_macaddess.efrm_lcl_mask[i]
		               & rule->efrm_rule.efr_macaddess.efrm_lcl_mac[i] )
		             == ( rule->efrm_rule.efr_macaddess.efrm_lcl_mask[i]
		               & addr[i] );
		    }

		    if ( match ) {
		    	rc = rule->efr_action;
		    	break;
		    }
		  }
		}
		else {
			/* UNSUPPORTED RULE!
			   Have to get out of the spinlock to report it */
			unsupported = 1;
			break;
		}
		rule = rule->efrm_fr_next;
	}

check_filter_complete:
	spin_unlock_bh(&efrm_ft_lock);
	
	if ( unsupported ) {
		EFRM_ERR( "efrm_filter_check unsupported rule type %d\n",
		          rule ? rule->eit_ruletype : -1 );
	}
	return ( rc == EFRM_FR_ACTION_DROP ) ? -EACCES : 0;
}

static efrm_filter_rule_t* efrm_allocate_blank_rule(void) {
	/* Create a new rule structure. */
	efrm_filter_rule_t* rule = kmalloc( sizeof(efrm_filter_rule_t),
	                                    GFP_KERNEL );
	memset( rule, 0, sizeof(efrm_filter_rule_t) );
	rule->eit_ruletype = EFRM_FR_PORTRANGE;
	rule->efrm_rule.efr_range.efrp_lcl_max = 65535;
	rule->efrm_rule.efr_range.efrp_rmt_max = 65535;
	rule->efr_protocol = ep_tcp;
	rule->efr_action = EFRM_FR_ACTION_ACCEPT;
	return rule;
}

/*
  buf and remain will be altered to point at the next rule
  ifname and rulenumber will output the interface and position for the rule
  buf expects rules of the form:
    if=%s rule=%d protocol=%s local_ip=a.d.b.c/mask \
    remote_ip=a.b.c.d/mask local_port=%d-%d remote_port=%d-%d action=%s
  Or:
    if=%s rule=%d protocol=eth mac=xx:xx:xx:xx:xx:xx/xx:xx:xx:xx:xx:xx action=%s
  Returns a newly allocated rule (or NULL)
*/
static efrm_filter_rule_t*
efrm_interpret_rule( const char** buf, size_t* remain,
                     char* ifname, int* rule_number )
{
    int num_matches = 0;
    int seen_action = 0;
    int seen_protocol = 0;
    int seen_interface = 0;
    efrm_filter_rule_t* rule = 0;
    
    if ( !buf || !remain || !*buf || !*remain ) return NULL;

    rule = efrm_allocate_blank_rule();
    if ( !rule ) {
        EFRM_ERR("%s: Out of memory allocating new rule.\n", __func__);
        return NULL;
    }

    while ( **buf != '\0' && *remain > 0 ) {
        efrm_skip_whitespace( buf, remain );
        if ( efrm_compare_and_skip( buf, remain, "if=" ) == 0 ) {
            if ( seen_interface ) {
                EFRM_WARN( "%s: Seen multiple interfaces", __func__ );
                break;
            }
            seen_interface = efrm_consume_next_word( buf, remain, ifname,
                                                     IFNAMSIZ );
        }
        else if ( efrm_compare_and_skip( buf, remain, "rule=" ) == 0 ) {
            if ( *rule_number != -1 ) {
                EFRM_ERR("%s: Seen multiple rule numbers", __func__ );
                break;
            }
            *rule_number = efrm_atoi( buf, remain );
        }
        else if ( efrm_compare_and_skip( buf, remain, "action=" ) == 0 ) {
            if ( seen_action ) {
                EFRM_WARN("%s: Seen multiple actions", __func__ );
                break;
            }
            if ( efrm_compare_and_skip( buf, remain, "ACCEPT" ) == 0 
                || efrm_compare_and_skip( buf, remain, "ACCELERATE" ) == 0 
                ) {
                rule->efr_action = EFRM_FR_ACTION_ACCEPT;
            }
            else if ( efrm_compare_and_skip( buf, remain, "REJECT" ) == 0
                || efrm_compare_and_skip( buf, remain, "DROP" ) == 0 
                || efrm_compare_and_skip( buf, remain, "DECELERATE" ) == 0 
                ) {
                rule->efr_action = EFRM_FR_ACTION_DROP;
            }
            else if ( **buf == '\0' ) {
                // We've reached the end.
                break;
            }
            else {
                EFRM_ERR("%s: Unable to understand action: %s (%d)",
                                 __func__, *buf, (int)*remain );
                break;
            }
            seen_action ++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "protocol=" ) == 0 ) {
            if ( seen_protocol ) {
                EFRM_WARN("%s: Seen multiple protocols", __func__ );
                break;
            }
            if ( efrm_compare_and_skip( buf, remain, "tcp" ) == 0 ) {
                rule->efr_protocol = ep_tcp;
            }
            else if ( efrm_compare_and_skip( buf, remain, "udp" ) == 0 ) {
                rule->efr_protocol = ep_udp;
            }
            else if ( efrm_compare_and_skip( buf, remain, "ip" ) == 0 ) {
                rule->efr_protocol = ep_ip;
            }
            else if ( efrm_compare_and_skip( buf, remain, "eth" ) == 0 ) {
                rule->efr_protocol = ep_eth;
                rule->eit_ruletype = EFRM_FR_MACADDRESS;
            }
            else {
                EFRM_ERR("%s: Unable to understand protocol: %s", __func__, *buf );
                break;
            }
            seen_protocol++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "local_ip=" ) == 0 ) {
            if ( !efrm_consume_ip_mask(buf, remain,
                                &rule->efrm_rule.efr_range.efrp_lcl_ip,
                                &rule->efrm_rule.efr_range.efrp_lcl_mask ) ) {
                EFRM_ERR("%s: Invalid local_ip rule.\n", __func__ );
                break;
            }
            num_matches++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "remote_ip=" ) == 0 ) {
            if ( !efrm_consume_ip_mask( buf, remain,
                                &rule->efrm_rule.efr_range.efrp_rmt_ip,
                                &rule->efrm_rule.efr_range.efrprmtl_mask ) ) {
                EFRM_ERR("%s: Invalid remote_ip rule.\n", __func__ );
                break;
            }
            num_matches++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "local_port=" ) == 0 ) {
            efrm_consume_portrange( buf, remain,
                                &rule->efrm_rule.efr_range.efrp_lcl_min,
                                &rule->efrm_rule.efr_range.efrp_lcl_max );
            num_matches++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "remote_port=" ) == 0 ) {
            efrm_consume_portrange( buf, remain,
                                &rule->efrm_rule.efr_range.efrp_rmt_min,
                                &rule->efrm_rule.efr_range.efrp_rmt_max );
            num_matches++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "mac=" ) == 0 ) {
            if ( !efrm_consume_mac( buf, remain,
                        rule->efrm_rule.efr_macaddess.efrm_lcl_mac,
                        rule->efrm_rule.efr_macaddess.efrm_lcl_mask ) ) {
                EFRM_ERR( "%s: Invalid mac= rule.\n", __func__ );
                goto fail;
            }
            num_matches++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "vlan=" ) == 0 ) {
            rule->efrm_rule.efr_macaddess.efrm_vlan_id = efrm_atoi(buf,remain); 
            num_matches++;
        }
        else if ( efrm_compare_and_skip( buf, remain, "\n" ) == 0 ) {
            /* End of rule, check it's valid and if so, return it. */
            if (  seen_interface
               && seen_protocol
               && seen_action
               && num_matches ) {
                return rule;
            }
            else {
                EFRM_ERR("%s: Invalid rule", __func__ );
                break;
            }
        }
        else {
            EFRM_ERR("%s: Unable to understand remainder of rule: %s",
                     __func__, *buf );
            break;
        }
    }

fail:
    kfree( rule );
    return NULL;
}

/* ***************************** */
/* Entry points via file access. */
/* ***************************** */
/* /proc/driver/sfc_resource/ */
/* ************************** */

int efrm_add_rule(struct file *file, const char *buf, unsigned long count,
		  void *data)
{
    /* ENTRYPOINT from firewall_add
       Interpret the provided buffer, and add the rules therein. */
    size_t remain = count;

    mutex_lock( &efrm_ft_mutex );
    while ( *buf != '\0' && remain > 0 ) {
        char ifname [IFNAMSIZ];
        int rule_number = -1;
        int rc;
        efrm_filter_rule_t* rule = efrm_interpret_rule( &buf, &remain, ifname,
                                                        &rule_number );
        if ( !rule ) break;
        
        /* And actually apply that rule to the table. */
        {
            /* Add the specified rule to the table associated with this
               interface name, at the given position - negative position means
               'append'.
               Returns 0, or a negative error code.
               May create a new table. */
            efrm_filter_table_t* table;
            int found;
            found = find_table_by_ifname( ifname, &table );
            if ( !found ) {
                EFRM_NOTICE( "%s: Adding rule for unknown interface %s.",
                             __func__, ifname );
                table = efrm_insert_new_table( NULL, ifname );
                if ( !table ) {
                    rc = -ENOMEM;
                    break;
                }
            }
            rc = add_rule_to_table( table, rule, rule_number );
        }
        
        if ( rc ) {
            EFRM_ERR( "%s: Unable to add rule %d to %s.",
                             __func__, rule_number, ifname );
            kfree( rule );
            break;
        }
    }
    
    /* Nothing different to do in the success case, currently. */
    mutex_unlock( &efrm_ft_mutex );
    return count;
}

int efrm_del_rule(struct file *file, const char *buf, unsigned long count,
		  void *data)
{
	/* ENTRYPOINT from firewall_del.
	   Interpret the buffer and delete the specified rule(s) */
	size_t remain = count;
	char ifname [IFNAMSIZ];
	int is_all = 0;
	int interface = 0;
	int rule_number = -1;
	int rc = 0;

	efrm_skip_whitespace( &buf, &remain );
	/* Either if=ethX or ethX supported */
	efrm_compare_and_skip( &buf, &remain, "if=" );
	efrm_skip_whitespace( &buf, &remain );
	interface = efrm_consume_next_word( &buf, &remain, ifname, IFNAMSIZ );
	
	if ( interface < 0 ) {
		EFRM_ERR( "%s: Failed to understand interface.", __func__ );
		return count;
	}
	
	/* Either rule= or plain, supported */
	efrm_skip_whitespace( &buf, &remain );
	efrm_compare_and_skip( &buf, &remain, "rule=" );
	efrm_skip_whitespace( &buf, &remain );

	is_all = efrm_compare_and_skip( &buf, &remain, "all" ) == 0;
	if ( !is_all ) {
		rule_number = efrm_atoi( &buf, &remain );
	}

	mutex_lock( &efrm_ft_mutex );
	if ( is_all ) {
		rc = remove_all_rules( ifname );
		if ( rc == -EINVAL && !interface_has_rules( ifname ) ) {
			/* While technically invalid to remove all rules from
			   a nonexistant table, when the result is that table
			   having no rules, count it as a success. */
			rc = 0;
		}
	} else {
		rc = remove_rule( ifname, rule_number );
	}
	mutex_unlock( &efrm_ft_mutex );

	if ( rc ) {
		EFRM_ERR( "%s: Failed to remove rule %d from %s. Code: %d\n",
		          __func__, rule_number, ifname, rc );
	}
	return count;
}

/* ******************************* */
/* /proc/driver/sfc_resource/ethX/ */
/* ******************************* */

int
efrm_read_rules(char *buffer,
	      char **buffer_location,
	      off_t offset, int buffer_length, int *eof, void *data)
{
	/* Entry point from /proc/driver/sfc_resource/ethX/firewall_rules */
	/* TODO: We may need to support offset if there are many rules */
	efrm_filter_table_t* table = (efrm_filter_table_t*) data;
	ssize_t bytes_used = 0;
	
	if ( !buffer || buffer_length < 0 || !table || !eof )
		return -EINVAL;
	
	bytes_used = efrm_print_all_rules( table, buffer, buffer_length );
	*eof = 1;
	return bytes_used;
}

/* ***************************************** */
/* Initialisation and shutdown entry points. */
/* ***************************************** */

void efrm_filter_shutdown()
{
	/* Complete shutdown */
	int rc = 0;

	mutex_lock( &efrm_ft_mutex );

	/* Make sure everything is freed up properly */
	while ( !rc && efrm_ft_root_table ) {
		rc = remove_table(efrm_ft_root_table);
		if ( rc ) {
			EFRM_ERR( "%s:Error %d removing table", __func__, rc );
		}
	}
	
	efrm_ft_root_table = NULL;

	mutex_unlock( &efrm_ft_mutex );
}


void efrm_filter_init()
{
	/* First time init */
	mutex_lock( &efrm_ft_mutex );
	efrm_ft_root_table = NULL;
	mutex_unlock( &efrm_ft_mutex );
}

void efrm_filter_install_proc_entries()
{
	/* Add the /proc/ files that are not per-interface. */
	efrm_pd_add_rule = efrm_proc_create_file( "firewall_add", 0200,
					NULL, NULL, efrm_add_rule, NULL );
	efrm_pd_del_rule = efrm_proc_create_file( "firewall_del", 0200,
					NULL, NULL, efrm_del_rule, NULL );
}

void efrm_filter_remove_proc_entries()
{
	/* Remove the /proc/ files that are not per-interface. */
	efrm_proc_remove_file( efrm_pd_add_rule );
	efrm_pd_add_rule = NULL;
	efrm_proc_remove_file( efrm_pd_del_rule );
	efrm_pd_del_rule = NULL;
}

void efrm_init_resource_filter(struct device *dev, int ifindex)
{
	/* Per-Interface init */
	char const* pciname;
	char const* ifname;
	int found;
	struct net_device* ndev;
	efrm_filter_table_t* table = NULL;
	
	mutex_lock( &efrm_ft_mutex );

	pciname = efrm_get_pciname_from_device( dev );
	ifname = efrm_get_interefacename_from_index( ifindex, &ndev );
	
	/* We may have:  A previous name for this pci_device
	                 Rules for this name, that don't yet have a device.
	                 No table at all.
	   Tables belong to *interface* names.
	   First: Erase any previous mapping to this device. */
	if ( pciname ) {
		found = find_table_by_pcidevice( pciname, &table );
		if ( found ) {
			efrm_remove_files( table );
			*table->efrm_ft_pcidev_name = '\0';
		}
	}
	/* Then: Set the new mapping */
	if ( ifname ) {
		found = find_table_by_ifname( ifname, &table );
		if ( !found ) {
			table = efrm_insert_new_table( pciname, ifname );
		}
		if ( table ) {
			efrm_add_files( table );
			strlcpy( table->efrm_ft_pcidev_name, pciname,
			         IFNAMSIZ );
		}
		dev_put(ndev);
	}

	mutex_unlock( &efrm_ft_mutex );
	return;
}

void efrm_shutdown_resource_filter(struct device *dev)
{
	/* Per interface shutdown */
	int found;
	efrm_filter_table_t* table;
	char const* pciname;
	
	if ( !dev )
		return;
	
	mutex_lock( &efrm_ft_mutex );

	/* Un-name the table, so its rules won't get used; but don't remove
	   the rules, as the interface can come back later. */
	pciname = efrm_get_pciname_from_device( dev );
	found = find_table_by_pcidevice( pciname, &table );
	if ( found ) {
		*table->efrm_ft_pcidev_name = '\0';
		efrm_remove_files( table );
	}

	mutex_unlock( &efrm_ft_mutex );
}


/* ************************************************************* */
/* Entry point: check if a filter is valid, and insert it if so. */
/* ************************************************************* */

int efrm_filter_insert(struct efx_dl_device *efx_dev,
			 struct efx_filter_spec *spec,
			 bool replace) {
	/* This should be called every time a driver wishes to insert a
	   filter to the NIC, to check whether the firewall rules want to
	   block it. */
	int rc = efrm_filter_check( efx_dev, spec );
	if ( rc >= 0 ) {
		rc = efx_dl_filter_insert( efx_dev, spec, replace );
	}
	return rc;
}

/* TODO: Export symbols and/or offer an IOCTL interface for add/del rules? */

EXPORT_SYMBOL(efrm_filter_insert);
