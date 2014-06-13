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
#include <ci/efrm/efrm_client.h>


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
	__be32                efrp_rmt_mask;
} efrm_filter_rule_portrange_t;

typedef struct efrm_filter_rule_macaddress_s {
	char                  efrm_lcl_mac     [6];
	char                  efrm_lcl_mask    [6];
	unsigned short        efrm_vlan_id;
} efrm_filter_rule_macaddress_t;

typedef struct efrm_filter_rule_s
{
	efrm_filter_ruletype_t                eit_ruletype;
	union efr_rules {
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


static int efrm_is_mac_spec( struct efx_filter_spec const* spec )
{
#if EFX_DRIVERLINK_API_VERSION < 9
	return spec->type &
	       (EFX_FILTER_MAC_FULL | EFX_FILTER_MAC_WILD);
#else
	return spec->match_flags &
	       (EFX_FILTER_MATCH_LOC_MAC | EFX_FILTER_MATCH_LOC_MAC_IG);
#endif

}

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

static int
efrm_consume_ip( const char** src, size_t* length, ci_uint8* trits )
{
	if ( ( efrm_get_ip_trit( src, length, trits + 0 ) < 0 ) ||
	     ( efrm_compare_and_skip( src, length, "." ) ) ||
	     ( efrm_get_ip_trit( src, length, trits + 1 ) < 0 ) ||
	     ( efrm_compare_and_skip( src, length, "." ) ) ||
	     ( efrm_get_ip_trit( src, length, trits + 2 ) < 0 ) ||
	     ( efrm_compare_and_skip( src, length, "." ) ) ||
	     ( efrm_get_ip_trit( src, length, trits + 3 ) < 0 ) )
	{
		return 0;
	}
	return 1;
}

static int efrm_consume_ip_mask( const char** src, size_t* length,
                                 __be32* ip, __be32* mask )
{
	/* Reads a standard IPv4 address and mask, in either form.
	   Expect to consume a.b.c.d, possibly with suffix of /e.f.g.h or /n */
	ci_uint8* ip_ptr = (ci_uint8*) ip;
	ci_uint8* mask_ptr = (ci_uint8*) mask;

	if ( !efrm_consume_ip( src, length, ip_ptr ) )
		return 0;

	if ( efrm_compare_and_skip( src, length, "/" ) ) {
		*mask = 0;
	}
	else if ( !efrm_consume_ip( src, length, mask_ptr ) )
	{
		return efrm_fill_top_bits( mask_ptr[0], mask_ptr, 4 );
	}
	return 1;
}

static int efrm_consume_mac_seperator( const char** src, size_t* length )
{
	if ( efrm_compare_and_skip( src, length, ":" ) &&
	     efrm_compare_and_skip( src, length, "-" ) )
		return 1;
	return 0;
}

static int efrm_consume_hex( const char** src, size_t* length,
                             unsigned char* out )
{
	out[0] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[1] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[2] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[3] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[4] = efrm_hextoi( src, length );
	if ( efrm_consume_mac_seperator(src, length ) ) return 0;
	out[5] = efrm_hextoi( src, length );

	return 1;
}

static int efrm_consume_mac( const char** src, size_t* length,
                             unsigned char* mac, unsigned char* mask )
{
	/* Consumes a mac address, with mask. */
	memset( mac, 0, 6 );
		memset( mask, 0xff, 6 );

	if ( !efrm_consume_hex( src, length, mac ) )
		return 0;

	if ( !efrm_compare_and_skip( src, length, "/" ) ) {
		if ( !efrm_consume_hex( src, length, mask ) )
		{
			return efrm_fill_top_bits( mask[0], mask, 6 );
		}
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

#if EFX_DRIVERLINK_API_VERSION < 9
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
#else
	if ( (spec->match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	     (spec->ether_type == htons(ETH_P_IP)) ) {
		if( proto == ep_ip )
			return 1;

		if( spec->match_flags & EFX_FILTER_MATCH_IP_PROTO ) {
			if( (spec->ip_proto == IPPROTO_TCP) &&
			    (proto == ep_tcp) )
				return 1;
			if( (spec->ip_proto == IPPROTO_UDP) &&
			    (proto == ep_udp) )
				return 1;
		}
	}

	/* TODO support remote MAC address matching */
	if ( efrm_is_mac_spec(spec) && (proto == ep_eth) )
		return 1;

	return 0;
#endif
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

static const struct file_operations efrm_fops_rules;

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
				&efrm_fops_rules, table
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

static int print_eth_rule ( struct seq_file *seq, char const* iface,
                                int number, char const* action,
                                efrm_filter_rule_macaddress_t* rule )
{
	return seq_printf( seq, "if=%s rule=%d protocol=eth "
		"mac=%02x:%02x:%02x:%02x:%02x:%02x"
		"/%02x:%02x:%02x:%02x:%02x:%02x action=%s\n",
		iface ? iface : "?", number,
		(unsigned char) rule->efrm_lcl_mac[0] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[1] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[2] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[3] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[4] & 0xff,
		(unsigned char) rule->efrm_lcl_mac[5] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[0] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[1] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[2] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[3] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[4] & 0xff,
		(unsigned char) rule->efrm_lcl_mask[5] & 0xff,
		action );
};

static int print_ip_rule ( struct seq_file *seq, char const* iface,
                               int number, char const* action,
                               efrm_filter_rule_portrange_t* rule,
                               efrm_protocol_t protocol )
{
	return seq_printf( seq, "if=%s rule=%d protocol=%s"
		" local_ip=" CI_IP_PRINTF_FORMAT "/" CI_IP_PRINTF_FORMAT
		" remote_ip=" CI_IP_PRINTF_FORMAT "/" CI_IP_PRINTF_FORMAT
		" local_port=%d-%d remote_port=%d-%d action=%s\n",
		iface ? iface : "?", number,
		efrm_get_protocol_name( protocol ),
		CI_IP_PRINTF_ARGS( &rule->efrp_lcl_ip ),
		CI_IP_PRINTF_ARGS( &rule->efrp_lcl_mask ),
		CI_IP_PRINTF_ARGS( &rule->efrp_rmt_ip ),
		CI_IP_PRINTF_ARGS( &rule->efrp_rmt_mask ),
		rule->efrp_lcl_min, rule->efrp_lcl_max,
		rule->efrp_rmt_min, rule->efrp_rmt_max,
		action );
}

static int print_rule ( struct seq_file *seq, char const* iface,
                        efrm_filter_rule_t* rule, int number )
{
	/* Print a rule in a human readable form (that the parser can read
	   back in) to the specified buffer.
	   Returns the number of characters printed. */

	/* TODO: Really should indicate a desire to print past the end of the
	   buffer, and handle the user reading further. */
	char const* action = efrm_get_action_name( rule->efr_action );
	if ( rule->efr_protocol == ep_eth ) {
		return print_eth_rule( seq, iface, number, action,
		                       &rule->efrm_rule.efr_macaddess );
	} else {
		return print_ip_rule( seq, iface, number, action,
		                      &rule->efrm_rule.efr_range,
		                      rule->efr_protocol );
	}
}

static int
efrm_print_all_rules( efrm_filter_table_t* table, struct seq_file *seq)
{
	/* Print all the rules from a table into the given buffer. */
	efrm_filter_rule_t* rule;
	int rule_number = 0;

	if ( !table )
		return 0;

	rule = table->efrm_ft_first_rule;
	while ( rule ) {
		print_rule(seq, table->efrm_ft_interface_name,
			   rule, rule_number++ );
		rule = rule->efrm_fr_next;
	}
	return 0;
}

#if EFX_DRIVERLINK_API_VERSION < 9
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
#else //#if EFX_DRIVERLINK_API_VERSION < 9

/* As not all filters will have ipv4 hosts/ports etc.  use this which
   checks the spec match_flags field first */
static inline int efx_filter_get_ipv4(const struct efx_filter_spec *spec,
				      __be32 *host1, __be16 *port1,
				      __be32 *host2, __be16 *port2)
{
	if( (spec->match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	    (spec->ether_type == htons(ETH_P_IP)) ) {
		if( spec->match_flags & EFX_FILTER_MATCH_LOC_HOST )
			*host2 = spec->loc_host[0];
		else 
			*host2 = 0;

		if( spec->match_flags & EFX_FILTER_MATCH_REM_HOST )
			*host1 = spec->rem_host[0];
		else
			*host1 = 0;

		if( spec->match_flags & EFX_FILTER_MATCH_LOC_PORT )
			*port2 = spec->loc_port;
		else 
			*port2 = 0;

		if( spec->match_flags & EFX_FILTER_MATCH_REM_PORT )
			*port1 = spec->rem_port;
		else 
			*port1 = 0;

		return 0;
	}
	else
		return -EINVAL;
}
#endif

static inline int
efx_filter_get_mac(const struct efx_filter_spec *spec, u8 *addr, u16* vid )
{
#if EFX_DRIVERLINK_API_VERSION < 9
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
#else
	/* TODO support remote MAC address matching */
	if( !efrm_is_mac_spec( spec ) )
		return -EINVAL;

	memcpy(addr, spec->loc_mac, ETH_ALEN);

	/* TODO support inner VLAN tag matching */
	if( spec->match_flags & EFX_FILTER_MATCH_OUTER_VID )
		*vid = CI_BSWAP_BE16(spec->outer_vid);
	else
		*vid = EFX_FILTER_VID_UNSPEC;

	return 0;
#endif
}

/* TODO: Move these helper functions to their own section */
static int within( int low, int high, int test )
{
	return ( test >= low ) && ( test <= high );
}

static int ip_matches( __be32 ip, __be32 mask, __be32 test )
{
	/* Unspecified IP, or match the mask? */
	if ( !test )
		return 1;
	return ( test & mask ) == ( ip & mask );
}

static int mac_byte_matches( char mac, char mask, char test )
{
	return ( test & mask ) == ( mac & mask );
}


static int efrm_portrange_match( struct efx_filter_spec *spec,
                                        efrm_filter_rule_portrange_t* range,
                                        efrm_protocol_t protocol,
                                        __be32 rmt, __be32 lcl,
                                        int rmt_prt, int lcl_prt )
{
	/* right protocol?  In range?  Ip's match? */
	return efrm_protocol_matches(spec, protocol ) &&
	       within( range->efrp_lcl_min, range->efrp_lcl_max, lcl_prt ) &&
	       within( range->efrp_rmt_min, range->efrp_rmt_max, rmt_prt ) &&
	       ip_matches( range->efrp_lcl_ip, range->efrp_lcl_mask, lcl ) &&
	       ip_matches( range->efrp_rmt_ip, range->efrp_rmt_mask, rmt );
}

static int efrm_vlan_matches( u16 vlan, efrm_filter_rule_macaddress_t* mac )
{
	return (vlan == EFX_FILTER_VID_UNSPEC) || (vlan == mac->efrm_vlan_id);
}

static int efrm_mac_match( efrm_filter_rule_macaddress_t* mac,
                           struct efx_filter_spec* spec )
{
	/* Does the mac+vlan in the spec match the mac rule? */
	u16 vlan = EFX_FILTER_VID_UNSPEC;
	int matches = 0;
	char addr[6];
	int i;

	if ( !efrm_is_mac_spec(spec) )
		return 0;

	efx_filter_get_mac(spec, addr, &vlan );
	for ( i=0; i<6; ++i ) {
		matches += mac_byte_matches( mac->efrm_lcl_mac[i],
		                             mac->efrm_lcl_mask[i],
		                             addr[i] );
	}
	return efrm_vlan_matches( vlan, mac ) && (matches == 6);
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
	efrm_filter_action_t rc = EFRM_FR_ACTION_UNSUPPORTED;
	efrm_filter_rule_t* rule = NULL;
	efrm_filter_table_t* table = NULL;
	char const* pci = efrm_get_pciname_from_device( &dl_dev->pci_dev->dev);
	int unsupported = 0;

	spin_lock_bh(&efrm_ft_lock);

	if ( !find_table_by_pcidevice( pci, &table ) )
	{
		/* No rules for this interface, so accept. */
		goto check_filter_complete;
	}
	rule = table->efrm_ft_first_rule;

	efx_filter_get_ipv4(spec, &host1, &port1, &host2, &port2);
	/* TODO: Ensure endianness of ef_iptble in a nicer way that this. */
	remote_port = CI_BSWAP_BE16(port1);
	local_port = CI_BSWAP_BE16(port2);

	while ( rule )
	{
		if ( rule->eit_ruletype == EFRM_FR_PORTRANGE ) {
			if ( efrm_portrange_match(
			     spec,
			     &rule->efrm_rule.efr_range,
			     rule->efr_protocol,
			     host1, host2,
			     remote_port, local_port ) )
			{
				/* Matched rule, take its action and stop */
				rc = rule->efr_action;
				break;
			}
		}
		else if ( rule->eit_ruletype == EFRM_FR_MACADDRESS )
		{
			/* TODO include remote MAC filters */
			if ( efrm_mac_match( &rule->efrm_rule.efr_macaddess,
			                     spec ) )
			{
				rc = rule->efr_action;
				break;
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

static int
efrm_read_if ( const char** buf, size_t* remain, int* done,
               char* name, int* seen )
{
	if ( efrm_compare_and_skip( buf, remain, "if=" ) != 0 )
		return 0;

	if ( *seen ) {
		EFRM_WARN( "%s: Seen multiple interfaces", __func__ );
		*done = 1;
	} else {
		*seen = efrm_consume_next_word( buf, remain, name, IFNAMSIZ );
	}
	return 1;
}

static int
efrm_read_rule ( const char** buf, size_t* remain, int* done,
                 int* rule_number )
{
	if ( efrm_compare_and_skip( buf, remain, "rule=" ) != 0 )
		return 0;

	if ( *rule_number == -1 ) {
		*rule_number = efrm_atoi( buf, remain );
	} else {
		EFRM_ERR("%s: Seen multiple rule numbers", __func__ );
		*done = 1;
	}
	return 1;
}

static int
efrm_read_action ( const char** buf, size_t* remain, int* done,
                   efrm_filter_action_t* action, int* seen )
{
	if ( efrm_compare_and_skip( buf, remain, "action=" ) != 0 )
		return 0;

	if ( *seen ) {
		EFRM_WARN("%s: Seen multiple actions", __func__ );
		*done = 1;
	} else {
		if ( !efrm_compare_and_skip( buf, remain, "ACCEPT" ) ||
		     !efrm_compare_and_skip( buf, remain, "ACCELERATE" ) )
		{
			*action = EFRM_FR_ACTION_ACCEPT;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "REJECT" ) ||
		          !efrm_compare_and_skip( buf, remain, "DROP" ) ||
		          !efrm_compare_and_skip( buf, remain, "DECELERATE" ) )
		{
			*action = EFRM_FR_ACTION_DROP;
			*seen = 1;
		}
		else if ( **buf == '\0' ) {
			*done = 1;
		} else {
			EFRM_ERR("%s: Unable to understand action: %s (%d)",
					 __func__, *buf, (int)*remain );
			*done = 1;
		}
	}
	return 1;
}

static int
efrm_read_protocol( const char** buf, size_t* remain, int* done,
                    char* protocol,
                    efrm_filter_ruletype_t* ruletype,
                    int* seen )
{
	if ( efrm_compare_and_skip( buf, remain, "protocol=" ) != 0 )
		return 0;

	if ( *seen )
	{
		EFRM_WARN("%s: Seen multiple protocols", __func__ );
		*done = 1;
	} else {
		if ( !efrm_compare_and_skip( buf, remain, "tcp" ) ) {
			*protocol = ep_tcp;
			*ruletype = EFRM_FR_PORTRANGE;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "udp" ) ) {
			*protocol = ep_udp;
			*ruletype = EFRM_FR_PORTRANGE;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "ip" ) ) {
			*protocol = ep_ip;
			*ruletype = EFRM_FR_PORTRANGE;
			*seen = 1;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "eth" ) ) {
			*protocol = ep_eth;
			*ruletype = EFRM_FR_MACADDRESS;
			*seen = 1;
		}
		else {
			EFRM_ERR("%s: Unable to understand protocol: %s",
			         __func__, *buf );
			*done = 1;
		}
	}
	return 1;
}

static int
efrm_read_lcl_ip( const char** buf, size_t* remain, int* done,
                  efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "local_ip=" ) )
		return 0;

	if ( !efrm_consume_ip_mask(buf, remain, &range->efrp_lcl_ip,
	                           &range->efrp_lcl_mask ) ) {
		EFRM_ERR("%s: Invalid local_ip rule.\n", __func__ );
		*done = 1;
		return 0;
	}
	return 1;
}

static int
efrm_read_rmt_ip( const char** buf, size_t* remain, int* done,
                  efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "remote_ip=" ) )
		return 0;

	if ( !efrm_consume_ip_mask(buf, remain, &range->efrp_rmt_ip,
	                           &range->efrp_rmt_mask ) ) {
		EFRM_ERR("%s: Invalid remote_ip rule.\n", __func__ );
		*done = 1;
		return 0;
	}
	return 1;
}

static int efrm_read_lcl_port( const char** buf, size_t* remain, int* done,
                               efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "local_port=" ) )
		return 0;

	efrm_consume_portrange( buf, remain,
	                        &range->efrp_lcl_min, &range->efrp_lcl_max );
	return 1;
}

static int efrm_read_rmt_port( const char** buf, size_t* remain, int* done,
                               efrm_filter_rule_portrange_t* range )
{
	if ( efrm_compare_and_skip( buf, remain, "remote_port=" ) )
		return 0;

	efrm_consume_portrange( buf, remain,
	                        &range->efrp_rmt_min, &range->efrp_rmt_max );
	return 1;
}

static int efrm_read_mac( const char** buf, size_t* remain, int* done,
                          efrm_filter_rule_macaddress_t* mac )
{
	if ( efrm_compare_and_skip( buf, remain, "mac=" ) )
		return 0;

	if ( !efrm_consume_mac( buf, remain,
                                mac->efrm_lcl_mac, mac->efrm_lcl_mask ) ) {
		EFRM_ERR( "%s: Invalid mac= rule.\n", __func__ );
		*done = 1;
		return 0;
	}
	return 1;
}

static int efrm_read_vlan( const char** buf, size_t* remain, int* done,
                           efrm_filter_rule_macaddress_t* mac )
{
	if ( efrm_compare_and_skip( buf, remain, "vlan=" ) )
		return 0;

	mac->efrm_vlan_id = efrm_atoi(buf,remain);
	return 1;
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
	int num_controls = 0;
	int act_seen = 0;
	int protocol_seen = 0;
	int if_seen = 0;
	int done = 0;
	efrm_filter_rule_t* rule = 0;

	if ( !buf || !remain || !*buf || !*remain ) return NULL;

	rule = efrm_allocate_blank_rule();
	if ( !rule ) {
		EFRM_ERR("%s: Out of memory allocating new rule.\n", __func__);
		return NULL;
	}

	while ( !done && **buf != '\0' && *remain > 0 ) {
		efrm_skip_whitespace( buf, remain );

		if ( efrm_read_if( buf, remain, &done, ifname, &if_seen ) ||
		     efrm_read_rule( buf, remain, &done, rule_number ) ||
		     efrm_read_action( buf, remain, &done,
		                       &rule->efr_action, &act_seen ) ||
		     efrm_read_protocol( buf, remain, &done,
		                         &rule->efr_protocol,
		                         &rule->eit_ruletype,
		                         &protocol_seen ) )
		{
			num_controls++;
		}
		else if ( efrm_read_lcl_ip( buf, remain, &done,
		                            &rule->efrm_rule.efr_range ) ||
		          efrm_read_rmt_ip( buf, remain, &done,
		                            &rule->efrm_rule.efr_range ) ||
		          efrm_read_lcl_port( buf, remain, &done,
		                              &rule->efrm_rule.efr_range ) ||
		          efrm_read_rmt_port( buf, remain, &done,
		                              &rule->efrm_rule.efr_range ) ||
		          efrm_read_mac( buf, remain, &done,
		                         &rule->efrm_rule.efr_macaddess ) ||
		          efrm_read_vlan( buf, remain, &done,
		                          &rule->efrm_rule.efr_macaddess ) )
		{
			num_matches++;
		}
		else if ( !efrm_compare_and_skip( buf, remain, "\n" ) ) {
			/* End of rule, check it's valid and return it. */
			if ( if_seen &&
			     protocol_seen &&
			     act_seen &&
			     (num_matches > 0 ) )
			{
				return rule;
			} else {
				EFRM_ERR("%s: Invalid rule", __func__ );
				break;
			}
		}
		else {
			EFRM_ERR("%s: Unable to understand remainder: %s",
			         __func__, *buf );
			done = 1;
		}
	}

	kfree( rule );
	return NULL;
}

static int efrm_text_to_table_entry( const char ** buf, size_t* remain )
{
	char ifname [IFNAMSIZ];
	int rule_number = -1;
	efrm_filter_table_t* table;
	int rc;

	efrm_filter_rule_t* rule = efrm_interpret_rule( buf, remain, ifname,
	                                                &rule_number );
	if ( !rule )
		return -ENOMEM;

	/* And actually apply that rule to the table. */
	/* Add the specified rule to the table associated with this
	   interface name, at the given position - negative position means
	   'append'.
	   Returns 0, or a negative error code.
	   May create a new table. */
	if ( !find_table_by_ifname( ifname, &table ) ) {
		EFRM_NOTICE( "%s: Adding rule for unknown interface %s.",
		             __func__, ifname );
		table = efrm_insert_new_table( NULL, ifname );
	}
	if ( !table ) {
	    return -ENOMEM;
	}
	rc = add_rule_to_table( table, rule, rule_number );
	if ( rc ) {
		EFRM_ERR( "%s: Unable to add rule %d to %s (%d).",
		          __func__, rule_number, ifname, rc );
		kfree( rule );
	}
	return rc;
}

/* ***************************** */
/* Entry points via file access. */
/* ***************************** */
/* /proc/driver/sfc_resource/ */
/* ************************** */

ssize_t efrm_add_rule(struct file *file, const char __user *buf,
		      size_t count, loff_t *ppos)
{
	/* ENTRYPOINT from firewall_add
	Interpret the provided buffer, and add the rules therein. */
	size_t remain = count;

	mutex_lock( &efrm_ft_mutex );

	while ( *buf != '\0' && remain > 0 ) {
		if ( efrm_text_to_table_entry( &buf, &remain ) )
			break;
	}

	mutex_unlock( &efrm_ft_mutex );
	return count;
}
static const struct file_operations efrm_fops_add_rule = {
	.owner		= THIS_MODULE,
	.write		= efrm_add_rule,
};

ssize_t efrm_del_rule(struct file *file, const char __user *buf,
		      size_t count, loff_t *ppos)
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
static const struct file_operations efrm_fops_del_rule = {
	.owner		= THIS_MODULE,
	.write		= efrm_del_rule,
};

/* ******************************* */
/* /proc/driver/sfc_resource/ethX/ */
/* ******************************* */

static int
efrm_read_rules(struct seq_file *seq, void *s)
{
	/* Entry point from /proc/driver/sfc_resource/ethX/firewall_rules */
	/* TODO: We may need to support offset if there are many rules */
	efrm_filter_table_t* table = (efrm_filter_table_t*) seq->private;
	
	if ( !table )
		return -EINVAL;
	
	efrm_print_all_rules( table, seq );
	return 0;
}
static int efrm_open_rules(struct inode *inode, struct file *file)
{
	return single_open(file, efrm_read_rules, PDE_DATA(inode));
}
static const struct file_operations efrm_fops_rules = {
	.owner		= THIS_MODULE,
	.open		= efrm_open_rules,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

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
					NULL, &efrm_fops_add_rule, NULL );
	efrm_pd_del_rule = efrm_proc_create_file( "firewall_del", 0200,
					NULL, &efrm_fops_del_rule, NULL );
}

void efrm_filter_remove_proc_entries()
{
	/* Remove the /proc/ files that are not per-interface. */
	efrm_proc_remove_file( efrm_pd_add_rule );
	efrm_pd_add_rule = NULL;
	efrm_proc_remove_file( efrm_pd_del_rule );
	efrm_pd_del_rule = NULL;
}

int efrm_remove_table_name( char const *pciname )
{
	efrm_filter_table_t* table;
	int found = find_table_by_pcidevice( pciname, &table );
	if ( found ) {
		*table->efrm_ft_pcidev_name = '\0';
		efrm_remove_files( table );
	}
	return found;
}

void efrm_map_table( char const* ifname, char const* pciname )
{
	int found;
	efrm_filter_table_t* table = NULL;

	/* We may have:  A previous name for this pci_device
	                 Rules for this name, that don't yet have a device.
	                 No table at all.
	   Tables belong to *interface* names.
	   First: Erase any previous mapping to this device. */
	/* Then: Set the new mapping */
	found = find_table_by_ifname( ifname, &table );
	if ( !found ) {
		table = efrm_insert_new_table( pciname, ifname );
	}
	if ( table ) {
		efrm_add_files( table );
		strlcpy( table->efrm_ft_pcidev_name, pciname,
			 IFNAMSIZ );
	}
}

void efrm_init_resource_filter(struct device *dev, int ifindex)
{
	/* Per-Interface init */
	char const* pciname;
	char const* ifname;
	struct net_device* ndev;
	
	mutex_lock( &efrm_ft_mutex );

	pciname = efrm_get_pciname_from_device( dev );
	ifname = efrm_get_interefacename_from_index( ifindex, &ndev );
	
	if ( pciname )
		efrm_remove_table_name( pciname );

	if ( ifname ) {
		efrm_map_table( ifname, pciname );
		dev_put(ndev);
	}

	mutex_unlock( &efrm_ft_mutex );
	return;
}

void efrm_shutdown_resource_filter(struct device *dev)
{
	/* Per interface shutdown */
	char const* pciname;
	
	if ( !dev )
		return;
	
	mutex_lock( &efrm_ft_mutex );

	/* Un-name the table, so its rules won't get used; but don't remove
	   the rules, as the interface can come back later. */
	pciname = efrm_get_pciname_from_device( dev );
	if ( pciname )
		efrm_remove_table_name( pciname );

	mutex_unlock( &efrm_ft_mutex );
}

/* *********************************** */
/* * Entry point for device renaming * */
/* *********************************** */
int efrm_filter_rename( struct efhw_nic *nic, struct net_device *net_dev )
{
	struct efx_dl_device *dl_dev;
	char const* ifname;
	char const* pciname;

	if ( !nic || !net_dev ) {
		EFRM_ERR("%s:Internal error %p %p", __func__, nic, net_dev );
		return -EINVAL;
	}
	
	/* efhw_nic is the device, which has the real id */
	dl_dev = linux_efhw_nic(nic)->dl_device;
	if ( !dl_dev ) {
		EFRM_ERR("%s:Internal error two %p", __func__, dl_dev );
		return -EINVAL;
	}
	pciname = efrm_get_pciname_from_device( &dl_dev->pci_dev->dev);
	if ( !pciname ) {
		EFRM_ERR("%s:Old device has no pciname", __func__ );
	}
	/* net_dev->name should contain the new name */
	ifname = net_dev->name;
	if ( !ifname ) {
		EFRM_ERR("%s:New device has no ifname", __func__ );
	}

	mutex_lock( &efrm_ft_mutex );

	EFRM_TRACE("%s:Renaming device %s, %s", __func__, pciname, ifname );

	if ( pciname )
		efrm_remove_table_name( pciname );
	if ( ifname )
		efrm_map_table( ifname, pciname );
	
	mutex_unlock( &efrm_ft_mutex );
	
	return 0;
}

/* ************************************************************* */
/* Entry point: check if a filter is valid, and insert it if so. */
/* ************************************************************* */

int efrm_filter_insert(struct efrm_client *client,
		       struct efx_filter_spec *spec,
		       bool replace)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev = linux_efhw_nic(efhw_nic)->dl_device;
	/* This should be called every time a driver wishes to insert a
	   filter to the NIC, to check whether the firewall rules want to
	   block it. */
	int rc = efrm_filter_check( efx_dev, spec );
	if ( rc >= 0 ) {
		rc = efx_dl_filter_insert( efx_dev, spec, replace );
	}
	return rc;
}
EXPORT_SYMBOL(efrm_filter_insert);


void efrm_filter_remove(struct efrm_client *client, int filter_id)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev = linux_efhw_nic(efhw_nic)->dl_device;
	efx_dl_filter_remove(efx_dev, filter_id);
}
EXPORT_SYMBOL(efrm_filter_remove);


void efrm_filter_redirect(struct efrm_client *client, int filter_id, int rxq_i)
{
	struct efhw_nic *efhw_nic = efrm_client_get_nic(client);
	struct efx_dl_device *efx_dev = linux_efhw_nic(efhw_nic)->dl_device;
	efx_dl_filter_redirect(efx_dev, filter_id, rxq_i);
}
EXPORT_SYMBOL(efrm_filter_redirect);
