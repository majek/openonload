/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** \author  cgg & ds
**  \brief  Decls & defs for the configuration database libraries.
**   \date  2005/11/17
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_EFABCFG_H__
#define __CI_INTERNAL_EFABCFG_H__

#include <ci/compat.h>
#include <ci/tools.h>
#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <onload/common.h>

#if !defined(__KERNEL__)
#include <onload/ul.h>
#endif



/* This is the layout of the data structure used to store configuration
   information :

   HEADER
   DEFAULT_PATCH_ID
   STRINGS
   EXCLUSIONS
   PATCHES
   USERS
   APPS

   A configuration binary object "BLOB" is constructed through its PATCH of
   another binary object.

   The configuration for an application run by a user is contructed by
   patching the empty configuration with the default patch, then the
   application patch and finally the users patch.

   The application and user patches are found by matching application and
   user information against the ordered lists of application and user patterns 
*/


/*--------------------------------------------------------------------
 * STRINGS
 *--------------------------------------------------------------------*/


/*! Offset from the beggining of the string data
 *  i.e. the offset of the first byte of the first string, is 0.
 */
typedef ci_uint16 ci_cfg_str_off_t;


#define CICFG_STR_OFF_BAD ((ci_cfg_str_off_t)(-1))


typedef struct {
  ci_uint32 strings; /*< number of strings in this section */
} ci_cfg_str_hdr_t;


typedef struct {
  ci_cfg_str_hdr_t hdr     CI_ALIGN(4);
  char             data[1] CI_ALIGN(4);
} ci_cfg_str_part_t;


#define ci_cfg_str_part(hdr) \
        _ci_cfg_part(ci_cfg_str_part_t*, (hdr), CICFG_PART_STR)


#define ci_cfg_string(hdr, str_off)                   \
        (_ci_cfg_part(char *, hdr, CICFG_PART_STR) + \
         sizeof(ci_cfg_str_hdr_t) + (str_off))



/*--------------------------------------------------------------------
 * EXCLUSIONS
 *--------------------------------------------------------------------*/


typedef struct
{   ci_cfg_str_off_t str_off; /*< byte offset of first byte of zero
                                  terminated string in the STRING area */
} ci_cfg_excl_t;


typedef struct
{   ci_uint16 rows;	      /*< number of exclusions following */
}  ci_cfg_excl_hdr_t;


typedef struct
{   ci_cfg_excl_hdr_t hdr        CI_ALIGN(4); /*< exclusion partition header */
    ci_cfg_excl_t     exclude[1] CI_ALIGN(4); /*< array of exclusions */
}  ci_cfg_excl_part_t;


#define ci_cfg_excl_part(hdr) \
        _ci_cfg_part(ci_cfg_excl_part_t*, (hdr), CICFG_PART_EXCL)



/*--------------------------------------------------------------------
 * BLOB ID
 *--------------------------------------------------------------------*/

  
typedef ci_uint8 ci_cfg_blob_id_t;
#define CICFG_BLOB_ID_BAD   0
#define CICFG_BLOB_ID_NETIF 1
#define CICFG_BLOB_ID_OS    2
#define CICFG_BLOB_ID_USER  3
#define CICFG_BLOB_ID_MAX   3
#define CICFG_BLOB_ID_COUNT (CICFG_BLOB_ID_MAX+1)


ci_inline int ci_cfg_blob_id_is_valid(ci_cfg_blob_id_t blob_id)
{
  return (blob_id > CICFG_BLOB_ID_BAD) && (blob_id <= CICFG_BLOB_ID_MAX);
}


ci_inline char *ci_cfg_blob_id_2_str(ci_cfg_blob_id_t blob_id)
{
  switch (blob_id) {
    case CICFG_BLOB_ID_NETIF:
      return "netif";
    case CICFG_BLOB_ID_OS:
      return "O/S";
    case CICFG_BLOB_ID_USER:
      return "user";
    default:
      return "invalid blob id";
  }
}


ci_inline size_t ci_cfg_pprint_blob_id(char *buf, size_t len,
                                       ci_cfg_blob_id_t blob_id)
{
  return snprintf(buf, len, "%s", ci_cfg_blob_id_2_str(blob_id));
}



/*--------------------------------------------------------------------
 * PATCHES
 *--------------------------------------------------------------------*/


/*! \TODO: blob_off and blob_id could be combined into a uint16 */
typedef struct
{   ci_uint16 blob_off;        /*< byte offset into the blob */
    ci_uint8  value;           /*< value of bits to be set in that byte */
    ci_uint8  mask;            /*< which bits in the blob to be set */
    ci_cfg_blob_id_t  blob_id; /*< id of data structure the patch applies to */
} ci_cfg_patch_item_t;

#define ci_cfg_patch_set_pos(ref_patch, _id, _offset) \
{  (ref_patch)->blob_id = (_id); (ref_patch)->blob_off = (_offset); }

#define ci_cfg_patch_pos_id(ref_patch)     ((ref_patch)->blob_id)
#define ci_cfg_patch_pos_offset(ref_patch) ((ref_patch)->blob_off)


typedef struct
{   ci_uint16 patch_index;    /*< offset in first patch item in patches */
    ci_uint16 patch_length;   /*< number of patch items in this patch   */
} ci_cfg_patch_id_t;

#define CICFG_PATCH_INDEX_BAD ((ci_uint16)-1)

typedef struct {
  ci_uint32 rows;             /*! number of patch items in the partition */
} ci_cfg_patch_hdr_t;


typedef struct {
  ci_cfg_patch_hdr_t  hdr     CI_ALIGN(4);
  ci_cfg_patch_item_t item[1] CI_ALIGN(4);
} ci_cfg_patch_part_t;


#define ci_cfg_patch_part(hdr) \
        _ci_cfg_part(ci_cfg_patch_part_t*, (hdr), CICFG_PART_PATCH)



/*--------------------------------------------------------------------
 * PATTERNS
 *--------------------------------------------------------------------*/



/*! write the lower-cased version of the multi-byte character encoded string
 *
 * The output buffer must be sufficient for both the translated lower-case
 * version of the string plus MB_LEN_MAX+1 bytes
 *
 * NB: this function is conditionally compiled for use in hosts
 *     that need to translate application names to a canonical case before
 *     comparison
 */
#ifdef USE_TOMBLOWER
extern int /* len/-rc */
tomblower(char *mb_outbuf, size_t outbuflen, const char *mb_buf);
#endif
    
typedef struct
{   ci_cfg_str_off_t str_off;   /*< text in the middle of the pattern */
    ci_uint8 match_type;        /*< unused flags must be set to zero */
#define CICFG_MATCH_ANY   0x00 /*< string must match app name anywhere */
#define CICFG_MATCH_START 0x01 /*< string must match at start of app name */
#define CICFG_MATCH_END   0x02 /*< string must match at end of app name */
#define CICFG_MATCH_EXACT 0x03 /*< string must match at start and end */
#define CICFG_MATCH_MASK  0x03 /*< mask that covers all the flags */
} ci_cfg_str_pattern_t;


/*! Searches 'str' for the pattern described by 'pattern' and 'match_type'. */
extern int ci_cfg_pattern_matches(const char *pattern,
                                  const char *str,
                                  ci_uint8 flags);



/*--------------------------------------------------------------------
 * USERS
 *--------------------------------------------------------------------*/


typedef ci_uint32 ci_cfg_uid_t;


typedef struct
{   ci_cfg_patch_id_t patch; /*< change to apply to blob */
    ci_cfg_uid_t      uid;   /*< user numerical id */
} ci_cfg_user_t;


typedef struct
{   ci_uint16 rows;	   /*< number of user rows following */
}  ci_cfg_user_hdr_t;


typedef struct
{   ci_cfg_user_hdr_t hdr     CI_ALIGN(4);
    ci_cfg_user_t     user[1] CI_ALIGN(4); /*< "rows" of them when alloc'd */
}
ci_cfg_user_part_t;


#define ci_cfg_user_part(hdr) \
        _ci_cfg_part(ci_cfg_user_part_t*, (hdr), CICFG_PART_USERS)



/*--------------------------------------------------------------------
 * APPS
 *--------------------------------------------------------------------*/


typedef struct
{   ci_cfg_patch_id_t    patch;   /*< change to apply to application blob */
    ci_cfg_str_pattern_t pattern; /*< pattern to match against full path */
} ci_cfg_app_t;


typedef struct
{   ci_uint16 rows;	        /*< number of application rows following */
} ci_cfg_app_hdr_t;


typedef struct
{   ci_cfg_app_hdr_t hdr    CI_ALIGN(4);
    ci_cfg_app_t     app[1] CI_ALIGN(4); /*< "rows" of them when alloc'd */
}
ci_cfg_app_part_t;


#define ci_cfg_app_part(hdr) \
        _ci_cfg_part(ci_cfg_app_part_t*, (hdr), CICFG_PART_APPS)



/*--------------------------------------------------------------------
 * Header
 *--------------------------------------------------------------------*/



typedef struct
{   ci_uint32 len;            /*< length in bytes of this binary data block */
    ci_uint32 ver;            /*< major version << 8 + minor version of data */
#define CICFG_VER_MAJOR_SHIFT 8
#define CICFG_VER_NUM ((0 << CICFG_VER_MAJOR_SHIFT) + 1)
#define CICFG_VER_MAJOR_MASK 0xffffff00
#define CICFG_VER_MAJOR ((CICFG_VER_NUM) & (CICFG_VER_MAJOR_MASK))
#define CICFG_VER_MINOR_MASK 0x000000ff
#define CICFG_VER_MINOR ((CICFG_VER_NUM) & (CICFG_VER_MINOR_MASK))
    ci_cfg_patch_id_t default_config;
    /*< the patch of a zeroed configuration used as the default prior to being
     *  merged with the contribution from the application and then the user
     */
    ci_uint32 rows;           /*< number of part offsets following */
#define CICFG_PART_EXCL    0
#define CICFG_PART_STR     1
#define CICFG_PART_PATCH   2
#define CICFG_PART_USERS   3
#define CICFG_PART_APPS    4
#define CICFG_PARTS_COUNT  5
    ci_uint32 part_off[CICFG_PARTS_COUNT];
                              /*< byte offset of start of each part 
			          allocated data structure will have "rows"
			          entries */
} ci_cfg_hdr_t;


#define _ci_cfg_part(type, hdr, off) \
        ((type)((ci_uint8 *)(hdr)+(hdr)->part_off[off]))


/*--------------------------------------------------------------------
 * Defined option sets
 *--------------------------------------------------------------------*/


#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <ci/internal/user_opts.h>

typedef struct {
  ci_user_ptr_t uid_ptr       CI_ALIGN(8); /*< pointer to uid */
  ci_user_ptr_t proc_name_ptr CI_ALIGN(8); /*< pointer to process name */
  ci_uint16     uid_len       CI_ALIGN(4); /*< length of uid in bytes */
  ci_uint16     proc_name_len CI_ALIGN(4); /*< length of process name in bytes
                                               without the terminating zero */
} ci_cfg_uid_n_proc_t;


typedef struct {
  citp_opts_t          citp_opts;
  ci_netif_config_opts netif_opts;
  ci_user_opts_t       user_opts;
} ci_cfg_opts_t;


/*! Used by CI_IOCTL_CFG_QUERY ioctl */
typedef struct {
  ci_cfg_uid_n_proc_t uid_n_proc;
  ci_cfg_opts_t       opts;
} ci_ioctl_cfg_query_t;


ci_inline const char *ci_cfg_pprint_desc_err(ci_uint32 err)
{
  switch(err) {
  case 0:                    return "0 is not an error";
  case CICFG_DESC_ENOTINST:  return "config not installed";
  case CICFG_DESC_ETOOSMALL: return "buffer too small";
  case CICFG_DESC_EPROCEXCL: return "process is excluded";
  case CICFG_DESC_EBADUID:   return "bad user ID";
  case CICFG_DESC_EBADPNAME: return "bad process ID or process ID descriptor";
  case CICFG_DESC_EFAULT:    return "bad pointer in ioctrl pdesc";
  case CICFG_DESC_EBADCMD:   return "bad ioctl command value";
  case CICFG_DESC_EPERM:     return "not authorised to alter configuration database";
  case CICFG_DESC_ENOMEM:    return "not enough memory";
  case CICFG_DESC_EINVAL:    return "configuration database not valid";
  case CICFG_DESC_EAGAIN:    return "retry the operation";
  default:                   return "(invalid efabcfg err)";
  }
}



/*--------------------------------------------------------------------
 * EMPTY DATABASE
 *--------------------------------------------------------------------*/


typedef struct {
  ci_cfg_hdr_t       hdr   CI_ALIGN(4);
  ci_cfg_excl_hdr_t  excl  CI_ALIGN(4);
  ci_cfg_str_hdr_t   str   CI_ALIGN(4);
  ci_cfg_patch_hdr_t patch CI_ALIGN(4);
  ci_cfg_user_hdr_t  user  CI_ALIGN(4);
  ci_cfg_app_hdr_t   app   CI_ALIGN(4);
} ci_cfg_empty_db_t;


extern void ci_cfg_create_empty_db(ci_cfg_empty_db_t *db);



/*--------------------------------------------------------------------
 * OPERATIONS
 *--------------------------------------------------------------------*/


/*! Validates a database binary object. Returns zero if the db is valid */
extern int ci_cfg_is_valid_for(ci_cfg_hdr_t *hdr, ci_uint32 len,
			       size_t *bufsize, size_t sizes);

/*! Validates database binary object against standard option datastructures */
ci_inline int ci_cfg_is_valid(ci_cfg_hdr_t *hdr, ci_uint32 len)
{
  size_t bufsize[CICFG_BLOB_ID_COUNT];
  memset(&bufsize[0], 0, sizeof(bufsize));
  
  bufsize[CICFG_BLOB_ID_NETIF] = sizeof(ci_netif_config_opts);
  bufsize[CICFG_BLOB_ID_OS]    = sizeof(citp_opts_t);
  bufsize[CICFG_BLOB_ID_USER]  = sizeof(ci_user_opts_t);
  
  return ci_cfg_is_valid_for(hdr, len, &bufsize[0], CICFG_BLOB_ID_COUNT);
}


/*! Returns 1, if app is to be excluded */
extern int ci_cfg_app_excluded(const char *app, const ci_cfg_hdr_t *hdr);


/*! Pretty print the config database */
extern size_t ci_cfg_pprint(char *buf, size_t len, const ci_cfg_hdr_t *hdr);


/*! efabcfg constructor */
extern int ci_cfg_drv_ctor(void);


/*! efabcfg destructor */
extern void ci_cfg_drv_dtor(void);


#define CITP_OPTS (ci_cfg_opts.citp_opts)
extern ci_cfg_opts_t ci_cfg_opts CI_HV;
extern int ci_cfg_query(char *proc_name_utf8, int *ref_cfgerr);

/* Needed to support list of port numbers in EF_ options */
struct ci_port_list {
  ci_dllink link;
  ci_uint16 port;
};

ci_inline void ci_cfg_dont_intercept(citp_opts_t *opts)
{
  opts->ul_tcp = opts->ul_udp = opts->intercept = 0;
}

#endif  /* __CI_INTERNAL_EFABCFG_H__ */

/*! \cidoxg_end */
