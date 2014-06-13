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

#ifndef HWD
#define HWD

#include <ci/compat.h>

/************************************************************/
#define HWD_PLATFORM_FALCON_ASIC 0x1
#define HWD_PLATFORM_FALCONB0_FPGA 0x2
#define HWD_PLATFORM_SIENA_ASIC 0x3
#define HWD_PLATFORM_SIENA_FALCONB0_FPGA 0x4 /* old SFC4007 platform */
#define HWD_PLATFORM_SIENA_PLAT_M 0x5
#define HWD_PLATFORM_SIENA_HALFSPPED 0x6

/*******************************************************/
#define HW_ACC_NA 0   /*< =access attribute not applicable */
#define HW_ACC_RW 1   /*< can read, can write */
#define HW_ACC_RO 2   /*< can read */
#define HW_ACC_RC 3   /*< can read, read clears */
#define HW_ACC_WO 4   /*< can write */
#define HW_ACC_RWC 5  /*< can read, can write, read clears */
#define HW_ACC_RWS 6  /*< can read, can write, sticky value over reset */
#define HW_ACC_RWC1 7 /*< can read, can write, write one bits clear bit? */
#define HW_ACC_RWC0 8 /*< can read, can write, write zero bits clear bit? */
#define HW_ACC_RSVDP 9
#define HW_ACC_RSVD 10
#define HW_ACC_ROZ 11
#define HW_ACC_RW1C HW_ACC_RWC1
#define HW_ACC_ROF 12

#define HWD_ACC_MAX_ENTRIES 4
#define HWD_ACC_ENTRY_DEFAULT 0
#define HWD_ACC_ENTRY_DBI 1
#define HWD_ACC_ENTRY_VF 2
#define HWD_ACC_ENTRY_VFDBI 3


/************************************************************/
/* the following 3 defines are used where 
   version param could be used */
#define HWD_NULL 0 /* when this is specified default version
                      see hwd_set_default_version() will be used */
#define HWD_FALCONA 0x01
#define HWD_FALCONB 0x02
#define HWD_SIENAA  0x04
#define HWD_HUNTA   0x08
#define HWD_INVALID 0xff

/* NOTE: in the API's you can also pass in ASCII version
   values = 'A'=HWD_FALCONA, 'B'=HWD_FALCONB, 'C'=HWD_SIENAA
   (we'll pay for this convenience later ... 
    but lets ignore it for now)*/

typedef unsigned char hwd_version_t;

/* this API gets the canonical version; translating 'A', 'B', 'C'
   into HWD_FALCONA, HWD_FALCONB definition form; in this form
   the version bit can be compared to version fields in the various
   hwd_* typedefs */
hwd_version_t hwd_get_version(hwd_version_t version);

#define HWD_MAX_NORM_TABLES 4 /* norm table for each version */

/************************************************************/
#define HWD_OP_ENDIAN_SWAP 0x1

/************************************************************/
/* The hwd_ifmaptblobj_t is arranged into tables and models an address map
 * each entry has an index into a table containing hwd_defobj_t definitions.
 * The referenced entry describes how to decode thet data at the given address
 *
 * In reality an address map is organized into N hwd_ifmaptblobj_t tables (one for
 * each asic version and 1 hwd_ifmaptblobj_t for special case addresses.
 * see hwd_ifmapstblentry_t
 *
 */

typedef struct _hwd_ifmaptblobj_t {
  ci_int32  hwddef; /* this is type hwd_def_e, but we don't use exact
                       type to avoid header entanglement, and consummers
                       having to unnecessarily rebuild */
  char* id;
  ci_uint32 addr;
  ci_uint32 num_rows;
  ci_uint16 step;
  ci_uint8 version;
  ci_uint16 width;

} hwd_ifmaptblobj_t;



/* The hwd_defobj_t, is instantiated as a table, with each 
 * entry describing how to decode some data. The code generator 
 * creates an enum table hwd_def_e which can be used to
 * lookup a definition, alternatively lookups can be done via the 
 * hwd_ifmaptblobj_t tables
 */
typedef struct _hwd_defobj_t {
  char* id;
  ci_int32 field_lut_offset;
  ci_int32 field_lut_num_rows;
  hwd_version_t version;
  ci_uint8 rtlblock; /* hwd_rtlblock_e */
  /* note we don't encode the width; may differ between versions
     you need to iterate over fields to find larges msb */
} hwd_defobj_t;



/* The hwd_deffieldobj_t is used to describe a field, a hwd_defobj_t
 *  indirects to one or more hwd_deffieldobj_t objects
 */
typedef struct _hwd_deffieldobj_t {
  char* id;
  ci_uint64 opvalue;
  ci_uint64 resetvalue;
  ci_uint16 msb;     
  ci_uint16 lsb; 
  ci_uint8 acc[HWD_ACC_MAX_ENTRIES];    
  hwd_version_t version;     
  
} hwd_deffieldobj_t;


/* this object is used to hold an "address map */
typedef struct _hwd_ifmapstblentry_t {
   char* id;
   char* desc;
  /* this holds an if map table which has entries that are not
     sparse, i.e. all registers and all tables that are packed,
     we have a separate one for each version to make searching easy */
  struct {
     hwd_ifmaptblobj_t* ifmaptbl;
     ci_int32 tbl_cnt;
     hwd_version_t version;     
  } norm[HWD_MAX_NORM_TABLES];

  /* this holds all tables that are not packed (i.e. page mapped) */
   hwd_ifmaptblobj_t* sparseifmaptbl;

  ci_int32 sparse_tbl_cnt;
  ci_int32 address_units; /* 8=byte addressing 32=dword addressing */
  ci_int32 access_group_idx;

} hwd_ifmapstblentry_t;


void hwd_set_default_ops(ci_uint32 ops);

void hwd_set_default_version(hwd_version_t version);

ci_int32 /*hw_ifmap_e or -1*/ hwd_ifmapstblobj_lookup_tbl(
   const char*map_id);

hwd_ifmaptblobj_t* hwd_ifmapstblobj_get_norm_tbl(
   ci_int32 map /* hw_ifmap_e */, 
   hwd_version_t version,
   ci_int32* table_cnt /* return the size of the table*/,
   int* access_group_out /* returns index for acc in hwd_deffieldobj_t */);

hwd_ifmaptblobj_t* hwd_ifmapstblobj_get_sparse_tbl(
   ci_int32 map /* hw_ifmap_e */, 
   hwd_version_t version,
   ci_int32* table_cnt /* return the size of the table*/);

/* get hwd_ifmaptblobj_t that represents address */
hwd_ifmaptblobj_t* hwd_ifmaptblobj_get(
   ci_uint32 addr, 
   ci_int32 map /* hw_ifmap_e */, 
   hwd_version_t version,
   ci_int32* result_row_idx, /* can be NULL, otherwise will 
                               fill in with row index */
   ci_int32* result_offset /* can be NULL, otherwise will 
                              fill in with offset within row */);

/* pretty print to buf address as symbolic address id */
char* hwd_ifmaptblobj_adrstr(
   ci_uint32 addr, 
   ci_int32 map /* hw_ifmap_e */, 
   hwd_version_t version,
   char* buf,
   ci_int32 buf_max_size,
   ci_uint32 ops);

/* pretty print to value, given its address */
char* hwd_ifmaptblobj_valstr(
   ci_uint32 addr, 
   ci_int32 map /* hw_ifmap_e */, 
   hwd_version_t version,
   void* value,
   char* buf,
   ci_int32 buf_max_size,
   ci_uint32 ops);

/* get hwd_ifmaptblobj_t that represents object */
hwd_defobj_t* hwd_defobj_get(
   ci_int32 defid /*hwd_def_e*/,
   hwd_version_t version);

/* get hwd_ifmaptblobj_t that represents object */
char* hwd_defobj_str(
   ci_int32 defid /*hwd_def_e*/,
   hwd_version_t version,
   void* value,
   char* buf,
   ci_int32 buf_max_size,
   ci_uint32 ops);

/* extract field value from value, where field is described by field object */
ci_uint64 hwd_deffieldobj_decode(
   hwd_deffieldobj_t* fldobj,
   void* value,
   ci_int32 chunk /*0 for 1st 64bits, 1 for 2nd 64 bits (if field >64bits wide)*/,
   ci_uint32 ops);


/* encode field value from value, where field is described by field object,
   the field_value is ORed into the existing value */
void hwd_deffieldobj_encode(
  hwd_deffieldobj_t* fldobj,
  void* value, ci_uint64  field_value,
   ci_int32 chunk /*0 for 1st 64bits, 1 for 2nd 64 bits (if field >64bits wide)*/,
   ci_uint32 ops);

hwd_deffieldobj_t* hwd_ifmaptblobj_get_fieldobj_tbl(
   hwd_ifmaptblobj_t* ifmaptblobj,
   ci_int32* table_cnt /* return the size of the table*/);

#endif
