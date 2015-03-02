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


#define MCC_INTERNAL "%1"

#define NLMCC_INTERNAL NL"%1"

#if (WINDOWS==1)
#if (DRIVER==1)
#define MCC_FP(x) L##x
#else
#define MCC_FP(x) TEXT(x)
#endif
#else
#define MCC_FP(x) x
#endif

#define MCC_FMT_STRING  MCC_FP("%s\r")
#define MCC_FMT_INT     MCC_FP("%d\r")
#define MCC_FMT_UINT    MCC_FP("%u\r")
#define MCC_FMT_PTR     MCC_FP("%p\r")

#if (WINDOWS==1)
#define MCC_FMT_WSTRING MCC_FP("%S\r") /* assumes use in sprintf not wsprintf */
#define MCC_FMT_IFID    MCC_FP("0x%05X\r")
#define MCC_FMT_SYSRC   MCC_FMT_UINT
#else
#define MCC_FMT_WSTRING MCC_FP("%ls\r")
#define MCC_FMT_IFID    MCC_FP("%02d\r")
#define MCC_FMT_SYSRC   MCC_FMT_INT
#endif

#define MCC_FMT_IPMASK  MCC_FP("%08X\r")
#define MCC_FMT_IPSET   MCC_FP("%d\r"/*CI_IP_ADDRSET_PRINTF_FORMAT*/) 
#define MCC_FMT_IP      MCC_FP("%d.%d.%d.%d\r"/*CI_IP_PRINTF_FORMAT*/)
/* use CI_IP_PRINTF_ARGS(&ipaddr) to generate argument */
#define MCC_FMT_MAC     MCC_FP("%02x:%02x:%02x:%02x:%02x:%02x\r"/*CI_MAC_PRINTF_FORMAT*/)
/* use CI_MAC_PRINTF_ARGS(&macaddr) to generate argument */
#define MCC_FMT_HWPORT  MCC_FP("%d:%d\r"/*CI_HWPORT_PRINTF_FORMAT*/)
/* use CI_HWPORT_PRINTF_ARGS(&macaddr) to generate argument */

/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
#if defined(MCC_FORMAT_CAT_FILE1)

#if (WINDOWS==1)

#if (DRIVER==1)
#define MCC_HEADER(void) 
#else
#define MCC_HEADER(void)
#endif

#define MCC_MESSAGE_HEADER(id,severity,facility,identifier,numargs,fargs)

#define MCC_MESSAGE_RECORD(language,fargs)

#else /* NOT WINDOWS */

#define MCC_HEADER(void) \
!HSinclude "ci/tools/customer_event_log_gendefs.h" !NL\
!HSdefine CURRENT_ID bad

#define MCC_MESSAGE_HEADER(id,severity,facility,identifier,numargs,fargs) \
!HSundef CURRENT_ID !NL\
!HSdefine CURRENT_ID identifier

#define MCC_MESSAGE_RECORD(language,fargs) \
MCC_MESSAGE_RECORDv(language,fargs)

#endif



#define MCC_TRAILER(void)
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
#elif defined(MCC_FORMAT_CAT_FILE1_STAGE2)


#define MCC_MESSAGE_RECORDv(language,fargs) \
!HSdefine CURRENT_ID !CC language  fargs
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
#elif defined(MCC_FORMAT_CAT_FILE2)

#if (WINDOWS==1) 

#if (DRIVER==1)
/* String formats must be reversed if wsprintf is used instead of sprintf */
#undef MCC_FMT_STRING
#define MCC_FMT_STRING MCC_FP("%S\r")  /* wsprintf format for single char string */
#undef MCC_FMT_WSTRING
#define MCC_FMT_WSTRING MCC_FP("%s\r") /* wsprintf format for wide char string */
#endif

#define MCC_NULL_RECORD -1,0,0,0,NULL
#define MCC_DEFAULT_EARG(identifier)

#else

#define MCC_NULL_RECORD -1,0,0,0,NULL,NULL
#define MCC_DEFAULT_EARG(identifier) ,identifier##English

#endif

#define MCC_HEADER(void)					\
const ci_cevtlog_format_cat_t _ci_cevtlog_format_cat[]={     !NL\
  { MCC_NULL_RECORD },					     !NL\
  { MCC_NULL_RECORD },					     !NL\
  { MCC_NULL_RECORD },					     !NL\
  { MCC_NULL_RECORD },					     !NL\
  { MCC_NULL_RECORD },

#define MCC_MESSAGE_HEADER(id,severity,facility,identifier,numargs,fargs)	\
  { identifier, EVENTLOG_##severity##_TYPE, FACILITY_##facility, numargs, fargs MCC_DEFAULT_EARG(identifier) },

#define MCC_MESSAGE_RECORD(language,fargs)

#define MCC_TRAILER(void)  { MCC_NULL_RECORD }!NL};

/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
#elif defined(MCC_MC_FILE)

#define MCC_HEADER(void)				   \
SeverityNames=(SUCCESS=0x0:STATUS_SEVERITY_SUCCESS	!NL\
    INFORMATION=0x1:STATUS_SEVERITY_INFORMATIONAL	!NL\
    WARNING=0x2:STATUS_SEVERITY_WARNING			!NL\
    ERROR=0x3:STATUS_SEVERITY_ERROR			!NL\
    )							!NL\
							!NL\
							!NL\
FacilityNames=(						!NL\
    SYSTEM=0x0:FACILITY_SYSTEM				!NL\
    APP=0x1:FACILITY_APP				!NL\
    CPLANE=0x2:FACILITY_CPLANE				!NL\
    ISCSI=0x3:FACILITY_ISCSI				!NL\
)							!NL\
							!NL\
LanguageNames=(English=0x409:MSG00409)			!NL\
LanguageNames=(German=0x407:MSG00407)			!NL\
							!NL\
MessageId=0x1						!NL\
SymbolicName=CI_CAT_LOG					!NL\
Language=English					!NL\
Log							!NL\
.							!NL\
Language=German						!NL\
Log          	       	     				!NL\
.							!NL\
MessageId=0x2						!NL\
SymbolicName=CI_CAT_ETHERFABRIC_APP			!NL\
Language=English					!NL\
Onload Application of Solarflare Device			!NL\
.							!NL\
Language=German						!NL\
Onload Application of Solarflare Device 		!NL\
.							!NL\
MessageId=0x3						!NL\
SymbolicName=CI_CAT_ETHERFABRIC_DEVICE		       	!NL\
Language=English					!NL\
Solarstorm Device    	       				!NL\
.							!NL\
Language=German						!NL\
Solarstorm Device 	 				!NL\
.							!NL\
MessageId=0x4						!NL\
SymbolicName=CI_CAT_ETHERFABRIC_CPLANE		       	!NL\
Language=English					!NL\
Solarflare device MIB Mirror   	       			!NL\
.							!NL\
Language=German						!NL\
Solarflare device MIB Mirror 	                	!NL\
.							!NL\
MessageId=0x5						!NL\
SymbolicName=CI_CAT_ETHERFABRIC_ISCSI		       	!NL\
Language=English					!NL\
Solarflare iSCSI Device    	       			!NL\
.							!NL\
Language=German						!NL\
Solarflare iSCSI Device 				!NL\
.


#define MCC_TRAILER(void)


#define MCC_MESSAGE_HEADER(id,severity,facility,identifier,numargs,fargs)\
MessageId=id								!NL\
Severity=severity							!NL\
Facility=facility							!NL\
SymbolicName=identifier

#define MCC_MESSAGE_RECORD(language,fargs)\
Language=language!NL##fargs                      !NL\
.

/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
#elif defined(MCC_H_FILE)

#define MCC_HEADER(void)
#define MCC_MESSAGE_HEADER(id,severity,facility,identifier,numargs,fargs) \
!HSdefine identifier id

#define MCC_MESSAGE_RECORD(language,fargs)
#define MCC_TRAILER(void)

/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
#elif defined(MCC_DAT_FILE)

#define MCC_HEADER(void) {
#define MCC_MESSAGE_HEADER(id,severity,facility,identifier,numargs,fargs)	!NL\
identity=id									!NL\
message=fargs!NL

#define MCC_MESSAGE_RECORD(language,fargs)
#define MCC_TRAILER(void)

#else 
#error unknown file type
#endif
