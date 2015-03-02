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
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef CUSTOMER_EVENT_LOG_H
#define CUSTOMER_EVENT_LOG_H

typedef int ci_cevtlog_cat_id_t;

#define CI_CEVTLOG_BUF_SIZE 80
#define CI_CEVTLOG_ARGS_MAX 8

#define CI_CEVTLOG_MAX_PATH 260

typedef char ci_cevtlog_char_t;


typedef struct _ci_cevtlog_format_cat_t {
  ci_cevtlog_cat_id_t id;
  int type;
  int facility; /* App / system */
  int numargs;
  ci_cevtlog_char_t* arglist;
  ci_cevtlog_char_t* default_msg;
} ci_cevtlog_format_cat_t;

#define CI_EVTLOG_NARG_TYPE int


struct ci_netif_s; /* forward declr */

/************************************************************************/
/* Public APIs for generating an event from driver or userspace
 */
extern void ci_cevtlog_app(
   struct ci_netif_s* netif,
   ci_cevtlog_cat_id_t cat_id, 
   CI_EVTLOG_NARG_TYPE num_args,...);


#ifdef __KERNEL__ /* we can only send a system event log from kernel */
extern void ci_cevtlog_sys(
   void* device_obj, 
   ci_cevtlog_cat_id_t cat_id, 
   CI_EVTLOG_NARG_TYPE num_args,...);
#endif

/************************************************************************/
/* Public API for emitting event from iSCSI driver
 */

extern void ci_vcevtlog_iscsi_nic(
   void *logger_handle, /* O/S dependent value */
   ci_cevtlog_cat_id_t cat_id, 
   CI_EVTLOG_NARG_TYPE num_args,
   va_list arg);


/************************************************************************/
/* Public API for emitting event from Control Plane
 */
extern void ci_cevtlog_cplane(
   void* device_obj /* set to NULL from user space */, 
   ci_cevtlog_cat_id_t cat_id, 
   CI_EVTLOG_NARG_TYPE num_args,...);

/************************************************************************/
/* Private APIs 
 */

extern int _ci_cevtlog_do_formatting(ci_cevtlog_cat_id_t cat_id, 
   int numargs,
   va_list args,
   ci_cevtlog_char_t** bufptrlist, 
   int facility,
   int* final_buf_size);

extern const ci_cevtlog_format_cat_t _ci_cevtlog_format_cat[];


#define EVENTLOG_INFORMATION_TYPE 1
#define EVENTLOG_ERROR_TYPE 2
#define EVENTLOG_WARNING_TYPE 3

#define FACILITY_SYSTEM 0
#define FACILITY_APP    1
#define FACILITY_CPLANE 2
#define FACILITY_ISCSI  3

#include "customer_event_log_msgs.h"

#endif
/*! \cidoxg_end */
