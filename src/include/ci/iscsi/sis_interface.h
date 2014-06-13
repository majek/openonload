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
*//*! \file interface.h
** <L5_PRIVATE L5_HEADER >
** \author  mjs
**  \brief  ISCSI kernel/UL interface
**   \date  2005/07/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal */

#ifndef __CI_ISCSI_INTERFACE_H__
#define __CI_ISCSI_INTERFACE_H__

/* ============================================================================
 *  Version of this interface
 * ============================================================================
 */
#define CI_ISCSI_INTERFACE_VERSION  10


/* ============================================================================
 *  Limits
 * ============================================================================
 */

#ifdef __ci_storport__
#define CI_ISCSI_MAX_SESSIONS        1
#else
#define CI_ISCSI_MAX_SESSIONS        16
#endif

#define CI_ISCSI_MAX_CONNS_PER_SESS  1


/* ============================================================================
 *  Parameter structures
 * ============================================================================
 */

typedef struct ci_iscsi_session_params_s {

  /* TODO: WMI has an "instance name"??? */
  /* TODO: WMI is a Windows artefact. Make sure it's ifdef'd correctly */

#define CI_ISCSI_NAME_MAXLEN 224                         /* RFC3270 3.2.6.1 */
  char target_name[CI_ISCSI_NAME_MAXLEN];
  char initiator_name[CI_ISCSI_NAME_MAXLEN];
  char initiator_alias[CI_ISCSI_NAME_MAXLEN];
#define CI_ISCSI_SESSION_DISCOVERY  0
#define CI_ISCSI_SESSION_NORMAL     1
  ci_uint32 session_type;
  ci_uint32 max_connections;
  ci_uint32 initial_r2t;
  ci_uint32 immediate_data;
  ci_uint32 max_burst_length;
  ci_uint32 first_burst_length;
  ci_uint32 default_time2wait;
  ci_uint32 default_time2retain;
  ci_uint32 max_outstanding_r2t;
  ci_uint32 data_pdu_in_order;
  ci_uint32 data_sequence_in_order;
  ci_uint32 error_recovery_level;
  
} ci_iscsi_session_params;

#ifdef __ci_storport__
typedef enum {
  LOGIN_STEP_GET_TARGETNAME_RESPONSE = 0x41,    /* Arbitary non-zero base */
  LOGIN_STEP_GET_PARAMETERS_RESPONSE,
  LOGIN_STEP_SEND_CHAP_CHALLENGE,
  LOGIN_STEP_EXPECTING_CHAP_RESPONSE,
  LOGIN_STEP_EXPECTING_REVCHAP_RESPONSE,
  LOGIN_STEP_CHAP_COMPLETE
} ci_storport_login_step;
#endif


typedef struct ci_iscsi_connection_params_s {

#define CI_ISCSI_AUTH_NONE          0
#define CI_ISCSI_AUTH_CHAP_UNI      1
#define CI_ISCSI_AUTH_CHAP_BI       2
  ci_uint32 auth_method;
#define CI_ISCSI_SECRET_LEN 224
  char      chap_i_name[CI_ISCSI_SECRET_LEN];
  ci_uint32 chap_i_secret_len;
  ci_uint8  chap_i_secret[CI_ISCSI_SECRET_LEN];
#define CI_ISCSI_RANDOM_LEN 16
  ci_uint8  random[CI_ISCSI_RANDOM_LEN];

  ci_uint32 ip_addr;
  ci_uint16 port;
  ci_uint16 padding;
#define CI_ISCSI_DIGEST_NONE        0
#define CI_ISCSI_DIGEST_CRC32C      1
  ci_uint32 header_digest;
  ci_uint32 data_digest;
  ci_uint32 tcp_timeout;
  ci_uint32 our_max_recv_data_segment_length;
  ci_uint32 their_max_recv_data_segment_length;
  
#ifdef __ci_storport__
  ci_storport_login_step next_login_step;
#endif

} ci_iscsi_connection_params;


/* ============================================================================
 *  Log selector bits
 * ============================================================================
 */

#define CI_ISCSI_LOG_E    0x1              /* errors */
#define CI_ISCSI_LOG_U    0x2              /* unexpected */
#define CI_ISCSI_LOG_S    0x4              /* setup */
#define CI_ISCSI_LOG_V    0x8              /* verbose */
#define CI_ISCSI_LOG_KS   0x10             /* kernel-created sockets */
#define CI_ISCSI_LOG_SD   0x20             /* SCSI driver */
#define CI_ISCSI_LOG_PN   0x40             /* parameter negotiation */
#define CI_ISCSI_LOG_PDU  0x80             /* iSCSI PDUs */
#define CI_ISCSI_LOG_RX   0x100            /* receive data path */
#define CI_ISCSI_LOG_TX   0x200            /* transmit data path */
#define CI_ISCSI_LOG_CO   0x400            /* control ops */
#define CI_ISCSI_LOG_SC   0x800            /* session/connection management */
#define CI_ISCSI_LOG_LOCK 0x1000           /* lock tracking */
#define CI_ISCSI_LOG_ATX  0x2000           /* async tx */
#define CI_ISCSI_LOG_SG   0x4000           /* scatter/gather lists */
#define CI_ISCSI_LOG_STM  0x8000           /* connection state management */
#define CI_ISCSI_LOG_DIG  0x10000          /* digest offload */
#define CI_ISCSI_LOG_WMIC 0x20000          /* WMI calls (Windows only) */
#define CI_ISCSI_LOG_WMI  0x40000          /* WMI ops (Windows only) */
#define CI_ISCSI_LOG_DHCP 0x80000          /* DHCP ops */

#define CI_ISCSI_LOG_ALL  0xFFFFFFFF       /* REALLY verbose */


/* ============================================================================
 *  Control op interface
 * ============================================================================
 */

typedef struct ci_iscsi_control_params
{

#define CI_ISCSI_CONTROL_OP_ALLOC_SESS   0  /* Allocate a new session        */
#define CI_ISCSI_CONTROL_OP_ADD_CONN     1  /* Add conn. to sess & log in    */
#define CI_ISCSI_CONTROL_OP_REMOVE_CONN  2  /* Log out and remove conn. (and
                                            **  destroy session if last one) */
                                     /*  3 - no longer used */
#define CI_ISCSI_CONTROL_OP_TEST         4  /* Greg's test stuff             */
#define CI_ISCSI_CONTROL_OP_SET_SECRET   5  /* ~= WMI SetCHAPSharedSecret    */
#define CI_ISCSI_CONTROL_OP_STARTUP      6  /* Start up iSCSI                */
#define CI_ISCSI_CONTROL_OP_SHUTDOWN     7  /* Shut down iSCSI               */
#define CI_ISCSI_CONTROL_OP_DEBUG        8  /* Hook for debug ops            */
                                     /*  9 - no longer used */
#define CI_ISCSI_CONTROL_OP_SET_LOG     10  /* Set logging bits              */
#define CI_ISCSI_CONTROL_OP_NEGOTIATE   11  /* Perform negotitation          */
#define CI_ISCSI_CONTROL_OP_ZC_TX       12 /* enable/disable zero-copy/async */
#define CI_ISCSI_CONTROL_OP_QUERY       13  /* Query various state / info    */
#define CI_ISCSI_CONTROL_OP_SENDTARGETS 14 /* Perform target discovery on
                                           ** existing session, which must
                                           ** have type discovery            */
#define CI_ISCSI_CONTROL_OP_TX_DO       15  /* en/disable tx digest offload  */
#define CI_ISCSI_CONTROL_OP_PING        16  /* send a ping over the HBA i'face*/

  ci_uint32 op;                                /*  IN: operation code        */
  ci_int32 result;                             /* OUT: result or error code  */
  union {
    struct {
      ci_uint32 sess_id;                       /* OUT: allocated session ID  */
      ci_iscsi_session_params sess_params;     /*  IN: session parameters    */
    } alloc_sess;
    struct {
      ci_uint32 sess_id;                       /*  IN: session to add to     */
      ci_uint32 conn_id;                       /* OUT: allocated conn. ID    */
      ci_uint32 max_redirect_count;            /*  IN: maximum redirects     */
#define CI_ISCSI_REDIRECT_NONE  0  /* No redirection occurred */
#define CI_ISCSI_REDIRECT_PERM  1  /* Permanent redirection occurred */
#define CI_ISCSI_REDIRECT_TEMP  2  /* Temporary redirection occurred */
#define CI_ISCSI_REDIRECT_MAXED 3  /* Too many redirections occurred */
      ci_uint32 redirect;                      /* OUT: did we redirect       */
      ci_iscsi_connection_params conn_params;  /*  IN: conn. parameters      */
    } add_conn;
    struct {
      ci_uint32 sess_id;                       /*  IN: session to remove from*/
      ci_uint32 conn_id;                       /*  IN: connection to remove  */
    } remove_conn;
    struct {
      ci_uint32 sess_id;                       /*  IN: session to log out    */
    } logout;
    struct {
      /* To make all targets use the same secret give a blank target name
       * (ie chap_t_name[0]=='\0') */
      char      chap_t_name[CI_ISCSI_SECRET_LEN];   /*  IN: target "name"    */
      ci_uint32 chap_t_secret_len;                  /*  IN: secret length    */
      ci_uint8  chap_t_secret[CI_ISCSI_SECRET_LEN]; /*  IN: target secret    */
    } set_secret;
    struct {
      ci_uint32 cpu_khz;                       /*  IN: CPU kHz from userlevel*/
#define CI_ISCSI_STARTUP_MAGIC 0x62616665
      ci_uint32 magic;                         /*  IN: Magic number          */
      ci_uint32 version;                       /* OUT: Driver interface ver. */
    } startup;
    struct {
      ci_uint32 reason;                        /*  IN: reason for shutdown ??*/
    } shutdown;
    struct {
      ci_uint32 debug_op;                      /*  IN: debug operation code  */
      ci_uint32 sess_id;                       /* I/O: session to poke       */
      ci_uint32 conn_id;                       /* I/O: connection to poke    */
      ci_uint32 fail_type;                     /*  IN: type of fail to test  */
      ci_uint32 param;                         /*  IN: misc parameter        */
#define DEBUG_DATA_LEN 256
      char data[DEBUG_DATA_LEN];               /* I/O: data in / reported    */
    } debug;
    struct {
      ci_uint32 sess_id;                       /*  IN: sess to discover on   */
      ci_uint32 conn_id;                       /*  IN: conn to discover on   */
      ci_uint32 buf_len;                       /*  IN: provided buffer length*/
      ci_uint32 len_needed;                    /* OUT: needed buffer length  */
      ci_user_ptr_t buffer;                    /*  IN: ptr to buf for output */
                                       /* NOTE: this buffer is in user space */
    } sendtargets;
    struct {
      ci_uint32 log_bits;                      /*  IN: log bits to change    */
      ci_uint32 set;                           /*  IN: 1 to set, 0 to clear  */
    } set_log;
    struct {
      ci_uint32 sess_id;                       /*  IN: sess to negotiate on */
      ci_uint32 conn_id;                       /*  IN: conn to negotiate on  */
      ci_uint32 keys;                          /*  IN: keys to negotiate     */
    } negotiate;
    struct {
      ci_uint32 enable;
    } zc_tx;
    struct {
      ci_uint32 ipaddr;
    } ping;
    struct {
      ci_uint32 query_op;                      /*  IN: query code            */
      ci_uint32 sess_id;                       /*  IN: session to query      */
      ci_uint32 conn_id;                       /*  IN: connection to query   */
      ci_uint32 result;                        /* OUT: query result          */
      ci_uint32 result2;                       /* OUT: query result 2        */
    } query;
    struct {
      ci_uint32 enable;
    } tx_do;
  } u;

} ci_iscsi_control_params;

#define CI_ISCSI_DEFAULT_PORT 3260

#define CI_ISCSI_DEFAULT_MAX_REDIRECT_COUNT 4

/* iSCSI result codes for the 'result' field in the control ops.  Most of these
 * correspond directly to the Status-Class + Status-Detail codes we get in the
 * iSCSI Login Response (ses RFC 3720, 10.13.5).
 *
 * The 'result' field may contain an negative errno code instead.  The ioctl
 * will normally give a result of ESUCCESS, and report any errors that are not
 * specifically related to the iSCSI protocol by setting the 'result' field,
 * and possibly updating other members of the data structure to provide more
 * information.  This allows for easier and better error reporting in the
 * calling code.  (In particular, it seems difficult to get at the returned
 * data structure from Python in the event of the ioctl itself failing.)
 *
 * Errors which prevent the correct operation of the ioctl (e.g. EFAULT if the
 * data pointer is bad) will of course still cause the ioctl itself to fail
 * with an * error.
 */
#define CI_ISCSI_RESULT_SUCCESS         0x0000 /* Success                    */
#define CI_ISCSI_RESULT_MOVED_TEMP      0x0101 /* Target moved temporarily   */
#define CI_ISCSI_RESULT_MOVED_PERM      0x0102 /* Target moved permanently   */
#define CI_ISCSI_RESULT_INITIATOR_ERR   0x0200 /* Initiator error            */
#define CI_ISCSI_RESULT_AUTHEN_FAILURE  0x0201 /* Authentication failure     */
#define CI_ISCSI_RESULT_AUTHOR_FAILURE  0x0202 /* Authorization failure      */
#define CI_ISCSI_RESULT_NOT_FOUND       0x0203 /* Not found                  */
#define CI_ISCSI_RESULT_TARGET_REMOVED  0x0204 /* Target removed             */
#define CI_ISCSI_RESULT_UNSUPP_VERSION  0x0205 /* Unsupported version        */
#define CI_ISCSI_RESULT_TOO_MANY_CONNS  0x0206 /* Too many connections       */
#define CI_ISCSI_RESULT_MISSING_PARAM   0x0207 /* Missing parameter          */
#define CI_ISCSI_RESULT_CANT_INCLUDE    0x0208 /* Can't include in session   */
#define CI_ISCSI_RESULT_BAD_SESS_TYPE   0x0209 /* Session type not supported */
#define CI_ISCSI_RESULT_NO_SUCH_SESS    0x020a /* Session does not exist     */
#define CI_ISCSI_RESULT_INVALID_REQ     0x020b /* Invalid during login       */
#define CI_ISCSI_RESULT_TARGET_ERR      0x0300 /* Target error               */
#define CI_ISCSI_RESULT_SERVICE_UNAVAIL 0x0301 /* Service unavailable        */
#define CI_ISCSI_RESULT_NO_RESOURCES    0x0302 /* Out of resources           */
/* (the remaining result codes are defined by us, not the iSCSI RFC) */
#define CI_ISCSI_RESULT_ERROR           0xffff /* generic error              */

/* Debug operations */
#define CI_ISCSI_DEBUG_OP_DUMP_SESS  0  /* Dump session    */
#define CI_ISCSI_DEBUG_OP_DUMP_CONN  1  /* Dump connection */
#define CI_ISCSI_DEBUG_OP_REPORT_SC  2  /* Report back sessions and conns */
#define CI_ISCSI_DEBUG_OP_FAIL_TEST  3  /* Fail in a specific way to see
					 * what happens */
#define CI_ISCSI_DEBUG_OP_LOG_TEXT   4  /* Send the given text to the system
                                         * log */
#define CI_ISCSI_DEBUG_OP_DUMP_SECRET 5 /* Dump CHAP secrets */

/* Debug fail tests.
 * Various types of failure can be scheduled to occur on a given connection.
 * The param field is used for different purposes by different tests:
 * For command failures we failure the (param)th SCSI command after the point at
 * which the test is scheduled.
 * For connection and session logout, logout will occur once we have (param)
 * commands outstanding.
 */
#define CI_ISCSI_DEBUG_FAIL_NONE      0  /* Clear scheduled failure */
#define CI_ISCSI_DEBUG_FAIL_CMD       1  /* Fail command */
#define CI_ISCSI_DEBUG_FAIL_LO_CONN   2  /* Schedule connection logout */
#define CI_ISCSI_DEBUG_FAIL_LO_SESS   3  /* Schedule session logout */
#define CI_ISCSI_DEBUG_FAIL_RECOVER   4  /* Schedule error recovery */
#define CI_ISCSI_DEBUG_FAIL_BLOCK     5  /* Disable command processing */
#define CI_ISCSI_DEBUG_FAIL_REJECT    6  /* Reject commands (connection 0) */
#define CI_ISCSI_DEBUG_FAIL_DROP_CONN 7  /* Drop conn as for async event */
#define CI_ISCSI_DEBUG_FAIL_DROP_ALL  8  /* Drop all conns as for async event */
#define CI_ISCSI_DEBUG_FAIL_SLOW      9  /* Pause after sending. */
#define CI_ISCSI_DEBUG_FAIL_MAX       9  /* Maximum value */

/* Enable / disable fail tests */
#if !defined(__ci_storport__)
#define CI_ISCSI_DEBUG_FAIL_TEST 1
#endif

/* Information queries. */

#endif

/*! \cidoxg_end */

