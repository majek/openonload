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

/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** * Redistributions of source code must retain the above copyright notice,
**   this list of conditions and the following disclaimer.
**
** * Redistributions in binary form must reproduce the above copyright
**   notice, this list of conditions and the following disclaimer in the
**   documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
** IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
** TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
** PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
** TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
** PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
** LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
** NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Onload extension API
**   \date  2010/12/20
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_EXTENSIONS_H__
#define __ONLOAD_EXTENSIONS_H__

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Use ONLOAD_MSG_WARM in the flags field of send(), sendto(), sendmsg(),
 * and onload_zc_send() to do 'fake' sends to keep the send path warm.
 *
 * This is advantageous because code paths that have not run recently
 * execute slowly.  ie. A send() call will take much longer if the previous
 * send was 1s ago than if it was 1ms ago, and the reason is because cached
 * state in the processor is lost over time.  This flag exercises Onload's
 * send path so that a subsequent performance critical send() will be
 * faster.
 *
 * WARNING!!! Note that if you use this flag with unaccelerated sockets,
 * then the message may actually be transmitted.  Therefore, we recommend
 * that before using this flag on a socket, you verify that the socket is
 * indeed accelerated by using onload_fd_stat() or onload_fd_check_feature()
 * You should check this for each socket, after you call bind() or connect()
 * on it; as these functions can cause the socket to be handed to the kernel.
 *
 * This flag corresponds to MSG_SYN in the kernel sources, which appears to
 * not be used.
 */
#define ONLOAD_MSG_WARM 0x400

/* Use ONLOAD_SOF_TIMESTAMPING_STREAM with SO_TIMESTAMPING on TCP sockets.
 *
 * The timestamp information is returned via MSG_ERRQUEUE using
 * onload_scm_timestamping_stream structure.
 * The only valid TX flag combination is
 * (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_SYS_HARDWARE |
 *  ONLOAD_SOF_TIMESTAMPING_STREAM).
 *
 * Onload sometimes sends packets via OS.  If it happens, the corresponding
 * timestamp is 0.
 *
 * If a segment was not retransmitted, last_sent is 0.
 */
#define ONLOAD_SOF_TIMESTAMPING_STREAM (1 << 23)

/* Use ONLOAD_SCM_TIMESTAMPING_STREAM when decoding error queue from TCP
 * socket.
 */
#define ONLOAD_SCM_TIMESTAMPING_STREAM ONLOAD_SOF_TIMESTAMPING_STREAM

struct onload_scm_timestamping_stream {
  struct timespec  first_sent; /* Time segment was first sent. */
  struct timespec  last_sent;  /* Time segment was last sent. */
  size_t           len; /* Number of bytes of message payload. */
};

extern int onload_is_present(void);


/* Describes the namespace for searching for matching stack names */
enum onload_stackname_scope {
  ONLOAD_SCOPE_NOCHANGE,
  ONLOAD_SCOPE_THREAD,
  ONLOAD_SCOPE_PROCESS,
  ONLOAD_SCOPE_USER,
  ONLOAD_SCOPE_GLOBAL
};

/* Describes who the stack name will apply to */
enum onload_stackname_who {
  ONLOAD_THIS_THREAD, /* just this thread */
  ONLOAD_ALL_THREADS  /* all threads in this process */
};

#define ONLOAD_DONT_ACCELERATE NULL

extern int onload_set_stackname(enum onload_stackname_who who,
                                enum onload_stackname_scope scope, 
                                const char* stackname);

extern int onload_stackname_save(void);

extern int onload_stackname_restore(void);

extern int onload_stack_opt_set_int(const char* opt, int64_t val);

extern int onload_stack_opt_get_int(const char* opt, int64_t* val);

extern int onload_stack_opt_reset(void);


struct onload_stat {
  int32_t   stack_id;
  char*     stack_name;
  int32_t   endpoint_id;
  int32_t   endpoint_state;
};

extern int onload_fd_stat(int fd, struct onload_stat* stat);


/**********************************************************************
 * onload_thread_set_spin: Per-thread control of spinning.
 *
 * By default each thread uses the spinning options as specified by the
 * Onload configuration options.  This call can be used to override those
 * settings on a per-thread basis.
 */

enum onload_spin_type {
  ONLOAD_SPIN_ALL,        /* enable or disable all spin options */
  ONLOAD_SPIN_UDP_RECV,
  ONLOAD_SPIN_UDP_SEND,
  ONLOAD_SPIN_TCP_RECV,
  ONLOAD_SPIN_TCP_SEND,
  ONLOAD_SPIN_TCP_ACCEPT,
  ONLOAD_SPIN_PIPE_RECV,
  ONLOAD_SPIN_PIPE_SEND,
  ONLOAD_SPIN_SELECT,
  ONLOAD_SPIN_POLL,
  ONLOAD_SPIN_PKT_WAIT,
  ONLOAD_SPIN_EPOLL_WAIT,
  ONLOAD_SPIN_STACK_LOCK,
  ONLOAD_SPIN_SOCK_LOCK,
  ONLOAD_SPIN_SO_BUSY_POLL,
  ONLOAD_SPIN_MAX /* special value to mark largest valid input */
};

/* Enable or disable spinning for the current thread. */
extern int onload_thread_set_spin(enum onload_spin_type type, int spin);


/**********************************************************************
 * onload_fd_check_feature : Check whether or not a feature is supported
 *
 * Will return >0 if the feature is supported, or 0 if not.
 * It will return -EOPNOTSUP if this version of Onload does not know how
 * to check for that particular feature, even if the feature itself may
 * be available; or -ENOSYS if onload_fd_check_feature() itself is not
 * supported.
 */

enum onload_fd_feature {
  /* Check whether this fd supports ONLOAD_MSG_WARM or not */
  ONLOAD_FD_FEAT_MSG_WARM
};

extern int onload_fd_check_feature(int fd, enum onload_fd_feature feature);

/**********************************************************************
 * onload_move_fd: Move the file descriptor to the current stack.
 *
 * Move Onload file descriptor to the current stack, set by
 * onload_set_stackname() or other tools.  Useful for descriptors obtained
 * by accept(), to move the client connection to per-thread stack out of
 * the listening one.
 *
 * Not all kinds of Onload file descriptors are supported. Currently, it
 * works only with TCP closed sockets and TCP accepted sockets with some
 * limitations.
 * Current limitations for accepted sockets:
 * a) empty send queue and retransmit queue (i.e. send() was never called
 *    on this socket);
 * b) simple receive queue: no loss, no reordering, no urgent data.
 *
 * Returns 0 f moved successfully, -1 otherwise.
 * In any case, fd is a good accelerated socket after this call.
 */
extern int onload_move_fd(int fd);


/**********************************************************************
 * onload_ordered_epoll_wait: Wire order delivery via epoll
 *
 * Where an epoll set contains accelerated sockets in only one stack this
 * function can be used as a replacement for epoll_wait, but where the returned
 * EPOLLIN events are ordered.
 *
 * This function can only be used if EF_UL_EPOLL=1, which is the default, or
 * EF_UL_EPOLL=3.
 *
 * Hardware timestamping is required for correct operation.
 *
 * Any file descriptors that are returned as ready without a valid timestamp
 * (tv_sec is 0) should be considered un-ordered, with respect to each other
 * and the rest of the set.  This will occur where data is received via the
 * kernel, or without a hardware timestamp, for example on a pipe, or on an
 * interface that does not provide hardware timestamps.
 *
 * This does not support use of EPOLLET or EPOLLONESHOT.
 */

struct onload_ordered_epoll_event {
  /* The hardware timestamp of the first readable data. */
  struct timespec ts;
  /* Number of bytes that may be read to respect ordering. */
  int bytes;
};

struct epoll_event;
int onload_ordered_epoll_wait(int epfd, struct epoll_event *events,
                              struct onload_ordered_epoll_event *oo_events,
                              int maxevents, int timeout);


/**********************************************************************
 * onload_delegated_send: send via EF_VI to the Onload-managed TCP connection
 *
 * onload_delegated_send_prepare: prepare to send up to "size" bytes.
 * Allocates "headers" and fill them in with Ethernet-IP-TCP header data.
 * Returns:
 * ONLOAD_DELEGATED_SEND_RC_OK=0 in case of success;
 * ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET: invalid socket
 *     (non-Onloaded, non-TCP, non-connected or write-shutdowned);
 * ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER: too small headers_len value
 *     (headers_len is set to the correct size);
 * ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY: send queue is not empty;
 * ONLOAD_DELEGATED_SEND_RC_NOARP: failed to find the destination MAC
 *      address;
 * ONLOAD_DELEGATED_SEND_RC_NOWIN: send window or congestion window
 *      is closed.  send_wnd and cong_wnd fields are filled in,
 *      so the caller can find out which window is closed.
 *
 * ARP resolution in onload_delegated_send_prepare():
 * default (flags=0):
 *   Ask kernel for ARP information if necessary;
 *   fail if such information is not available.
 *   It is recommended to use a normal send() for the first part of the
 *   data if onload_delegated_send_prepare() returns
 *   ONLOAD_DELEGATED_SEND_RC_NOARP.
 * flags=ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP:
 *   Do not look for correct ARP.  The caller will fill in
 *   the destination MAC address.
 * flags=ONLOAD_DELEGATED_SEND_FLAG_RESOLVE_ARP:
 *   If ARP information is not available, send a speculative TCP ACK
 *   to provoke kernel into ARP resolution.  Wait up to 1ms for ARP
 *   information to appear.
 * 
 *
 * onload_delegated_send_prepare() can be called speculatively.
 *
 *
 * onload_delegated_send_tcp_update: update packet headers with data length
 * and push flag details.
 * TCP PUSH flag: The flag is expected to be set on the last packet when
 * sending a large data chunk.  In the most cases, contemporary OSes ignore
 * TCP PUSH flag on receive.  However, you probably want to set it
 * correcctly if your TCP stream is received by an older OS.
 * Length: onload_delegated_send_prepare() assumes that the packet length
 * is equal to mss.  If it is a correct assumption, there is no need to
 * call onload_delegated_send_tcp_update().
 *
 *
 * onload_delegated_send_tcp_advance: advance headers after sending
 * one TCP packet via EF_VI.
 *
 *
 * onload_delegated_send_complete: tell this TCP connection that
 * some data was sent via EF_VI.  This function can be thought as send() or
 * sendmsg() replacement.
 * Most of the flags are ignored, except: MSG_DONTWAIT, MSG_NOSIGNAL.
 *
 * If the call is successful, Onload takes care about any further issues
 * with the data: retransmit in case of packet loss, PMTU changes, etc.
 * This function can block because of SO_SNDBUF limitation.  When blocked,
 * the function call can be interrupted by signal and return the number of
 * bytes already processed (added to retransmit queue).
 * This function ignores SO_SNDTIMEO value.
 * You can pass your data to onload via multiple _complete() calls after
 * one _prepare() call.
 *
 *
 * onload_delegated_send_cancel: No more delegated send is planned.
 * Normal send(), shutdown() or close() can be called after this call.
 * This call is necessary if you need to close the connection graciously
 * when the file descriptor is closed via close() or exit().
 * 
 * There is no need to call _cancel() before _prepare().
 * There is no need to call _cancel if all the bytes specified in _prepare
 * were sent.
 *
 *
 * Note 1, serialization.
 * User is responsible for serialization of onload_delegated_send_*()
 * calls.  I.e. user should call onload_delegated_send_prepare() first,
 * and onload_delegated_send_cancel() later.  Normal send(), write(),
 * sendfile() function MUST NOT be called in between or in parallel with
 * these calls.  Misbehaving applications might crash.
 *
 *
 * Note 2, latency/performance.
 * If you need the best latency in the worst case, you must call
 * _complete() as soon as possible.  If you are using EF_VI to send the
 * real packets, do not wait for TX complete events - call _complete() at
 * once.  It will allow TCP machinery to retransmit packet if any of them
 * are lost.
 * If you want to save some CPU cycles at cost of making TCP retransmits
 * a bit slower (i.e. at the cost of worse latency in case of packet loss):
 * call _complete() later, to allow the network peer to acknowledge your data.
 * With the late _complete() call, you'll avoid copying of your data into TCP
 * retransmit queue (if there are no packet loss).
 *
 *
 * Sample code0: Try to send via delegated sends API and if not enough space
   fall back to normal send.

 start:
  onload_delegated_send_prepare(fd, size, flags, &ds);
  bytes = min(ds.send_wnd, ds->cong_wnd, ds.user_size, ds.mss);
  if( bytes != ds.user_size ) {
    onload_delegated_send_cancel(fd);
    send(fd, buf, size);
  }
  else {
    if( bytes != ods.mss )
      onload_delegated_send_tcp_update(&ds, bytes, 1);
    // Send via ef_vi
    onload_delegated_send_complete(fd, iovec pointing to data, 0);
  }

 * Sample code1: More involved.  Here, we will only send via delegated sends
   API.  If there isn't enough space to send, we use multiple delegated sends
   to send the entire payload.
 
 start:
  onload_delegated_send_prepare(fd, size, &ds,
                                ONLOAD_DELEGATED_SEND_FLAG_RESOLVE_ARP);
  sent = 0;
  while( (bytes = min(ds->send_wnd, ds->cong_wnd,
                      ds->user_size, ds->mss)) > 0 ) {
    uint8_t packet[1500];
 
    // set correct length and push for the last packet
    if( bytes != ds->mss ||
        bytes == min(ds->send_wnd, ds->cong_wnd, ds->user_size) )
      onload_delegated_send_tcp_update(ds, bytes, true);
 
    // compose and send the packet
    memcpy(packet, ds->headers, ds->headers_len);
    memcpy(packet + ds->headers_len, my_data, bytes);
    send "packet" via EF_VI;
 
    // increment everything
    onload_delegated_send_tcp_advance(ds, bytes);
    sent += bytes;
    my_data += bytes;
    if( something is wrong )
      break; // no need to send all the "size" bytes
  }
  assert(sent <= size);
  if( sent > 0 )
    onload_delegated_send_complete(fd, msg pointing to "my_data", 0);
  if( have more data to send )
    goto start;
  onload_delegated_send_cancel(fd);
  close(fd);
 
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

struct onload_delegated_send {
  void* headers;
  int   headers_len; /* buffer len on input, headers len on output */

  int   mss;         /* one packet payload may not exceed this */
  int   send_wnd;    /* send window */
  int   cong_wnd;    /* congestion window */
  int   user_size;   /* the "size" value from send_prepare() call */

  /* User should not look under the hood of those: */
  int   tcp_seq_offset;
  int   ip_len_offset;
  int   ip_tcp_hdr_len;
  int   reserved[5];
};

enum onload_delegated_send_rc {
  ONLOAD_DELEGATED_SEND_RC_OK = 0,
  ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET,
  ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER,
  ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY,
  ONLOAD_DELEGATED_SEND_RC_NOWIN,
  ONLOAD_DELEGATED_SEND_RC_NOARP,
};

/* Do not try to find the destination MAC address -
 * user will fill it in the packet */
#define ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP  0x1
/* Resolve ARP if necessary - it might take some time */
#define ONLOAD_DELEGATED_SEND_FLAG_RESOLVE_ARP 0x2

extern enum onload_delegated_send_rc
onload_delegated_send_prepare(int fd, int size, unsigned flags,
                              struct onload_delegated_send* out);

static inline void
onload_delegated_send_tcp_update(struct onload_delegated_send* ds, int bytes,
                                 int/*bool*/ push)
{
  uint16_t* ip_len_p;
  uint8_t* tcp_flags_p;

  ip_len_p = (uint16_t*) ((uintptr_t) ds->headers + ds->ip_len_offset);
  *ip_len_p = htons(bytes + ds->ip_tcp_hdr_len);

#define TCP_OFFSET_SEQ_TO_FLAGS   9
#define TCP_FLAG_PSH            0x8
  tcp_flags_p = (uint8_t*)((uintptr_t) ds->headers + ds->tcp_seq_offset +
                           TCP_OFFSET_SEQ_TO_FLAGS);
  if( push )
    *tcp_flags_p |= TCP_FLAG_PSH;
  else
    *tcp_flags_p &= ~TCP_FLAG_PSH;
#undef TCP_OFFSET_SEQ_TO_FLAGS
#undef TCP_FLAG_PSH
}

static inline void
onload_delegated_send_tcp_advance(struct onload_delegated_send* ds, int bytes)
{
  uint32_t seq;
  uint32_t* seq_p;

  ds->send_wnd -= bytes;
  ds->cong_wnd -= bytes;
  ds->user_size -= bytes;

  seq_p = (uint32_t*) ((uintptr_t) ds->headers + ds->tcp_seq_offset);
  seq = ntohl(*seq_p);
  seq += bytes;
  *seq_p = htonl(seq);
}

extern int
onload_delegated_send_complete(int fd, const struct iovec* iov, int iovlen,
                               int flags);

extern int
onload_delegated_send_cancel(int fd);


#ifdef __cplusplus
}
#endif
#endif /* __ONLOAD_EXTENSIONS_H__ */
