/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * This function can only be used if EF_UL_EPOLL=1, which is the default.
 *
 * Hardware timestamping is required for correct operation.
 *
 * Any file descriptors that are returned as ready without a valid timestamp
 * (tv_sec is 0) should be considered un-ordered, with respect to each other
 * and the rest of the set.  This will occur where data is received via the
 * kernel, or without a hardware timestamp, for example on a pipe, or on an
 * interface that does not provide hardware timestamps.
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

#ifdef __cplusplus
}
#endif
#endif /* __ONLOAD_EXTENSIONS_H__ */
