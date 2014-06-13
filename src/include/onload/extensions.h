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

/*
** Copyright 2005-2013  Solarflare Communications Inc.
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


#ifdef __cplusplus
}
#endif
#endif /* __ONLOAD_EXTENSIONS_H__ */
