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
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Onload extension API stub library.
**   \date  2010/12/11
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <errno.h>

#include <onload/extensions.h>
#include <onload/extensions_zc.h>

unsigned int onload_ext_version[] = 
  {ONLOAD_EXT_VERSION_MAJOR,
   ONLOAD_EXT_VERSION_MINOR,
   ONLOAD_EXT_VERSION_MICRO
  };


__attribute__((weak))
int onload_set_stackname(enum onload_stackname_who who, 
                         enum onload_stackname_scope context, 
                         const char* stackname)
{
  return 0;
}

__attribute__((weak))
int onload_stackname_save(void)
{
  return 0;
}

__attribute__((weak))
int onload_stackname_restore(void)
{
  return 0;
}

__attribute__((weak))
int onload_stack_opt_set_int(const char* opt, int64_t val)
{
  return 0;
}

__attribute__((weak))
int onload_stack_opt_reset(void)
{
  return 0;
}

__attribute__((weak))
int onload_is_present(void)
{
  return 0;
}

__attribute__((weak))
int onload_fd_stat(int fd, struct onload_stat* stat)
{
  return 0;
}

/**************************************************************************/

__attribute__((weak))
int onload_zc_alloc_buffers(int fd, struct onload_zc_iovec* iovecs,
                            int iovecs_len, 
                            enum onload_zc_buffer_type_flags flags)
{
  return -ENOSYS;
}

__attribute__((weak))
int onload_zc_release_buffers(int fd, onload_zc_handle* bufs, int bufs_len)
{
  return -ENOSYS;
}

__attribute__((weak))
int onload_zc_recv(int fd, struct onload_zc_recv_args* args)
{
  return -ENOSYS;
}

__attribute__((weak))
int onload_zc_send(struct onload_zc_mmsg* msgs, int mlen, int flags)
{
  return -ENOSYS;
}

/**************************************************************************/

__attribute__((weak))
int onload_set_recv_filter(int fd, onload_zc_recv_filter_callback filter,
                           void* cb_arg, int flags)
{
  return -ENOSYS;
}

/**************************************************************************/

__attribute__((weak))
int onload_msg_template_alloc(int fd, struct iovec* initial_msg, int mlen,
                              onload_template_handle* handle, unsigned flags)
{
  return -ENOSYS;
}

__attribute__((weak))
int onload_msg_template_update(int fd, onload_template_handle handle,
                               struct onload_template_msg_update_iovec* updates,
                               int ulen, unsigned flags)
{
  return -ENOSYS;
}

__attribute__((weak))
int onload_msg_template_abort(int fd, onload_template_handle handle)
{
  return -ENOSYS;
}

/**************************************************************************/

__attribute__((weak))
int onload_recvmsg_kernel(int fd, struct msghdr* msg, int flags)
{
  return -ENOSYS;
}

/**************************************************************************/

__attribute__((weak))
int onload_fd_check_feature(int fd, enum onload_fd_feature feature)
{
  return -ENOSYS;
}
/**************************************************************************/

__attribute__((weak))
int onload_thread_set_spin(enum onload_spin_type type, int spin)
{
  return -ENOSYS;
}
