/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** Copyright 2005-2016  Solarflare Communications Inc.
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


#ifndef __UTILS_H__
#define __UTILS_H__


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <inttypes.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stddef.h>


#ifndef MAP_HUGETLB
/* Not always defined in glibc headers.  If the running kernel does not
 * understand this flag it will ignore it and you may not get huge pages.
 * (In that case ef_memreg_alloc() may fail when using packed-stream mode).
 */
# define MAP_HUGETLB  0x40000
#endif


#ifdef __PPC__
# define huge_page_size    (16ll * 1024 * 1024)
#elif defined(__x86_64__) || defined(__i386__)
# define huge_page_size    (2ll * 1024 * 1024)
#else
# error "Please define huge_page_size"
#endif


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      abort();                                                  \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      abort();                                                  \
    }                                                           \
  } while( 0 )


#define LOGE(...)   do{ fprintf(stderr, __VA_ARGS__); }while(0)
#define LOGW(...)   do{ fprintf(stderr, __VA_ARGS__); }while(0)
#define LOGI(...)   do{ fprintf(stderr, __VA_ARGS__); }while(0)
#ifdef NDEBUG
# define LOGV(...)  do{}while(0)
#else
# define LOGV(...)  do{ if( cfg_verbose)  printf(__VA_ARGS__); }while(0)
#endif


#define ROUND_UP(p, align)   (((p)+(align)-1u) & ~((align)-1u))
#define IS_POW2(n)           (((n) & (n - 1)) == 0)

#define __BUILD_ASSERT_NAME(_x) __BUILD_ASSERT_CPP(_x)
#define __BUILD_ASSERT_CPP(_x)  __BUILD_ASSERT__##_x
#define BUILD_ASSERT(e) \
  typedef char __BUILD_ASSERT_NAME(__LINE__)[(e) ? 1 : -1] \
    __attribute__((unused))



#ifndef SO_TIMESTAMPING
# define SO_TIMESTAMPING                 37
#endif
#ifndef SOF_TIMESTAMPING_TX_HARDWARE
# define SOF_TIMESTAMPING_TX_HARDWARE    (1<<0)
# define SOF_TIMESTAMPING_TX_SOFTWARE    (1<<1)
# define SOF_TIMESTAMPING_RX_HARDWARE    (1<<2)
# define SOF_TIMESTAMPING_RX_SOFTWARE    (1<<3)
# define SOF_TIMESTAMPING_SOFTWARE       (1<<4)
# define SOF_TIMESTAMPING_SYS_HARDWARE   (1<<5)
# define SOF_TIMESTAMPING_RAW_HARDWARE   (1<<6)
#endif


#ifdef __EFAB_VI_H__
extern int
filter_parse(ef_filter_spec* fs, const char* s_in);
#endif


extern void sock_put_int(int sock, int i);

extern int sock_get_int(int sock);

extern int sock_get_ifindex(int sock, int* ifindex_out);

extern int getaddrinfo_storage(int family,
                               const char* host, const char* port,
                               struct sockaddr_storage* sas);

extern int mk_socket(int family, int socktype,
                     int op(int sockfd, const struct sockaddr *addr,
                            socklen_t addrlen),
                     const char* host, const char* port);


/* Helper functions to query host configuration */
extern void get_ipaddr_of_intf(const char* intf, char** ipaddr_out);
extern int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out);
extern int parse_host(const char* s, struct in_addr* ip_out);
extern int parse_interface(const char* s, int* ifindex_out);

#endif  /* __UTILS_H__ */
