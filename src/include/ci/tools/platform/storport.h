/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

/*! \cidoxg_include_ci_tools_platform  */

#ifndef __CI_TOOLS_PLATFORM_STORPORT_H__
#define __CI_TOOLS_PLATFORM_STORPORT_H__


/*
 * This is used to pull in ci_frc64 in msvcx86.h and msvcx64.h.
 */
#define CI_HAVE_INT64

/*
 * Semaphore handling for Storport.
 * Initial version is completely empty, and the trydown
 * always succeeds.
 */
typedef ULONG   ci_semaphore_t;
#define ci_sem_trydown(_s)    1
#define ci_sem_up(_s)
#define ci_sem_down(_s)
#define ci_sem_init(_s,_v)

/*
 * Lock & Irqlock handling for Storport.
 * Initial version is completely empty, and the trydown
 * always succeeds.
 */
#define ci_lock_lock(_l)
#define ci_lock_trylock(_l)
#define ci_lock_unlock(_l)
#define ci_lock_dtor(_l)

#define ci_irqlock_lock(l,s)
#define ci_irqlock_unlock(l,s)
#define ci_irqlock_dtor(l)
#define ci_irqlock_ctor(l)

#define ci_netif_trylock(l) 1


/*
 * Get a proper OS!
 */
#define	IPPROTO_IP	0
#define	IPPROTO_ICMP	1
#define	IPPROTO_IGMP	2
#define	IPPROTO_TCP	6
#define	IPPROTO_UDP	17
#define	IPPROTO_ICMPV6	58

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define CI_BOMB()  DbgBreakPoint()


#define CI_LOG_FN_DEFAULT  ci_log_syslog

typedef int ssize_t;
typedef int socklen_t;

typedef union  citp_waitable_obj_u	citp_waitable_obj;
typedef struct ci_tcp_state_s       ci_tcp_state;
typedef citp_waitable_obj*          oo_sp;

# define S_SP(s)                 ((citp_waitable_obj*) (s))

/* Fixed width type equivalent of struct timeval */
struct oo_timeval {
  ci_int32 tv_sec;
  ci_int32 tv_usec;
};


/**********************************************************************
 * IOVEC abstraction
 */
/*! \TODO There are places where this is still used, need to confirm that
 *  they're safe or replace them. */
/*struct iovec {
  void*  iov_base;
  size_t iov_len;
  };*/

typedef struct ci_iovec_s {
  char * buf;
  unsigned long len;
} ci_iovec;

struct msghdr {
  char*         msg_name;
  socklen_t     msg_namelen;
  ci_iovec*     msg_iov;
  size_t        msg_iovlen;
  char*         msg_control;
  socklen_t     msg_controllen;
  int           msg_flags;
};

/* Accessors for buffer/length in [msg_iov] */
#define CI_IOVEC_BASE(i) ((i)->buf)
#define CI_IOVEC_LEN(i)  ((i)->len)

/* Copy of WSABUF */



/* by default everything uses standard allocator */
#define ci_alloc        __ci_alloc
#define ci_alloc_fn     __ci_alloc
#define ci_vmalloc      __ci_alloc
#define ci_vmalloc_fn   __ci_alloc
#define ci_atomic_alloc __ci_alloc

#define ci_alloc_nonpaged __ci_alloc_nonpaged

/*
 * Memory allocation & disposal from lwip.
 */
#ifdef __x86_64__
typedef __int64 mem_size_t;
#else
typedef int mem_size_t;
#endif 

void *mem_malloc(mem_size_t size);
void  mem_free(void *mem);


ci_inline void *
__ci_alloc(size_t n)
{
  return mem_malloc((mem_size_t)n);
}

ci_inline void *
__ci_alloc_nonpaged(size_t n)
{
  return mem_malloc((mem_size_t)n);     /* NB all memory is nonpaged in STORPORT */
}

ci_inline void
ci_free(void* p)
{
  mem_free(p);
}

#define ci_vfree    ci_free


#define CI_ADDR_SPC_KERNEL      ((ci_addr_spc_t)(ci_uintptr_t) 2)


#define ci_is_multithreaded()	1

#define ci_in_interrupt() ci_assert(0)
#define ci_in_ ()         ci_assert(0)
#define ci_in_irq()       ci_assert(0)

#ifndef HZ
#define HZ 100
#endif
/*
*/

#ifndef _OFF_T_DEFINED
typedef long _off_t;                /* file offset value */
#if     !__STDC__
/* Non-ANSI name for compatibility */
typedef long off_t;
#endif
#define _OFF_T_DEFINED
#endif


#define KERNEL_VERSION(x,y,z)   0
#define LINUX_VERSION_CODE      0

#endif  /* __CI_TOOLS_PLATFORM_STORPORT_H__ */

/*! \cidoxg_end */
