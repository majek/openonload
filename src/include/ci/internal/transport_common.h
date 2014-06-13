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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  al
**  \brief  Declaration of common helper functions, global variables.
**   \date  2005/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_common  */

#ifndef _CI_TRANSPORT_COMMON_H_
#define _CI_TRANSPORT_COMMON_H_

#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <onload/ul/rwlock.h>


/**********************************************************************
 ** Logging
 */

extern unsigned citp_log_level CI_HV;

#define Log_C_always(c,x)    do{ if(c) do{ x; }while(0); }while(0)
#ifdef NDEBUG
# define Log_C(c,x)          do{}while(0)
#else
# define Log_C               Log_C_always
#endif

#define Log_FL(f,x)          Log_C(citp_log_level & (f), x);
#define Log_FL_always(f,x)   Log_C_always(citp_log_level & (f), x);

#define Log_E(x)      Log_FL(CI_UL_LOG_E, x)
#define Log_U(x)      Log_FL(CI_UL_LOG_U, x)
#define Log_S(x)      Log_FL(CI_UL_LOG_S, x)
#define Log_V(x)      Log_FL(CI_UL_LOG_V, x)
#define Log_SEL(x)    Log_FL(CI_UL_LOG_SEL, x)
#define Log_POLL(x)   Log_FL(CI_UL_LOG_POLL, x)
#define Log_VSS(x)    Log_FL(CI_UL_LOG_VSS, x)
#define Log_VSC(x)    Log_FL(CI_UL_LOG_VSC, x)
#define Log_EP(x)     Log_FL(CI_UL_LOG_EP, x)
#define Log_SIG(x)    Log_FL(CI_UL_LOG_SIG, x)
#define Log_LIB(x)    Log_FL(CI_UL_LOG_LIB, x)
#define Log_CALL(x)   Log_FL(CI_UL_LOG_CALL, x)
#define Log_CLUT(x)   Log_FL(CI_UL_LOG_CLUT, x)
#define Log_PT(x)     Log_FL(CI_UL_LOG_PT, x)
#define Log_VPT(x)    Log_FL(CI_UL_LOG_VPT, x)
#define Log_VTC(x)    Log_FL(CI_UL_LOG_VTC, x)
#define Log_VV(x)     Log_FL(CI_UL_LOG_VV, x)
#define Log_VVTC(x)   Log_FL(CI_UL_LOG_VVTC, x)
#define Log_VE(x)     Log_FL(CI_UL_LOG_VE, x)
#define Log_VVE(x)    Log_FL(CI_UL_LOG_VVE, x)

#define log  ci_log

# define Log_CALL_RESULT(x) \
  Log_CALL(ci_log("%s returning %d (errno %d)",__FUNCTION__,x,errno))
# define Log_CALL_RESULT_PTR(x) \
  Log_CALL(ci_log("%s returning %p (errno %d)",__FUNCTION__,x,errno))

ci_inline void citp_set_log_level(unsigned log_level) {
  citp_log_level = log_level;
}

/**********************************************************************
 ** Transport library user-level lock
 */


/******************************************************************************
 * Even our carefully optimized lock operations and atomic ops are quite slow.
 * Specifically, this is caused by the presence of the LOCK prefix seems to
 * cost up to 100 cycles.  The glibc boys have apparently noticed the same
 * issues, and so keep a bit hanging of gs (at gs:0x10) that says whether the
 * current process is multithreaded.  We use this to determine whether or not
 * we need to assert the LOCK bit on the bus when doing atomic operations.
 * Note however that any atomic types in the shared state must assert the LOCK
 * bit regardless of whether the app is multithreaded -- it's only the state
 * private to the process for which we can play this game.
 */

typedef oo_rwlock		citp_ul_lock_t;
extern citp_ul_lock_t		citp_ul_lock CI_HV;

#define CITP_LOCK_CTOR(l)	oo_rwlock_ctor((oo_rwlock*)(l))
#define CITP_LOCK_DTOR(l)	oo_rwlock_dtor((oo_rwlock*)(l))

#define CITP_LOCK(l) do {                    \
    if (ci_is_multithreaded())               \
      oo_rwlock_lock_write((oo_rwlock*)(l)); \
  } while(0)

ci_inline int CITP_TRY_LOCK(citp_ul_lock_t *l)
{
  int rc = 1;
  if (ci_is_multithreaded())
    rc = oo_rwlock_try_write(l);
  return rc;
}

#define CITP_LOCK_RD(l) do {			\
    if (ci_is_multithreaded())			\
      oo_rwlock_lock_read((oo_rwlock *)(l));	\
  } while(0)

#define CITP_LOCK_TRY_RD(l)			\
	( ci_is_multithreaded() ? 1, oo_rwlock_try_read((oo_rwlock *)l) )

#define CITP_UNLOCK(l) do {			\
    if (ci_is_multithreaded())			\
      oo_rwlock_unlock((oo_rwlock*)(l));	\
  } while(0)

#define CITP_ISLOCKED_RD(l)			\
	( !ci_is_multithreaded() ||		\
	oo_rwlock_is_locked((oo_rwlock *)(l),CI_RWLOCK_READ) )

#define CITP_ISLOCKED(l)			\
	( !ci_is_multithreaded() ||		\
	oo_rwlock_is_locked((oo_rwlock *)(l),CI_RWLOCK_WRITE) )

/* \TODO Add specific unlock read and unlock write operations */

/*! Safety wrapper used to ensure that we're not making a system API call
 * while holding the UL lock. */
#ifndef NDEBUG
#define CITP_ASSERT_SAFE_SYSCALL(x) do {        \
  ci_assert( !CITP_ISLOCKED(&citp_ul_lock));    \
  do { x; } while(0); } while(0)
#else
#define CITP_ASSERT_SAFE_SYSCALL(x) do{x;}while(0)
#endif


/**********************************************************************
 ** Netif initialisation (netif_init.c).
 */


extern void citp_cmn_netif_init_ctor(unsigned netif_dtor_mode) CI_HF;

/* Check the active netifs to look for one with
 * a matching ID
 * \param id     ID to look for (as returned by NI_ID())
 * \return       ptr to UL netif or NULL if not found
 */
extern ci_netif* citp_find_ul_netif(int id, int locked) CI_HF;

/*! Allocate and initialise a common-pool netif (if necessary) and
  return it  */
extern int citp_netif_alloc_and_init(ef_driver_handle*, ci_netif**) CI_HF;

/* Recreate a netif for a 'probed' user-level endpoint */
extern int citp_netif_recreate_probed(ci_fd_t caller_fd,
                                      ef_driver_handle* fd,
				      ci_netif** out_ni) CI_HF;

/* Add a reference to a netif */
ci_inline void citp_netif_add_ref( ci_netif* ni ) {
  ci_assert(ni);
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  oo_atomic_inc(&ni->ref_count);
}

/*! Handles release of resources etc. when the ref count hits
** zero.  Call with [locked] = 0 if the fd table lock is NOT held
** or [locked] != 0 if * the fd table lock IS held.
*/
extern void __citp_netif_ref_count_zero( ci_netif* ni, int locked ) CI_HF;

/*! Release one ref count, when the ref count hits zero the netif will be
** freed.  Call with [locked] = 0 if the fd table lock is NOT held
** or [locked] != 0 if * the fd table lock IS held.
*/
ci_inline void citp_netif_release_ref( ci_netif* ni, int locked ) {
  ci_assert(ni);
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  if( oo_atomic_dec_and_test(&ni->ref_count) )
    __citp_netif_ref_count_zero(ni, locked);
}

/*! Platform specific hook called after creating a netif */
extern void citp_netif_ctor_hook(ci_netif* ni, int realloc) CI_HF;

/*! Platform specific hook called prior to freeing a netif */
extern void citp_netif_free_hook(ci_netif* ni) CI_HF;

/*! Get any active netif for this process */
extern ci_netif* __citp_get_any_netif(void) CI_HF;

/*! Is there a netif in this process */
extern int citp_netif_exists(void) CI_HF;

/*! Get all (or as many as will fit) active netifs for this process 
 * and increment their ref. counts */
extern int citp_get_active_netifs(ci_netif **result, int maxnum);

/*! Mark all active netifs as shared */
extern void __citp_netif_mark_all_shared(void) CI_HF;

/*! Remove extra references that protect against destruction  */
extern void __citp_netif_unprotect_all(void) CI_HF;

/*! Mark all active netifs as "not for use by new sockets" */
extern void __citp_netif_mark_all_dont_use(void) CI_HF;

/*! Free and destruct a netif */
extern void __citp_netif_free(ci_netif* ni) CI_HF;


/**********************************************************************
 ** Protocol-agnostic common
 */

/* ***************************
 * abstraction of types - usually just to keep the compiler from
 * sulking about minutae - or pre-supposing a sulk!
 */

# define ci_socklen socklen_t
# define ci_optval void


/* common handler for TCP & UDP setsockname. */
ci_inline void __citp_getsockname(ci_sock_cmn* s, struct sockaddr* sa,
				  socklen_t* salen)
{
  CI_TEST(sa);
  CI_TEST(salen);

  ci_addr_to_user(sa, salen, s->domain, 
                  sock_lport_be16(s), sock_laddr_be32(s));
}


#endif
/*! \cidoxg_end */
