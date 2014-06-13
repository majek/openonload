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
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Control of access to the shared state.
**   \date  2005/01/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */
#ifndef __CI_INTERNAL_IP_SHARED_OPS_H__
#define __CI_INTERNAL_IP_SHARED_OPS_H__

/*
** READ ME FIRST please.
**
** This header contains the definition of the API for accessing the state
** of the Etherfabric TCP/IP stack (not including types, see
** ip_shared_types.h).
**
** The only stuff that may appear here is function declarations, macros and
** inline function definitions.
**
** NO TYPE DEFINITIONS IN THIS FILE PLEASE.
*/



/**********************************************************************
****************************** Netif lock *****************************
**********************************************************************/

#define ci_netif_is_locked(ni)        ef_eplock_is_locked(&(ni)->state->lock)

extern void ci_netif_unlock(ci_netif*) CI_HF;


/*! Blocking calls that grab the stack lock return 0 on success.  When
 * called at userlevel, this is the only possible outcome.  In the kernel,
 * they return -EINTR if interrupted by a signal.
 */
#define ci_netif_lock(ni)        ef_eplock_lock(ni)
#define ci_netif_lock_id(ni,id)  ef_eplock_lock(ni)
#define ci_netif_trylock(ni)     ef_eplock_trylock(&(ni)->state->lock)

#define ci_netif_lock_fdi(epi)   ci_netif_lock_id((epi)->sock.netif,    \
                                                  SC_SP((epi)->sock.s))
#define ci_netif_unlock_fdi(epi) ci_netif_unlock((epi)->sock.netif)

/* ci_netif_lock_count()
**
** Just like ci_netif_lock(), but increments the specified ci_netif_stats
** member on contention.
*/
#if CI_CFG_STATS_NETIF
ci_inline int __ci_netif_lock_count(ci_netif* ni, ci_uint32* stat) {
  if( ! ci_netif_trylock(ni) ) {
    int rc = ci_netif_lock(ni);
    if( rc )  return rc;
    ++*stat;
  }
  return 0;
}

# define ci_netif_lock_count(ni, stat_name)                     \
  __ci_netif_lock_count((ni), &(ni)->state->stats.stat_name)
#else
# define ci_netif_lock_count(ni, stat)  ci_netif_lock(ni)
#endif



/**********************************************************************
****************** Shared state consistency assertion *****************
**********************************************************************/

#define ci_ss_assert2(ni, e, x, y)                      \
  ci_ss_assertfl2((ni), e, x, y, __FILE__, __LINE__)

#if defined(__KERNEL__) && ! defined(NDEBUG)

/* Module parameter */
extern int no_shared_state_panic;

# define ci_ss_assertfl2(ni, e, x, y, file, line)  do {                 \
    if(CI_UNLIKELY( ! (e) )) {                                          \
      (ni)->error_flags |= CI_NETIF_ERROR_ASSERT;                       \
      (ni)->state->error_flags |= CI_NETIF_ERROR_ASSERT;                \
      LOG_SSA(ci_log("ci_ss_assert(%s)\nwhere [%s=%"CI_PRIx64"] "       \
                     "[%s=%"CI_PRIx64"]\nat %s:%d\nfrom %s:%d", #e      \
                     , #x, (ci_uint64)(ci_uintptr_t)(x)                 \
                     , #y, (ci_uint64)(ci_uintptr_t)(y),                \
                     __FILE__, __LINE__, (file), (line)));              \
      if( no_shared_state_panic == 0 )       \
          ci_fail(("Panic!"));                                          \
    }                                                                   \
  } while(0)
#else
# define ci_ss_assertfl2(netif, e, x, y, file, line)    \
        _ci_assert2(e, x, y, (file), (line))
#endif


#define ci_ss_assert_eq(ni, x, y)    ci_ss_assert2((ni), (x)==(y), x, y)
#define ci_ss_assert_neq(ni, x, y)   ci_ss_assert2((ni), (x)!=(y), x, y)
#define ci_ss_assert_le(ni, x, y)    ci_ss_assert2((ni), (x)<=(y), x, y)
#define ci_ss_assert_lt(ni, x, y)    ci_ss_assert2((ni), (x)< (y), x, y)
#define ci_ss_assert_ge(ni, x, y)    ci_ss_assert2((ni), (x)>=(y), x, y)
#define ci_ss_assert_gt(ni, x, y)    ci_ss_assert2((ni), (x)> (y), x, y)
#define ci_ss_assert_or(ni, x, y)    ci_ss_assert2((ni), (x)||(y), x, y)

#define ci_ss_assert_impl(ni, x, y)  ci_ss_assert2((ni), !(x) || (y), x, y)
#define ci_ss_assert_equiv(ni, x, y) ci_ss_assert2((ni), !(x)== !(y), x, y)



#define ci_ss_assert(ni, x)  ci_ss_assertfl(ni, x, __FILE__, __LINE__)

#if defined(__KERNEL__) && ! defined(NDEBUG)
# define ci_ss_assertfl(ni, x, file, line)  do {                        \
    if(CI_UNLIKELY( ! (x) )) {                                          \
      (ni)->error_flags |= CI_NETIF_ERROR_ASSERT;                       \
      (ni)->state->error_flags |= CI_NETIF_ERROR_ASSERT;                \
      LOG_SSA(ci_log("ci_ss_assert(%s)\nat %s:%d\nfrom %s:%d", #x,      \
                     __FILE__, __LINE__, (file), (line)));              \
      if( no_shared_state_panic == 0 )       \
          ci_fail(("Panic!"));                                          \
    }                                                                   \
  } while(0)
#else
# define ci_ss_assertfl(netif, x, file, line)  _ci_assert(x, file, line)
#endif



/**********************************************************************
*********************** Netif address conversion **********************
**********************************************************************/

/*
** The shared state consists of a contiguous region (the region accessible
** via netif->state) and various discontiguous regions including the socket
** buffers and packet buffers.
**
** The contiguous region and the socket buffers form a unified virtual
** address space, addressed by a "netif address".
**
** CI_NETIF_PTR(ni, na) converts a netif address [na] to a pointer.  This
** function does not attempt to validate the address: If necessary it
** should already have been cleaned/validated by the caller.  This call is
** safe provided [na] is valid.
**
** oo_ptr_to_statep() converts a pointer to a netif address, but can
** only be applied to a pointer that lies within the contiguous region.
*/

#ifndef CI_HAVE_OS_NOPAGE
# define NI_ADDR_SHIFT           20u
# define NI_ADDR_SHMBUF(na)      ((na) >> NI_ADDR_SHIFT)
# define NI_ADDR_OFFSET(na)      ((na) & ((1u << NI_ADDR_SHIFT) - 1u))
# define NI_ADDR_BUILD(buf, off) (((buf) << NI_ADDR_SHIFT) | (off))
#endif


/* Get from a pointer to an [oo_p].  This must only be used for a pointer
** that lies within the contiguous region of the netif state.
*/
#if CI_CFG_OOP_IS_PTR
ci_inline oo_p oo_ptr_to_statep(const ci_netif* ni, void* ptr)
{ return ptr; }
#else
ci_inline oo_p oo_ptr_to_statep(const ci_netif* ni, void* ptr) {
  oo_p sp;
  OO_P_INIT(sp, ni, (ci_uint32) ((char*) ptr - (char*) ni->state));
  return sp;
}
#endif


/* The driver has a trusted version of ep_ofs. */
#if CI_CFG_NETIF_HARDEN
# define ci_netif_ep_ofs(ni)  ((ni)->ep_ofs)
#else
# define ci_netif_ep_ofs(ni)  ((ni)->state->ep_ofs)
#endif


#ifdef __ci_driver__

# ifdef CI_HAVE_OS_NOPAGE

ci_inline char* oo_state_off_to_ptr(ci_netif* ni, unsigned off) {
  return off < ci_netif_ep_ofs(ni)
    ? (char*) ni->state + off
    : ci_shmbuf_ptr(&ni->pages_buf, off - ci_netif_ep_ofs(ni));
}

# else

ci_inline char* oo_state_off_to_ptr(ci_netif* ni, unsigned off) {
  return NI_ADDR_SHMBUF(off)
    ? ci_shmbuf_ptr(ni->k_shmbufs[NI_ADDR_SHMBUF(off)-1], NI_ADDR_OFFSET(off))
    : (char*) ni->state + off;
}

# endif 

#else /* not driver */

# ifdef CI_HAVE_OS_NOPAGE

ci_inline char* oo_state_off_to_ptr(ci_netif* ni, unsigned off)
{ return (char*) ni->state + off; }

# else

extern int ci_netif_mmap_shmbuf(ci_netif* netif, int shmbufid);

ci_inline char* oo_state_off_to_ptr(ci_netif* ni, unsigned off) {
  unsigned shm_i = NI_ADDR_SHMBUF(off);
  if(CI_UNLIKELY( ! ni->u_shmbufs[shm_i] ))
    ci_netif_mmap_shmbuf(ni, shm_i);
  return (char*) ni->u_shmbufs[shm_i] + NI_ADDR_OFFSET(off);
}

# endif

#endif  /* __ci_driver__ */


#if CI_CFG_OOP_IS_PTR
# define __CI_NETIF_PTR(ni, oop)  (oop)
#else
# define __CI_NETIF_PTR(ni, oop)  oo_state_off_to_ptr((ni), OO_P_OFF(oop))
#endif


#if CI_CFG_DETAILED_CHECKS
  extern char* CI_NETIF_PTR(ci_netif*, oo_p);
#else
# define CI_NETIF_PTR(ni, oop)   __CI_NETIF_PTR((ni), (oop))
#endif


/**********************************************************************
**************** Socket / citp_waitable buffers access ****************
**********************************************************************/

/* EP_BUF_SIZE must be an exact divisor of CI_PAGE_SIZE to ensure we don't
** straddle page boundaries.  We'd like to compute the number of EPs that
** fit in a page at compile-time, but that ain't easy.  So it is hard coded
** here, and checked in ci_netif_ctor() to ensure it is sensible.
*/
#define EP_BUF_SIZE 1024 /* MUST be 2^n, with n<=12 */
#if (CI_PAGE_SIZE % EP_BUF_SIZE != 0)
#error "EP_BUF_SIZE *must* be a divisor of PAGE_SIZE, and it's not"
#endif
#define EP_BUF_PER_PAGE    (CI_PAGE_SIZE / EP_BUF_SIZE)

#ifndef CI_HAVE_OS_NOPAGE
/* For platforms that have multiple mmaps() for socket buffers, these
** macros define the number of buffers in each mmap/block.
*/
# define EP_BUF_BLOCKSHIFT  3u
# define EP_BUF_BLOCKNUM    (1u << EP_BUF_BLOCKSHIFT)
# define EP_BUF_BLOCKMASK   (EP_BUF_BLOCKNUM - 1u)
# define EP_BUF_BLOCKPAGES  (EP_BUF_BLOCKNUM / EP_BUF_PER_PAGE)
# define EP_BUF_FINDBLOCKREF(id)  ((id) >> EP_BUF_BLOCKSHIFT)
# define EP_BUF_FINDBLOCKID(id)   ((id) & EP_BUF_BLOCKMASK)
#endif


/* TRUSTED_SOCK_ID(ni, id)
**
** Munge a socket id so that it is guaranteed to be valid when in a
** hardened build.  Generates an ss-fault if not valid.
*/
#if CI_CFG_NETIF_HARDEN
ci_inline unsigned __TRUSTED_SOCK_ID(ci_netif* ni, unsigned id,
                                  const char* f, int l) {
  ci_ss_assertfl(ni, id < ni->ep_tbl_n, f, l);
  return id % ni->ep_tbl_n;
}
#else
ci_inline unsigned __TRUSTED_SOCK_ID(ci_netif* ni, unsigned id,
                                     const char* f, int l) {
  ci_ss_assertfl(ni, id < ni->state->n_ep_bufs, f, l);
  return id;
}
#endif


#define TRUSTED_SOCK_ID(ni, id)                         \
  __TRUSTED_SOCK_ID((ni), (id), __FILE__, __LINE__)

#define TRUSTED_SOCK_ID_FROM_P(ni, sockp)       \
  TRUSTED_SOCK_ID((ni), OO_SP_TO_INT(sockp))


#ifdef CI_HAVE_OS_NOPAGE
ci_inline unsigned oo_sockid_to_state_off(ci_netif* ni, unsigned sock_id)
{ return ci_netif_ep_ofs(ni) + sock_id * EP_BUF_SIZE; }
#else
ci_inline unsigned oo_sockid_to_state_off(ci_netif* ni, unsigned sock_id) {
  return NI_ADDR_BUILD(EP_BUF_FINDBLOCKREF(sock_id) + 1,
                       EP_BUF_FINDBLOCKID(sock_id) * EP_BUF_SIZE);
}
#endif


/* oo_sockp_to_statep(ni, oo_sp)
**
** Convert an [oo_sp] to an [oo_p].  The result is guaranteed valid
** provided the socket id is valid.
*/
#if CI_CFG_OOP_IS_PTR && CI_CFG_SOCKP_IS_PTR
ci_inline oo_p oo_sockp_to_statep(ci_netif* ni, oo_sp sockp)
{ return (char*) sockp; }
#elif CI_CFG_OOP_IS_PTR
ci_inline oo_p oo_sockp_to_statep(ci_netif* ni, oo_sp sockp) {
  return
    oo_state_off_to_ptr(ni, oo_sockid_to_state_off(ni, OO_SP_TO_INT(sockp)));
}
#else
ci_inline oo_p oo_sockp_to_statep(ci_netif* ni, oo_sp sockp) {
  oo_p sp;
  OO_P_INIT(sp, ni, oo_sockid_to_state_off(ni, OO_SP_TO_INT(sockp)));
  return sp;
}
#endif


#if defined(__KERNEL__) && ! defined(CI_HAVE_OS_NOPAGE)
ci_inline char* oo_sockid_to_ptr(ci_netif* ni, int sock_id) {
  return ci_shmbuf_ptr(ni->k_shmbufs[EP_BUF_FINDBLOCKREF(sock_id)],
                       EP_BUF_FINDBLOCKID(sock_id) * EP_BUF_SIZE);
}
#endif


/* oo_sockp_to_ptr(ni, sockp)
**
** Convert a socket id to a pointer.  Safe if [sockp] is valid.
*/
#if CI_CFG_SOCKP_IS_PTR
ci_inline char* oo_sockp_to_ptr(ci_netif* ni, oo_sp sockp)
{ return (char*) sockp; }
#elif defined(CI_HAVE_OS_NOPAGE)
# ifdef __KERNEL__
ci_inline char* oo_sockp_to_ptr(ci_netif* ni, oo_sp sockp)
{ return ci_shmbuf_ptr(&ni->pages_buf, OO_SP_TO_INT(sockp) * EP_BUF_SIZE); }
# else
ci_inline char* oo_sockp_to_ptr(ci_netif* ni, oo_sp sockp)
{ return CI_NETIF_PTR(ni, oo_sockp_to_statep(ni, sockp)); }
# endif
#else
ci_inline char* oo_sockp_to_ptr(ci_netif* ni, oo_sp sockp)
{ return CI_NETIF_PTR(ni, oo_sockp_to_statep(ni, sockp)); }
#endif


/* oo_sockp_to_ptr_safe(ni, sockp)
**
** Convert a socket id to a pointer.  This operation is safe even if
** [sockp] is invalid (in which case some arbitrary buffer is returned).
*/
#if ! CI_CFG_SOCKP_IS_PTR
# define TRUSTED_SOCK_P(ni, sockp)                                      \
  OO_SP_FROM_INT((ni), TRUSTED_SOCK_ID((ni), OO_SP_TO_INT(sockp)))
# define oo_sockp_to_ptr_safe(ni, sockp)                \
  oo_sockp_to_ptr((ni), TRUSTED_SOCK_P((ni), (sockp)))
#else
# define oo_sockp_to_ptr_safe(ni, sockp)  oo_sockp_to_ptr((ni), (sockp))
#endif


/* SP_TO_foo(ni, oo_sp)
**
** Convert an [oo_sp] to the requested typed buffer.  These operations are
** safe.  It is up to the caller to be sure that the socket is of the
** appropriate type.
*/
#define SP_TO_foo(ni, sp, foo)     ((foo*) oo_sockp_to_ptr_safe((ni), (sp)))
#define SP_TO_WAITABLE_OBJ(ni, sp) SP_TO_foo((ni), (sp), citp_waitable_obj)
#define SP_TO_WAITABLE(ni, sp)	   SP_TO_foo((ni), (sp), citp_waitable)
#define SP_TO_SOCK(ni, sp)	   SP_TO_foo((ni), (sp), ci_sock_cmn)
#define SP_TO_SOCK_CMN(ni, sp)	   SP_TO_foo((ni), (sp), ci_sock_cmn)
#define SP_TO_UDP(ni, sp)	   SP_TO_foo((ni), (sp), ci_udp_state)
#define SP_TO_TCP(ni, sp)	   SP_TO_foo((ni), (sp), ci_tcp_state)
#define SP_TO_TCP_LISTEN(ni, sp)   SP_TO_foo((ni), (sp), ci_tcp_socket_listen)
#if CI_CFG_USERSPACE_PIPE
#define SP_TO_PIPE_BUF(ni, sp) SP_TO_foo((ni), (sp), struct oo_pipe_buf)
#define SP_TO_PIPE(ni, sp)     SP_TO_foo((ni), (sp), struct oo_pipe)
#endif

#define ID_TO_foo(ni, id, foo)     SP_TO_##foo((ni), OO_SP_FROM_INT((ni),(id)))
#define ID_TO_WAITABLE_OBJ(ni, id) ID_TO_foo((ni), (id), WAITABLE_OBJ)
#define ID_TO_WAITABLE(ni, id)     ID_TO_foo((ni), (id), WAITABLE)
#define ID_TO_SOCK(ni, id)         ID_TO_foo((ni), (id), SOCK)
#define ID_TO_SOCK_CMN(ni, id)     ID_TO_foo((ni), (id), SOCK_CMN)
#define ID_TO_UDP(ni, id)          ID_TO_foo((ni), (id), UDP)
#define ID_TO_TCP(ni, id)          ID_TO_foo((ni), (id), TCP)
#define ID_TO_TCP_LISTEN(ni, id)   ID_TO_foo((ni), (id), TCP_LISTEN)


/*********************************************************************
************************ Packet buffer access ************************
*********************************************************************/

#define PKTS_PER_SET    (1u << CI_CFG_PKTS_PER_SET_S)
#define PKTS_PER_SET_M  (PKTS_PER_SET - 1u)


/* VALID_PKT_ID(ni, id)
**
** Converts a packet id that may be out of range into one that definitely
** is valid and safe to use.  This is relatively expensive, so don't use in
** fast-path code.
*/
ci_inline oo_pkt_p VALID_PKT_ID(ci_netif* ni, oo_pkt_p pp) {
#if ! CI_CFG_PP_IS_PTR
# ifdef __KERNEL__
# define pkt_sets_n(ni) (ni)->pkt_sets_n
#else
# define pkt_sets_n(ni) (ni)->state->pkt_sets_n
#endif
  OO_PP_INIT(ni, pp,
             OO_PP_ID(pp) % (pkt_sets_n(ni) << CI_CFG_PKTS_PER_SET_S));
#undef pkt_sets_n
#endif
  return pp;
}





/* TRUSTED_PKT_ID(ni, id)
**
** Munge a packet id so that it is guaranteed to be valid when in a trusted
** build.  Generates an ss-fault if not valid.
*/
#if CI_CFG_NETIF_HARDEN
ci_inline oo_pkt_p __TRUSTED_PKT_ID(ci_netif* ni, oo_pkt_p pp,
                                    const char* f, int l) {
  unsigned id = OO_PP_ID(pp);
  ci_ss_assertfl(ni, id < ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S, f, l);
  OO_PP_INIT(ni, pp, id % (ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S));
  return pp;
}
#else
ci_inline oo_pkt_p __TRUSTED_PKT_ID(ci_netif* ni, oo_pkt_p pp,
                                    const char* f, int l) {
  ci_ss_assertfl(ni, (unsigned) OO_PP_ID(pp) < ni->state->n_pkts_allocated,
                 f, l);
  return pp;
}
#endif

#define TRUSTED_PKT_ID(ni, id)                          \
  __TRUSTED_PKT_ID((ni), (id), __FILE__, __LINE__)


/* __PKT_BUF(ni, id)
**
** Convert packet id to buffer.  Internal use only please, no checks.
** You'd better be sure [id] is valid, and that the packet is mapped (on
** platforms that require it).
*/
#ifdef __KERNEL__
/* Note that, to avoid us having kernel-only args (or unused args in 
 * user mode), ef_iobufset_ptr() doesn't exist in the kernel */
# define __PKT_BUF(ni, id)                                          \
  oo_iobufset_ptr((ni)->buf_pages[(id) >> CI_CFG_PKTS_PER_SET_S],   \
                  ((id) & PKTS_PER_SET_M) * CI_CFG_PKT_BUF_SIZE)
#else
# define __PKT_BUF(ni, id)                                      \
  ((ni)->pkt_sets[(id) >> CI_CFG_PKTS_PER_SET_S] +              \
            ((id) & PKTS_PER_SET_M) * CI_CFG_PKT_BUF_SIZE)
#endif

/* __PKT(ni, pp)
**
** Converts an [oo_pkt_p] to a packet without any checks.  Maps it into the
** current address space if necessary.
*/
#if CI_CFG_PP_IS_PTR

/* ?? this cast should not be necessary!!!!!!!!!!! */
# define __PKT(ni, pp)  ((ci_ip_pkt_fmt*) (pp))

#elif defined(__KERNEL__)

  /* Buffer will already be mmaped, or faulted in on demand. */
# define __PKT(ni, pp)  ((ci_ip_pkt_fmt*) __PKT_BUF((ni),OO_PP_ID(pp)))

#else

# define PKT_BUFSET_U_MMAPPED(ni, setid)  ((ni)->pkt_sets[setid] != NULL)

extern ci_ip_pkt_fmt* __ci_netif_pkt(ci_netif* ni, unsigned id) CI_HF;

ci_inline ci_ip_pkt_fmt* __PKT(ci_netif* ni, unsigned id) {
  if(CI_LIKELY( PKT_BUFSET_U_MMAPPED((ni), (id) >> CI_CFG_PKTS_PER_SET_S) ))
    return (ci_ip_pkt_fmt*) __PKT_BUF((ni), (id));
  else
    return __ci_netif_pkt(ni, id);
}

#endif


/* PKT() converts a packet id to a pointer to the packet.  In debug
** builds it checks the id is valid.  Netif must be locked.
**
** PKT_CHK() does some additional checks on fields on the packet, so use
** this when the packet should be in a valid state.  Netif must be locked.
*/
#define PKT(ni, id)      __PKT((ni), TRUSTED_PKT_ID((ni), (id)))


/* Validate packet.  Requires netif lock. */
extern void __ci_assert_valid_pkt(ci_netif*, ci_ip_pkt_fmt*,
                                  const char* file, int line) CI_HF;
/* Validate packet.  Netif lock optional. */
extern void ci_assert_valid_pkt(ci_netif*, ci_ip_pkt_fmt*,
                                ci_boolean_t ni_locked,
                                const char* file, int line) CI_HF;


ci_inline ci_ip_pkt_fmt* __ci_pkt_chk(ci_netif* ni, oo_pkt_p pp, int ni_locked,
                                      const char* file, int line) {
#if CI_CFG_DETAILED_CHECKS
  (void) __TRUSTED_PKT_ID(ni, pp, file, line);
  ci_assert_valid_pkt(ni, __PKT(ni, pp), ni_locked, file, line);
#endif
  return __PKT(ni, __TRUSTED_PKT_ID(ni, pp, file, line));
}

#define PKT_CHK(ni, id)                                 \
  __ci_pkt_chk((ni), (id), CI_TRUE, __FILE__, __LINE__)
#define PKT_CHK_NNL(ni, id)                                     \
  __ci_pkt_chk((ni), (id), CI_FALSE, __FILE__, __LINE__)
#define PKT_CHK_NML(ni, id, ni_locked)                    \
  __ci_pkt_chk((ni), (id), (ni_locked), __FILE__, __LINE__)


/*********************************************************************
********************* Ethernet header access *************************
*********************************************************************/

ci_inline struct oo_eth_hdr* oo_ether_hdr(ci_ip_pkt_fmt* pkt)
{
  return (void*) (pkt->dma_start + pkt->pkt_start_off);
}

ci_inline uint8_t* oo_ether_dhost(ci_ip_pkt_fmt* pkt)
{
  return oo_ether_hdr(pkt)->ether_dhost;
}

ci_inline uint8_t* oo_ether_shost(ci_ip_pkt_fmt* pkt)
{
  return oo_ether_hdr(pkt)->ether_shost;
}

ci_inline void* oo_ether_data(ci_ip_pkt_fmt* pkt)
{
  return pkt->dma_start + pkt->pkt_eth_payload_off;
}

ci_inline int oo_ether_hdr_size(const ci_ip_pkt_fmt* pkt)
{
  return pkt->pkt_eth_payload_off - pkt->pkt_start_off;
}

ci_inline uint16_t oo_ether_type_get(const ci_ip_pkt_fmt* pkt)
{
  const uint16_t* p = (const void*) oo_ether_data((ci_ip_pkt_fmt*) pkt);
  return p[-1];
}


/*********************************************************************
************************ IP header access ****************************
*********************************************************************/

ci_inline ci_ip4_hdr* oo_ip_hdr(ci_ip_pkt_fmt* pkt)
{
  return (ci_ip4_hdr*) oo_ether_data(pkt);
}

ci_inline const ci_ip4_hdr* oo_ip_hdr_const(const ci_ip_pkt_fmt* pkt)
{
  return (const ci_ip4_hdr*) oo_ether_data((ci_ip_pkt_fmt*) pkt);
}

ci_inline void* oo_ip_data(ci_ip_pkt_fmt* pkt)
{
  const ci_ip4_hdr* ip = oo_ip_hdr(pkt);
  return (uint8_t*) ip + CI_IP4_IHL(ip);
}


/**********************************************************************
 * Transmit packet layout.
 *
 * When we initialise the layer-3 (and above) parts of a packet we don't
 * yet know what the layer-2 encapsulation will be, so we have to leave
 * space for the worst case.  So we place the IP header at a fixed offset,
 * and the start of the Ethernet header varies.
 */

ci_inline void oo_tx_pkt_layout_init(ci_ip_pkt_fmt* pkt)
{
  ci_assert_equal((ci_uint8) pkt->pkt_start_off, 0xff);
  ci_assert_equal(pkt->pkt_eth_payload_off, 0xff);
  pkt->pkt_start_off = 0;
  pkt->pkt_eth_payload_off = ETH_HLEN;
}

ci_inline void oo_tx_pkt_layout_update(ci_ip_pkt_fmt* pkt, int ether_offset)
{
  int delta;
  ci_assert(ether_offset == 0 || ether_offset == ETH_VLAN_HLEN);
  ci_assert_equal(pkt->pkt_eth_payload_off, ETH_HLEN);
  ci_assert(pkt->pkt_start_off == 0 || pkt->pkt_start_off == -ETH_VLAN_HLEN);
  ether_offset -= ETH_VLAN_HLEN;
  delta = (int) pkt->pkt_start_off - ether_offset;
  ci_assert(delta == 0 || delta == ETH_VLAN_HLEN || delta == -ETH_VLAN_HLEN);
  pkt->buf_len += delta;
  pkt->pay_len += delta;
  pkt->pkt_start_off = ether_offset;
}

ci_inline struct oo_eth_hdr* oo_tx_ether_hdr(ci_ip_pkt_fmt* pkt)
{
  return oo_ether_hdr(pkt);
}

ci_inline void* oo_tx_ether_data(ci_ip_pkt_fmt* pkt)
{
  ci_assert_equal(pkt->pkt_eth_payload_off, ETH_HLEN);
  return pkt->dma_start + ETH_HLEN;
}

ci_inline void oo_tx_ether_type_set(ci_ip_pkt_fmt* pkt, uint16_t ether_type)
{
  uint16_t* p = oo_tx_ether_data(pkt);
  p[-1] = ether_type;
}

ci_inline ci_ip4_hdr* oo_tx_ip_hdr(ci_ip_pkt_fmt* pkt)
{
  return (ci_ip4_hdr*) oo_tx_ether_data(pkt);
}

ci_inline void* oo_tx_ip_data(ci_ip_pkt_fmt* pkt)
{
  return oo_tx_ip_hdr(pkt) + 1;
}


/*********************************************************************
**************** access to cached IP header fields *******************
*********************************************************************/

ci_inline void *ci_ip_cache_ether_hdr(const ci_ip_cached_hdrs *ipcache)
{
  return (void *)(ipcache->ether_header + ipcache->ether_offset);
}
ci_inline void *ci_ip_cache_ether_dhost(const ci_ip_cached_hdrs *ipcache)
{
  return (void *)(ipcache->ether_header + ipcache->ether_offset);
}
ci_inline void *ci_ip_cache_ether_shost(const ci_ip_cached_hdrs *ipcache)
{
  return (void *)(ipcache->ether_header + ipcache->ether_offset + ETH_ALEN);
}

#endif  /* __CI_INTERNAL_IP_SHARED_OPS_H__ */
/*! \cidoxg_end */
