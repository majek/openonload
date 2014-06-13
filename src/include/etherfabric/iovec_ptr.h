/*
** Copyright 2005-2013  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  Misc resources.
**   \date  2004/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_etherfabric */
#ifndef __ETHERFABRIC_IOVEC_PTR_H__
#define __ETHERFABRIC_IOVEC_PTR_H__

#ifdef __cplusplus
extern "C" {
#endif

  /*! \i_ef_base [ef_iovec_ptr] provides a convenient means to iterate
  ** through an ef_iovec non-destructively.
  */
typedef struct {
  const ef_iovec*	iov;
  int			iovlen;
  ef_iovec		io;
} ef_iovec_ptr;


ef_vi_inline void ef_iovec_ptr_init(ef_iovec_ptr* p, const ef_iovec* iov,
				    int iovlen) {
  p->iov = iov;
  p->iovlen = iovlen;
  p->io.iov_len = 0;
}

ef_vi_inline void ef_iovec_ptr_init_nz(ef_iovec_ptr* p, const ef_iovec* iov,
				       int iovlen) {
  ci_assert(iovlen > 0);
  p->iov = iov + 1;
  p->iovlen = iovlen - 1;
  p->io = *iov;
}

  /*! Returns true if [p] is known to be empty.  Note that it will return
  ** false if [p] only contains zero-length segments (even though it is
  ** technically 'empty').
  */
ef_vi_inline int ef_iovec_ptr_is_empty(const ef_iovec_ptr* p)
{ return p->io.iov_len == 0 && p->iovlen == 0; }

  /*! This one does a thorough job of determining whether [p] is empty.
  ** That is, it skips over empty segments.
  */
ef_vi_inline int ef_iovec_ptr_is_empty_proper(ef_iovec_ptr* p) {
  while( p->io.iov_len == 0 ) {
    if( p->iovlen == 0 )  return 1;
    p->io = *p->iov++;
    --p->iovlen;
  }
  return 0;
}

  /*! Advance through current segment. */
ef_vi_inline void ef_iovec_ptr_advance(ef_iovec_ptr* p, int n) {
  ci_assert_ge(p->io.iov_len, (ci_uint32)n);
  p->io.iov_len -= n;
  p->io.iov_base += n;
}

  /*! Advance to next segment (current must have been emptied). */
ef_vi_inline void ef_iovec_ptr_next(ef_iovec_ptr* p) {
  ci_assert_equal(p->io.iov_len, 0);
  ci_assert_gt(p->iovlen, 0);
  p->io = *p->iov++;
  --p->iovlen;
}

#ifdef __cplusplus
}
#endif

#endif  /* __ETHERFABRIC_IOVEC_PTR_H__ */
/*! \cidoxg_end */
