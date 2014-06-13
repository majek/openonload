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

#ifndef __ONLOAD_ATOMICS_H__
#define __ONLOAD_ATOMICS_H__


ci_inline ci_int32 oo_atomic_read(const oo_atomic_t* a) { return a->n; }
ci_inline void oo_atomic_set(oo_atomic_t* a, ci_int32 v) { a->n = v; }

ci_inline void oo_atomic_inc(oo_atomic_t* a)
{ ci_atomic32_inc(&a->n); }

ci_inline int oo_atomic_dec_and_test(oo_atomic_t* a)
{ return ci_atomic32_dec_and_test(&a->n); }

ci_inline void oo_atomic_add(oo_atomic_t* a, int n)
{ ci_atomic32_add(&a->n, n); }


#endif  /* __ONLOAD_ATOMICS_H__ */
