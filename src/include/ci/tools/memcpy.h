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
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_MEMCPY_H__
#define __CI_TOOLS_MEMCPY_H__


/*!
** Bringing in the convention:
**
**   ci_memcpy[X][_salignY][_dalignZ](dest, src, bytes)
**
**   X, Y, Z can be 1, 4, or 8  (if 1, then omitted)
**
**   X = byte alignment of the transfer length 
**   Y = byte alignment of the src buffer
**   Z = byte alignment of the dest buffer
*/
/*! \TODO some memcpy code can be further optimised / more versions.
**  \TODO use of old macros deprecated.
*/

#if defined(__x86_64__) || defined(__ia64__)
/* TODO think about x86_64 optimisations */
  extern void * ci_memcpy_io2(volatile void *dest, const void *src, size_t n);

# define ci_memcpy_byte_aligned  ci_memcpy_io2
# define ci_memcpy_dword_aligned ci_memcpy_io2
# define ci_memcpy_io(d, s, n)  memcpy((void*) (d), (const void*) (s), (n))

# define ci_memcpy4_dalign8(d,s,n)				\
  do {								\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign4_dalign4(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 4) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 4) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign4_dalign8(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 4) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign8_dalign8(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 8) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_assert(n > 0);						\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)
#endif

#ifdef __i386__
/* on moderen cores, the simple minded byte aligned code does a pretty good job
   we can reassess and possibly move to more optimised versions later */
  extern void * ci_memcpy_mmx(void *dest, const void *src, size_t n);
  extern void * ci_memcpy_io2(volatile void *dest, const void *src, size_t n);
  extern void * ci_memcpy_byte_aligned(void *dest, const void *src, size_t n);
# define ci_memcpy_dword_aligned ci_memcpy_byte_aligned
# define ci_memcpy_io(d, s, n)  memcpy((void*) (d), (const void*) (s), (n))

# define ci_memcpy4_dalign8(d,s,n)				\
  do {								\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign4_dalign4(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 4) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 4) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign4_dalign8(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 4) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign8_dalign8(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 8) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_assert(n > 0);						\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

#endif


#ifdef __PPC__

/* on moderen cores, the simple minded byte aligned code does a pretty good job
   we can reassess and possibly move to more optimised versions later */
   
//  extern void * ci_memcpy_mmx(void *dest, const void *src, size_t n);
//  extern void * ci_memcpy_io2(volatile void *dest, const void *src, size_t n);
  extern void * ci_memcpy_byte_aligned(void *dest, const void *src, size_t n);
  
# define ci_memcpy_dword_aligned ci_memcpy_byte_aligned
# define ci_memcpy_io(d, s, n)  memcpy((void*) (d), (const void*) (s), (n))

# define ci_memcpy4_dalign8(d,s,n)				\
  do {								\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign4_dalign4(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 4) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 4) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign4_dalign8(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 4) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

# define ci_memcpy4_salign8_dalign8(d,s,n)			\
  do {								\
    ci_assert(CI_PTR_OFFSET(s, 8) == 0);			\
    ci_assert(CI_PTR_OFFSET(d, 8) == 0);			\
    ci_assert(CI_OFFSET(n, 4) == 0);				\
    ci_assert(n > 0);						\
    ci_memcpy_byte_aligned((void*)(d),(const void*)(s),(n));	\
  } while(0)

#endif	/* __PPC__ */



#endif  /* __CI_TOOLS_MEMCPY_H__ */

/*! \cidoxg_end */
