/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  System dependent support for ef vi lib
**   \date  2015/11/11
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __CIUL_MEMCPY_TO_IO_H__
#define __CIUL_MEMCPY_TO_IO_H__


/* memcpy_to_pio: Copy packet to PIO buffer on the adapter.  The PIO region
 * on NIC is write only, and to avoid silicon bugs must only be hit with
 * writes at are 64-bit aligned and a multiple of 64-bits in size.
 */
#if defined(__PPC64__) && ! defined(__KERNEL__)

#define MEMCPY_TO_PIO_ALIGN  16

static inline void __memcpy_to_pio(void* dst, const void* src, size_t len,
                                   int aligned)
{
  const ci_oword_t* o_src = src;
  ci_oword_t* o_dst = dst;
  ci_oword_t* o_dst_end = o_dst + (len >> 4);
  ci_oword_t merge;

  while( o_dst < o_dst_end ) {
    __asm__ __volatile__("lxvw4x %%vs32, 0, %2\n\t"
                         "stxvw4x %%vs32, 0, %1"
                         : "=m" (*o_dst)
                         : "r" (o_dst),
                           "r" (o_src),
                           "m" (*o_src)
                         : "vs32");
    ++o_src;
    ++o_dst;
  }
  if( ! aligned && (len & 15) ) {
    memcpy(&merge, o_src, len & 15);
    __asm__ __volatile__("lxvw4x %%vs32, 0, %2\n\t"
                         "stxvw4x %%vs32, 0, %1"
                         : "=m" (*o_dst)
                         : "r" (o_dst),
                           "r" (&merge),
                           "m" (merge)
                         : "vs32");
    ++o_dst;
  }
  /* Pad to 64-byte boundary.  Reduces number of transactions
   * on the power bus.
   */
  o_dst_end = (void*) EF_VI_ALIGN_FWD((ci_uintptr_t) o_dst, (ci_uintptr_t) 64);
  while( o_dst < o_dst_end ) {
    __asm__ __volatile__("lxvw4x %%vs32, 0, %2\n\t"
                         "stxvw4x %%vs32, 0, %1"
                         : "=m" (*o_dst)
                         : "r" (o_dst),
                           "r" (&merge)
                         : "vs32");
    ++o_dst;
  }
  __asm__ __volatile__("eieio" : : : "memory");
}

# define memcpy_to_pio(dst, src, len)           \
       __memcpy_to_pio((dst), (src), (len), 0)

# define memcpy_to_pio_aligned(dst, src, len)   \
       __memcpy_to_pio((dst), (src), (len), 1)

#else

#define MEMCPY_TO_PIO_ALIGN  8

/* @param aligned dst, src and len are all qword aligned */
static inline void __memcpy_to_pio(void* dst, const void* src, size_t len,
                                   int aligned)
{
  const uint64_t* q_src = src;
  volatile uint64_t* q_dst = dst;
  int src_aligned = aligned || (((long)src) & 7) == 0;
  /* For efficiency we may read beyond our src buffer, but we do that only
   * when src ptr is qword aligned as this ensures we do not to trample
   * on next cache line (or page).
   *
   * We will read up to:
   * * the qword boundary past the end in src_aligned case, or
   * * the qword boundary before the end in !src_aligned case */
  volatile uint64_t* q_dst_end = q_dst +
                                 ((len + (src_aligned ? 7 : 0)) >> 3);

  while( q_dst < q_dst_end ) {
    *(q_dst++) = *(q_src++);
    ci_compiler_barrier();
  }
  if(CI_UNLIKELY( ! src_aligned && (len & 7) )) {
    /* Read an qword containng the remaining bytes but within the buffer limit,
     * then adjust position of bytes accordingly before storing */
    uint64_t a = *(const uint64_t*)((const uint8_t*)q_src - (-len & 7));
#if EF_VI_LITTLE_ENDIAN
    a >>= 8 * (-len & 7);
#else
    a <<= 8 * (-len & 7);
#endif
    *q_dst = a;
  }
}

# define memcpy_to_pio(dst, src, len)           \
       __memcpy_to_pio((dst), (src), (len), 0)

# define memcpy_to_pio_aligned(dst, src, len)   \
       __memcpy_to_pio((dst), (src), (len), 1)

#endif


#endif  /* __CIUL_MEMCPY_TO_IO_H__ */
