/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** \author  stg
**  \brief  System dependent support for ef vi lib
**   \date  2007/05/10
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __CI_CIUL_SYSDEP_UNIX_H__
#define __CI_CIUL_SYSDEP_UNIX_H__

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


/**********************************************************************
 * Processor/architecture
 */

#if defined(__i386__) || defined(__x86_64__)
# define EF_VI_LITTLE_ENDIAN   1
#elif defined(__PPC__)
# define EF_VI_LITTLE_ENDIAN   0
#else
# error Unknown processor
#endif


typedef uint64_t ef_vi_dma_addr_t;


/**********************************************************************
 * Compiler/processor dependencies.
 *
 * The following describes how we are using these primitives:
 *
 * wmb: Ensure ordering between writes to device, or write to memory and
 *      write to device.
 *
 * wmb_wc: Ensure WC write completes before uncached write to device.
 *
 * mmiowb: Ensure write to device is flushed out promptly.
 */

#define __printf(fmt, arg)  __attribute__((format(printf, fmt, arg)))

#if defined(__GNUC__)

# if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ > 91)
#  define likely(t)    __builtin_expect((t), 1)
#  define unlikely(t)  __builtin_expect((t), 0)
# endif

# if __GNUC__ >= 3
#  define EF_VI_HF __attribute__((visibility("hidden")))
#  define EF_VI_HV __attribute__((visibility("hidden")))
# endif

# if defined(__i386__) || defined(__x86_64__)  /* GCC x86/x64 */
#  define wmb()       __asm__ __volatile__("": : :"memory")
#  define wmb_wc()    __builtin_ia32_sfence()
#  define mmiowb()    do{}while(0)
#  define smp_rmb()   __asm__ __volatile__("lfence": : :"memory")

# elif defined(__PPC__)
#  define wmb()       __asm__ __volatile__("sync" : : :"memory")
#  define wmb_wc()    __asm__ __volatile__("sync" : : :"memory")
#  define mmiowb()    __asm__ __volatile__("sync" : : :"memory")
#  define smp_rmb()   __asm__ __volatile__("lwsync": : :"memory")

# else
#  error Unknown processor architecture
# endif

#else
# error Unknown compiler.
#endif


/*
 * Defaults for anything left undefined.
 */
#ifndef  EF_VI_HF
# define  EF_VI_HF
# define  EF_VI_HV
#endif

#ifndef likely
# define likely(t)    (t)
# define unlikely(t)  (t)
#endif

#if EF_VI_LITTLE_ENDIAN
# define cpu_to_le16(v)   (v)
# define le16_to_cpu(v)   (v)
# define cpu_to_le32(v)   (v)
# define le32_to_cpu(v)   (v)
# define cpu_to_le64(v)   (v)
# define le64_to_cpu(v)   (v)
#else
/* TODO: use optimised versions of these */
# define cpu_to_le16(v)   (((v) >> 8) |		\
			   ((v) << 8))
# define le16_to_cpu(v)   (cpu_to_le16(v))
# define cpu_to_le32(v)   (((v) >> 24)               |  \
	                   (((v) & 0x00ff0000) >> 8) |	\
			   (((v) & 0x0000ff00) << 8) |	\
			   ((v) << 24))
# define le32_to_cpu(v)   (cpu_to_le32(v))
# define cpu_to_le64(v)   (((v) >> 56)                           |	\
	                   (((v) & 0x00ff000000000000ull) >> 40) |	\
	                   (((v) & 0x0000ff0000000000ull) >> 24) |	\
		           (((v) & 0x000000ff00000000ull) >> 8)  |	\
			   (((v) & 0x00000000ff000000ull) << 8)  |	\
			   (((v) & 0x0000000000ff0000ull) << 24) |	\
			   (((v) & 0x000000000000ff00ull) << 40) |	\
			   ((v) << 56))
# define le64_to_cpu(v)   (cpu_to_le64(v))
#endif


#if defined(__PPC__)

ef_vi_inline void __nosync_writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("stwbrx %1,0,%2"
                       : "=m" (*(uint32_t*)addr)
                       : "r" (data), "r" (addr));
}


ef_vi_inline void __nosync_writed(uint64_t data, volatile void *addr)
{
  __asm__ __volatile__("stdbrx %1,0,%2"
                       : "=m" (*(uint64_t*)addr)
                       : "r" (data), "r" (addr));
}

ef_vi_inline void writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("sync; stwbrx %1,0,%2"
                       : "=m" (*(uint32_t*)addr)
                       : "r" (data), "r" (addr));
}

#else

ef_vi_inline void __raw_writel(uint32_t data, volatile void *addr)
{
  *((volatile uint32_t *) addr) = data;
}

ef_vi_inline void writel(uint32_t data, volatile void *addr)
{
  __raw_writel(cpu_to_le32(data), addr);
}

#endif


#define BUG_ON(exp)  assert(!(exp))

#endif  /* __CI_CIUL_SYSDEP_UNIX_H__ */
