/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"

/****************************************************************************
 *
 * memcpy code optimised to support IO bus bursting with any alignments
 *
 * On Intels this can be done bytewise. On alpha we only have dword 
 * granularity over the IO bus (dense memory space). The caller is supposed to
 * know what they're doing, so we silently fail in the case that an alpha is
 * given a byte aligned copy
 *
 ****************************************************************************/

#define	aligned_word_t		unsigned long int
#define aligned_word_size	(sizeof(aligned_word_t))

#if CI_MY_BYTE_ORDER == CI_LITTLE_ENDIAN
#define MERGE_MISALIGNED(w0, shift1, w1, shift2) (((w0) >> (shift1)) | \
						  ((w1) << (shift2)))

#elif CI_MY_BYTE_ORDER == CI_BIG_ENDIAN

#define MERGE_MISALIGNED(w0, shift1, w1, shift2) (((w0) << (shift1)) | \
						  ((w1) >> (shift2)))

#endif

/* max # words dealt with by the copy_aligned and copy_misaligned functions */
#define ALIGNED_WORD_CHUNK	(8) 


/* Copy block beginning at <source> to block beginning at <dest> with
** <words> aligned_word_t words. Both source and dest must be aligned.
*/
static void
copy_src_and_dest_aligned (long int dest, long int source, size_t words)
{
  aligned_word_t a0, a1, a2, a3, a4, a5, a6, a7;

  ci_assert(CI_OFFSET(dest, aligned_word_size) == 0);
  ci_assert(CI_OFFSET(source, aligned_word_size) == 0);

  switch (words & 7u) {
  case 1:
    a7 = ((aligned_word_t*) source)[0];
    source += 1 * aligned_word_size;
    dest   -= 7 * aligned_word_size;
    words  -= 1;
    goto copy_out1;

  case 2:
    a6 = ((aligned_word_t*) source)[0];
    a7 = ((aligned_word_t*) source)[1];
    source += 2 * aligned_word_size;
    dest   -= 6 * aligned_word_size;
    words  -= 2;
    goto copy_out2;

  case 3:
    a5 = ((aligned_word_t*) source)[0];
    a6 = ((aligned_word_t*) source)[1];
    a7 = ((aligned_word_t*) source)[2];
    source += 3 * aligned_word_size;
    dest   -= 5 * aligned_word_size;
    words  -= 3;
    goto copy_out3;
      
  case 4:
    a4 = ((aligned_word_t*) source)[0];
    a5 = ((aligned_word_t*) source)[1];
    a6 = ((aligned_word_t*) source)[2];
    a7 = ((aligned_word_t*) source)[3];
    source += 4 * aligned_word_size;
    dest   -= 4 * aligned_word_size;
    words  -= 4;
    goto copy_out4;
      
  case 5:
    a3 = ((aligned_word_t*) source)[0];
    a4 = ((aligned_word_t*) source)[1];
    a5 = ((aligned_word_t*) source)[2];
    a6 = ((aligned_word_t*) source)[3];
    a7 = ((aligned_word_t*) source)[4];
    source += 5 * aligned_word_size;
    dest   -= 3 * aligned_word_size;
    words  -= 5;
    goto copy_out5;

  case 6:
    a2 = ((aligned_word_t*) source)[0];
    a3 = ((aligned_word_t*) source)[1];
    a4 = ((aligned_word_t*) source)[2];
    a5 = ((aligned_word_t*) source)[3];
    a6 = ((aligned_word_t*) source)[4];
    a7 = ((aligned_word_t*) source)[5];
    source += 6 * aligned_word_size;
    dest   -= 2 * aligned_word_size;
    words  -= 6;
    goto copy_out6;

  case 7:
    a1 = ((aligned_word_t*) source)[0];
    a2 = ((aligned_word_t*) source)[1];
    a3 = ((aligned_word_t*) source)[2];
    a4 = ((aligned_word_t*) source)[3];
    a5 = ((aligned_word_t*) source)[4];
    a6 = ((aligned_word_t*) source)[5];
    a7 = ((aligned_word_t*) source)[6];
    source += 7 * aligned_word_size;
    dest   -= 1 * aligned_word_size;
    words  -= 7;
    goto copy_out7;

  case 0:
    if (words == 0) return;
    goto copy_out8;
  }

  do {
  copy_out8:
    a0 = ((aligned_word_t*) source)[0];
    a1 = ((aligned_word_t*) source)[1];
    a2 = ((aligned_word_t*) source)[2];
    a3 = ((aligned_word_t*) source)[3];
    a4 = ((aligned_word_t*) source)[4];
    a5 = ((aligned_word_t*) source)[5];
    a6 = ((aligned_word_t*) source)[6];
    a7 = ((aligned_word_t*) source)[7];

    source += aligned_word_size << 3u;
    words  -= 8;

    ((aligned_word_t*) dest)[0] = a0;
  copy_out7:
    ((aligned_word_t*) dest)[1] = a1;
  copy_out6:
    ((aligned_word_t*) dest)[2] = a2;
  copy_out5:
    ((aligned_word_t*) dest)[3] = a3;
  copy_out4:
    ((aligned_word_t*) dest)[4] = a4;
  copy_out3:
    ((aligned_word_t*) dest)[5] = a5;
  copy_out2:
    ((aligned_word_t*) dest)[6] = a6;
  copy_out1:
    ((aligned_word_t*) dest)[7] = a7;

    dest   += aligned_word_size << 3u;
  }
  while (words != 0);
}


/* copy block beginning at <source> to block beginning at <dest> with <words> 
   aligned_word_t words. dest should be aligned, but source MUST not */
static void
copy_dest_aligned (long int dest, long int source, long int words)
{
  aligned_word_t a0, a1, a2, a3, a4, a5, a6, a7, a8;
  unsigned shift1, shift2;

  ci_assert(CI_OFFSET(dest, aligned_word_size) == 0);
  ci_assert(CI_OFFSET(source, aligned_word_size));

  /* required shifts for aligned copies */

  shift1 = (source & (aligned_word_size - 1u)) << 3u;
  shift2 = (aligned_word_size << 3u) - shift1;

  /* align source */
  source &=~ (aligned_word_size - 1);

  switch (words & 7u) {	  
  case 1:
    a7 = ((aligned_word_t*) source)[0];
    a8 = ((aligned_word_t*) source)[1];
    source += 1 * aligned_word_size;
    dest   -= 7 * aligned_word_size;
    words  -= 1;
    goto copy_out1;

  case 2:
    a6 = ((aligned_word_t*) source)[0];
    a7 = ((aligned_word_t*) source)[1];
    a8 = ((aligned_word_t*) source)[2];
    source += 2 * aligned_word_size;
    dest   -= 6 * aligned_word_size;
    words  -= 2;
    goto copy_out2;

  case 3:
    a5 = ((aligned_word_t*) source)[0];
    a6 = ((aligned_word_t*) source)[1];
    a7 = ((aligned_word_t*) source)[2];
    a8 = ((aligned_word_t*) source)[3];
    source += 3 * aligned_word_size;
    dest   -= 5 * aligned_word_size;
    words  -= 3;
    goto copy_out3;
      
  case 4:
    a4 = ((aligned_word_t*) source)[0];
    a5 = ((aligned_word_t*) source)[1];
    a6 = ((aligned_word_t*) source)[2];
    a7 = ((aligned_word_t*) source)[3];
    a8 = ((aligned_word_t*) source)[4];
    source += 4 * aligned_word_size;
    dest   -= 4 * aligned_word_size;
    words  -= 4;
    goto copy_out4;
      
  case 5:
    a3 = ((aligned_word_t*) source)[0];
    a4 = ((aligned_word_t*) source)[1];
    a5 = ((aligned_word_t*) source)[2];
    a6 = ((aligned_word_t*) source)[3];
    a7 = ((aligned_word_t*) source)[4];
    a8 = ((aligned_word_t*) source)[5];
    source += 5 * aligned_word_size;
    dest   -= 3 * aligned_word_size;
    words  -= 5;
    goto copy_out5;

  case 6:
    a2 = ((aligned_word_t*) source)[0];
    a3 = ((aligned_word_t*) source)[1];
    a4 = ((aligned_word_t*) source)[2];
    a5 = ((aligned_word_t*) source)[3];
    a6 = ((aligned_word_t*) source)[4];
    a7 = ((aligned_word_t*) source)[5];
    a8 = ((aligned_word_t*) source)[6];
    source += 6 * aligned_word_size;
    dest   -= 2 * aligned_word_size;
    words  -= 6;
    goto copy_out6;

  case 7:
    a1 = ((aligned_word_t*) source)[0];
    a2 = ((aligned_word_t*) source)[1];
    a3 = ((aligned_word_t*) source)[2];
    a4 = ((aligned_word_t*) source)[3];
    a5 = ((aligned_word_t*) source)[4];
    a6 = ((aligned_word_t*) source)[5];
    a7 = ((aligned_word_t*) source)[6];
    a8 = ((aligned_word_t*) source)[7];
    source += 7 * aligned_word_size;
    dest   -= 1 * aligned_word_size;
    words  -= 7;
    goto copy_out7;

  case 0:
    if (words == 0) return;
    goto copy_out8;	
  }

  do {
  copy_out8:
    a0 = ((aligned_word_t*) source)[0];
    a1 = ((aligned_word_t*) source)[1];
    a2 = ((aligned_word_t*) source)[2];
    a3 = ((aligned_word_t*) source)[3];
    a4 = ((aligned_word_t*) source)[4];
    a5 = ((aligned_word_t*) source)[5];
    a6 = ((aligned_word_t*) source)[6];
    a7 = ((aligned_word_t*) source)[7];
    a8 = ((aligned_word_t*) source)[8];

    source += aligned_word_size << 3u;
    words  -= 8;

    ((aligned_word_t*) dest)[0] = MERGE_MISALIGNED (a0, shift1, a1, shift2);
  copy_out7:
    ((aligned_word_t*) dest)[1] = MERGE_MISALIGNED (a1, shift1, a2, shift2);
  copy_out6:
    ((aligned_word_t*) dest)[2] = MERGE_MISALIGNED (a2, shift1, a3, shift2);
  copy_out5:
    ((aligned_word_t*) dest)[3] = MERGE_MISALIGNED (a3, shift1, a4, shift2);
  copy_out4:
    ((aligned_word_t*) dest)[4] = MERGE_MISALIGNED (a4, shift1, a5, shift2);
  copy_out3:
    ((aligned_word_t*) dest)[5] = MERGE_MISALIGNED (a5, shift1, a6, shift2);
  copy_out2:
    ((aligned_word_t*) dest)[6] = MERGE_MISALIGNED (a6, shift1, a7, shift2);
  copy_out1:
    ((aligned_word_t*) dest)[7] = MERGE_MISALIGNED (a7, shift1, a8, shift2);
  
    dest   += aligned_word_size << 3u;
  }
  while (words != 0);
}


/* Copy dwords from source to dest. Requires dword alignment on dest, but
** not for source.  CAREFUL: this macro modifies its arguments.
*/
#define MAYBE_COPY_DWORD(dest, source, bytes)			\
do {								\
  if( bytes ) {							\
    ci_uint32 w;						\
    ci_uint8* d = (ci_uint8*) &w;				\
    ci_assert(bytes == 4);					\
    while( (bytes)-- )  *d++ = *(ci_uint8*)((source)++);	\
    *(ci_uint32*)dest = w;					\
    (dest) += 4;						\
  }								\
} while(0)


extern void*
ci_memcpy_io2(volatile void *destp, const void *sourcep, size_t bytes)
{
  /* This code supports arbitrary alignment of [sourcep].  On the alpha,
  ** [destp] and [bytes] must be 4-byte aligned.  No such restriction on
  ** Intels.
  */
  unsigned long int dest = (long int) destp;
  unsigned long int source = (long int) sourcep;

  if (bytes >= ALIGNED_WORD_CHUNK) {
    unsigned off_align;

    /* Word align destination */
    off_align = (unsigned) CI_ALIGN_NEEDED(dest, aligned_word_size, long);
    bytes -= off_align;

    while( off_align-- )  *(char*)(dest++) = *(char*)(source++);

    /* Now that dest is aligned, copy as much as possible. If source is
    ** misaligned, then we're going to have to do this with a pipelined
    ** shift.
    */
    if( CI_OFFSET(source, aligned_word_size) == 0 )
      copy_src_and_dest_aligned (dest, source, bytes / aligned_word_size);
    else								      
      copy_dest_aligned (dest, source, bytes / aligned_word_size);      

    source += bytes &~ (aligned_word_size - 1);
    dest   += bytes &~ (aligned_word_size - 1);
    bytes   = bytes &  (aligned_word_size - 1);
  }

  /* copy any misaligned bytes at the tail */
  while( bytes-- )  *(char*)(dest++) = *(char*)(source++);

  return (void*) destp;
}


#if defined(__GNUC__) && defined(__i386__) /* ?? MMX config flags */

/****************************************************************************
 *
 * memcpy code MMX optimised to support IO bus bursting with any alignments
 *
 ****************************************************************************/

#define mmx_word_size 8 
#define mmx_chunk 64 
#define mmx_shift 6

extern void * 
ci_memcpy_mmx(void * destp, const void * sourcep, size_t bytes) 
{ 
  unsigned long int dest = (long int) destp;
  unsigned long int source = (long int) sourcep;

  int iter; 

  if (bytes >= mmx_chunk) { 
      unsigned off_align;

      /* Word align destination */
      off_align = dest & (mmx_word_size - 1); 
      bytes -= off_align;

      while( off_align-- )  *(char*)(dest++) = *(char*)(source++);

      /* Now that dest is aligned, copy as much as possible. */
      for (iter = bytes >> mmx_shift; iter > 0; iter--) { 
	  __asm__ __volatile__ ( 
				"prefetchnta 0(%0)\n" 
				"prefetchnta 32(%0)\n" 
				"movq (%0), %%mm0\n" 
				"movq 8(%0), %%mm1\n" 
				"movq 16(%0), %%mm2\n" 
				"movq 24(%0), %%mm3\n" 
				"movq 32(%0), %%mm4\n" 
				"movq 40(%0), %%mm5\n" 
				"movq 48(%0), %%mm6\n" 
				"movq 56(%0), %%mm7\n" 
				"movntq %%mm0, (%1)\n" 
				"movntq %%mm1, 8(%1)\n" 
				"movntq %%mm2, 16(%1)\n" 
				"movntq %%mm3, 24(%1)\n" 
				"movntq %%mm4, 32(%1)\n" 
				"movntq %%mm5, 40(%1)\n" 
				"movntq %%mm6, 48(%1)\n" 
				"movntq %%mm7, 56(%1)\n" 
				:: "r" (source), "r" (dest) : "memory"); 
	  source += mmx_chunk;
	  dest += mmx_chunk;
      } 
      /* Ensure memory ordering and clean up MMX unit */
      __asm__ __volatile__ ("sfence":::"memory"); 
      __asm__ __volatile__ ("emms":::"memory"); 
    } 

  bytes &= (mmx_chunk - 1); 

  while( bytes-- )  *(char*)(dest++) = *(char*)(source++);

  return destp; 
} 

#endif

#if (defined(_WIN32) && defined(__i386__)) || defined(__PPC__)

extern void * 
ci_memcpy_byte_aligned(void * destp, const void * sourcep, size_t bytes)
{
  /*! \TODO MASM implementation of code in memcpy.s */
  return memcpy(destp, sourcep, bytes);	  
}

#endif

/*! \cidoxg_end */
