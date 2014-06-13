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

#ifndef __ONLOAD_SYSDEP_H__
#define __ONLOAD_SYSDEP_H__

#if defined(__GNUC__)

# if defined(__i386__) || defined(__x86_64__)  /* GCC x86/x64 */

   static inline int ef_vi_cas32_succeed(volatile int32_t* p, int32_t oldval,
                                         int32_t newval) {
     char ret;
     int32_t prevval;
     __asm__ __volatile__("lock; cmpxchgl %3, %1; sete %0"
	                  : "=q"(ret), "+m"(*p), "=a"(prevval)
		          : "r"(newval), "a"(oldval));
     return ret;
   }
   static inline int ef_vi_cas32_fail(volatile int32_t* p, int32_t oldval,
                                      int32_t newval) {
     char ret;
     int32_t prevval;
     __asm__ __volatile__("lock; cmpxchgl %3, %1; setne %0"
                          : "=q"(ret), "+m"(*p), "=a"(prevval)
                          : "r"(newval), "a"(oldval));
     return ret;
   }

# elif defined(__PPC__)  /* GCC, PPC */

   static inline unsigned ef_vi_cas32(volatile uint32_t *p, uint32_t old, 
                                      uint32_t new)
   {
     unsigned prev;

     __asm__ __volatile__ (

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2,1     \n"	
      "       cmpw    0,%0,%3     \n"
      "       bne-    2f          \n"
      "       stwcx.  %4,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      "2:                         \n"

      : "=&r" (prev), "=m" (*p)
      : "r" (p), "r" (old), "r" (new), "m" (*p)
      : "cc", "memory"
     );
   return prev;
   }

   static inline int ef_vi_cas32_succeed(volatile uint32_t* p, uint32_t oldval, 
                                         uint32_t newval)
   { return (int)(ef_vi_cas32(p, oldval, newval) == oldval); }

# elif defined(__ia64__)  /* GCC, IA64 */

   static inline int32_t 
   ef_vi_cas32(volatile int32_t* p, int32_t oldval, int32_t newval)
   {
    uint64_t _ret;							\
  __asm__ __volatile__ ("mov ar.ccv=%0;;" :: "rO"(oldval));		\
  __asm__ __volatile__ ("cmpxchg4.acq %0=[%1],%2,ar.ccv":		\
			"=r"(_ret) : "r"(p), "r"(newval) : "memory");	\
    return (int32_t) _ret;
   }

   static inline int 
   ef_vi_cas32_succeed(volatile int32_t* p, int32_t oldval, int32_t newval)
   { return (int) (ef_vi_cas32(p, oldval, newval) == oldval); }
   static inline int 
   ef_vi_cas32_fail(volatile uint32_t* p, uint32_t oldval, uint32_t newval)
   { return (int)(ef_vi_cas32(p, oldval, newval) != oldval); }

# else
#  error Unknown processor - GNU C
# endif

#elif defined(_MSC_VER)

# if defined(__i386__)  /* MSC, x86 */

   static __inline int
   ef_vi_cas32_succeed(volatile int32_t* p, long oldval, long newval)
   {
     char rc = 0;

     __asm
     {
       mov EDX, newval
       mov EAX, oldval
       mov EDI, p
       lock cmpxchg [EDI], EDX
       sete rc
     }
     return rc;
   }
   static __inline int
   ef_vi_cas32_fail(volatile int32_t* p, long oldval, long newval)
   {
     char rc = 1;

     __asm
     {
       mov EDX, newval
         mov EAX, oldval
         mov EDI, p
         lock cmpxchg [EDI], EDX
         setne rc
     }
     return rc;
   }

# elif defined(__x86_64__)  /* MSC, x64 */

   static __inline int
   ef_vi_cas32_succeed(volatile int32_t* p, int32_t oldval, int32_t newval)
   {
      return (_InterlockedCompareExchange((volatile LONG*)p, newval, oldval) == oldval);
   }
   static __inline int
   ef_vi_cas32_fail(volatile int32_t* p, int32_t oldval, int32_t newval)
   {
     return (_InterlockedCompareExchange((volatile LONG*)p, newval, oldval) != oldval);
   }


# else
#  error Unknown processor MSC
# endif

#elif defined(__PGI)
# error PGI not supported 

#else
# error Unknown compiler.
#endif


#endif /* __ONLOAD_SYSDEP_H__ */
