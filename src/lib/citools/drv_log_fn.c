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




#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#endif

#ifdef CONFIG_KALLSYMS
/* linux/kallsyms.h exists starting from 2.6 (or in RH kernels), 
 * and we'd like to avoid warning when it does not exist. */
#include <linux/kallsyms.h>
#else
#define print_symbol(fmt, addr)
#endif

#include <linux/module.h>

void ci_log_syslog(const char* msg)
{
  printk(KERN_ERR "%s\n", msg);

#ifndef NDEBUG
#ifndef __x86_64__          /* x86_64 stacks not aligned to their size */
  {
    /* This code checks for low stack conditions.  Rather than waiting for the
     * kernel to detect it, it does it's best to give a stack trace with
     * slightly more useful info (specifically - sufficient info to know what
     * functions are consuming how much stack space).  We are slightly more
     * sensitive that the kernel (our 'redzone' is 64 bytes bigger), in order
     * to prevent the kernel stack overflow kicking in while we're busy
     * reporting it here.
     */
    ci_uintptr_t  *stack = (void*)&msg;  /* __builtin_frame_address() unreliable */
    ci_uintptr_t  esp = (ci_uintptr_t)stack;

    if (CI_UNLIKELY((esp & (THREAD_SIZE-1)) < THREAD_SIZE/8+64)) {
      /* We're in the stack red-zone.  If an IRQ came in at this point the
       * kernel would panic with a stack-overflow message.  We'll save it the
       * hassle :-)
       */
      ci_uintptr_t *prev_stack = stack;
      ci_uintptr_t *stack_end = (ci_uintptr_t*)((esp + THREAD_SIZE) & -THREAD_SIZE);
      ci_uintptr_t prev_addr = 0;

      printk ("Stack overflow detected! (SP: %p, end %p)\n", stack, stack_end);
      while (stack < stack_end) {
        ci_uintptr_t addr = *stack;

        /* Hmm - I can't figure out how to determine whether we're in one of
         * our modules.  There are various ways, but none is exported for
         * non-GPL modules' use :-(  Oh well - we'll just print out addresses
         * which are suspiciously close (i.e. within 16M) to this function.
         */
        if (((long)ci_log_syslog - addr < 0x1000000) ||
            (addr - (long)ci_log_syslog < 0x1000000)) {

          if (prev_addr) {
            printk ("STACK <%p> = 0x%lX, %4ld ",
                    stack, (unsigned long)prev_addr, (long)stack - (long)prev_stack);
            print_symbol (" -- %s\n", prev_addr);
          }
          prev_addr = addr;
          prev_stack = stack;
        }
        stack++;
      }

      if (prev_addr) {
        printk ("[END] <%p> = 0x%lX, %4ld ",
                stack, (unsigned long)prev_addr, (long)stack - (long)prev_stack);
        print_symbol (" -- %s\n", prev_addr);
      }
      else {
        printk ("I couldn't find anything like %p on stack.\n", ci_log_syslog);
        stack = (void*)&msg;  /* __builtin_frame_address seems unreliable */
        printk ("Here is a complete dump of the stack %p->%p:\n",
                stack, stack_end);
        while (stack < stack_end) {
            printk ("STACK <%p> = 0x%lX", stack, (unsigned long)*stack);
            print_symbol (" -- %s\n", *stack);
            stack++;
        }
      }
      printk ("--- End of backtrace --- \n");

      CI_BOMB();
    }
  }
#endif /* 32-bit kernels only */
#endif /* Debug builds only */
}



/*! \cidoxg_end */
