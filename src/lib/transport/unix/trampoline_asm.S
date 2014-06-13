	.file	"trampoline_asm.S"

	/* This code just sorts out the stack for the trampoline receiving
	 * C code.  (Stack and registers are set up appropriately by the kernel
	 * side.)
	 */

#if defined(__i386__)

	/* x86 calling convention: args pushed on stack in reverse order */

	.text
	.align 16
	.globl	ci_trampoline_handler_entry
	.hidden ci_trampoline_handler_entry
	.type	ci_trampoline_handler_entry,@function
ci_trampoline_handler_entry:
	/* stack layout set up by kernel is:
	 *    return address
	 *    original %ecx
	 *    original %edx
	 *    data argument
	 *    opcode argument   <- %esp
	 */
	call	ci_trampoline_handler
	add	$8,%esp		/* Fix stack (ie. remove params) */
        pop     %edx            /* restore preserved edx */
        pop     %ecx            /* restore preserved ecx */
	ret			/* Return to whence sys-call originally came */
.Lfe1:
	.size	ci_trampoline_handler_entry,.Lfe1-ci_trampoline_handler_entry

#elif defined(__x86_64__)

	/* x86_64 calling convention: args 1,2,3 in registers rdi,rsi,rdx */

	.text
	.align 16
	.globl	ci_trampoline_handler_entry
	.hidden ci_trampoline_handler_entry
	.type	ci_trampoline_handler_entry,@function
ci_trampoline_handler_entry:
        /* calling conventions for syscall and func call differ.  The function
         * may trash rsi,rdi,rdx,r8,r9; syscalls do not (note: preserved rsi/
         * rdi already placed on stack by kernel trampoline code)
         */
        push    %rdx
        push    %r8
        push    %r9
	call	ci_trampoline_handler@PLT
        pop     %r9
        pop     %r8
        pop     %rdx
        pop     %rsi
        pop     %rdi
	ret			/* Return to whence sys-call originally came */
.Lfe1:
	.size	ci_trampoline_handler_entry,.Lfe1-ci_trampoline_handler_entry

#endif	 /* __1386__ or __x86_64__ */



#if defined(__PPC__)

   .text
   .align   3
   .globl   ci_trampoline_handler_entry
   .hidden  ci_trampoline_handler_entry
   .type    ci_trampoline_handler_entry,@function

ci_trampoline_handler_entry:

/*
 * Calling protocol for syscall.
 * r0 = sys call number
 * r3, r4, r5, r6, r7 and r8 hold up to six possible params
 *
 * What we do here is
 * 1) Claim a local stack frame pointer (sfp). Nominal 32 bytes will do.
 * 2) Save all pertinent in coming register contents
 * 3) Load up registers with params for our 'trampoline_handler'
 * 4) Call our 'trampoline_handler'
 * 5) Upon gaining control after a return from the handler, we
 *    reload the original return address to the caller and return back
 *    cleanly.
 */

   /* Claim local stack space & set up stack back chain as per ABI convention*/

   stwu  1,-44(1)    # r1 = new sfp which is 32 bytes away from caller's
   stw   31,40(1)    # Save caller's sfp (r31) to our sfp +40 (Caller's stk -4)
   mflr  31          # Get Return addr from LR reg
   stw   31,46(1)    # Save in Caller's stk loc +4
   mr    31,1        # Load r31 to be our working sfp

   /* Preserve syscall parameters */
   
   stw   0,2*4(31)   # Save Syscall fn() num away.
   stw   3,3*4(31)   # Save all potential parameters 
   stw   4,4*4(31)   # -  passed to the syscall held
   stw   5,5*4(31)   # -  in registers r3 - r8
   stw   6,6*4(31)
   stw   7,7*4(31)
   stw   8,8*4(31)

  /* Transfer control to our trampoline handler to do the business */
  
   #bl    ci_trampoline_handler
   
  /* Reinstate r1 & r31 to Caller's original & setup for returning to caller */
  
   lwz   11,0(1)     # Get caller's sfp
   lwz   0,4(11)     # Get the saved return address. The original LR reg.
   mtlr  0           # Reinstate LR to the target return address.
   lwz   31,-4(11)   # Get back caller's sfp into r31
   mr    1,11        # Get r1 to point to caller's stk frame
   blr					# Go back to caller ...
   
.Lfe1:
   .size   ci_trampoline_handler_entry,.Lfe1-ci_trampoline_handler_entry

#endif	/* __PPC__ */

    /* Tell everybody that we do not need executable stack.
     * Make SELinux happy. */
    .section .note.GNU-stack
    .previous


