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

#if defined(__PPC64__)
   /* Note lack of a .func declaration for this bit of code - it is
    * emphatically _not_ a function
    */
   .globl onload_trampoline_user_fixup_64
onload_trampoline_user_fixup_64:
        /* Restore the link register */
        ld 2, 72(1)
        mtlr 2
        /* Restore the old IP to ctr */
        ld 2, 88(1)
        mtctr 2
        /* Restore the TOC */
        ld 2, 80(1)
        /* Restore the stack */
        ld 1, 0(1)
        /* And branch */
        bctr
#else
        .globl onload_trampoline_user_fixup_32
onload_trampoline_user_fixup_32:
        lwz 2, 36(1)
        mtlr 2
        lwz 2, 44(1)
        mtctr 2
        lwz 2, 40(1)
        lwz 1, 0(1)
        bctr
#endif

#endif	/* __PPC__ */

    /* Tell everybody that we do not need executable stack.
     * Make SELinux happy. */
    .section .note.GNU-stack
    .previous


