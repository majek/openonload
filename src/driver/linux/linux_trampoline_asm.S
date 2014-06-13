	.file	"linux_trampoline_asm.S"

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#endif
#include <ci/internal/trampoline.h>

	/* This wraps our replacement for sys_close.  It calls our handler with
	 * a second argument pointing to the stack frame so that we can hook in
	 * the trampoline.
	 *
	 * (This is not strictly necessary for x86, where we can use the
	 * address of the first argument, but is needed for x86_64 where args
	 * are passed in registers.  Doing it the same way for both keeps
	 * things tidy.)
	 */

#if defined(__i386__)

	.globl	efab_linux_trampoline_close
	.type	efab_linux_trampoline_close,@function
efab_linux_trampoline_close:
	leal	4(%esp),%ecx	/* Base of struct pt_regs in syscall */
	movl	(%ecx),%eax	/* Original 1st argument = file descriptor */
                                /* 3rd arg is ret-addr -- already on stack */
	pushl	%ecx		/* 2nd arg to our handler = struct pt_regs */
	pushl	%eax		/* 1st arg to our handler = file descriptor */
	call	efab_linux_trampoline_handler_close
	add	$8,%esp		/* Pop args from stack */
	ret			/* Return to original syscall entry point */
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

#elif defined(__x86_64__)

	.globl	efab_linux_trampoline_close
	.type	efab_linux_trampoline_close,@function
	.align 16
efab_linux_trampoline_close:
	leaq	-40(%rsp),%rsi	/* 2nd arg to our handler = struct pt_regs */
	mov	(%rsp),%rdx     /* 3rd arg is return address */
	jmp	efab_linux_trampoline_handler_close
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

# ifdef CONFIG_COMPAT
	.globl	efab_linux_trampoline_close32
	.type	efab_linux_trampoline_close32,@function
	.align 16
efab_linux_trampoline_close32:
	leaq	-40(%rsp),%rsi	/* 2nd arg to our handler = struct pt_regs */
	mov	(%rsp),%rdx     /* 3rd arg is return address */
	jmp	efab_linux_trampoline_handler_close32
.Lfe2:
	.size	efab_linux_trampoline_close32,.Lfe2-efab_linux_trampoline_close32
# endif

#elif defined(__PPC__)

	.globl	efab_linux_trampoline_close
	.type	efab_linux_trampoline_close,@function
	.align 4
efab_linux_trampoline_close:
	nop
	nop
	nop
	nop
	nop
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

/*  end elif __PPC__ */

#elif defined(__ia64__)
	/* trampoline unsupported on ia64 */
#else

#error "Don't know how to build trampolines for this platform"

#endif

