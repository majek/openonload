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
	pushl	%ecx		/* 2nd arg to our handler = struct pt_regs */
	call	efab_linux_trampoline_handler_close3232
	add	$4,%esp		/* Pop args from stack */
	ret			/* Return to original syscall entry point */
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

#elif defined(__x86_64__)

/* we have return address on the stack before pt_regs, so
 * pt_regs is expected on 8(%rsp) */
#define RSP_TP_PT_REGS_OFFSET_BASE 8

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
/* See Linux changeset 76f5df43cab5e765c0bd42289103e8f625813ae1
 * "Always allocate a complete "struct pt_regs" on the kernel stack":
 * linux used to skip callee-preserved r15-bx registers on older kernels.
 * 6 registers, 8 bytes each gives 48 bytes of offset above base. */
#define RSP_TP_PT_REGS_OFFSET (RSP_TP_PT_REGS_OFFSET_BASE - 6*8)
#else
#define RSP_TP_PT_REGS_OFFSET (RSP_TP_PT_REGS_OFFSET_BASE)
#endif

	.globl	efab_linux_trampoline_close
	.type	efab_linux_trampoline_close,@function
	.align 16
efab_linux_trampoline_close:
	leaq	RSP_TP_PT_REGS_OFFSET(%rsp),%rsi	/* 2nd arg to our handler = struct pt_regs */
	mov	(%rsp),%rdx     /* 3rd arg is return address */
	jmp	efab_linux_trampoline_handler_close64
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

# ifdef CONFIG_COMPAT
	.globl	efab_linux_trampoline_close32
	.type	efab_linux_trampoline_close32,@function
	.align 16
efab_linux_trampoline_close32:
	leaq	RSP_TP_PT_REGS_OFFSET(%rsp),%rax	/* struct pt_regs */
	pushq	%rax					/* last arg */
	call	efab_linux_trampoline_handler_close32
	add	$8,%rsp					/* pop pt_regs */
	ret
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

