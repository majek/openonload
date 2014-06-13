	.file	"vfork_intercept.S"


#if defined(__i386__)

	/* x86 calling convention: args pushed on stack in reverse order */

	.text
	.align 16
	.globl	onload_vfork
	.type	onload_vfork,@function
	.globl onload___vfork_as_fork
	.globl ci_sys_vfork
	.globl onload___vfork_rtaddr
	.globl onload___vfork_ebx
	.globl onload___vfork_is_vfork
	.globl citp_netif_child_vfork_hook
	.globl citp_netif_parent_vfork_hook
onload_vfork:
	pushl %ebx
	call 1f
1:
    popl %ebx
	addl $_GLOBAL_OFFSET_TABLE_+[.-1b], %ebx
	call onload___vfork_is_vfork@PLT
	test %eax, %eax
	jz 1f
	popl %eax
	movl onload___vfork_ebx@GOT(%ebx), %edx
	movl %eax, (%edx)
	popl %eax
	movl onload___vfork_rtaddr@GOT(%ebx), %edx
	movl %eax, (%edx)
	movl ci_sys_vfork@GOT(%ebx), %eax
	call *(%eax)
	push %eax
	testl %eax, %eax
	jz 2f
	call citp_netif_parent_vfork_hook
	jmp 3f
2:
	call citp_netif_child_vfork_hook
3:
	pop %eax
	movl onload___vfork_ebx@GOT(%ebx), %ecx
	movl onload___vfork_rtaddr@GOT(%ebx), %edx
	movl (%ecx), %ebx
	jmp *(%edx)
1:
	call onload___vfork_as_fork@PLT
	popl %ebx
	ret

	.globl vfork
	vfork = onload_vfork
#elif defined(__x86_64__)

	/* x86_64 calling convention: args 1,2,3 in registers rdi,rsi,rdx */
	.text
	.align 16
	.globl	onload_vfork
	.type	onload_vfork,@function
	.globl ci_sys_vfork
	.globl onload___vfork_rtaddr
	.globl onload___vfork_as_fork
	.globl onload___vfork_is_vfork
	.globl citp_netif_child_vfork_hook
	.globl citp_netif_parent_vfork_hook
onload_vfork:

	call onload___vfork_is_vfork@PLT	
	testl %eax, %eax
	jz 1f
	popq %rdi
	movq onload___vfork_rtaddr@GOTPCREL(%rip), %rsi
	movq %rdi, (%rsi) 
	movq ci_sys_vfork@GOTPCREL(%rip), %rax
	call *(%rax)
	pushq %rax
	testl %eax, %eax
	jz 2f
	call citp_netif_parent_vfork_hook
	jmp 3f
2:
	call citp_netif_child_vfork_hook
3:
	popq %rax
	movq onload___vfork_rtaddr@GOTPCREL(%rip), %rdx
	jmp *(%rdx)
1:
	jmp onload___vfork_as_fork@PLT

	.globl vfork
	vfork = onload_vfork

#endif	 /* __1386__ or __x86_64__ */
#if defined(__PPC64__)

   .text
   .align   3
   .globl .onload_vfork
   .type .onload_vfork,@function
   .section ".opd","aw";
   .globl onload_vfork;
   .align 3;
onload_vfork: .quad .onload_vfork, .TOC.@tocbase, 0; 
   .previous

.onload_vfork:
	mflr %r0
	ld %r6, onload___vfork_rtaddr@got(%r2)
	std %r0, 0(%r6)
	ld %r6, onload___vfork_r31@got(%r2)
	std %r31, 0(%r6)
	bl .onload___vfork_is_vfork 
	nop
 	cmpdi %r3,0	
	beq .Lfork
	ld    %r6,ci_sys_vfork@got(%r2)
        ld    %r6,0(%r6)
        ld    %r0,0(%r6)
        mr   %r31,%r2
        mtctr %r0
        ld    %r2,8(%r6)
        bctrl
        mr    %r2,%r31
	mr    %r31,%r3
	cmpdi %r3,0
        beq .Linchild
        bl .citp_netif_parent_vfork_hook
	nop
	mr %r3,%r31
	b .Lret
.Linchild:
        bl .citp_netif_child_vfork_hook
	nop
	mr %r3,%r31
	b .Lret
.Lfork:
        bl .onload___vfork_as_fork
	nop
.Lret:
	ld %r6, onload___vfork_r31@got(%r2)
	ld %r31, 0(%r6)
	ld %r6, onload___vfork_rtaddr@got(%r2)
	ld %r0, 0(%r6)
	mtlr %r0
	blr

.globl vfork
vfork = onload_vfork
.globl .vfork
.vfork = .onload_vfork
#elif defined(__PPC__)
    .text
    .align 3
    .globl onload_vfork
    .type onload_vfork,@function

onload_vfork:
     mflr %r0
     bcl     20,31,1f
1:   mflr    %r6
     addis   %r6,%r6,_GLOBAL_OFFSET_TABLE_-1b@ha
     addi    %r6,%r6,_GLOBAL_OFFSET_TABLE_-1b@l
     lwz %r7, onload___vfork_rtaddr@got(%r6)
     stw %r0, 0(%r7)
     lwz %r7, onload___vfork_r31@got(%r6)
     stw %r31, 0(%r7)
     mr %r31, %r6
     bl onload___vfork_is_vfork
     cmpwi %r3, 0
     beq 2f
     lwz %r6, ci_sys_vfork@got(%r31)
     lwz %r0, 0(%r6)
     mtctr %r0
     bctrl
     lwz %r7, onload___vfork_r3@got(%r31)
     stw %r3, 0(%r7)
     cmpwi %r3, 0
     beq 4f
     bl citp_netif_parent_vfork_hook
     b 5f
4:
     bl citp_netif_child_vfork_hook
5:  
     lwz %r7, onload___vfork_r3@got(%r31)
     lwz %r3, 0(%r7)
     b 3f
2:
     bl onload___vfork_as_fork
3:
     lwz %r6, onload___vfork_rtaddr@got(%r31)
     lwz %r0, 0(%r6)
     mtlr %r0
     lwz %r6, onload___vfork_r31@got(%r31)
     lwz %r31, 0(%r6)
     blr

.globl vfork
vfork = onload_vfork

#endif /* __PPC64__ */



    /* Tell everybody that we do not need executable stack.
     * Make SELinux happy. */
    .section .note.GNU-stack
    .previous

