/*
** This was generated from csum_copy.c with [gcc -O4 -march=i686].
**
** ?? Could bear some improvement...
**
*/
	.file	"asm_csum_copy.S"
#ifdef __i386__
	.text
	.align 16
	.globl	ci_ip_csum_copy_asm
	.type	ci_ip_csum_copy_asm,@function
ci_ip_csum_copy_asm:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	movl	16(%ebp), %edi
	pushl	%esi
	movl	12(%ebp), %edx
	pushl	%ebx
	movl	20(%ebp), %ecx
	movl	%edi, %eax
	andl	$-4, %eax
	leal	(%eax,%edx), %esi
	cmpl	%esi, %edx
	movl	8(%ebp), %ebx
	je	.L293
	.p2align 4
.L288:
	movl	(%edx), %eax
#APP
	addl %eax, %ecx ;adcl $0, %ecx ;
#NO_APP
	addl	$4, %edx
	movl	%eax, (%ebx)
	addl	$4, %ebx
	cmpl	%esi, %edx
	jne	.L288
.L293:
	testl	$3, %edi
	je	.L291
	testl	$2, %edi
	je	.L290
	movzwl	(%edx), %esi
#APP
	addl %esi, %ecx ;adcl $0, %ecx ;
#NO_APP
	movw	%si, (%ebx)
.L290:
	testl	$1, %edi
	je	.L291
	cmpl	$3, %edi
	movl	%edx, %eax
	movl	%ebx, %edx
	je	.L295
.L292:
	movzbl	(%eax), %ebx
	movb	%bl, (%edx)
	movzbl	%bl, %edx
#APP
	addl %edx, %ecx ;adcl $0, %ecx ;
#NO_APP
.L291:
	movl	%ecx, %eax
	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
	.p2align 4,,7
.L295:
	addl	$2, %eax
	addl	$2, %edx
	jmp	.L292
.Lfe1:
	.size	ci_ip_csum_copy_asm,.Lfe1-ci_ip_csum_copy_asm
#endif
