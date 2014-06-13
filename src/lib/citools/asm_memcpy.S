#ifdef __i386__

	/* copes with any alignment and on modern cores does a pretty good job
	   of hitting the IO bus */
	.text
	.align 4
	.globl ci_memcpy_byte_aligned
ci_memcpy_byte_aligned:
	push   %ebp
	mov    %esp,%ebp
	push   %edi
	push   %esi
	mov    0x8(%ebp),%edx
	mov    0x10(%ebp),%eax
	mov    %edx,%edi
	mov    0xc(%ebp),%esi
	cmp    $0x7,%eax
	jbe    1f
	mov    %edx,%ecx
	neg    %ecx
	and    $0x3,%ecx
	sub    %ecx,%eax
	cld    
	repz 
	movsb  %ds:(%esi),%es:(%edi)
	mov    %eax,%ecx
	shr    $0x2,%ecx
	cld    
	repz 
	movsl %ds:(%esi),%es:(%edi)
	and    $0x3,%eax
	lea    0x0(%esi,1),%esi
1:	mov    %eax,%ecx
	cld    
	repz 
	movsb %ds:(%esi),%es:(%edi)
	mov    %edx,%eax
	lea    0xfffffff8(%ebp),%esp
	pop    %esi
	pop    %edi
	leave  
	ret    
#endif


