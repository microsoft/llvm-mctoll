# REQUIRES: x86_64-linux
# RUN: clang -o %t %s
# RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
# RUN: clang -o %t-dis %t-dis.ll
# RUN: %t-dis 2>&1 | FileCheck %s
# CHECK: data: 8877
# CHECK: data after not: ffff7788

# This test will produce the mi as follows:
#   $eax = NOT32r $eax(tied-def 0), <0x56331826a2e8>

	.text
	.file	"test-not.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$16, %rsp
	movl	$0, -12(%rbp)
	movl	$34935, -4(%rbp)        # imm = 0x8877
	movl	-4(%rbp), %esi
	movabsq	$.L.str, %rdi
	movb	$0, %al
	callq	printf
	movl	-4(%rbp), %eax
	not	%eax
	movl	%eax, -8(%rbp)
	movl	-8(%rbp), %esi
	movabsq	$.L.str.1, %rdi
	movb	$0, %al
	callq	printf
	xorl	%eax, %eax
	addq	$16, %rsp
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
					# -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"data: %x \n"
	.size	.L.str, 11

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"data after not: %x \n"
	.size	.L.str.1, 21
