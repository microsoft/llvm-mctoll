// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 24
// CHECK-NEXT: 48
// CHECK-NEXT: 100
// CHECK-EMPTY:

	.text
	.file	"raise-shlmi.c"
	.globl	testSHL8mi                      # -- Begin function testSHL8mi
	.p2align	4, 0x90
	.type	testSHL8mi,@function
testSHL8mi:                             # @testSHL8mi
	.cfi_startproc
# %bb.0:                                # %entry
	shlb	$2, (%rdi)
	retq
.Lfunc_end0:
	.size	testSHL8mi, .Lfunc_end0-testSHL8mi
	.cfi_endproc
                                        # -- End function
	.globl	testSHL16mi                     # -- Begin function testSHL16mi
	.p2align	4, 0x90
	.type	testSHL16mi,@function
testSHL16mi:                            # @testSHL16mi
	.cfi_startproc
# %bb.0:                                # %entry
	shlw	$2, (%rdi)
	retq
.Lfunc_end1:
	.size	testSHL16mi, .Lfunc_end1-testSHL16mi
	.cfi_endproc
                                        # -- End function
	.globl	testSHL32mi                     # -- Begin function testSHL32mi
	.p2align	4, 0x90
	.type	testSHL32mi,@function
testSHL32mi:                            # @testSHL32mi
	.cfi_startproc
# %bb.0:                                # %entry
	shll	$2, (%rdi)
	retq
.Lfunc_end2:
	.size	testSHL32mi, .Lfunc_end2-testSHL32mi
	.cfi_endproc
                                        # -- End function
	.globl	main                            # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rax
	.cfi_def_cfa_offset 16
	movb	$6, 1(%rsp)
	leaq	1(%rsp), %rdi
	callq	testSHL8mi
	movsbl	1(%rsp), %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	movw	$12, 2(%rsp)
	leaq	2(%rsp), %rdi
	callq	testSHL16mi
	movswl	2(%rsp), %esi
	movl	$.L.str.1, %edi
	xorl	%eax, %eax
	callq	printf
	movl	$25, 4(%rsp)
	leaq	4(%rsp), %rdi
	callq	testSHL32mi
	movl	4(%rsp), %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end3:
	.size	main, .Lfunc_end3-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%d\n"
	.size	.L.str, 4

	.type	.L.str.1,@object                # @.str.1
.L.str.1:
	.asciz	"%hd\n"
	.size	.L.str.1, 5

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
