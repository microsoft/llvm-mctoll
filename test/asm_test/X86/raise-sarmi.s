// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 6
// CHECK-NEXT: 12
// CHECK-NEXT: 25
// CHECK-EMPTY:

	.text
	.file	"raise-sarmi.c"
	.globl	testSAR8mi                      # -- Begin function testSAR8mi
	.p2align	4, 0x90
	.type	testSAR8mi,@function
testSAR8mi:                             # @testSAR8mi
	.cfi_startproc
# %bb.0:                                # %entry
	sarb	$2, (%rdi)
	retq
.Lfunc_end0:
	.size	testSAR8mi, .Lfunc_end0-testSAR8mi
	.cfi_endproc
                                        # -- End function
	.globl	testSAR16mi                     # -- Begin function testSAR16mi
	.p2align	4, 0x90
	.type	testSAR16mi,@function
testSAR16mi:                            # @testSAR16mi
	.cfi_startproc
# %bb.0:                                # %entry
	sarw	$2, (%rdi)
	retq
.Lfunc_end1:
	.size	testSAR16mi, .Lfunc_end1-testSAR16mi
	.cfi_endproc
                                        # -- End function
	.globl	testSAR32mi                     # -- Begin function testSAR32mi
	.p2align	4, 0x90
	.type	testSAR32mi,@function
testSAR32mi:                            # @testSAR32mi
	.cfi_startproc
# %bb.0:                                # %entry
	sarl	$2, (%rdi)
	retq
.Lfunc_end2:
	.size	testSAR32mi, .Lfunc_end2-testSAR32mi
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
	movb	$25, 1(%rsp)
	leaq	1(%rsp), %rdi
	callq	testSAR8mi
	movsbl	1(%rsp), %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	movw	$50, 2(%rsp)
	leaq	2(%rsp), %rdi
	callq	testSAR16mi
	movswl	2(%rsp), %esi
	movl	$.L.str.1, %edi
	xorl	%eax, %eax
	callq	printf
	movl	$100, 4(%rsp)
	leaq	4(%rsp), %rdi
	callq	testSAR32mi
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
