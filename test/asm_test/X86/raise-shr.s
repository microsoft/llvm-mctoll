// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 2
// CHECK-NEXT: 4
// CHECK-NEXT: 6
// CHECK-NEXT: 12
// CHECK-EMPTY:



	.text
	.file	"raise-shr.s"
	.globl	testSHR64                       # -- Begin function testSHR64
	.p2align	4, 0x90
	.type	testSHR64,@function
testSHR64:                              # @testSHR64
	.cfi_startproc
# %bb.0:                                # %entry
	shrq	$2, (%rdi)
	retq
.Lfunc_end0:
	.size	testSHR64, .Lfunc_end0-testSHR64
	.cfi_endproc
                                        # -- End function
	.globl	testSHR32                       # -- Begin function testSHR32
	.p2align	4, 0x90
	.type	testSHR32,@function
testSHR32:                              # @testSHR32
	.cfi_startproc
# %bb.0:                                # %entry
	shrl	$2, (%rdi)
	retq
.Lfunc_end1:
	.size	testSHR32, .Lfunc_end1-testSHR32
	.cfi_endproc
                                        # -- End function
	.globl	testSHR16                       # -- Begin function testSHR16
	.p2align	4, 0x90
	.type	testSHR16,@function
testSHR16:                              # @testSHR16
	.cfi_startproc
# %bb.0:                                # %entry
	shrw	$2, (%rdi)
	retq
.Lfunc_end2:
	.size	testSHR16, .Lfunc_end2-testSHR16
	.cfi_endproc
                                        # -- End function
	.globl	testSHR8                        # -- Begin function testSHR8
	.p2align	4, 0x90
	.type	testSHR8,@function
testSHR8:                               # @testSHR8
	.cfi_startproc
# %bb.0:                                # %entry
	shrb	$2, (%rdi)
	retq
.Lfunc_end3:
	.size	testSHR8, .Lfunc_end3-testSHR8
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
	movl	$.L.str, %edi
	movl	$2, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$4, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$6, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str.1, %edi
	movl	$12, %esi
	xorl	%eax, %eax
	callq	printf
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end4:
	.size	main, .Lfunc_end4-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%u\n"
	.size	.L.str, 4

	.type	.L.str.1,@object                # @.str.1
.L.str.1:
	.asciz	"%lu\n"
	.size	.L.str.1, 5

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
