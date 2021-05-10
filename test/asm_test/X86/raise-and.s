// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 3
// CHECK-NEXT: 3
// CHECK-NEXT: 3
// CHECK-NEXT: 3
// CHECK-EMPTY:


	.text
	.file	"raise-and.s"
	.globl	testAND64mr                     # -- Begin function testAND64mr
	.p2align	4, 0x90
	.type	testAND64mr,@function
testAND64mr:                            # @testAND64mr
	.cfi_startproc
# %bb.0:                                # %entry
	andq	%rsi, (%rdi)
	retq
.Lfunc_end0:
	.size	testAND64mr, .Lfunc_end0-testAND64mr
	.cfi_endproc
                                        # -- End function
	.globl	testAND32mi                     # -- Begin function testAND32mi
	.p2align	4, 0x90
	.type	testAND32mi,@function
testAND32mi:                            # @testAND32mi
	.cfi_startproc
# %bb.0:                                # %entry
	andl	$43947, (%rdi)                  # imm = 0xABAB
	retq
.Lfunc_end1:
	.size	testAND32mi, .Lfunc_end1-testAND32mi
	.cfi_endproc
                                        # -- End function
	.globl	testAND32mr                     # -- Begin function testAND32mr
	.p2align	4, 0x90
	.type	testAND32mr,@function
testAND32mr:                            # @testAND32mr
	.cfi_startproc
# %bb.0:                                # %entry
	andl	%esi, (%rdi)
	retq
.Lfunc_end2:
	.size	testAND32mr, .Lfunc_end2-testAND32mr
	.cfi_endproc
                                        # -- End function
	.globl	testAND16mi                     # -- Begin function testAND16mi
	.p2align	4, 0x90
	.type	testAND16mi,@function
testAND16mi:                            # @testAND16mi
	.cfi_startproc
# %bb.0:                                # %entry
	andw	$171, (%rdi)
	retq
.Lfunc_end3:
	.size	testAND16mi, .Lfunc_end3-testAND16mi
	.cfi_endproc
                                        # -- End function
	.globl	testAND16mr                     # -- Begin function testAND16mr
	.p2align	4, 0x90
	.type	testAND16mr,@function
testAND16mr:                            # @testAND16mr
	.cfi_startproc
# %bb.0:                                # %entry
	andw	%si, (%rdi)
	retq
.Lfunc_end4:
	.size	testAND16mr, .Lfunc_end4-testAND16mr
	.cfi_endproc
                                        # -- End function
	.globl	testAND8mi                      # -- Begin function testAND8mi
	.p2align	4, 0x90
	.type	testAND8mi,@function
testAND8mi:                             # @testAND8mi
	.cfi_startproc
# %bb.0:                                # %entry
	andb	$11, (%rdi)
	retq
.Lfunc_end5:
	.size	testAND8mi, .Lfunc_end5-testAND8mi
	.cfi_endproc
                                        # -- End function
	.globl	testAND8mr                      # -- Begin function testAND8mr
	.p2align	4, 0x90
	.type	testAND8mr,@function
testAND8mr:                             # @testAND8mr
	.cfi_startproc
# %bb.0:                                # %entry
	andb	%sil, (%rdi)
	retq
.Lfunc_end6:
	.size	testAND8mr, .Lfunc_end6-testAND8mr
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
	movl	$3, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$3, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$3, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str.1, %edi
	movl	$3, %esi
	xorl	%eax, %eax
	callq	printf
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end7:
	.size	main, .Lfunc_end7-main
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
