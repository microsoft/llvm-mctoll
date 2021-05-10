// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 15
// CHECK-NEXT: 175
// CHECK-NEXT: 34959
// CHECK-NEXT: 15
// CHECK-EMPTY:

	.text
	.file	"raise-or.s"
	.globl	testOR64mr                      # -- Begin function testOR64mr
	.p2align	4, 0x90
	.type	testOR64mr,@function
testOR64mr:                             # @testOR64mr
	.cfi_startproc
# %bb.0:                                # %entry
	orq	%rsi, (%rdi)
	retq
.Lfunc_end0:
	.size	testOR64mr, .Lfunc_end0-testOR64mr
	.cfi_endproc
                                        # -- End function
	.globl	testOR32mi                      # -- Begin function testOR32mi
	.p2align	4, 0x90
	.type	testOR32mi,@function
testOR32mi:                             # @testOR32mi
	.cfi_startproc
# %bb.0:                                # %entry
	orl	$34952, (%rdi)                  # imm = 0x8888
	retq
.Lfunc_end1:
	.size	testOR32mi, .Lfunc_end1-testOR32mi
	.cfi_endproc
                                        # -- End function
	.globl	testOR32mr                      # -- Begin function testOR32mr
	.p2align	4, 0x90
	.type	testOR32mr,@function
testOR32mr:                             # @testOR32mr
	.cfi_startproc
# %bb.0:                                # %entry
	orl	%esi, (%rdi)
	retq
.Lfunc_end2:
	.size	testOR32mr, .Lfunc_end2-testOR32mr
	.cfi_endproc
                                        # -- End function
	.globl	testOR16mi                      # -- Begin function testOR16mi
	.p2align	4, 0x90
	.type	testOR16mi,@function
testOR16mi:                             # @testOR16mi
	.cfi_startproc
# %bb.0:                                # %entry
	orw	$-88, (%rdi)
	retq
.Lfunc_end3:
	.size	testOR16mi, .Lfunc_end3-testOR16mi
	.cfi_endproc
                                        # -- End function
	.globl	testOR16mr                      # -- Begin function testOR16mr
	.p2align	4, 0x90
	.type	testOR16mr,@function
testOR16mr:                             # @testOR16mr
	.cfi_startproc
# %bb.0:                                # %entry
	orw	%si, (%rdi)
	retq
.Lfunc_end4:
	.size	testOR16mr, .Lfunc_end4-testOR16mr
	.cfi_endproc
                                        # -- End function
	.globl	testOR8mi                       # -- Begin function testOR8mi
	.p2align	4, 0x90
	.type	testOR8mi,@function
testOR8mi:                              # @testOR8mi
	.cfi_startproc
# %bb.0:                                # %entry
	orb	$11, (%rdi)
	retq
.Lfunc_end5:
	.size	testOR8mi, .Lfunc_end5-testOR8mi
	.cfi_endproc
                                        # -- End function
	.globl	testOR8mr                       # -- Begin function testOR8mr
	.p2align	4, 0x90
	.type	testOR8mr,@function
testOR8mr:                              # @testOR8mr
	.cfi_startproc
# %bb.0:                                # %entry
	orb	%sil, (%rdi)
	retq
.Lfunc_end6:
	.size	testOR8mr, .Lfunc_end6-testOR8mr
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
	movl	$15, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$175, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$34959, %esi                    # imm = 0x888F
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str.1, %edi
	movl	$15, %esi
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
