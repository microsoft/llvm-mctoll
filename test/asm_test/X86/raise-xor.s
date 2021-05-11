// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 10
// CHECK-NEXT: 10
// CHECK-NEXT: 1290
// CHECK-EMPTY:

	.text
	.file	"raise-xor.s"
	.globl	testXOR32mi                     # -- Begin function testXOR32mi
	.p2align	4, 0x90
	.type	testXOR32mi,@function
testXOR32mi:                            # @testXOR32mi
	.cfi_startproc
# %bb.0:                                # %entry
	xorl	$64250, (%rdi)                  # imm = 0xFAFA
	retq
.Lfunc_end0:
	.size	testXOR32mi, .Lfunc_end0-testXOR32mi
	.cfi_endproc
                                        # -- End function
	.globl	testXOR32mr                     # -- Begin function testXOR32mr
	.p2align	4, 0x90
	.type	testXOR32mr,@function
testXOR32mr:                            # @testXOR32mr
	.cfi_startproc
# %bb.0:                                # %entry
	xorl	%esi, (%rdi)
	retq
.Lfunc_end1:
	.size	testXOR32mr, .Lfunc_end1-testXOR32mr
	.cfi_endproc
                                        # -- End function
	.globl	testXOR16mi                     # -- Begin function testXOR16mi
	.p2align	4, 0x90
	.type	testXOR16mi,@function
testXOR16mi:                            # @testXOR16mi
	.cfi_startproc
# %bb.0:                                # %entry
	xorw	$-6, (%rdi)
	retq
.Lfunc_end2:
	.size	testXOR16mi, .Lfunc_end2-testXOR16mi
	.cfi_endproc
                                        # -- End function
	.globl	testXOR16mr                     # -- Begin function testXOR16mr
	.p2align	4, 0x90
	.type	testXOR16mr,@function
testXOR16mr:                            # @testXOR16mr
	.cfi_startproc
# %bb.0:                                # %entry
	xorw	%si, (%rdi)
	retq
.Lfunc_end3:
	.size	testXOR16mr, .Lfunc_end3-testXOR16mr
	.cfi_endproc
                                        # -- End function
	.globl	testXOR8mi                      # -- Begin function testXOR8mi
	.p2align	4, 0x90
	.type	testXOR8mi,@function
testXOR8mi:                             # @testXOR8mi
	.cfi_startproc
# %bb.0:                                # %entry
	xorb	$10, (%rdi)
	retq
.Lfunc_end4:
	.size	testXOR8mi, .Lfunc_end4-testXOR8mi
	.cfi_endproc
                                        # -- End function
	.globl	testXOR8mr                      # -- Begin function testXOR8mr
	.p2align	4, 0x90
	.type	testXOR8mr,@function
testXOR8mr:                             # @testXOR8mr
	.cfi_startproc
# %bb.0:                                # %entry
	xorb	%sil, (%rdi)
	retq
.Lfunc_end5:
	.size	testXOR8mr, .Lfunc_end5-testXOR8mr
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
	movl	$10, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$10, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$.L.str, %edi
	movl	$1290, %esi                     # imm = 0x50A
	xorl	%eax, %eax
	callq	printf
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end6:
	.size	main, .Lfunc_end6-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%u\n"
	.size	.L.str, 4

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
