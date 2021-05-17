// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Global: 12
// CHECK-NEXT: Combined: 17
// CHECK-NEXT: Global: 17
// CHECK-NEXT: Global: 7
// CHECK-EMPTY:

	.text
	.file	"raise-basic-globals.s"
	.globl	readGInt                        # -- Begin function readGInt
	.p2align	4, 0x90
	.type	readGInt,@function
readGInt:                               # @readGInt
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	gvar, %esi
	movabsq	$.L.str, %rdi
	movb	$0, %al
	callq	printf
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end0:
	.size	readGInt, .Lfunc_end0-readGInt
	.cfi_endproc
                                        # -- End function
	.globl	updateGInt                      # -- Begin function updateGInt
	.p2align	4, 0x90
	.type	updateGInt,@function
updateGInt:                             # @updateGInt
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
	movl	-4(%rbp), %eax
	addl	gvar, %eax
	movl	%eax, gvar
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end1:
	.size	updateGInt, .Lfunc_end1-updateGInt
	.cfi_endproc
                                        # -- End function
	.globl	combinedTest                    # -- Begin function combinedTest
	.p2align	4, 0x90
	.type	combinedTest,@function
combinedTest:                           # @combinedTest
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	movl	-4(%rbp), %eax
	addl	gvar, %eax
	movl	%eax, gvar
	movl	-8(%rbp), %eax
	addl	gvar, %eax
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end2:
	.size	combinedTest, .Lfunc_end2-combinedTest
	.cfi_endproc
                                        # -- End function
	.globl	readGPtr                        # -- Begin function readGPtr
	.p2align	4, 0x90
	.type	readGPtr,@function
readGPtr:                               # @readGPtr
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movq	gptr, %rax
	movl	(%rax), %esi
	movabsq	$.L.str, %rdi
	movb	$0, %al
	callq	printf
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end3:
	.size	readGPtr, .Lfunc_end3-readGPtr
	.cfi_endproc
                                        # -- End function
	.globl	updateGPtr                      # -- Begin function updateGPtr
	.p2align	4, 0x90
	.type	updateGPtr,@function
updateGPtr:                             # @updateGPtr
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
	movl	-4(%rbp), %ecx
	movq	gptr, %rax
	addl	(%rax), %ecx
	movl	%ecx, (%rax)
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end4:
	.size	updateGPtr, .Lfunc_end4-updateGPtr
	.cfi_endproc
                                        # -- End function
	.globl	readGArray                      # -- Begin function readGArray
	.p2align	4, 0x90
	.type	readGArray,@function
readGArray:                             # @readGArray
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	Arr, %esi
	movabsq	$.L.str, %rdi
	movb	$0, %al
	callq	printf
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end5:
	.size	readGArray, .Lfunc_end5-readGArray
	.cfi_endproc
                                        # -- End function
	.globl	updateGArray                    # -- Begin function updateGArray
	.p2align	4, 0x90
	.type	updateGArray,@function
updateGArray:                           # @updateGArray
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movl	%edi, -4(%rbp)
	movl	-4(%rbp), %eax
	addl	Arr, %eax
	movl	%eax, Arr
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end6:
	.size	updateGArray, .Lfunc_end6-updateGArray
	.cfi_endproc
                                        # -- End function
	.globl	main                            # -- Begin function main
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
	movl	$0, -4(%rbp)
	movl	$15, -8(%rbp)
	movl	$2, %edi
	callq	updateGInt
	callq	readGInt
	movl	$2, %edi
	movl	$3, %esi
	callq	combinedTest
	movl	%eax, %esi
	movabsq	$.L.str.1, %rdi
	movb	$0, %al
	callq	printf
	leaq	-8(%rbp), %rax
	movq	%rax, gptr
	movl	$2, %edi
	callq	updateGPtr
	callq	readGPtr
	movl	$5, Arr
	movl	$2, %edi
	callq	updateGArray
	callq	readGArray
	xorl	%eax, %eax
	addq	$16, %rsp
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end7:
	.size	main, .Lfunc_end7-main
	.cfi_endproc
                                        # -- End function
	.type	gvar,@object                    # @gvar
	.data
	.globl	gvar
	.p2align	2
gvar:
	.long	10                              # 0xa
	.size	gvar, 4

	.type	gptr,@object                    # @gptr
	.bss
	.globl	gptr
	.p2align	3
gptr:
	.quad	0
	.size	gptr, 8

	.type	Arr,@object                     # @Arr
	.data
	.globl	Arr
	.p2align	4
Arr:
	.long	0                               # 0x0
	.long	1                               # 0x1
	.long	2                               # 0x2
	.long	3                               # 0x3
	.size	Arr, 16

	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Global: %d\n"
	.size	.L.str, 12

	.type	.L.str.1,@object                # @.str.1
.L.str.1:
	.asciz	"Combined: %d\n"
	.size	.L.str.1, 14

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym readGInt
	.addrsig_sym printf
	.addrsig_sym updateGInt
	.addrsig_sym combinedTest
	.addrsig_sym readGPtr
	.addrsig_sym updateGPtr
	.addrsig_sym readGArray
	.addrsig_sym updateGArray
	.addrsig_sym gvar
	.addrsig_sym gptr
	.addrsig_sym Arr
