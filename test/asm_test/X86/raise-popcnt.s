// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 4
// CHECK: 8
// CHECK: 12

	.text
	.file	"raise-popcnt.s"
	.globl	_Z14countSetBits16s             # -- Begin function _Z14countSetBits16s
	.p2align	4, 0x90
	.type	_Z14countSetBits16s,@function
_Z14countSetBits16s:                    # @_Z14countSetBits16s
	.cfi_startproc
# %bb.0:                                # %entry
	popcntw	%di, %ax
	retq
.Lfunc_end0:
	.size	_Z14countSetBits16s, .Lfunc_end0-_Z14countSetBits16s
	.cfi_endproc
                                        # -- End function
	.globl	_Z14countSetBits32i             # -- Begin function _Z14countSetBits32i
	.p2align	4, 0x90
	.type	_Z14countSetBits32i,@function
_Z14countSetBits32i:                    # @_Z14countSetBits32i
	.cfi_startproc
# %bb.0:                                # %entry
	popcntl	%edi, %eax
	retq
.Lfunc_end1:
	.size	_Z14countSetBits32i, .Lfunc_end1-_Z14countSetBits32i
	.cfi_endproc
                                        # -- End function
	.globl	_Z14countSetBits64m             # -- Begin function _Z14countSetBits64m
	.p2align	4, 0x90
	.type	_Z14countSetBits64m,@function
_Z14countSetBits64m:                    # @_Z14countSetBits64m
	.cfi_startproc
# %bb.0:                                # %entry
	popcntq	%rdi, %rax
	retq
.Lfunc_end2:
	.size	_Z14countSetBits64m, .Lfunc_end2-_Z14countSetBits64m
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
	movl	$15, %edi
	callq	_Z14countSetBits16s
	movswl	%ax, %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	movl	$255, %edi
	callq	_Z14countSetBits32i
	movl	$.L.str, %edi
	movl	%eax, %esi
	xorl	%eax, %eax
	callq	printf
	movl	$4095, %edi                     # imm = 0xFFF
	callq	_Z14countSetBits64m
	movl	$.L.str, %edi
	movq	%rax, %rsi
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

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
