// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 2
// CHECK-NEXT: 5
// CHECK-NEXT: 10
// CHECK-EMPTY:


//Test raising sar instructions with implicit immediate operand
	.text
	.file	"raise-sar1.s"
	.globl	example8                        # -- Begin function example8
	.p2align	4, 0x90
	.type	example8,@function
example8:                               # @example8
	.cfi_startproc
# %bb.0:                                # %entry
	movl	%edi, %eax
	sarb	%al
                                        # kill: def $al killed $al killed $eax
	retq
.Lfunc_end0:
	.size	example8, .Lfunc_end0-example8
	.cfi_endproc
                                        # -- End function
	.globl	example16                       # -- Begin function example16
	.p2align	4, 0x90
	.type	example16,@function
example16:                              # @example16
	.cfi_startproc
# %bb.0:                                # %entry
	movl	%edi, %eax
	sarw	%ax
                                        # kill: def $ax killed $ax killed $eax
	retq
.Lfunc_end1:
	.size	example16, .Lfunc_end1-example16
	.cfi_endproc
                                        # -- End function
	.globl	example32                       # -- Begin function example32
	.p2align	4, 0x90
	.type	example32,@function
example32:                              # @example32
	.cfi_startproc
# %bb.0:                                # %entry
	movl	%edi, %eax
	sarl	%eax
	retq
.Lfunc_end2:
	.size	example32, .Lfunc_end2-example32
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
	movl	$5, %edi
	callq	example8
	movsbl	%al, %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	movl	$11, %edi
	callq	example16
	movswl	%ax, %esi
	movl	$.L.str.1, %edi
	xorl	%eax, %eax
	callq	printf
	movl	$21, %edi
	callq	example32
	movl	$.L.str, %edi
	movl	%eax, %esi
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
