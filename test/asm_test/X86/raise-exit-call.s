	
// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 0 2>&1 | FileCheck %s
// CHECK: End of function: 2
// CHECK-EMPTY:

  .text
	.file	"raise-exit-call.s"
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
	movl	%edi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movl	$0, var
	cmpl	$1, -8(%rbp)
	jg	.LBB0_2
# %bb.1:                                # %if.then
	xorl	%edi, %edi
	callq	exit
.LBB0_2:                                # %if.else
	movl	var, %eax
	addl	$1, %eax
	movl	%eax, var
# %bb.3:                                # %if.end
	movl	var, %eax
	addl	$1, %eax
	movl	%eax, var
	movl	var, %esi
	movabsq	$.L.str, %rdi
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
	.type	var,@object                     # @var
	.bss
	.globl	var
	.p2align	2
var:
	.long	0                               # 0x0
	.size	var, 4

	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"End of function: %d\n"
	.size	.L.str, 21

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym exit
	.addrsig_sym printf
	.addrsig_sym var
