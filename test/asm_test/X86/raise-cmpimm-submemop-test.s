# REQUIRES: x86_64-linux
# RUN: clang -o %t %s
# RUN: llvm-mctoll -d %t
# RUN: clang -o %t-dis %t-dis.ll
# RUN: %t-dis 2>&1 | FileCheck %s
# CHECK: val : 2

	.text
	.file	"cmp.c"
	.globl	my_printf               # -- Begin function my_printf
	.p2align	4, 0x90
	.type	my_printf,@function
my_printf:                              # @my_printf
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movl	-4(%rbp), %esi
	movabsq	$.L.str, %rdi
	movb	$0, %al
	callq	printf
	addq	$16, %rsp
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end0:
	.size	my_printf, .Lfunc_end0-my_printf
	.cfi_endproc
                                        # -- End function
	.globl	call_me                 # -- Begin function call_me
	.p2align	4, 0x90
	.type	call_me,@function
call_me:                                # @call_me
	.cfi_startproc
# %bb.0:                                # %entry
	movl	$4, -4(%rbp)
	movl	$2, %edi
	subl	%edi, -4(%rbp)
	movl	$65535, %eax
	cmpl	$65535, %eax
	ja	.LBB1_2
# %bb.1:                                # %if.then
	movl	-4(%rbp), %edi
	callq	my_printf
.LBB1_2:                                # %if.end
	retq
.Lfunc_end1:
	.size	call_me, .Lfunc_end1-call_me
	.cfi_endproc
                                        # -- End function
	.globl	main                    # -- Begin function main
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
	movl	$5, %edi
	callq	call_me
	xorl	%eax, %eax
	addq	$16, %rsp
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end2:
	.size	main, .Lfunc_end2-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"val : %d\n"
	.size	.L.str, 10


	.ident	"clang version 9.0.0 (https://github.com/llvm-mirror/clang.git 28f597c2ef2338dcae6d3aa47c73639eec99afd9) (https://github.com/llvm-mirror/llvm.git 2ec48fc90d9daa2dae46cfeee465be33299fed65)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym my_printf
	.addrsig_sym printf
	.addrsig_sym call_me
