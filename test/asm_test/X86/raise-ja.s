# RUN: clang -o %t %s
# RUN: llvm-mctoll -d %t
# RUN: clang -o %t-dis %t-dis.ll
# RUN: %t-dis 2>&1 | FileCheck %s
# CHECK: call funcion 15

#
# This test will produce the mi as follows:
#   JCC_1 11, 7, <0x55da748a5948>, implicit $eflags
#

        .text
        .file	"test-jcc-7.c"
        .globl	call_func               # -- Begin function call_func
        .p2align	4, 0x90
        .type	call_func,@function
call_func:                              # @call_func
        .cfi_startproc
# %bb.0:                                # %entry
        pushq	%rbp
        .cfi_def_cfa_offset 16
        .cfi_offset %rbp, -16
        movq	%rsp, %rbp
        .cfi_def_cfa_register %rbp
        movl	%edi, -4(%rbp)
        cmpl	$0, -4(%rbp)
        ja 	.LBB0_2
# %bb.1:                                # %if.then
        movl	-4(%rbp), %eax
        addl	$5, %eax
        movl	%eax, -4(%rbp)
        jmp	.LBB0_3
.LBB0_2:                                # %if.else
        movl	-4(%rbp), %eax
        addl	$2, %eax
        movl	%eax, -4(%rbp)
.LBB0_3:                                # %if.end
        movl	-4(%rbp), %eax
        addl	$10, %eax
        popq	%rbp
        .cfi_def_cfa %rsp, 8
        retq
.Lfunc_end0:
        .size	call_func, .Lfunc_end0-call_func
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
        movl	$0, -12(%rbp)
        movl	$3, -8(%rbp)
        movl	-8(%rbp), %edi
        callq	call_func
        movl	%eax, -4(%rbp)
        movl	-4(%rbp), %esi
        movabsq	$.L.str, %rdi
        movb	$0, %al
        callq	printf
        xorl	%eax, %eax
        addq	$16, %rsp
        popq	%rbp
        .cfi_def_cfa %rsp, 8
        retq
.Lfunc_end1:
        .size	main, .Lfunc_end1-main
        .cfi_endproc
                                        # -- End function
        .type	.L.str,@object          # @.str
        .section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
        .asciz	"call funcion %d\n"
        .size	.L.str, 17
