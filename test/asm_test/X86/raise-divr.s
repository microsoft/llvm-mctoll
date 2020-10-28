# REQUIRES: x86_64-linux
# RUN: clang -o %t %s
# RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
# RUN: clang -o %t-dis %t-dis.ll
# RUN: %t-dis 2>&1 | FileCheck %s
# CHECK: Value 3

	.text
	.file	"divr.c"
	.globl	call_me                 # -- Begin function call_me
	.p2align	4, 0x90
	.type	call_me,@function
call_me:                                # @call_me
	.cfi_startproc
# %bb.0:                                # %entry
	movl	%edi, %eax
	cltd
	div	%ecx
	movl	$.L.str, %edi
	movl	%eax, %esi
	xorl	%eax, %eax
	jmp	printf                  # TAILCALL
.Lfunc_end0:
	.size	call_me, .Lfunc_end0-call_me
	.cfi_endproc
                                        # -- End function
	.globl	main                    # -- Begin function main
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
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end1:
	.size	main, .Lfunc_end1-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Value %d\n"
	.size	.L.str, 10
