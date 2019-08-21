// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// RUN: FileCheck --input-file=%t-dis.ll --check-prefix=CHECK_LL %s
// CHECK: ret val: 5
// CHECK_LL:  %0 = trunc i32 %arg1 to i16
// CHECK_LL:  %1 = trunc i32 %arg1 to i16
// CHECK_LL:  %2 = and i16 %0, %1


// Test for TEST16rr instruction raising.
// Make sure the physical register size and type match.

// Without the changes, the testw instruction is raised as
// %0 = and i32 %arg1, %arg1

// With the changes, it is correctly raised as
// %0 = trunc i32 %arg1 to i16
// %1 = trunc i32 %arg1 to i16
// %2 = and i16 %0, %1


	.text
	.file	"argument.c"
	.globl	call_me                 # -- Begin function call_me
	.p2align	4, 0x90
	.type	call_me,@function
call_me:                                # @call_me
	.cfi_startproc
# %bb.0:                                # %entry
	movl	%edi, %eax
    testw	%ax, %ax
	subl	%esi, %eax
	retq
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
	movl	$4, %edi
	movl	$-1, %esi
	callq	call_me
	movl	$.L.str, %edi
	movl	%eax, %esi
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
	.asciz	"ret val: %d\n"
	.size	.L.str, 13


	.ident	"clang version 9.0.0 (https://github.com/llvm-mirror/clang.git 884b0b4b1912d272bdf140a63b7d779c785ce7c1) (https://github.com/llvm-mirror/llvm.git dabd4d53f4e2ae51e4ff71501075f0896863178b)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
