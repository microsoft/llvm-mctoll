// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: -1
// CHECK-EMPTY:

	.text
	.file	"raise-setnp.s"
	.globl	compare                         # -- Begin function compare
	.p2align	4, 0x90
	.type	compare,@function
compare:                                # @compare
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	movss	%xmm0, -4(%rbp)
	movss	%xmm1, -8(%rbp)
	movss	-4(%rbp), %xmm0                 # xmm0 = mem[0],zero,zero,zero
	ucomiss	-8(%rbp), %xmm0
	jbe	.LBB0_2
# %bb.1:                                # %cond.true
	movl	$1, %eax
	movl	%eax, -12(%rbp)                 # 4-byte Spill
	jmp	.LBB0_3
.LBB0_2:                                # %cond.false
	movss	-4(%rbp), %xmm0                 # xmm0 = mem[0],zero,zero,zero
	movss	-8(%rbp), %xmm1                 # xmm1 = mem[0],zero,zero,zero
	movl	$4294967295, %eax               # imm = 0xFFFFFFFF
	xorl	%ecx, %ecx
	ucomiss	%xmm1, %xmm0
	setnp	%sil
	sete	%dl
	testb	%sil, %dl
	cmovnel	%ecx, %eax
	movl	%eax, -12(%rbp)                 # 4-byte Spill
.LBB0_3:                                # %cond.end
	movl	-12(%rbp), %eax                 # 4-byte Reload
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end0:
	.size	compare, .Lfunc_end0-compare
	.cfi_endproc
                                        # -- End function
	.section	.rodata.cst4,"aM",@progbits,4
	.p2align	2                               # -- Begin function main
.LCPI1_0:
	.long	0x402e147b                      # float 2.72000003
.LCPI1_1:
	.long	0x4048f5c3                      # float 3.1400001
	.text
	.globl	main
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
	movss	.LCPI1_0(%rip), %xmm0           # xmm0 = mem[0],zero,zero,zero
	movss	.LCPI1_1(%rip), %xmm1           # xmm1 = mem[0],zero,zero,zero
	callq	compare
	movl	%eax, %esi
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
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%d\n"
	.size	.L.str, 4

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git 26d72bd93a01c2fb831e469b715bf223b0a24e8f)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym compare
	.addrsig_sym printf
