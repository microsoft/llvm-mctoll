// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 2


// Test for correct raising of the cmovs instruction.
// The cmovs conditional move if sign check the state of SF.
// If SF=1 then condition is satisfied, otherwise it will be skipped.
// https://wiki.cheatengine.org/index.php?title=Assembler:Commands:CMOVS
// This code snippet was extracted from adpcm_c in the MiBench benchmark suite.
	.text
	.file	"raise-cmovs.s"
	.globl	adpcm_decoder                   # -- Begin function adpcm_decoder
	.p2align	4, 0x90
	.type	adpcm_decoder,@function
adpcm_decoder:                          # @adpcm_decoder
	.cfi_startproc
# %bb.0:                                # %entry
	movsbl	2(%rsi), %eax
	movzbl	(%rdi), %ecx
	shrq	$2, %rcx
	andl	$60, %ecx
	xorl	%edx, %edx
	addl	indexTable(%rcx), %eax
	cmovsl	%edx, %eax
	cmpl	$88, %eax
	movl	$88, %ecx
	cmovll	%eax, %ecx
	movb	%cl, 2(%rsi)
	retq
.Lfunc_end0:
	.size	adpcm_decoder, .Lfunc_end0-adpcm_decoder
	.cfi_endproc
                                        # -- End function
	.globl	main                            # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbx
	.cfi_def_cfa_offset 16
	subq	$48, %rsp
	.cfi_def_cfa_offset 64
	.cfi_offset %rbx, -16
	movabsq	$2851464966991703, %rax         # imm = 0xA21646C726F57
	movq	%rax, 38(%rsp)
	movabsq	$8022916924116329800, %rax      # imm = 0x6F57206F6C6C6548
	movq	%rax, 32(%rsp)
	movl	$0, 12(%rsp)
	leaq	32(%rsp), %rdi
	movq	%rdi, 24(%rsp)
	#APP
	#NO_APP
	leaq	12(%rsp), %rbx
	movq	%rbx, %rsi
	callq	adpcm_decoder
	movq	%rbx, 16(%rsp)
	#APP
	#NO_APP
	movsbl	14(%rsp), %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	xorl	%eax, %eax
	addq	$48, %rsp
	.cfi_def_cfa_offset 16
	popq	%rbx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end1:
	.size	main, .Lfunc_end1-main
	.cfi_endproc
                                        # -- End function
	.type	indexTable,@object              # @indexTable
	.section	.rodata,"a",@progbits
	.p2align	4
indexTable:
	.long	4294967295                      # 0xffffffff
	.long	4294967295                      # 0xffffffff
	.long	4294967295                      # 0xffffffff
	.long	4294967295                      # 0xffffffff
	.long	2                               # 0x2
	.long	4                               # 0x4
	.long	6                               # 0x6
	.long	8                               # 0x8
	.long	4294967295                      # 0xffffffff
	.long	4294967295                      # 0xffffffff
	.long	4294967295                      # 0xffffffff
	.long	4294967295                      # 0xffffffff
	.long	2                               # 0x2
	.long	4                               # 0x4
	.long	6                               # 0x6
	.long	8                               # 0x8
	.size	indexTable, 64

	.type	.L__const.main.indata,@object   # @__const.main.indata
	.section	.rodata.str1.1,"aMS",@progbits,1
.L__const.main.indata:
	.asciz	"Hello World!\n"
	.size	.L__const.main.indata, 14

	.type	.L.str,@object                  # @.str
.L.str:
	.asciz	"%d\n"
	.size	.L.str, 4

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git 28d31320894cc5c1c2ce358c5beeb9fe99abab09)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
