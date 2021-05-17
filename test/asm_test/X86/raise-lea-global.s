// REQUIRES: system-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: 31
// CHECK-EMPTY:
  
  .text
	.file	"raise-lea-global.s"
	.globl	leaGlobal                       # -- Begin function leaGlobal
	.p2align	4, 0x90
	.type	leaGlobal,@function
leaGlobal:                              # @leaGlobal
	.cfi_startproc
# %bb.0:                                # %entry
	movq	gval(%rip), %rax
	leaq	15(,%rax,8), %rax
	retq
.Lfunc_end0:
	.size	leaGlobal, .Lfunc_end0-leaGlobal
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
	movq	$2, gval(%rip)
	callq	leaGlobal
	movl	$.L.str, %edi
	movq	%rax, %rsi
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
	.type	gval,@object                    # @gval
	.bss
	.globl	gval
	.p2align	3
gval:
	.quad	0                               # 0x0
	.size	gval, 8

	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%d\n"
	.size	.L.str, 4

	.ident	"clang version 13.0.0 (https://github.com/llvm/llvm-project.git f5ba3eea6746559513af7ed32db8083ad52661a3)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
