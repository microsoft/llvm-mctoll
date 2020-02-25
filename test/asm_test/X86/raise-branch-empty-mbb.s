# REQUIRES: x86_64-linux
# RUN: clang -o %t %s
# RUN: llvm-mctoll -d %t
# RUN: clang -o %t-dis %t-dis.ll
# RUN: %t-dis 2>&1 | FileCheck %s
# CHECK: Translation IR compiled successfully!

	.text
	.file	"mbb-empty.c"
	.globl	cmp_complex             # -- Begin function cmp_complex
	.p2align	4, 0x90
	.type	cmp_complex,@function
cmp_complex:                            # @cmp_complex
.Lcmp_complex$local:
	.cfi_startproc
# %bb.0:                                # %entry
	movl	$1, %eax
	retq
.Lfunc_end0:
	.size	cmp_complex, .Lfunc_end0-cmp_complex
	.cfi_endproc
                                        # -- End function
	.globl	list_mergesort     # -- Begin function list_mergesort
	.p2align	4, 0x90
	.type	list_mergesort,@function
list_mergesort:                    # @list_mergesort
.Llist_mergesort$local:
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$40, %rsp
	.cfi_def_cfa_offset 96
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rdx, 32(%rsp)          # 8-byte Spill
	movq	%rsi, %rbx
	movq	%rdi, %rax
	movl	$1, %r13d
	jmp	.LBB1_1
	.p2align	4, 0x90
.LBB1_26:                               # %while.end37
                                        #   in Loop: Header=BB1_1 Depth=1
	movq	$0, (%rbp)
	addl	%r13d, %r13d
	cmpl	$0, 16(%rsp)            # 4-byte Folded Reload
	movq	8(%rsp), %rax           # 8-byte Reload
	je	.LBB1_27
.LBB1_1:                                # %while.cond
                                        # =>This Loop Header: Depth=1
                                        #     Child Loop BB1_3 Depth 2
                                        #       Child Loop BB1_8 Depth 3
                                        #       Child Loop BB1_11 Depth 3
	movl	%r13d, %esi
	negl	%esi
	xorl	%ecx, %ecx
	xorl	%ebp, %ebp
	movq	%rax, %r15
	xorl	%eax, %eax
	movq	%rax, 8(%rsp)           # 8-byte Spill
	movl	%r13d, (%rsp)           # 4-byte Spill
	movq	%rsi, 24(%rsp)          # 8-byte Spill
	jmp	.LBB1_3
	.p2align	4, 0x90
.LBB1_2:                                # %while.cond1.loopexit
                                        #   in Loop: Header=BB1_3 Depth=2
	testq	%r15, %r15
	movl	(%rsp), %r13d           # 4-byte Reload
	movq	24(%rsp), %rsi          # 8-byte Reload
	movl	4(%rsp), %ecx           # 4-byte Reload
	je	.LBB1_26
.LBB1_3:                                # %while.body2
                                        #   Parent Loop BB1_1 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB1_8 Depth 3
                                        #       Child Loop BB1_11 Depth 3
	movl	%ecx, %edi
	testl	%r13d, %r13d
	jle	.LBB1_4
# %bb.7:                                # %for.body.preheader
                                        #   in Loop: Header=BB1_3 Depth=2
	movl	$1, %r12d
	movq	%r15, %rax
	.p2align	4, 0x90
.LBB1_8:                                # %for.body
                                        #   Parent Loop BB1_1 Depth=1
                                        #     Parent Loop BB1_3 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
	movq	(%rax), %rax
	testq	%rax, %rax
	je	.LBB1_9
# %bb.5:                                # %for.cond
                                        #   in Loop: Header=BB1_8 Depth=3
	leal	(%rsi,%r12), %ecx
	addl	$1, %ecx
	movl	%r12d, %edx
	addl	$1, %edx
	movl	%edx, %r12d
	cmpl	$1, %ecx
	jne	.LBB1_8
# %bb.6:                                #   in Loop: Header=BB1_3 Depth=2
	movl	%r13d, %r12d
	jmp	.LBB1_10
	.p2align	4, 0x90
.LBB1_4:                                #   in Loop: Header=BB1_3 Depth=2
	xorl	%r12d, %r12d
	movq	%r15, %rax
	jmp	.LBB1_10
	.p2align	4, 0x90
.LBB1_9:                                #   in Loop: Header=BB1_3 Depth=2
	xorl	%eax, %eax
.LBB1_10:                               # %while.cond7.preheader
                                        #   in Loop: Header=BB1_3 Depth=2
	movq	%rdi, %rcx
	movq	%rdi, 16(%rsp)          # 8-byte Spill
	leal	1(%rdi), %ecx
	movl	%ecx, 4(%rsp)           # 4-byte Spill
	movq	%r15, %rcx
	jmp	.LBB1_11
	.p2align	4, 0x90
.LBB1_24:                               #   in Loop: Header=BB1_11 Depth=3
	movq	%rdx, %rsi
	movq	%rdx, 8(%rsp)           # 8-byte Spill
	movq	%rdx, %rbp
.LBB1_11:                               # %while.cond7.outer
                                        #   Parent Loop BB1_1 Depth=1
                                        #     Parent Loop BB1_3 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
	movq	%rcx, %r14
	movq	%rax, %r15
	testl	%r12d, %r12d
	jg	.LBB1_17
	.p2align	4, 0x90
.LBB1_13:                               # %lor.rhs
                                        #   in Loop: Header=BB1_11 Depth=3
	testq	%r15, %r15
	je	.LBB1_2
# %bb.14:                               # %lor.rhs
                                        #   in Loop: Header=BB1_11 Depth=3
	testl	%r13d, %r13d
	jle	.LBB1_2
# %bb.15:                               # %while.body11
                                        #   in Loop: Header=BB1_11 Depth=3
	testl	%r12d, %r12d
	je	.LBB1_16
.LBB1_17:                               # %if.else
                                        #   in Loop: Header=BB1_11 Depth=3
	testq	%r15, %r15
	je	.LBB1_19
# %bb.18:                               # %if.else
                                        #   in Loop: Header=BB1_11 Depth=3
	testl	%r13d, %r13d
	je	.LBB1_19
# %bb.20:                               # %if.else20
                                        #   in Loop: Header=BB1_11 Depth=3
	movq	8(%r14), %rdi
	movq	8(%r15), %rsi
	movq	32(%rsp), %rdx          # 8-byte Reload
	callq	cmp_complex
	testl	%eax, %eax
	jle	.LBB1_19
# %bb.21:                               # %if.else26
                                        #   in Loop: Header=BB1_11 Depth=3
	movq	(%r15), %rax
	addl	$-1, %r13d
	jmp	.LBB1_22
	.p2align	4, 0x90
.LBB1_19:                               # %if.then17
                                        #   in Loop: Header=BB1_11 Depth=3
	movq	(%r14), %rcx
	addl	$-1, %r12d
	movq	%r15, %rax
	movq	%r14, %rdx
	testq	%rbp, %rbp
	jne	.LBB1_25
	jmp	.LBB1_24
	.p2align	4, 0x90
.LBB1_16:                               # %if.then13
                                        #   in Loop: Header=BB1_11 Depth=3
	movq	(%r15), %rax
	addl	$-1, %r13d
	xorl	%r12d, %r12d
.LBB1_22:                               # %if.end31
                                        #   in Loop: Header=BB1_11 Depth=3
	movq	%r14, %rcx
	movq	%r15, %rdx
	testq	%rbp, %rbp
	je	.LBB1_24
.LBB1_25:                               # %if.then33
                                        #   in Loop: Header=BB1_11 Depth=3
	movq	%rdx, (%rbp)
	movq	%rcx, %r14
	movq	%rax, %r15
	movq	%rdx, %rbp
	testl	%r12d, %r12d
	jg	.LBB1_17
	jmp	.LBB1_13
.LBB1_27:                               # %if.then40
	addq	$40, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end1:
	.size	list_mergesort, .Lfunc_end1-list_mergesort
	.cfi_endproc
                                        # -- End function
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
.Lmain$local:
	.cfi_startproc
# %bb.0:                                # %entry
	pushq	%rax
	.cfi_def_cfa_offset 16
	movl	$.Lstr, %edi
	callq	puts
	xorl	%eax, %eax
	popq	%rcx
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end2:
	.size	main, .Lfunc_end2-main
	.cfi_endproc
                                        # -- End function
	.type	.Lstr,@object           # @str
	.section	.rodata.str1.1,"aMS",@progbits,1
.Lstr:
	.asciz	"Translation IR compiled successfully!"
	.size	.Lstr, 36

	.ident	"clang version 11.0.0 (https://github.com/llvm/llvm-project b2e884bee7ef6e22881861c5b720fa9934d46ae9)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
