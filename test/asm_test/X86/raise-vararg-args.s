// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: Swapping 1 and 8
// CHECK: Swapping 2 and 7
// CHECK: Swapping 3 and 6
// CHECK: Swapping 4 and 5
// CHECK-EMPTY

	.text
	.intel_syntax noprefix
	.file	"discover-varargs.s"

// swap_bytes function adapted from
// https://github.com/kozyraki/phoenix/blob/master/phoenix-2.0/tests/histogram/histogram-seq.c#L70
	.globl	swap_bytes              # -- Begin function swap_bytes
	.p2align	4, 0x90
	.type	swap_bytes,@function
swap_bytes:                             # @swap_bytes
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 32
	mov	qword ptr [rbp - 8], rdi
	mov	dword ptr [rbp - 12], esi
	mov	dword ptr [rbp - 16], 0
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
	mov	eax, dword ptr [rbp - 16]
	mov	ecx, dword ptr [rbp - 12]
	mov	dword ptr [rbp - 24], eax # 4-byte Spill
	mov	eax, ecx
	cdq
	mov	ecx, 2
	idiv	ecx
	mov	ecx, dword ptr [rbp - 24] # 4-byte Reload
	cmp	ecx, eax
	jge	.LBB0_4
# %bb.2:                                #   in Loop: Header=BB0_1 Depth=1
	mov	rax, qword ptr [rbp - 8]
	movsxd	rcx, dword ptr [rbp - 16]
	movsx	esi, byte ptr [rax + rcx]
	mov	rax, qword ptr [rbp - 8]
	mov	edx, dword ptr [rbp - 12]
	sub	edx, dword ptr [rbp - 16]
	sub	edx, 1
	movsxd	rcx, edx
	movsx	edx, byte ptr [rax + rcx]
	movabs	rdi, offset .L.str
	mov	al, 0
	call	printf
	mov	rcx, qword ptr [rbp - 8]
	movsxd	rdi, dword ptr [rbp - 16]
	mov	r8b, byte ptr [rcx + rdi]
	mov	byte ptr [rbp - 17], r8b
	mov	rcx, qword ptr [rbp - 8]
	mov	edx, dword ptr [rbp - 12]
	sub	edx, dword ptr [rbp - 16]
	sub	edx, 1
	movsxd	rdi, edx
	mov	r8b, byte ptr [rcx + rdi]
	mov	rcx, qword ptr [rbp - 8]
	movsxd	rdi, dword ptr [rbp - 16]
	mov	byte ptr [rcx + rdi], r8b
	mov	r8b, byte ptr [rbp - 17]
	mov	rcx, qword ptr [rbp - 8]
	mov	edx, dword ptr [rbp - 12]
	sub	edx, dword ptr [rbp - 16]
	sub	edx, 1
	movsxd	rdi, edx
	mov	byte ptr [rcx + rdi], r8b
	mov	dword ptr [rbp - 28], eax # 4-byte Spill
# %bb.3:                                #   in Loop: Header=BB0_1 Depth=1
	mov	eax, dword ptr [rbp - 16]
	add	eax, 1
	mov	dword ptr [rbp - 16], eax
	jmp	.LBB0_1
.LBB0_4:
	add	rsp, 32
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end0:
	.size	swap_bytes, .Lfunc_end0-swap_bytes
	.cfi_endproc
                                        # -- End function
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset rbp, -16
	mov	rbp, rsp
	.cfi_def_cfa_register rbp
	sub	rsp, 16
	lea	rdi, [rbp - 8]
	mov	rax, qword ptr [.Lmain.buf]
	mov	qword ptr [rbp - 8], rax
	mov	esi, 8
	call	swap_bytes
	xor	eax, eax
	add	rsp, 16
	pop	rbp
	.cfi_def_cfa rsp, 8
	ret
.Lfunc_end1:
	.size	main, .Lfunc_end1-main
	.cfi_endproc
                                        # -- End function
	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Swapping %d and %d\n"
	.size	.L.str, 20

	.type	.Lmain.buf,@object      # @main.buf
	.section	.rodata.cst8,"aM",@progbits,8
.Lmain.buf:
	.ascii	"\001\002\003\004\005\006\007\b"
	.size	.Lmain.buf, 8


	.ident	"clang version 7.0.1-8+deb10u2 (tags/RELEASE_701/final)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym swap_bytes
	.addrsig_sym printf
	.addrsig_sym main
