// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1.5
// CHECK-NEXT: 0.0
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-call64r-float.s"

.p2align    4, 0x90
.type    func1,@function
func1:
    # first parameter is in xmm0, move xmm0 to itself just so mctoll knows it is defined
	movaps xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    movsd xmm0, [.L.val]
    mov rax, OFFSET func1
    call rax

    xorps xmm0, xmm0
    mov rax, offset func1
    call rax

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%.1f\n"
    .size   .L.str, 6

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
