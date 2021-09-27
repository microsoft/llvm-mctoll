// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1.0
// CHECK-NEXT: 1.0
// CHECK-NEXT: 1.0
// CHECK-NEXT: 0.0
// CHECK-NEXT: 0.0
// CHECK-NEXT: 0.0
// CHECK-NEXT: 1.0
// CHECK-NEXT: 1.0
// CHECK-NEXT: 1.0
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-xorps-xorpd.s"

.p2align    4, 0x90
.type    test_xorp_zero,@function
test_xorp_zero:
    xorps xmm0, xmm0
    cvtss2sd xmm0, xmm0
    mov al, 1
    mov rdi, offset .L.str
    call printf
    xorpd xmm1, xmm1
    movapd xmm0, xmm1
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.p2align    4, 0x90
.type    test_pxor,@function
test_pxor:
    pxor xmm0, xmm1
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.p2align    4, 0x90
.type    test_pxor_zero,@function
test_pxor_zero:
    pxor xmm0, xmm0
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.p2align    4, 0x90
.type    test_xorps,@function
test_xorps:
    xorps xmm0, xmm1
    cvtss2sd xmm0, xmm0
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.p2align    4, 0x90
.type    test_xorpd,@function
test_xorpd:
    xorpd xmm0, xmm1
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

# memory referencing

.p2align    4, 0x90
.type    test_pxor_mem,@function
test_pxor_mem:
    pxor xmm0, [.L.val.4]
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.p2align    4, 0x90
.type    test_xorps_mem,@function
test_xorps_mem:
    xorps xmm0, [.L.val.5]
    cvtss2sd xmm0, xmm0
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.p2align    4, 0x90
.type    test_xorpd_mem,@function
test_xorpd_mem:
    xorpd xmm0, [.L.val.4]
    mov al, 1
    mov rdi, offset .L.str
    call printf
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val.1]
    call test_pxor

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val.1]
    call test_xorpd

    movss xmm0, [.L.val.2]
    movss xmm1, [.L.val.3]
    call test_xorps

    movsd xmm0, [.L.val]
    movss xmm1, [.L.val.2]
    call test_xorp_zero

    movsd xmm0, [.L.val]
    call test_pxor_zero

    movsd xmm0, [.L.val]
    call test_pxor_mem

    movsd xmm0, [.L.val]
    call test_xorpd_mem

    movss xmm0, [.L.val.2]
    call test_xorps_mem

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
.L.val.1:
    .quad 0x0008000000000000 # used to flip single bit in .L.val
.L.val.2:
    .long 0x3fc00000 # float 1.5
.L.val.3:
    .long 0x400000 # used to flip single bit in .L.val.2
.section    .rodata.cst16,"aM",@progbits,16
.align 16
.L.val.4:
    .quad 0x0008000000000000 # used to flip single bit in .L.val
    .quad 0x0000000000000000 # padding
.L.val.5:
    .quad 0x0000000000400000 # used to flip single bit in .L.val.4
    .quad 0x0000000000000000 # padding
