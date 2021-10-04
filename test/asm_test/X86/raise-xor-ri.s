// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 4 xor 1 = 5
// CHECK-NEXT: 2 xor 1 = 3
// CHECK-NEXT: 4 xor 100 = 104
// CHECK-NEXT: 2 xor 100 = 102
// CHECK-NEXT: 4 xor 1 = 5
// CHECK-NEXT: 2 xor 1 = 3
// CHECK-NEXT: 4 xor 1 = 5
// CHECK-NEXT: 2 xor 1 = 3
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-xor-ri.s"

.p2align    4, 0x90
.type    test_xor64ri8,@function
test_xor64ri8:
    mov rsi, rdi
    mov rcx, rdi
    mov edx, 1
    xor rcx, 1
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    test_xor64ri32,@function
test_xor64ri32:
    mov rsi, rdi
    mov rcx, rdi
    mov edx, 0x100
    xor rcx, 0x100
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    test_xor16ri8,@function
test_xor16ri8:
    movzx esi, di
    mov cx, di
    mov edx, 1
    xor cx, 1
    movzx edx, dx
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    ret

.p2align    4, 0x90
.type    test_xor8ri8,@function
test_xor8ri8:
    movzx esi, dil
    mov cl, dil
    mov edx, 1
    xor cl, 1
    movzx edx, dl
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    mov rdi, 4
    call test_xor64ri8

    mov rdi, 2
    call test_xor64ri8

    mov rdi, 4
    call test_xor64ri32

    mov rdi, 2
    call test_xor64ri32

    mov di, 4
    call test_xor16ri8

    mov di, 2
    call test_xor16ri8

    mov dil, 4
    call test_xor8ri8

    mov dil, 2
    call test_xor8ri8

    mov eax, 0
    ret

.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%llx xor %x = %llx\n"
    .size   .L.str, 20
.L.str.1:
    .asciz  "%x xor %x = %x\n"
    .size   .L.str, 16
