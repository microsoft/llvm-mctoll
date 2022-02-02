// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 16
// CHECK-NEXT: 15
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-add16rr.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    xor esi, esi
    mov si, 10
    mov dx, 6
    add si, dx
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor esi, esi
    mov si, 10
    add si, [.L.val]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov eax, 0
    ret

.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%d\n"
    .size   .L.str, 20

.section    .rodata.cst2,"aM",@progbits,2
.align 2
.L.val:
    .word 0x0005
