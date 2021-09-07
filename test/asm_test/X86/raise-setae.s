// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: SETAE: 0
// CHECK: SETAE: 1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-setae.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    xor esi, esi
    # set CF = 1
    mov al, 0xff
    add al, 1

    setae sil
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor esi, esi
    # set CF = 0
    mov al, 0
    add al, 1

    setae sil
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "SETAE: %d\n"
    .size   .L.str, 11
