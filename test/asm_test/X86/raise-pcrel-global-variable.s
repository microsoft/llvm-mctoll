// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: i = 0
// CHECK: i = 10
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-call64r-float.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    movabs rdi, offset .L.str
    mov esi, [rip + i]
    mov al, 0
    call printf

    mov dword ptr [rip + i], 10

    movabs rdi, offset .L.str
    mov esi, [rip + i]
    mov al, 0
    call printf

    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "i = %d\n"
    .size   .L.str, 8

.bss
.type   i,@object
.globl i
.p2align 2
i:
    .long 0
    .size i, 4
