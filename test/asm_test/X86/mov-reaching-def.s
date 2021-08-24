// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/string.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: format string length: 25
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "ramov-reaching-def.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    movabs rdi, offset .L.str
    call strlen # eax defined here
    cmp eax, 0 # access eax here, before the bb that will store in the store location
    je .eq

.neq:
    mov esi, eax # store should occur here
    cmp eax, 0 # this instruction still accesses eax, not the stack location
    jne .before_print

.eq:
    mov esi, 0 # store should occur here
    jmp .print

.before_print:
    mov ebx, esi
    cmp ebx, 0
    jne .before_print_1

    mov esi, 0
    jmp .print


.before_print_1:
    mov esi, ebx

.print:
    movabs rdi, offset .L.str
    mov al, 0
    call printf # this will access the stack location

    xor eax, eax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "format string length: %d\n"
    .size   .L.str, 26
