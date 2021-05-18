// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: Everything ok

.text
.intel_syntax noprefix
.file "movaps.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    xor rax, rax
    push rax # allocate something from the stack
    movsd xmm0, [.L.val]
    movaps xmm1, xmm0
    movsd [rsp - 8], xmm1
    mov rdi, 0x3ff8000000000000
    mov rsi, [rsp - 8]
    add rsp, 8
    cmp rdi, rsi
    je .ok
notok:
    movabs rdi, offset .L.str.1
    jmp .print
.ok:
    movabs rdi, offset .L.str
    jmp .print
.print:
    mov al, 0
    call printf
    xor rax, rax
    ret


    .type   .L.str,@object                  # @.str
    .section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "Everything ok\n"
    .size   .L.str, 15

    .type   .L.str.1,@object                # @.str.1
.L.str.1:
    .asciz  "Not ok\n"
    .size   .L.str.1, 8
    .section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
