// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: PF not set
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-jnp.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val]
    ucomisd xmm0, xmm1
    jnp .np

    movabs rdi, offset .L.str.p
    jmp .print

.np:
    movabs rdi, offset .L.str.np
    jmp .print

.print:
    mov al, 0
    call printf

    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str.p:
    .asciz  "PF set\n"
    .size   .L.str.p, 8
.L.str.np:
    .asciz  "PF not set\n"
    .size   .L.str.np, 12

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
.L.val.1:
    .quad 0x4045400000000000 # double 42.5
