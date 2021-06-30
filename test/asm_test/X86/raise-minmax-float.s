// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 42.5
// CHECK: 1.5
// CHECK: 42.5
// CHECK: 1.5
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-minmax-float.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val.1]
    maxsd xmm0, xmm1
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movsd xmm0, [.L.val]
    movsd xmm1, [.L.val.1]
    minsd xmm0, xmm1
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.2]
    movss xmm1, [.L.val.3]
    maxss xmm0, xmm1
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.2]
    movss xmm1, [.L.val.3]
    minss xmm0, xmm1
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movsd xmm0, [.L.val]
    maxsd xmm0, [.L.val.1]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movsd xmm0, [.L.val]
    minsd xmm0, [.L.val.1]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.2]
    maxss xmm0, [.L.val.3]
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.2]
    minss xmm0, [.L.val.3]
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    add rsp, 8
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
    .quad 0x4045400000000000 # double 42.5
.L.val.2:
    .long 0x3fc00000 # float 1.5
.L.val.3:
    .long 0x422a0000 # float 42.5
