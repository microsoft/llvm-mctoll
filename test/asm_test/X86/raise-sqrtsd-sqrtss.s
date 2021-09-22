// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 2.000000
// CHECK-NEXT: 1.414214
// CHECK-NEXT: 2.000000
// CHECK-NEXT: 1.414214
// CHECK-NEXT: -nan
// CHECK-NEXT: -nan
// CHECK-NEXT: 2.000000
// CHECK-NEXT: 1.414214
// CHECK-NEXT: 2.000000
// CHECK-NEXT: 1.414214
// CHECK-NEXT: -nan
// CHECK-NEXT: -nan
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-sqrtsd-sqrtss.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8

    // register instructions
    movsd xmm0, [.L.val]
    sqrtsd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movsd xmm0, [.L.val.1]
    sqrtsd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.2]
    sqrtss xmm0, xmm0
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.3]
    sqrtss xmm0, xmm0
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movsd xmm0, [.L.val.4]
    sqrtsd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movss xmm0, [.L.val.5]
    sqrtss xmm0, xmm0
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    // memory referencing instructions
    sqrtsd xmm0, [.L.val]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    sqrtsd xmm0, [.L.val.1]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    sqrtss xmm0, [.L.val.2]
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    sqrtss xmm0, [.L.val.3]
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    sqrtsd xmm0, [.L.val.4]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    sqrtss xmm0, [.L.val.5]
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf


    add rsp, 8
    mov eax, 0
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%f\n"
    .size   .L.str, 6

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .double 4.0
.L.val.1:
    .double 2.0
.L.val.2:
    .float 4.0
.L.val.3:
    .float 2.0
.L.val.4:
    .double -1.0
.L.val.5:
    .float -1.0
    .float 0.0 # padding