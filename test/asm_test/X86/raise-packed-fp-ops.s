// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 7.500000, 4.500000
// CHECK-NEXT: 2.500000, 1.500000
// CHECK-NEXT: 12.500000, 4.500000
// CHECK-NEXT: 2.000000, 2.000000
// CHECK-NEXT: 100.000000, 46.500000, 15.500000, 11.500000
// CHECK-NEXT: 98.000000, 38.500000, 14.500000, 8.500000
// CHECK-NEXT: 99.000000, 170.000000, 7.500000, 15.000000
// CHECK-NEXT: 99.000000, 10.625000, 30.000000, 6.666667
// CHECK-NEXT: 7.500000, 4.500000
// CHECK-NEXT: 2.500000, 1.500000
// CHECK-NEXT: 12.500000, 4.500000
// CHECK-NEXT: 2.000000, 2.000000
// CHECK-NEXT: 100.000000, 46.500000, 15.500000, 11.500000
// CHECK-NEXT: 98.000000, 38.500000, 14.500000, 8.500000
// CHECK-NEXT: 99.000000, 170.000000, 7.500000, 15.000000
// CHECK-NEXT: 99.000000, 10.625000, 30.000000, 6.666667
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-packed-fp-ops.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8
    sub rsp, 16

    movapd xmm0, [.L.val]
    movapd xmm1, [.L.val.1]
    addpd xmm0, xmm1
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movapd xmm0, [.L.val]
    movapd xmm1, [.L.val.1]
    subpd xmm0, xmm1
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movapd xmm0, [.L.val]
    movapd xmm1, [.L.val.1]
    mulpd xmm0, xmm1
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movapd xmm0, [.L.val]
    movapd xmm1, [.L.val.1]
    divpd xmm0, xmm1
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movaps xmm0, [.L.val.2]
    movaps xmm1, [.L.val.3]
    addps xmm0, xmm1
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    movaps xmm0, [.L.val.2]
    movaps xmm1, [.L.val.3]
    subps xmm0, xmm1
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    movaps xmm0, [.L.val.2]
    movaps xmm1, [.L.val.3]
    mulps xmm0, xmm1
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    movaps xmm0, [.L.val.2]
    movaps xmm1, [.L.val.3]
    divps xmm0, xmm1
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    # memory referencing
    movapd xmm0, [.L.val]
    addpd xmm0, [.L.val.1]
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movapd xmm0, [.L.val]
    subpd xmm0, [.L.val.1]
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movapd xmm0, [.L.val]
    mulpd xmm0, [.L.val.1]
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movapd xmm0, [.L.val]
    divpd xmm0, [.L.val.1]
    movapd xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movaps xmm0, [.L.val.2]
    addps xmm0, [.L.val.3]
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    movaps xmm0, [.L.val.2]
    subps xmm0, [.L.val.3]
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    movaps xmm0, [.L.val.2]
    mulps xmm0, [.L.val.3]
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    movaps xmm0, [.L.val.2]
    divps xmm0, [.L.val.3]
    movaps xmm3, xmm0
    movdqu [rsp], xmm0
    movd xmm0, [rsp + 12]
    movd xmm1, [rsp + 8]
    movd xmm2, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    cvtss2sd xmm2, xmm2
    cvtss2sd xmm3, xmm3
    movabs rdi, offset .L.str.1
    mov al, 4
    call printf

    add rsp, 16
    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%f, %f\n"
    .size   .L.str, 8
.L.str.1:
    .asciz  "%f, %f, %f, %f\n"
    .size   .L.str.1, 16

.section    .rodata.cst16,"aM",@progbits,16
.align 16
.L.val:
    .quad 0x4008000000000000
    .quad 0x4014000000000000
.L.val.1:
    .quad 0x3FF8000000000000
    .quad 0x4004000000000000
.L.val.2:
    .long 0x41200000 # 10
    .long 0x41700000 # 15
    .long 0x422a0000 # 42.5
    .long 0x42c60000 # 99
.L.val.3:
    .long 0x3fc00000 # 1.5
    .long 0x3f000000 # 0.5
    .long 0x40800000 # 4.0
    .long 0x3f800000 # 1.0
