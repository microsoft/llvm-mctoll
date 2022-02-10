// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 15.000000, 10.000000
// CHECK-NEXT: 42.000000, 23.000000
// CHECK-NEXT: 42, 12
// CHECK-NEXT: 42.250000, 12.500000
// CHECK-NEXT: 42, 12
// CHECK-NEXT: 42.250000, 12.500000
// CHECK-NEXT: 15.000000, 10.000000
// CHECK-NEXT: 42.000000, 23.000000
// CHECK-NEXT: 42, 12
// CHECK-NEXT: 42.250000, 12.500000
// CHECK-NEXT: 42, 12
// CHECK-NEXT: 42.250000, 12.500000
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-pcmp.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8
    sub rsp, 16

    mov rax, 0x0000000f0000000a # 15, 10
    movq xmm1, rax
    cvtdq2pd xmm0, xmm1
    movdqa xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    mov rax, 0x0000002a00000017 # 42, 23
    movq xmm1, rax
    cvtdq2ps xmm0, xmm1
    movdqa xmm1, xmm0
    movq [rsp], xmm0
    movd xmm0, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movdqa xmm1, [.L.val]
    cvtpd2dq xmm0, xmm1
    movq [rsp], xmm0
    mov esi, [rsp + 4]
    mov edx, [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    movdqa xmm1, [.L.val]
    cvtpd2ps xmm0, xmm1
    movdqa xmm1, xmm0
    movq [rsp], xmm0
    movd xmm0, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    movq xmm1, [.L.val.1]
    cvtps2dq xmm0, xmm1
    movq [rsp], xmm0
    mov esi, [rsp + 4]
    mov edx, [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    movq xmm1, [.L.val.1]
    cvtps2pd xmm0, xmm1
    movdqa xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    # memory
    mov rax, 0x0000000f0000000a # 15, 10
    mov [rsp], rax
    cvtdq2pd xmm0, [rsp]
    movdqa xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    mov rax, 0x0000002a00000017 # 42, 23
    mov [rsp], rax
    cvtdq2ps xmm0, [rsp]
    movdqa xmm1, xmm0
    movq [rsp], xmm0
    movd xmm0, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    cvtpd2dq xmm0, [.L.val]
    movq [rsp], xmm0
    mov esi, [rsp + 4]
    mov edx, [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    cvtpd2ps xmm0, [.L.val]
    movdqa xmm1, xmm0
    movq [rsp], xmm0
    movd xmm0, [rsp + 4]
    cvtss2sd xmm0, xmm0
    cvtss2sd xmm1, xmm1
    movabs rdi, offset .L.str
    mov al, 2
    call printf

    cvtps2dq xmm0, [.L.val.1]
    movq [rsp], xmm0
    mov esi, [rsp + 4]
    mov edx, [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    cvtps2pd xmm0, [.L.val.1]
    movdqa xmm1, xmm0
    movdqu [rsp], xmm0
    movq xmm0, [rsp + 8]
    movabs rdi, offset .L.str
    mov al, 2
    call printf


    add rsp, 16
    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%f, %f\n"
    .size   .L.str, 18
.L.str.1:
    .asciz  "%d, %d\n"
    .size   .L.str.1, 18

.section    .rodata.cst16,"aM",@progbits,16
.align 16
.L.val:
    .quad 0x4029000000000000
    .quad 0x4045200000000000
.L.val.1:
    .long 0x41480000
    .long 0x42290000
    .quad 0x0000000000000000
