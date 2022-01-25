// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 12.500000
// CHECK-NEXT: 42.250000
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-movq-mem.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8
    sub rsp, 16

    mov rax, 0x4029000000000000
    movq xmm1, rax
    movq [rsp], xmm1
    movq xmm0, [rsp]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    mov eax, 0x42290000
    movd xmm1, eax
    movd [rsp], xmm1
    movd xmm0, [rsp]
    cvtss2sd xmm0, xmm0
    movabs rdi, offset .L.str
    mov al, 1
    call printf


    add rsp, 16
    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%f\n"
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
