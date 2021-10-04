// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1.500000
// CHECK: 3ff8000000000000 4045400000000000
// CHECK: 3fc00000 40400000 42280000 422a0000
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-movups.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8 # align stack
    sub rsp, 16

    movupd xmm0, [.L.val]
    movabs rdi, offset .L.str
    mov al, 1
    call printf

    movupd xmm0, [.L.val]
    movupd [rsp], xmm0
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    movups xmm0, [.L.val.1]
    movups [rsp], xmm0
    mov esi, [rsp]
    mov edx, [rsp + 4]
    mov ecx, [rsp + 8]
    mov r8d, [rsp + 12]
    movabs rdi, offset .L.str.2
    mov al, 0
    call printf

    add rsp, 24
    xor rax, rax
    ret


    .type   .L.str,@object                  # @.str
    .section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%f\n"
    .size   .L.str, 4

    .type   .L.str.1,@object                # @.str.1
.L.str.1:
    .asciz  "%016lx %016lx\n"
    .size   .L.str.1, 15

    .type   .L.str.2,@object                # @.str.1
.L.str.2:
    .asciz  "%08x %08x %08x %08x\n"
    .size   .L.str.2, 21

    .section    .rodata.cst16,"aM",@progbits,16
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
    .quad 0x4045400000000000 # 42.5
.L.val.1:
    .float 1.5
    .float 3.0
    .float 42.0
    .float 42.5
