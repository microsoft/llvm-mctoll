// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: byte[0] = dd
// CHECK-NEXT: byte[1] = cc
// CHECK-NEXT: byte[2] = bb
// CHECK-NEXT: byte[3] = aa
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-cindexreg-int.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    mov eax, 0xAABBCCDD
    push rax

    mov rbx, 0

    movzx edx, byte ptr [rsp + rbx + 0]
    mov esi, 0
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    movzx edx, byte ptr [rsp + rbx + 1]
    mov esi, 1
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    movzx edx, byte ptr [rsp + rbx + 2]
    mov esi, 2
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    movzx edx, byte ptr [rsp + rbx + 3]
    mov esi, 3
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "byte[%d] = %x\n"
    .size   .L.str, 4
