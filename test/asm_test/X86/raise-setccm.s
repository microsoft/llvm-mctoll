// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: x = 0
// CHECK-NEXT: x = 1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-xor-ri.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 1
    mov byte ptr [rsp], 0xff

    mov eax, 1
    sub eax, 1
    setne [rsp]

    movzx esi, byte ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov byte ptr [rsp], 0xff

    mov eax, 1
    sub eax, 0
    setne [rsp]

    movzx esi, byte ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    add rsp, 1
    mov eax, 0
    ret

.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "x = %d\n"
    .size   .L.str, 8
