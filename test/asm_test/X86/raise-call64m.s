// REQUIRES: x86_64-linux
// RUN: clang -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: Called function
// CHECK: Returned from function
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-call64m.s"

.p2align    4, 0x90
.type    func1,@function
func1:
    movabs rdi, offset .L.str
    mov al, 0
    call printf
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    mov rax, OFFSET func1
    sub rsp, 8
    mov [rsp], rax
    call [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf
    xor rax, rax
    add rsp, 8
    ret


    .type   .L.str,@object                  # @.str
    .section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "Called function\n"
    .size   .L.str, 17

    .type   .L.str.1,@object                # @.str.1
.L.str.1:
    .asciz  "Returned from function\n"
    .size   .L.str.1, 24