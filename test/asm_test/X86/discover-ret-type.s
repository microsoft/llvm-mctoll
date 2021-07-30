// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 3.0
// CHECK: 10
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "discover-ret-ty.s"

.p2align    4, 0x90
.type    func1,@function
func1:
    addsd xmm0, xmm0
    ret
    # int3 instruction after ret, so mctoll won't discover this BB as a return block
    # int3 is frequently inserted by clang-13 as a padding after functions
    int3

.p2align    4, 0x90
.type    func2,@function
func2:
    mov eax, edi
    ret
    # int3 instruction after ret, so mctoll won't discover this BB as a return block
    # int3 is frequently inserted by clang-13 as a padding after functions
    int3

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8
    movsd xmm0, [.L.val]

    call func1

    movabs rdi, offset .L.str
    mov al, 1
    call printf

    mov edi, 0xa
    call func2
    mov esi, eax
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    add rsp, 8
    xor rax, rax
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%.1f\n"
    .size   .L.str, 6
.L.str.1:
    .asciz  "%d\n"
    .size   .L.str.1, 4

.section    .rodata.cst8,"aM",@progbits,8
.L.val:
    .quad 0x3ff8000000000000 # double 1.5
