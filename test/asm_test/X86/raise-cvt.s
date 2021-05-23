// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 1.5
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-cvt.s"

.p2align    4, 0x90
.type    convert_from_register,@function
convert_from_register:                  # @convert_from_register
    push    rax
    cvtsi2ss        xmm2, edi
    cvtsi2sd        xmm4, edi
    cvtsi2ss        xmm3, rsi
    cvtss2sd        xmm5, xmm2
#    xorps   xmm2, xmm2
    cvtss2sd        xmm2, xmm3
#    xorps   xmm3, xmm3
    cvtsi2sd        xmm3, rsi
    cvttss2si       esi, xmm0
    cvttss2si       rdx, xmm0
    cvttsd2si       ecx, xmm1
    cvttsd2si       r8, xmm1
    mov     edi, offset .L.str
    movapd  xmm0, xmm5
    movapd  xmm1, xmm4
    mov     al, 4
    call    printf
    pop     rax
    ret

.p2align    4, 0x90
.type    convert_from_memory,@function
convert_from_memory:                  # @convert_from_register
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    mov     qword ptr [rbp - 8], rdi
    mov     qword ptr [rbp - 16], rsi
    mov     qword ptr [rbp - 24], rdx
    mov     qword ptr [rbp - 32], rcx
    mov     rax, qword ptr [rbp - 8]
    cvtsi2ss        xmm0, dword ptr [rax]
    cvtss2sd        xmm0, xmm0
    mov     rax, qword ptr [rbp - 8]
    cvtsi2sd        xmm1, dword ptr [rax]
    mov     rax, qword ptr [rbp - 16]
    cvtsi2ss        xmm2, qword ptr [rax]
    cvtss2sd        xmm2, xmm2
    mov     rax, qword ptr [rbp - 16]
    cvtsi2sd        xmm3, qword ptr [rax]
    mov     rax, qword ptr [rbp - 24]
    cvttss2si       esi, dword ptr [rax]
    mov     rax, qword ptr [rbp - 24]
    cvttss2si       rdx, dword ptr [rax]
    mov     rax, qword ptr [rbp - 32]
    cvttsd2si       ecx, qword ptr [rax]
    mov     rax, qword ptr [rbp - 32]
    cvttsd2si       r8, qword ptr [rax]
    movabs  rdi, offset .L.str
    mov     al, 4
    call    printf
    add     rsp, 32
    pop     rbp
    ret

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    mov     dword ptr [rbp - 4], 0
    mov     dword ptr [rbp - 8], 42
    mov     qword ptr [rbp - 16], 42
    movss   xmm0, dword ptr [rip + .LCPI2_0]
    movss   dword ptr [rbp - 20], xmm0
    movsd   xmm0, qword ptr [rip + .LCPI2_1]
    movsd   qword ptr [rbp - 32], xmm0
    cvttss2si       eax, dword ptr [rbp - 20]
    mov     dword ptr [rbp - 36], eax

    mov     edi, 42
    mov     rsi, 42
    movss   xmm0, dword ptr [rbp - 20]
    movsd   xmm1, qword ptr [rbp - 32]
    call    convert_from_register

    lea     rdi, [rbp - 8]
    lea     rsi, [rbp - 16]
    lea     rdx, [rbp - 20]
    lea     rcx, [rbp - 32]
    call    convert_from_memory

    xor     eax, eax
    add     rsp, 48
    pop     rbp
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%.1f %.1f %.1f %.1f %d %lld %d %lld\n"
    .size   .L.str, 37

.section    .rodata.cst8,"aM",@progbits,8
.LCPI2_0:
    .long   0x422a0000                      # float 42.5
.LCPI2_1:
    .quad   0x4045400000000000              # double 42.5