// REQUIRES: x86_64-linux
// RUN: clang -O0 -o %t %s
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 1
// CHECK-NEXT: 1
// CHECK-NEXT: 1
// CHECK-NEXT: 1
// CHECK-NEXT: -1
// CHECK-NEXT: -1
// CHECK-NEXT: -1
// CHECK-NEXT: -1
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 4
// CHECK-NEXT: 1
// CHECK-NEXT: 1
// CHECK-NEXT: 1
// CHECK-NEXT: 1
// CHECK-NEXT: -1
// CHECK-NEXT: -1
// CHECK-NEXT: -1
// CHECK-NEXT: -1
// CHECK-EMPTY

.text
.intel_syntax noprefix
.file "raise-shift-cl.s"

.globl    main                    # -- Begin function main
.p2align    4, 0x90
.type    main,@function
main:                                   # @main
    sub rsp, 8
    # shl
    mov rsi, 1
    mov cl, 2
    shl rsi, cl
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov esi, 1
    mov cl, 2
    shl esi, cl
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov si, 1
    mov cl, 2
    shl si, cl
    movsx esi, si
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov sil, 1
    mov cl, 2
    shl sil, cl
    movsx esi, sil
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # shr
    mov rsi, 4
    mov cl, 2
    shr rsi, cl
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov esi, 4
    mov cl, 2
    shr esi, cl
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov si, 4
    mov cl, 2
    shr si, cl
    movsx esi, si
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov sil, 4
    mov cl, 2
    shr sil, cl
    movsx esi, sil
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # sar
    mov rsi, -4
    mov cl, 2
    sar rsi, cl
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov esi, -4
    mov cl, 2
    sar esi, cl
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov si, -4
    mov cl, 2
    sar si, cl
    movsx esi, si
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov sil, -4
    mov cl, 2
    sar sil, cl
    movsx esi, sil
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # memory operations
    # shl
    mov qword ptr [rsp], 1
    mov cl, 2
    shl qword ptr [rsp], cl
    mov rsi, qword ptr [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov dword ptr [rsp], 1
    mov cl, 2
    shl dword ptr [rsp], cl
    mov esi, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov word ptr [rsp], 1
    mov cl, 2
    shl word ptr [rsp], cl
    movsx esi, word ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov byte ptr [rsp], 1
    mov cl, 2
    shl byte ptr [rsp], cl
    movsx esi, byte ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # shr
    mov qword ptr [rsp], 4
    mov cl, 2
    shr qword ptr [rsp], cl
    mov rsi, qword ptr [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov dword ptr [rsp], 4
    mov cl, 2
    shr dword ptr [rsp], cl
    mov esi, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov word ptr [rsp], 4
    mov cl, 2
    shr word ptr [rsp], cl
    movsx esi, word ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov byte ptr [rsp], 4
    mov cl, 2
    shr byte ptr [rsp], cl
    movsx esi, byte ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    # sar
    mov qword ptr [rsp], -4
    mov cl, 2
    sar qword ptr [rsp], cl
    mov rsi, qword ptr [rsp]
    movabs rdi, offset .L.str.1
    mov al, 0
    call printf

    mov dword ptr [rsp], -4
    mov cl, 2
    sar dword ptr [rsp], cl
    mov esi, [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov word ptr [rsp], -4
    mov cl, 2
    sar word ptr [rsp], cl
    movsx esi, word ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf

    mov byte ptr [rsp], -4
    mov cl, 2
    sar byte ptr [rsp], cl
    movsx esi, byte ptr [rsp]
    movabs rdi, offset .L.str
    mov al, 0
    call printf


    add rsp, 8
    mov eax, 0
    ret


.type   .L.str,@object                  # @.str
.section        .rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz  "%d\n"
    .size   .L.str, 6
.L.str.1:
    .asciz  "%lld\n"
    .size   .L.str.1, 8
