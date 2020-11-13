# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d  -debug %t.o 2>&1 | FileCheck %s

# CHECK: ARMEliminatePrologEpilog start
# CHECK: Frame Objects:
# CHECK-NOT: early-clobber $sp = STR_PRE_IMM $r11
# CHECK-NOT: $r11 = ADDri $sp, 0, 14,
# CHECK-NOT: $sp = SUBri $r11, 0, 14,
# CHECK-NOT: $r11, $sp = LDR_POST_IMM $sp,
# CHECK: ARMEliminatePrologEpilog end

# test str ldr
        .text
        .align 4
        .code 32
        .global test
        .type test, %function
test:
        str fp, [sp, #-4]!
        add fp, sp, #0

        mov r3, #0
        mov r0,r3

        sub sp, fp, #0
        ldr fp, [sp], #4

        .size    test, .-test
        .global test
        .type test, %function
