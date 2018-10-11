# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s

# CHECK: ARMEliminatePrologEpilog start
# CHECK: Frame Objects:
# CHECK-NOT: $sp = STMDB_UPD %SP
# CHECK-NOT: $sp = ADDri $r11
# CHECK-NOT: $r11, $sp = LDR_POST_IMM $sp
# CHECK: ARMEliminatePrologEpilog end

# test push pop and branch
        .global test2
        .type test2, %function
test2:
        push {r11,lr}
        add r11, sp, #4
        sub sp, sp, #16
        mov r0, #1
        mov r1, #2
        bl max
        sub sp, r11, #4
        pop {r11, pc}
max:
        push {r11}
        add r11, sp, #0
        sub sp, sp, #12
        cmp r0, r1
        movlt r0, r1
        add sp, r11, #0
        pop {r11}
        bx lr
        .size    test2, .-test2
