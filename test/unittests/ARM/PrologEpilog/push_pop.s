# RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
# RUN: llvm-mctoll -d -print-after-all -debug %t.o 2>&1 | FileCheck %s

# CHECK: ARMEliminatePrologEpilog start
# CHECK: Frame Objects:
# CHECK-NOT: $sp = STMDB_UPD %SP
# CHECK-NOT: $sp = SUBri %SP
# CHECK-NOT: $r11 = ADDri $sp
# CHECK-NOT: $sp = LDMIA_UPD %SP
# CHECK: ARMEliminatePrologEpilog end

# test push pop
       .global test1
       .type test1, %function
test1:
        push {r11,lr}
        add r11, sp, #4
        sub sp, sp, #16

        mov r0, #1
        mov r1, #2

        sub sp, r11, #4
        pop {r11, pc}
        .size    test1, .-test1
