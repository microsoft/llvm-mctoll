// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d -debug  %t.o 2>&1 | FileCheck %s
// CHECK: ARMFrameBuilder start
// CHECK: %stack.2.stack.2
// CHECK: %stack.3.stack.3
// CHECK: %stack.4.stack.4
// CHECK: %stack.5.stack.5
// CHECK: %stack.6.stack.6
// CHECK: ARMFrameBuilder end

int func(int x) {
  int a, b, c, e;
  a = 3;
  b = a + x;
  c = b + a;
  e = c - x;

  return e;
}

