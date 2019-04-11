// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d -print-after-all %t.o 2>&1 | FileCheck %s
// CHECK: ARMMIRevising start
// CHECK: BL 48,
// CHECK: ARMMIRevising end

int func1(int a, int b) {
  return a + b;
}

int func2(int c, int d) {
  return c - d;
}

int funcend() {
  return func2(5, 3);
}

