// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d  -debug %t.o 2>&1 | FileCheck %s
// CHECK: ARMFunctionPrototype start
// CHECK: void @func()
// CHECK: ARMFunctionPrototype end

void func() {
  return;
}
