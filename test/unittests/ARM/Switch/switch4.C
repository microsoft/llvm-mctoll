// RUN: clang -target arm -mfloat-abi=soft -c -o %t.o %s
// RUN: llvm-mctoll -d  %t.o 2>&1 | FileCheck %s

// CHECK: switch i32 %2, label %3 [
// CHECK-NEXT:   i32 0, label %sw.bb0
// CHECK-NEXT:   i32 1, label %sw.bb1
// CHECK-NEXT:   i32 2, label %sw.bb2
// CHECK-NEXT:   i32 3, label %sw.bb3
// CHECK-NEXT: ]

int main() {

  int n = 4;

  switch (n) {

  case 1:
    n = n + 11;
    break;
  case 2:
    n = n + 12;
    break;
  case 3:
    n = n + 13;
    break;
  case 4:
    n = n + 14;
    break;
   }

  return 0 ;
}


