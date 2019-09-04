// RUN: clang -o %t %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Copied String: Hello

/* Raising the binary of this source file tests
    a) correct detection of void return type of wrapper_free()
    b) correct return type of functions based on any tail calls -
              such as wrapper_strncpy and wrapper_malloc

    NOTES:
    a) All pointer return types are converted as i64 types.
    b) Return type of a function such as
        void foo(int i) {
               printf("Value %d\n", i);
        }
        is detected as i32 becasue the binary typically contains a
        tail call to printf whose return value type is int. Distinguising
        return values of tail calls in a function with void return from one
        that returns the tail call return is not possible.
*/

#include <stdlib.h>
#include <string.h>

void * __attribute__((noinline))
  wrapper_malloc(size_t size) {
  return malloc(size);
}

void * __attribute__((noinline))
  wrapper_strncpy(void *dest, const char *src, size_t n) {
  return strncpy(dest, src, n);
}

void __attribute__((noinline))
  wrapper_free(void * p) {
  return free(p);
}

#include <stdio.h>
int main(int argc, char **argv) {
  char * dest = wrapper_malloc(8);
  if (dest == NULL) {
    printf("Failed to allocate memory. Exiting\n");
    exit(-1);
  }
  if (wrapper_strncpy(dest, "Hello World!", 6) != dest) {
    printf("strncpy failed. Exiting\n");
    exit(-1);
  }
  printf("Copied String: %s\n", dest);
  wrapper_free(dest);
  return 0;
}
