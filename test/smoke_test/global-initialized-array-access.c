// RUN: clang -o %t %s
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK:mem_name Static
// CHECK:mem_name Heap
// CHECK:mem_name Stack
// CHECK:list_known_crc 5e47
// CHECK:list_known_crc 39bf
// CHECK:list_known_crc e5a4
// CHECK:list_known_crc 8e3a
// CHECK:list_known_crc 8d84
// CHECK:array 4006a4
// CHECK:array 4006ab
// CHECK:array 4006b0
// CHECK:array 0
// CHECK static_constant 0xbeef

/* 
 * This code tests raising of global arrays, their initialization and access.
 */
#include <stdio.h>

typedef unsigned short ee_u16;
static ee_u16 list_known_crc[] = {(ee_u16)0x5e47, (ee_u16)0x39bf,
                                  (ee_u16)0xe5a4, (ee_u16)0x8e3a,
                                  (ee_u16)0x8d84};
static char *mem_name[3] = {"Static", "Heap", "Stack"};
static int array[] = {0x4006a4, 0x4006ab, 0x4006b0, 0};
static int static_constant = 0xbeef;

int main() {
  printf("mem_name %s\n", mem_name[0]);
  printf("mem_name %s\n", mem_name[1]);
  printf("mem_name %s\n", mem_name[2]);
  printf("list_known_crc %x\n", list_known_crc[0]);
  printf("list_known_crc %x\n", list_known_crc[1]);
  printf("list_known_crc %x\n", list_known_crc[2]);
  printf("list_known_crc %x\n", list_known_crc[3]);
  printf("list_known_crc %x\n", list_known_crc[4]);
  printf("array %x\n", array[0]);
  printf("array %x\n", array[1]);
  printf("array %x\n", array[2]);
  printf("array %x\n", array[3]);
  printf("static_constamt %x\n", static_constant);
  return 0;
}
