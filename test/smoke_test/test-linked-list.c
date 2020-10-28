// REQUIRES: system-linux
// RUN: clang -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s

// CHECK:Initialized list:
// CHECK:[0000,8080]

#include <stdio.h>

typedef struct list_data_s {
  signed short data16;
  signed short idx;
} list_data;

typedef struct list_head_s {
  struct list_head_s *next;
  struct list_data_s *info;
} list_head;

typedef struct RESULTS_S {
  void *memblock[4];
  struct list_head_s *list;
} core_results;

list_head *__attribute__((noinline))
core_list_init(unsigned int blksize, list_head *memblock) {
  unsigned int per_item = 16 + sizeof(struct list_data_s);
  unsigned int size = (blksize / per_item) - 2;
  list_head *memblock_end = memblock + size;
  list_data *datablock = (list_data *)(memblock_end);
  list_head *finder, *list = memblock;

  list->next = NULL;
  list->info = datablock;
  list->info->idx = 0x0000;
  list->info->data16 = (signed short)0x8080;

  printf("Initialized list:\n");
  finder = list;
  while (finder) {
    printf("[%04x,%04x] \n", finder->info->idx,
           (unsigned short)finder->info->data16);
    finder = finder->next;
  }
  printf("\n");
  return list;
}

int main() {
  core_results results[1];
  results[0].list = core_list_init(666, results[0].memblock[1]);
  return 0;
}
