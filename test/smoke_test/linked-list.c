// REQUIRES: system-linux
// RUN: clang -g -o %t-opt %s -O2 -mno-sse
// RUN: llvm-mctoll -d %t-opt
// RUN: clang -o %t-opt-dis %t-opt-dis.ll
// RUN: %t-opt-dis 2>&1 | FileCheck %s

// CHECK:Initialized list:
// CHECK:[0000,8080]
// CHECK:[7fff,1212]
// CHECK:[7fff,0909]
// CHECK:[7fff,0000]
// CHECK:[7fff,ffff]

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
} results;

list_head *list_insert_new(list_head *insert_point, list_data *info,
                           list_head **memblock, list_data **datablock,
                           list_head *memblock_end, list_data *datablock_end) {
  list_head *newitem;

  if ((*memblock + 1) >= memblock_end)
    return NULL;

  if ((*datablock + 1) >= datablock_end)
    return NULL;

  newitem = *memblock;
  (*memblock)++;
  newitem->next = insert_point->next;
  insert_point->next = newitem;

  newitem->info = *datablock;
  (*datablock)++;
  newitem->info->idx = info->idx;
  newitem->info->data16 = info->data16;
  return newitem;
}

list_head *list_init(unsigned int blksize, list_head *memblock,
                     signed short seed) {
  unsigned int per_item = 16 + sizeof(struct list_data_s);
  unsigned int size = (blksize / per_item) - 2;
  list_head *memblock_end = memblock + size;
  list_data *datablock = (list_data *)(memblock_end);
  list_data *datablock_end = datablock + size;
  unsigned int i;
  list_head *finder, *test, *list = memblock;
  list_data info;

  list->next = NULL;
  list->info = datablock;
  list->info->idx = 0x0000;
  list->info->data16 = (signed short)0x8080;
  memblock++;
  datablock++;
  info.idx = 0x7fff;
  info.data16 = (signed short)0xffff;
  list_insert_new(list, &info, &memblock, &datablock, memblock_end,
                  datablock_end);

  for (i = 0; i < 3; i++) {
    unsigned short datpat = ((unsigned short)(seed ^ i) & 0xf);
    unsigned short dat = (datpat << 3) | (i & 0x7);
    info.data16 = (dat << 8) | dat;
    list_insert_new(list, &info, &memblock, &datablock, memblock_end,
                    datablock_end);
  }

  printf("Initialized list:\n");
  finder = list;
  while (finder) {
    printf("[%04x,%04x]\n", finder->info->idx,
           (unsigned short)finder->info->data16);
    finder = finder->next;
  }
  printf("\n");

  return list;
}

int main() {
  results res[1];
  res[0].list = list_init(666, res[0].memblock[1], 0);
  return 0;
}
