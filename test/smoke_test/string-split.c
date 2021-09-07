// REQUIRES: system-linux
// RUN: clang -o %t %s -O3 -mno-sse
// RUN: llvm-mctoll -d -I /usr/include/stdio.h -I /usr/include/stdlib.h -I /usr/include/string.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: hello
// CHECK: world
// CHECK: how
// CHECK: is
// CHECK: your
// CHECK: day
// CHECK: end
// CHECK-EMPTY

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *str;
  int len;
} Data;

typedef enum {
  IN_WORD,
  NOT_IN_WORD
} State;

void my_print(int len, char *str);

__attribute__((noinline))
void split_str(Data *data) {
  State state = NOT_IN_WORD;

  char *curr_start = data->str;

  for (int i = 0; i < data->len; ++i) {
    char curr = data->str[i];
    switch (state) {
    case IN_WORD:
      if (curr < 'a' || curr > 'z') {
        data->str[i] = 0;
        my_print(&data->str[i] - curr_start + 1, curr_start);
        state = NOT_IN_WORD;
      }
      break;
    case NOT_IN_WORD:
      if (curr >= 'a' && curr <= 'z') {
        curr_start = &data->str[i];
        state = IN_WORD;
      }
      break;
    }
  }

  if (state == IN_WORD) {
    data->str[data->len] = 0;
    my_print(&data->str[data->len] - curr_start + 1, curr_start);
  }
}

__attribute__((noinline))
void my_print(int len, char *str) {
  printf("%.*s\n", len, str);
}


int main(int argc, char **argv) {
  Data data;
  data.str = malloc(35);
  data.len = 35;

  char *str = "hello, world! how is your day? end";
  memcpy(data.str, str, 35);

  split_str(&data);

  free(data.str);
  return 0;
}
