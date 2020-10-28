// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d -I /usr/include/stdio.h %t
// RUN: clang -o %t-dis %t-dis.ll
// RUN: %t-dis 2>&1 | FileCheck %s
// CHECK: ret is: 4

#include <stdio.h>
#include <stdlib.h>

typedef enum CORE_STATE {
  CORE_START = 0,
  CORE_INVALID,
  CORE_S1,
  CORE_S2,
  CORE_INT,
  CORE_FLOAT,
  CORE_EXPONENT,
  CORE_SCIENTIFIC,
  NUM_CORE_STATES
} core_state_e;

static char ee_isdigit(char c) {
  char retval;
  retval = ((c >= '0') & (c <= '9')) ? 1 : 0;
  return retval;
}

enum CORE_STATE __attribute__((noinline))
call_me(char **instr, int *transition_count) {
  char *str = *instr;
  char NEXT_SYMBOL;
  enum CORE_STATE state = CORE_START;
  for (; *str && state != CORE_INVALID; str++) {
    NEXT_SYMBOL = *str;
    if (NEXT_SYMBOL == ',') /* end of this input */ {
      str++;
      break;
    }
    switch (state) {
    case CORE_START:
      if (ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INT;
      } else if (NEXT_SYMBOL == '+' || NEXT_SYMBOL == '-') {
        state = CORE_S1;
      } else if (NEXT_SYMBOL == '.') {
        state = CORE_FLOAT;
      } else {
        state = CORE_INVALID;
        transition_count[CORE_INVALID]++;
      }
      transition_count[CORE_START]++;
      break;
    case CORE_S1:
      if (ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INT;
        transition_count[CORE_S1]++;
      } else if (NEXT_SYMBOL == '.') {
        state = CORE_FLOAT;
        transition_count[CORE_S1]++;
      } else {
        state = CORE_INVALID;
        transition_count[CORE_S1]++;
      }
      break;
    case CORE_INT:
      if (NEXT_SYMBOL == '.') {
        state = CORE_FLOAT;
        transition_count[CORE_INT]++;
      } else if (!ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INVALID;
        transition_count[CORE_INT]++;
      }
      break;
    case CORE_FLOAT:
      if (NEXT_SYMBOL == 'E' || NEXT_SYMBOL == 'e') {
        state = CORE_S2;
        transition_count[CORE_FLOAT]++;
      } else if (!ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INVALID;
        transition_count[CORE_FLOAT]++;
      }
      break;
    case CORE_S2:
      if (NEXT_SYMBOL == '+' || NEXT_SYMBOL == '-') {
        state = CORE_EXPONENT;
        transition_count[CORE_S2]++;
      } else {
        state = CORE_INVALID;
        transition_count[CORE_S2]++;
      }
      break;
    case CORE_EXPONENT:
      if (ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_SCIENTIFIC;
        transition_count[CORE_EXPONENT]++;
      } else {
        state = CORE_INVALID;
        transition_count[CORE_EXPONENT]++;
      }
      break;
    case CORE_SCIENTIFIC:
      if (!ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INVALID;
        transition_count[CORE_INVALID]++;
      }
      break;
    default:
      break;
    }
  }
  *instr = str;
  return state;
}

int main(int argc, char **argv) {
  char *str = "012,";
  int *trans_count;
  enum CORE_STATE ret = call_me(&str, trans_count);
  printf("ret is: %d\n", ret);
  return 0;
}
