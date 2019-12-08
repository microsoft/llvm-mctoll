// REQUIRES: system-linux
// RUN: clang -o %t %s -O2
// RUN: llvm-mctoll -d %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: Case : CORE_START
// CHECK: State : CORE_INVALID
// CHECK: ret value: 1

#include <stdio.h>

/* state machine related stuff */
/* List of all the possible states for the FSM */
typedef enum CORE_STATE {
  CORE_START=0,
  CORE_INVALID,
  CORE_S1,
  CORE_S2,
  CORE_INT,
  CORE_FLOAT,
  CORE_EXPONENT,
  CORE_SCIENTIFIC,
  NUM_CORE_STATES
} core_state_e ;

static short ee_isdigit(short c) {
  short retval;
  retval = ((c>='0') & (c<='9')) ? 1 : 0;
  return retval;
}

enum CORE_STATE indirect_mem(short **instr , int *transition_count) {
  short *str = *instr;
  short NEXT_SYMBOL;
  enum CORE_STATE state = CORE_START;
  for(; *str && state != CORE_INVALID; str++) {
    NEXT_SYMBOL = *str;
    if (NEXT_SYMBOL==',') /* end of this input */ {
      str++;
      break;
    }
    switch(state) {
    case CORE_START:
      printf("Case : CORE_START\n");
      if (ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INT;
	printf("State : CORE_INT\n");
      }
      else if (NEXT_SYMBOL == '+' || NEXT_SYMBOL == '-') {
        state = CORE_S1;
	printf("State : CORE_INT\n");
      }
      else if (NEXT_SYMBOL == '.') {
        state = CORE_FLOAT;
	printf("State : CORE_FLOAT\n");
      }
      else {
        state = CORE_INVALID;
        transition_count[CORE_INVALID]++;
	printf("State : CORE_INVALID\n");
      }
      transition_count[CORE_START]++;
      break;
    case CORE_S1:
      printf("Case : CORE_S1\n");
      if (ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INT;
        transition_count[CORE_S1]++;
	printf("State : CORE_INT\n");
      }
      else if (NEXT_SYMBOL == '.') {
        state = CORE_FLOAT;
        transition_count[CORE_S1]++;
	printf("State : CORE_FLOAT\n");
      }
      else {
        state = CORE_INVALID;
        transition_count[CORE_S1]++;
	printf("State : CORE_INVALID\n");
      }
      break;
    case CORE_INT:
      printf("Case : CORE_INT\n");
      if (NEXT_SYMBOL == '.') {
        state = CORE_FLOAT;
        transition_count[CORE_INT]++;
	printf("State : CORE_FLOAT\n");
      }
      else if (!ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INVALID;
        transition_count[CORE_INT]++;
	printf("State : CORE_INVALID\n");
      }
      break;
    case CORE_FLOAT:
      printf("Case : CORE_FLOAT\n");
      if (NEXT_SYMBOL == 'E' || NEXT_SYMBOL == 'e') {
        state = CORE_S2;
        transition_count[CORE_FLOAT]++;
	printf("State : CORE_FLOAT\n");
      }
      else if (!ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INVALID;
        transition_count[CORE_FLOAT]++;
	printf("State : CORE_INVALID\n");
      }
      break;
    case CORE_S2:
      printf("Case : CORE_S2\n");
      if (NEXT_SYMBOL == '+' || NEXT_SYMBOL == '-') {
        state = CORE_EXPONENT;
        transition_count[CORE_S2]++;
	printf("State : CORE_EXPONENT\n");
      }
      else {
        state = CORE_INVALID;
        transition_count[CORE_S2]++;
	printf("State : CORE_INVALID\n");
      }
      break;
    case CORE_EXPONENT:
      printf("Case : CORE_EXPONENT\n");
      if (ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_SCIENTIFIC;
        transition_count[CORE_EXPONENT]++;
	printf("State : CORE_SCIENTFIC\n");
      }
      else {
        state = CORE_INVALID;
        transition_count[CORE_EXPONENT]++;
	printf("State : CORE_INVALID\n");
      }
      break;
    case CORE_SCIENTIFIC:
      printf("Case : CORE_SCIENTIFIC\n");
      if (!ee_isdigit(NEXT_SYMBOL)) {
        state = CORE_INVALID;
        transition_count[CORE_INVALID]++;
	printf("State : CORE_INVALID\n");
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
  short *str = "012AGK";
  int track_counts[7]; 
  enum CORE_STATE ret = indirect_mem(&str, track_counts);
  printf("ret value: %d\n", ret);
  return 0;
}
