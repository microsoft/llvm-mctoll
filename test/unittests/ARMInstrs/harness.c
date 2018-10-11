#include <stdio.h>

extern int funcAddReg(int a, int b);
int main() {
  printf("funcAddReg result is %d\n", funcAddReg(2, 3));
  return 0;
}
