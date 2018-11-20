int switch_test(int n) {

  switch (n) {
  case 4:
    n = n + 10;
    break;
  case 5:
    n = n + 11;
    break;
  case 6:
    n = n + 12;
    break;
  case 9:
    n = n + 13;
    break;
  case 1:
    n = n + 14;
    break;
  default:
    n = n + 15;
  }

  return n;
}
