#include <stdint.h>

void increment8(uint8_t* arr, int n)
{
  for (int i = 0; i < n; ++i)
    ++arr[i];
}

void increment16(uint16_t* arr, int n)
{
  for (int i = 0; i < n; ++i)
    ++arr[i];
}

void increment32(uint32_t* arr, int n)
{
  for (int i = 0; i < n; ++i)
    ++arr[i];
}

void increment64(uint64_t* arr, int n)
{
  for (int i = 0; i < n; ++i)
    ++arr[i];
}
