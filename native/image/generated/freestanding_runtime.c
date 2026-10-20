/* SPDX-License-Identifier: MIT */
#include "luma.h"
static long transfer(long number, long descriptor, const void *buffer, luma_size count) {
  long result;
  __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(descriptor), "S"(buffer), "d"(count) : "rcx", "r11", "memory");
  return result;
}
long luma_read(void *buffer, luma_size count) { return transfer(0, 0, buffer, count); }
long luma_write(const void *buffer, luma_size count) { return transfer(1, 1, buffer, count); }
long luma_error(const void *buffer, luma_size count) { return transfer(1, 2, buffer, count); }
int main(void);
void luma_start(void) {
  int result = main();
  __asm__ volatile("syscall" : : "a"(60L), "D"((long)result) : "rcx", "r11", "memory");
  for (;;) {}
}
__asm__(".globl _start\n_start:\n andq $-16, %rsp\n call luma_start\n");
