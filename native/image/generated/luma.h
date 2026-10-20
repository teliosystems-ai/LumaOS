/* SPDX-License-Identifier: MIT
 * Declared syscall shim for c99-freestanding-tcc-v1. The separately pinned
 * TinyCC builtin archive is the only additional permitted runtime dependency.
 * No libc, filesystem, network, allocator, threads or external packages.
 */
#ifndef LUMA_SYSCALL_V1_H
#define LUMA_SYSCALL_V1_H
typedef unsigned long luma_size;
long luma_read(void *buffer, luma_size count);
long luma_write(const void *buffer, luma_size count);
long luma_error(const void *buffer, luma_size count);
#endif
