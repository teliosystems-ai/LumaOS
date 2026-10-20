/* SPDX-License-Identifier: MIT */
#ifndef LUMA_HARDWARE_QUERY_H
#define LUMA_HARDWARE_QUERY_H
#include <stddef.h>
#include <stdint.h>
#define HQ_REQUEST_MAX 512
#define HQ_REPLY_MAX 4096
#define HQ_IDS_MAX 32
struct hq_request {
    char nonce[65], boot[33];
    uint64_t device, inode;
    int acquisition;
};
struct hq_snapshot { uint32_t flags, count, ids[HQ_IDS_MAX]; };
struct hq_direction { struct hq_snapshot direct, effective; };
typedef int (*hq_query_fn)(int, uint32_t, uint32_t, struct hq_snapshot *);
int hq_parse(const char *, size_t, struct hq_request *);
int hq_snapshot_valid(const struct hq_snapshot *);
int hq_observe(int, uint32_t, hq_query_fn, struct hq_direction *);
int hq_kernel_query(int, uint32_t, uint32_t, struct hq_snapshot *);
int hq_format(const struct hq_request *, const struct hq_direction *,
              const struct hq_direction *, char *, size_t);
int hq_lock_syscalls(void);
#endif
