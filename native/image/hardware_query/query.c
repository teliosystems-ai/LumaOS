/* SPDX-License-Identifier: MIT
 * Query-only kernel observations: no attach/load/detach operation exists here.
 */
#define _GNU_SOURCE
#include "query.h"
#include <errno.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int literal(const char **at, const char *end, const char *word) {
    size_t size = strlen(word);
    if ((size_t)(end - *at) < size || memcmp(*at, word, size)) return -1;
    *at += size; return 0;
}
static int hex(const char **at, const char *end, char *out, size_t size) {
    if ((size_t)(end - *at) < size) return -1;
    int nonzero = 0;
    for (size_t i = 0; i < size; i++) {
        char value = (*at)[i];
        if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) return -1;
        nonzero |= value != '0'; out[i] = value;
    }
    out[size] = 0; *at += size;
    return nonzero ? 0 : -1;
}
static int decimal(const char **at, const char *end, uint64_t *out) {
    if (*at == end || **at < '1' || **at > '9') return -1;
    uint64_t value = 0;
    while (*at != end && **at >= '0' && **at <= '9') {
        unsigned digit = (unsigned)(**at - '0');
        if (value > (UINT64_MAX - digit) / 10) return -1;
        value = value * 10 + digit; ++*at;
    }
    *out = value; return 0;
}
int hq_parse(const char *input, size_t size, struct hq_request *out) {
    if (!input || !out || !size || size > HQ_REQUEST_MAX) return -1;
    const char *at = input, *end = input + size;
    memset(out, 0, sizeof(*out));
    if (literal(&at,end,"{\"schema_version\":1,\"nonce\":\"") || hex(&at,end,out->nonce,64) ||
        literal(&at,end,"\",\"boot\":\"") || hex(&at,end,out->boot,32) ||
        literal(&at,end,"\",\"device\":\"") || decimal(&at,end,&out->device) ||
        literal(&at,end,"\",\"inode\":\"") || decimal(&at,end,&out->inode) ||
        literal(&at,end,"\",\"worker\":\"")) return -1;
    if ((size_t)(end-at) == strlen("model\"}") && !memcmp(at,"model\"}",strlen("model\"}")))
        out->acquisition = 0;
    else if ((size_t)(end-at) == strlen("acquisition\"}") &&
             !memcmp(at,"acquisition\"}",strlen("acquisition\"}"))) out->acquisition = 1;
    else return -1;
    return 0;
}
int hq_snapshot_valid(const struct hq_snapshot *value) {
    if (value->flags > 2 || value->count > HQ_IDS_MAX) return -1;
    for (uint32_t i = 0; i < value->count; i++) {
        if (!value->ids[i]) return -1;
        for (uint32_t j = 0; j < i; j++) if (value->ids[j] == value->ids[i]) return -1;
    }
    return 0;
}
int hq_kernel_query(int fd, uint32_t attach, uint32_t effective, struct hq_snapshot *out) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr)); memset(out, 0, sizeof(*out));
    attr.query.target_fd = (uint32_t)fd; attr.query.attach_type = attach;
    attr.query.query_flags = effective;
    attr.query.prog_ids = (uint64_t)(uintptr_t)out->ids; attr.query.prog_cnt = HQ_IDS_MAX;
    if (syscall(SYS_bpf, BPF_PROG_QUERY, &attr, sizeof(attr))) return -1;
    out->count = attr.query.prog_cnt; out->flags = attr.query.attach_flags;
    return hq_snapshot_valid(out);
}
static int equal(const struct hq_snapshot *a, const struct hq_snapshot *b) {
    return a->flags == b->flags && a->count == b->count &&
        !memcmp(a->ids,b->ids,(size_t)a->count * sizeof(a->ids[0]));
}
int hq_observe(int fd, uint32_t attach, hq_query_fn query, struct hq_direction *out) {
    struct hq_direction again;
    if (query(fd,attach,0,&out->direct) ||
        query(fd,attach,BPF_F_QUERY_EFFECTIVE,&out->effective) ||
        query(fd,attach,0,&again.direct) ||
        query(fd,attach,BPF_F_QUERY_EFFECTIVE,&again.effective) ||
        hq_snapshot_valid(&out->direct) || hq_snapshot_valid(&out->effective) ||
        hq_snapshot_valid(&again.direct) || hq_snapshot_valid(&again.effective) ||
        !equal(&out->direct,&again.direct) || !equal(&out->effective,&again.effective)) return -1;
    for (uint32_t i = 0; i < out->direct.count; i++) {
        int found = 0;
        for (uint32_t j = 0; j < out->effective.count; j++)
            found |= out->direct.ids[i] == out->effective.ids[j];
        if (!found) return -1;
    }
    return 0;
}
static int append(char *out, size_t bound, size_t *used, const char *text) {
    size_t size = strlen(text);
    if (*used >= bound || size >= bound - *used) return -1;
    memcpy(out + *used,text,size); *used += size; out[*used] = 0; return 0;
}
static int number(char *out, size_t bound, size_t *used, uint32_t value) {
    char text[16]; int size = snprintf(text,sizeof(text),"%" PRIu32,value);
    return size <= 0 || size >= (int)sizeof(text) ? -1 : append(out,bound,used,text);
}
static int snapshot(char *out, size_t bound, size_t *used, const struct hq_snapshot *value) {
    if (hq_snapshot_valid(value) || number(out,bound,used,value->flags) || append(out,bound,used,",\"")) return -1;
    return 0;
}
static int direction(char *out, size_t bound, size_t *used, const struct hq_direction *value) {
    if (append(out,bound,used,"{\"direct_flags\":") || snapshot(out,bound,used,&value->direct) ||
        append(out,bound,used,"direct_ids\":[")) return -1;
    for (uint32_t i=0;i<value->direct.count;i++)
        if ((i && append(out,bound,used,",")) || number(out,bound,used,value->direct.ids[i])) return -1;
    if (append(out,bound,used,"],\"effective_flags\":") || snapshot(out,bound,used,&value->effective) ||
        append(out,bound,used,"effective_ids\":[")) return -1;
    for (uint32_t i=0;i<value->effective.count;i++)
        if ((i && append(out,bound,used,",")) || number(out,bound,used,value->effective.ids[i])) return -1;
    return append(out,bound,used,"]}");
}
int hq_format(const struct hq_request *request, const struct hq_direction *ingress,
              const struct hq_direction *egress, char *out, size_t bound) {
    if (!bound || bound > HQ_REPLY_MAX) return -1;
    int size = snprintf(out,bound,"{\"schema_version\":1,\"nonce\":\"%s\",\"boot\":\"%s\","
        "\"device\":\"%" PRIu64 "\",\"inode\":\"%" PRIu64 "\",\"worker\":\"%s\",\"ingress\":",
        request->nonce,request->boot,request->device,request->inode,
        request->acquisition ? "acquisition" : "model");
    if (size <= 0 || (size_t)size >= bound) return -1;
    size_t used = (size_t)size;
    if (direction(out,bound,&used,ingress) || append(out,bound,&used,",\"egress\":") ||
        direction(out,bound,&used,egress) || append(out,bound,&used,"}")) return -1;
    return (int)used;
}
int hq_lock_syscalls(void) {
    /* No open/socket/exec/ioctl/fork/ptrace/attach remains after authentication.
     * bpf is admitted for command16 only; all extant non-cgroup descriptors
     * (socket/pidfd/stderr) are invalid BPF query targets by kernel type.
     */
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_bpf,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,BPF_PROG_QUERY,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        ALLOW(fstat), ALLOW(newfstatat), ALLOW(fstatfs), ALLOW(poll), ALLOW(ppoll),
        ALLOW(sendmsg), ALLOW(recvfrom), ALLOW(write), ALLOW(close),
        ALLOW(capset), ALLOW(capget), ALLOW(getpid), ALLOW(clock_gettime), ALLOW(rt_sigreturn),
        ALLOW(exit), ALLOW(exit_group),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    };
#undef ALLOW
    struct sock_fprog program = {.len=sizeof(rules)/sizeof(rules[0]),.filter=rules};
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
