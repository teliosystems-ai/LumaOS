/* SPDX-License-Identifier: MIT
 * Real query-only seccomp checks plus closed-wire and observation algorithms.
 * No program is loaded, attached, detached, replaced or otherwise mutated.
 */
#define _GNU_SOURCE
#include "query.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned cases;
#define CHECK(condition) do { ++cases; if (!(condition)) { \
    fprintf(stderr,"hardware query case %u failed at line%d\n",cases,__LINE__);exit(1); } } while(0)
static unsigned calls,variant;
static int observed(int fd,uint32_t attach,uint32_t effective,struct hq_snapshot *out) {
    (void)fd;(void)attach;memset(out,0,sizeof(*out));++calls;
    out->flags=effective?0:2;out->count=effective?2:1;out->ids[0]=7;out->ids[1]=9;
    switch(variant) {
        case 1: if(calls==3)out->ids[0]=8;break;
        case 2: if(calls==4)out->flags=1;break;
        case 3: out->flags=3;break;
        case 4: out->count=33;break;
        case 5: out->ids[0]=0;break;
        case 6: if(effective)out->ids[1]=7;break;
        case 7: if(effective)out->ids[0]=8;break;
        case 8: if(calls==2)return -1;break;
        case 9: out->count=0;break;
    }
    return 0;
}
static int forbidden(long result) {return result==-1 && errno==EPERM;}
static void filter_test(int fd) {
    if(hq_lock_syscalls())_exit(40);
    struct hq_snapshot actual;
    if(hq_kernel_query(fd,BPF_CGROUP_INET_INGRESS,0,&actual))_exit(41);
    if(hq_kernel_query(fd,BPF_CGROUP_INET_EGRESS,BPF_F_QUERY_EFFECTIVE,&actual))_exit(42);
    if(!forbidden(syscall(SYS_bpf,BPF_PROG_LOAD,NULL,0)))_exit(43);
    if(!forbidden(syscall(SYS_bpf,BPF_MAP_CREATE,NULL,0)))_exit(44);
    if(!forbidden(syscall(SYS_openat,AT_FDCWD,"/etc/hostname",O_RDONLY,0)))_exit(45);
    if(!forbidden(syscall(SYS_socket,AF_INET,SOCK_STREAM,0)))_exit(46);
    if(!forbidden(syscall(SYS_fork)))_exit(47);
    if(!forbidden(syscall(SYS_execve,"/nonexistent",NULL,NULL)))_exit(48);
    if(!forbidden(syscall(SYS_ptrace,0,0,NULL,NULL)))_exit(49);
    if(!forbidden(syscall(SYS_ioctl,fd,0,0)))_exit(50);
    if(!forbidden(syscall(SYS_mount,NULL,NULL,NULL,0,NULL)))_exit(51);
    _exit(0);
}
int main(void) {
    const char *valid="{\"schema_version\":1,\"nonce\":\"2323232323232323232323232323232323232323232323232323232323232323\",\"boot\":\"12121212121212121212121212121212\",\"device\":\"29\",\"inode\":\"402\",\"worker\":\"model\"}";
    struct hq_request request;CHECK(!hq_parse(valid,strlen(valid),&request));
    CHECK(request.device==29&&request.inode==402&&!request.acquisition);
    for(size_t size=0;size<strlen(valid);size++)CHECK(hq_parse(valid,size,&request));
    char changed[HQ_REQUEST_MAX+2];strcpy(changed,valid);strcat(changed,"\n");
    CHECK(hq_parse(changed,strlen(changed),&request));
    const char *needles[]={"schema_version","nonce","boot","device","inode","worker","model"};
    for(size_t i=0;i<sizeof(needles)/sizeof(needles[0]);i++) {
        strcpy(changed,valid);char *at=strstr(changed,needles[i]);*at='X';
        CHECK(hq_parse(changed,strlen(changed),&request));
    }
    strcpy(changed,valid);char *nonce=strstr(changed,"232323");memset(nonce,'0',64);
    CHECK(hq_parse(changed,strlen(changed),&request));
    strcpy(changed,valid);*strstr(changed,"232323")='A';CHECK(hq_parse(changed,strlen(changed),&request));
    strcpy(changed,valid);*strstr(changed,"29")='0';CHECK(hq_parse(changed,strlen(changed),&request));
    strcpy(changed,valid);memset(strstr(changed,"121212"),'0',32);CHECK(hq_parse(changed,strlen(changed),&request));
    CHECK(!hq_parse(valid,strlen(valid),&request));
    struct hq_direction direction;
    for(variant=0;variant<10;variant++) {
        calls=0;int result=hq_observe(3,BPF_CGROUP_INET_INGRESS,observed,&direction);
        CHECK((variant==0||variant==9)?result==0:result!=0);
    }
    variant=0;calls=0;CHECK(!hq_observe(3,BPF_CGROUP_INET_INGRESS,observed,&direction));
    char reply[HQ_REPLY_MAX];int size=hq_format(&request,&direction,&direction,reply,sizeof(reply));
    CHECK(size>0&&(size_t)size==strlen(reply));
    CHECK(strstr(reply,"\"ingress\":{\"direct_flags\":2,\"direct_ids\":[7],\"effective_flags\":0,\"effective_ids\":[7,9]}")!=NULL);
    CHECK(hq_format(&request,&direction,&direction,reply,16)<0);
    int fd=open("/sys/fs/cgroup",O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(fd>=0);
    struct hq_snapshot snapshot;
    CHECK(!hq_kernel_query(fd,BPF_CGROUP_INET_INGRESS,0,&snapshot));
    CHECK(!hq_kernel_query(fd,BPF_CGROUP_INET_EGRESS,BPF_F_QUERY_EFFECTIVE,&snapshot));
    pid_t child=fork();CHECK(child>=0);if(!child)filter_test(fd);
    int status=0;CHECK(waitpid(child,&status,0)==child);
    if(!WIFEXITED(status)||WEXITSTATUS(status))fprintf(stderr,"intrinsic seccomp child status=%d\n",status);
    CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);close(fd);
    printf("{\"status\":\"passed\",\"assertions\":%u,\"real_kernel_queries\":4,\"real_seccomp_denials\":9,\"bpf_mutations\":0,\"installed_qualified\":false}\n",cases);
    return 0;
}
