/* SPDX-License-Identifier: MIT
 * One systemd-accepted SOCK_SEQPACKET request. SYS_PTRACE is used only for
 * read-only peer identity and dropped before the query-only syscall cut.
 * NET_ADMIN is dropped before reply; the controller receives neither.
 */
#define _GNU_SOURCE
#include "query.h"
#include "peer.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

static int cgroup(int fd, const struct hq_request *request, struct stat *held) {
    struct stat expected;struct statfs fs;
    const char *path=request->acquisition ? "/sys/fs/cgroup/lumaacquisition.slice" : "/sys/fs/cgroup/lumamodel.slice";
    int fixed=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fixed<0)return -1;
    int bad=fstat(fixed,&expected)||fstat(fd,held)||fstatfs(fd,&fs);
    if(close(fixed))bad=1;
    if(bad||fs.f_type!=CGROUP2_SUPER_MAGIC||!S_ISDIR(held->st_mode)||held->st_uid||!held->st_nlink||
        (held->st_mode&0022)||held->st_dev!=expected.st_dev||held->st_ino!=expected.st_ino||
        (uint64_t)held->st_dev!=request->device||(uint64_t)held->st_ino!=request->inode)return -1;
    return 0;
}
static int identity(void) {
    char text[16384];
    if(getuid()||geteuid()||getgid()||getegid()||
        read_file("/proc/self/attr/current",text,sizeof(text))<0||strcmp(text,"luma-hardware-query (enforce)\n")||
        read_file("/proc/self/status",text,sizeof(text))<0||
        line(text,"CapPrm:\t","0000000000081000")||line(text,"CapEff:\t","0000000000081000")||
        line(text,"CapBnd:\t","0000000000081000")||line(text,"CapInh:\t","0000000000000000")||
        line(text,"CapAmb:\t","0000000000000000")||line(text,"NoNewPrivs:\t","1")||
        line(text,"Seccomp:\t","2"))return -1;
    return 0;
}
static int receive(struct hq_request *request) {
    char bytes[HQ_REQUEST_MAX+1];
    union {struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(int)*4)];} control;
    struct iovec iov={.iov_base=bytes,.iov_len=sizeof(bytes)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    ssize_t size=recvmsg(0,&message,MSG_CMSG_CLOEXEC);
    int fd=-1,count=0,bad=size<=0||size>HQ_REQUEST_MAX||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
    for(struct cmsghdr *at=CMSG_FIRSTHDR(&message);at;at=CMSG_NXTHDR(&message,at)) {
        if(at->cmsg_level!=SOL_SOCKET||at->cmsg_type!=SCM_RIGHTS||at->cmsg_len<CMSG_LEN(0)) {bad=1;continue;}
        size_t amount=at->cmsg_len-CMSG_LEN(0);
        if(amount%sizeof(int))bad=1;
        for(size_t i=0;i<amount/sizeof(int);i++) {
            int value;memcpy(&value,(char*)CMSG_DATA(at)+i*sizeof(int),sizeof(value));
            if(count++==0)fd=value;else {close(value);bad=1;}
        }
    }
    if(count!=1||bad||hq_parse(bytes,(size_t)(size>0?size:0),request)) {if(fd>=0)close(fd);return -1;}
    return fd;
}
static int run(void) {
    int type=0,pidfd=-1;socklen_t size=sizeof(type);
    struct ucred owner;socklen_t owner_size=sizeof(owner),pidfd_size=sizeof(pidfd);
    if(identity()||getsockopt(0,SOL_SOCKET,SO_TYPE,&type,&size)||size!=sizeof(type)||type!=SOCK_SEQPACKET||
        getsockopt(0,SOL_SOCKET,SO_PEERCRED,&owner,&owner_size)||owner_size!=sizeof(owner)||
        owner.uid||owner.gid||owner.pid<=1||getsockopt(0,SOL_SOCKET,SO_PEERPIDFD,&pidfd,&pidfd_size)||
        pidfd_size!=sizeof(pidfd)||pidfd<0)return -1;
    char first_stat[8192],second_stat[8192],actual_boot[33];
    if(peer(owner.pid,pidfd,first_stat,sizeof(first_stat)))return -1;
    struct pollfd ready={.fd=0,.events=POLLIN};
    if(poll(&ready,1,500)!=1||ready.revents!=POLLIN)return -1;
    struct hq_request request;int fd=receive(&request);
    if(fd<0)return -1;
    struct stat before,after;
    if(boot(actual_boot)||strcmp(actual_boot,request.boot)||cgroup(fd,&request,&before)||
        peer(owner.pid,pidfd,second_stat,sizeof(second_stat))||same_start(first_stat,second_stat))return -1;
    /* Normalize without a 3/4 collision, then close even inherited high FDs.
     * A low RLIMIT_NOFILE alone does not close descriptors already inherited.
     */
    if(descriptors(&fd,&pidfd))return -1;
    if(prctl(PR_GET_DUMPABLE,0,0,0,0)!=1||restrict_capabilities(1U<<CAP_NET_ADMIN)||hq_lock_syscalls())return -1;
    struct hq_direction ingress,egress,ingress2,egress2;
    if(hq_observe(fd,BPF_CGROUP_INET_INGRESS,hq_kernel_query,&ingress)||
        hq_observe(fd,BPF_CGROUP_INET_EGRESS,hq_kernel_query,&egress)||
        hq_observe(fd,BPF_CGROUP_INET_INGRESS,hq_kernel_query,&ingress2)||
        hq_observe(fd,BPF_CGROUP_INET_EGRESS,hq_kernel_query,&egress2)||
        memcmp(&ingress,&ingress2,sizeof(ingress))||memcmp(&egress,&egress2,sizeof(egress))||
        fstat(fd,&after)||!after.st_nlink||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||live(pidfd)||
        restrict_capabilities(0))return -1;
    char reply[HQ_REPLY_MAX];int length=hq_format(&request,&ingress,&egress,reply,sizeof(reply));
    if(length<0)return -1;
    union {struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(struct ucred))];} control;
    struct iovec iov={.iov_base=reply,.iov_len=(size_t)length};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    struct cmsghdr *at=CMSG_FIRSTHDR(&message);
    at->cmsg_level=SOL_SOCKET;at->cmsg_type=SCM_CREDENTIALS;at->cmsg_len=CMSG_LEN(sizeof(struct ucred));
    struct ucred self={.pid=getpid(),.uid=0,.gid=0};memcpy(CMSG_DATA(at),&self,sizeof(self));
    if(live(pidfd)||sendmsg(0,&message,MSG_NOSIGNAL)!=length)return -1;
    /* Client validates the kernel-supplied SCM_PIDFD sender while we remain
     * alive. ACK is not a grant and cannot permit another query. */
    ready.revents=0;
    if(poll(&ready,1,250)!=1||ready.revents!=POLLIN)return -1;
    char ack[2];return recv(0,ack,sizeof(ack),MSG_DONTWAIT)==1&&ack[0]=='1'?0:-1;
}
int main(int argc,char **argv) {
    (void)argv;
    if(argc!=1||run()) {
        static const char refused[]="hardware BPF observation refused\n";
        ssize_t written=write(2,refused,sizeof(refused)-1);(void)written;
        return 1;
    }
    return 0;
}
