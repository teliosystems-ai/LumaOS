/* SPDX-License-Identifier: MIT
 * Calls the actual production parser/FD functions in a distinct test binary.
 * The production binary has no fixture mode or identity bypass.
 */
#define main production_worker_entry
#include "../image/hardware_query/worker.c"
#undef main
#include <sys/wait.h>

static unsigned cases;
#define CHECK(condition) do { ++cases; if (!(condition)) { \
    fprintf(stderr,"hardware worker case%u failed line%d\n",cases,__LINE__);exit(1); } } while(0)
static const char valid_request[]="{\"schema_version\":1,\"nonce\":\"2323232323232323232323232323232323232323232323232323232323232323\",\"boot\":\"12121212121212121212121212121212\",\"device\":\"29\",\"inode\":\"402\",\"worker\":\"model\"}";
static unsigned open_count(void) {
    unsigned count=0;
    for(int fd=0;fd<128;fd++)if(fcntl(fd,F_GETFD)>=0)count++;
    return count;
}
static void transfer(unsigned variant) {
    int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair));
    int source=syscall(SYS_memfd_create,"actual-query-ancillary",1);CHECK(source>=0);
    struct stat original;CHECK(!fstat(source,&original));
    pid_t child=fork();CHECK(child>=0);
    if(!child) {
        close(pair[0]);if(dup2(pair[1],0)!=0)_exit(11);if(pair[1]!=0)close(pair[1]);
        if(variant==5) {int enabled=1;if(setsockopt(0,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)))_exit(12);}
        if(send(0,"r",1,MSG_NOSIGNAL)!=1)_exit(16);
        unsigned before=open_count();struct hq_request request;int fd=receive(&request);
        if(variant==0) {
            struct stat actual;
            if(fd<0||fstat(fd,&actual)||actual.st_dev!=original.st_dev||actual.st_ino!=original.st_ino||
                request.device!=29||request.inode!=402||!(fcntl(fd,F_GETFD)&FD_CLOEXEC))_exit(13);
            close(fd);
        } else if(fd>=0)_exit(14);
        if(open_count()!=before)_exit(15);
        _exit(0);
    }
    close(pair[1]);
    char ready=0;CHECK(recv(pair[0],&ready,1,0)==1&&ready=='r');
    char data[HQ_REQUEST_MAX+2];memcpy(data,valid_request,sizeof(valid_request));
    size_t length=strlen(valid_request);if(variant==3){memset(data,'x',sizeof(data));length=sizeof(data);}
    if(variant==4)data[0]='[';
    struct iovec iov={.iov_base=data,.iov_len=length};
    union {struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(int)*2)];} control;
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    if(variant!=1) {
        message.msg_control=control.bytes;message.msg_controllen=CMSG_SPACE(sizeof(int)*(variant==2?2:1));
        struct cmsghdr *at=CMSG_FIRSTHDR(&message);at->cmsg_level=SOL_SOCKET;at->cmsg_type=SCM_RIGHTS;
        at->cmsg_len=CMSG_LEN(sizeof(int)*(variant==2?2:1));
        int values[2]={source,source};memcpy(CMSG_DATA(at),values,sizeof(int)*(variant==2?2:1));
    }
    CHECK(sendmsg(pair[0],&message,MSG_NOSIGNAL)==(ssize_t)length);
    close(source);close(pair[0]);int status=0;CHECK(waitpid(child,&status,0)==child);
    if(!WIFEXITED(status)||WEXITSTATUS(status))fprintf(stderr,"actual ancillary variant%u status%d\n",variant,status);
    CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
}
int main(void) {
    const char *status="Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";
    CHECK(!zero_caps(status));CHECK(zero_caps("Uid:\t0\t0\t0\t0\n"));
    char altered[512];strcpy(altered,status);*strstr(altered,"0000000000000000")='1';CHECK(zero_caps(altered));
    strcpy(altered,status);strcat(altered,"Seccomp:\t2\n");CHECK(zero_caps(altered));
    CHECK(!transaction("Policy_One.2-test",17));CHECK(transaction("1-invalid",9));CHECK(transaction("bad/path",8));
    CHECK(!identifier("local_user",10,32));CHECK(identifier("UPPER",5,32));CHECK(identifier("dot.name",8,32));
    char current_boot[33];CHECK(!boot(current_boot));CHECK(!generation(current_boot,32));
    char actual_stat[8192];CHECK(proc_file(getpid(),"stat",actual_stat,sizeof(actual_stat))>0);
    CHECK(!same_start(actual_stat,actual_stat));
    for(unsigned variant=0;variant<6;variant++)transfer(variant);
    pid_t child=fork();CHECK(child>=0);
    if(!child) {
        int a=open("/sys/fs/cgroup",O_RDONLY|O_DIRECTORY|O_CLOEXEC),b=(int)syscall(SYS_pidfd_open,getpid(),0);
        if(a<0||b<0)_exit(20);
        struct stat expected_a,expected_b,actual_a,actual_b;
        if(fstat(a,&expected_a)||fstat(b,&expected_b))_exit(21);
        int high=fcntl(a,F_DUPFD_CLOEXEC,200);if(high<200)_exit(22);
        if(descriptors(&a,&b)||a!=3||b!=4||fstat(a,&actual_a)||fstat(b,&actual_b)||
            expected_a.st_dev!=actual_a.st_dev||expected_a.st_ino!=actual_a.st_ino||
            expected_b.st_dev!=actual_b.st_dev||expected_b.st_ino!=actual_b.st_ino||
            fcntl(high,F_GETFD)!=-1||errno!=EBADF)_exit(23);
        for(int fd=5;fd<256;fd++)if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF)_exit(24);
        _exit(0);
    }
    int child_status=0;CHECK(waitpid(child,&child_status,0)==child);
    if(!WIFEXITED(child_status)||WEXITSTATUS(child_status))fprintf(stderr,"descriptor child status%d\n",child_status);
    CHECK(WIFEXITED(child_status)&&WEXITSTATUS(child_status)==0);
    printf("{\"status\":\"passed\",\"assertions\":%u,\"actual_ancillary_cases\":6,\"actual_high_fd_closure\":true,\"installed_authority_qualified\":false}\n",cases);
    return 0;
}
