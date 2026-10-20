/* SPDX-License-Identifier: MIT
 * Fresh read-only identity of three fixed image-owned platform daemons.
 * No arbitrary PID, filesystem path, command, grant or TPM request exists.
 */
#define _GNU_SOURCE
#include "peer.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <time.h>

struct request {char nonce[65],boot_id[33],role[32];uint64_t deadline;};
struct proof {pid_t pid;uint64_t ticks,device,inode;uid_t uid;gid_t gid;char sha[65];};

static uint64_t boottime(void) {
    struct timespec now;
    if(clock_gettime(CLOCK_BOOTTIME,&now)||now.tv_sec<0||now.tv_nsec<0||now.tv_nsec>=1000000000)return 0;
    return (uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
}
static int within(uint64_t deadline) {uint64_t now=boottime();return now&&now<deadline?0:-1;}
static int nonzero_hex(const char *value,size_t size) {
    if(strlen(value)!=size)return -1;
    int nonzero=0;
    for(size_t i=0;i<size;i++) {
        char c=value[i];
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return -1;
        nonzero|=c!='0';
    }
    return nonzero?0:-1;
}
static int decimal_value(const char *text,uint64_t *out) {
    size_t size=strlen(text);
    if(!size||size>20||text[0]<'1'||text[0]>'9')return -1;
    uint64_t value=0;
    for(size_t i=0;i<size;i++) {
        if(text[i]<'0'||text[i]>'9')return -1;
        unsigned digit=(unsigned)(text[i]-'0');
        if(value>(UINT64_MAX-digit)/10)return -1;
        value=value*10+digit;
    }
    *out=value;return 0;
}
static int parse(const char *bytes,size_t size,struct request *request) {
    if(!size||size>512)return -1;
    char input[513],deadline[21]={0},canonical[513];int consumed=0;
    memset(request,0,sizeof(*request));memcpy(input,bytes,size);input[size]=0;
    if(sscanf(input,"{\"schema_version\":1,\"nonce\":\"%64[0-9a-f]\",\"boot\":\"%32[0-9a-f]\",\"deadline_ms\":\"%20[0-9]\",\"role\":\"%31[a-z-]\"}%n",
        request->nonce,request->boot_id,deadline,request->role,&consumed)!=4||consumed!=(int)size||
        nonzero_hex(request->nonce,64)||nonzero_hex(request->boot_id,32)||decimal_value(deadline,&request->deadline)||
        (strcmp(request->role,"systemd-manager")&&strcmp(request->role,"system-bus")&&strcmp(request->role,"power-profiles")))return -1;
    int length=snprintf(canonical,sizeof(canonical),"{\"schema_version\":1,\"nonce\":\"%s\",\"boot\":\"%s\",\"deadline_ms\":\"%" PRIu64 "\",\"role\":\"%s\"}",
        request->nonce,request->boot_id,request->deadline,request->role);
    return length==(int)size&&!memcmp(canonical,bytes,size)?0:-1;
}
static int receive_request(struct request *request) {
    char bytes[513];union {struct cmsghdr alignment;char bytes[CMSG_SPACE(4*sizeof(int))];} control;
    struct iovec iov={.iov_base=bytes,.iov_len=sizeof(bytes)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    ssize_t size=recvmsg(0,&message,MSG_CMSG_CLOEXEC);int fd=-1,count=0,bad=size<=0||size>512||
        (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
    for(struct cmsghdr *at=CMSG_FIRSTHDR(&message);at;at=CMSG_NXTHDR(&message,at)) {
        if(at->cmsg_level!=SOL_SOCKET||at->cmsg_type!=SCM_RIGHTS||at->cmsg_len<CMSG_LEN(0)){bad=1;continue;}
        size_t amount=at->cmsg_len-CMSG_LEN(0);if(amount%sizeof(int))bad=1;
        for(size_t i=0;i<amount/sizeof(int);i++) {
            int received;memcpy(&received,(char*)CMSG_DATA(at)+i*sizeof(int),sizeof(received));
            if(count++==0)fd=received;else{close(received);bad=1;}
        }
    }
    if(count!=1||bad||parse(bytes,(size_t)(size>0?size:0),request)){if(fd>=0)close(fd);return -1;}
    return fd;
}
static int pid_from_fd(int fd,pid_t *pid) {
    char path[128],link[128],text[4096];
    int length=snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    if(length<=0||length>=(int)sizeof(path)||live(fd))return -1;
    ssize_t size=readlink(path,link,sizeof(link));
    if(size!=(ssize_t)strlen("anon_inode:[pidfd]")||memcmp(link,"anon_inode:[pidfd]",(size_t)size))return -1;
    length=snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",fd);
    if(length<=0||length>=(int)sizeof(path)||read_file(path,text,sizeof(text))<0)return -1;
    const char *at=text;int found=0;
    while(*at) {
        const char *end=strchr(at,'\n');if(!end)return -1;
        if((size_t)(end-at)>5&&!memcmp(at,"Pid:\t",5)) {
            char number[32];size_t count=(size_t)(end-at-5);uint64_t value;
            if(found++||count>=sizeof(number))return -1;
            memcpy(number,at+5,count);number[count]=0;
            if(decimal_value(number,&value)||value>INT32_MAX)return -1;
            *pid=(pid_t)value;
        }
        at=end+1;
    }
    return found==1&&!live(fd)?0:-1;
}
static int start_ticks(const char *text,uint64_t *ticks) {
    const char *at=strrchr(text,')');if(!at||at[1]!=' ')return -1;at+=2;
    for(unsigned field=3;field<22;field++){at=strchr(at,' ');if(!at)return -1;++at;}
    const char *end=strchr(at,' ');char number[32];
    if(!end||(size_t)(end-at)>=sizeof(number))return -1;
    memcpy(number,at,(size_t)(end-at));number[end-at]=0;return decimal_value(number,ticks);
}
static int same_metadata(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&
        a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int identity_alias(struct stat *alias) {
    static const char *directories[]={"/etc","/var","/var/lib","/var/lib/luma-os","/var/lib/luma-os/identity"};
    for(size_t i=0;i<sizeof(directories)/sizeof(directories[0]);i++) {
        struct stat item;
        if(lstat(directories[i],&item)||!S_ISDIR(item.st_mode)||item.st_uid||item.st_gid||(item.st_mode&0022))return -1;
    }
    static const char expected[]="../var/lib/luma-os/identity/passwd";
    char target[sizeof(expected)];
    ssize_t size=readlink("/etc/passwd",target,sizeof(target));
    return lstat("/etc/passwd",alias)||!S_ISLNK(alias->st_mode)||alias->st_uid||alias->st_gid||alias->st_nlink!=1||
        size!=(ssize_t)(sizeof(expected)-1)||memcmp(target,expected,sizeof(expected)-1)?-1:0;
}
static int messagebus(uid_t *uid,gid_t *gid) {
    struct stat alias,alias_after,named,before,after;
    if(identity_alias(&alias))return -1;
    static const char account[]="/var/lib/luma-os/identity/passwd";
    int fd=open(account,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    char text[65536];ssize_t size;
    int bad=fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_uid||before.st_gid||before.st_nlink!=1||
        (before.st_mode&0022)||before.st_size<=0||before.st_size>=(off_t)sizeof(text);
    size=bad?-1:read(fd,text,sizeof(text));
    if(size<0||size!=before.st_size||fstat(fd,&after)||!same_metadata(&before,&after)||
        identity_alias(&alias_after)||!same_metadata(&alias,&alias_after)||
        lstat(account,&named)||!same_metadata(&before,&named))bad=1;
    if(close(fd))bad=1;
    if(bad)return -1;
    text[size]=0;
    char *at=text;int found=0;
    while(*at) {
        char *end=strchr(at,'\n');if(!end)return -1;*end=0;
        if(!strncmp(at,"messagebus:",11)) {
            if(found++||strncmp(at,"messagebus:x:",13))return -1;
            char *user_text=at+13,*user_end=strchr(user_text,':');
            if(!user_end)return -1;
            *user_end=0;char *group_text=user_end+1,*group_end=strchr(group_text,':');
            if(!group_end)return -1;
            *group_end=0;uint64_t user=0,group=0;
            if(decimal_value(user_text,&user)||decimal_value(group_text,&group)||user>=65534||group>=65534)return -1;
            *uid=(uid_t)user;*gid=(gid_t)group;
        }
        at=end+1;
    }
    return found==1?0:-1;
}
static const char *executable_path(const char *role) {
    if(!strcmp(role,"systemd-manager"))return "/usr/lib/systemd/systemd";
    if(!strcmp(role,"system-bus"))return "/usr/bin/dbus-daemon";
    return "/usr/libexec/power-profiles-daemon";
}
static const char *unit(const char *role) {
    if(!strcmp(role,"systemd-manager"))return "0::/init.scope\n";
    if(!strcmp(role,"system-bus"))return "0::/system.slice/dbus.service\n";
    return "0::/system.slice/power-profiles-daemon.service\n";
}
static const char *escaped_unit(const char *role) {
    if(!strcmp(role,"systemd-manager"))return "0::/init.scope\\n";
    if(!strcmp(role,"system-bus"))return "0::/system.slice/dbus.service\\n";
    return "0::/system.slice/power-profiles-daemon.service\\n";
}
static int hash_executable(pid_t pid,const struct request *request,struct proof *proof) {
    char path[64];struct stat expected={0},before={0},after={0},named={0};
    const char *fixed=executable_path(request->role);
    if(lstat(fixed,&expected)||!S_ISREG(expected.st_mode)||expected.st_uid||expected.st_gid||
        expected.st_nlink!=1||(expected.st_mode&0022)||expected.st_size<=0||expected.st_size>16*1024*1024)return -1;
    int length=snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    if(length<=0||length>=(int)sizeof(path))return -1;
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;
    int bad=fstat(fd,&before)||before.st_dev!=expected.st_dev||before.st_ino!=expected.st_ino;
    EVP_MD_CTX *digest=EVP_MD_CTX_new();if(!digest){close(fd);return -1;}
    if(EVP_DigestInit_ex(digest,EVP_sha256(),NULL)!=1)bad=1;
    unsigned char buffer[32768],sha[32];size_t total=0;unsigned sha_size=0;
    while(!bad) {
        if(within(request->deadline)){bad=1;break;}
        ssize_t size=read(fd,buffer,sizeof(buffer));if(size<0){bad=1;break;}if(!size)break;
        total+=(size_t)size;
        if(total>(size_t)expected.st_size||EVP_DigestUpdate(digest,buffer,(size_t)size)!=1)bad=1;
    }
    if(!bad&&(EVP_DigestFinal_ex(digest,sha,&sha_size)!=1||sha_size!=32||total!=(size_t)expected.st_size))bad=1;
    EVP_MD_CTX_free(digest);
    if(fstat(fd,&after)||stat(path,&named)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||
        before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||
        before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||before.st_ctim.tv_sec!=after.st_ctim.tv_sec||
        before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec||before.st_dev!=named.st_dev||before.st_ino!=named.st_ino)bad=1;
    if(close(fd))bad=1;
    if(bad)return -1;
    static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<32;i++){proof->sha[i*2]=hex[sha[i]>>4];proof->sha[i*2+1]=hex[sha[i]&15];}proof->sha[64]=0;
    if(!strcmp(request->role,"power-profiles")&&strcmp(proof->sha,"9d02f65b9314a62847a8460325dcd9009855df050dc423d2941a45e3aac8e43a"))return -1;
    if(!strcmp(request->role,"systemd-manager")&&strcmp(proof->sha,"b472aadf808bef87c0eb203056a77cb64bd268b71b756306013a53de68a94173"))return -1;
    if(!strcmp(request->role,"system-bus")&&strcmp(proof->sha,"8c479f1fcddfd6693c736ce541da0955f6752834bdeeef4b928e27f5e974c247"))return -1;
    proof->device=(uint64_t)before.st_dev;proof->inode=(uint64_t)before.st_ino;return 0;
}
static int capture(int target,const struct request *request,struct proof *proof) {
    memset(proof,0,sizeof(*proof));char text[16384],ids[64],boot_id[33];
    if(within(request->deadline)||pid_from_fd(target,&proof->pid)||boot(boot_id)||strcmp(boot_id,request->boot_id))return -1;
    if(!strcmp(request->role,"systemd-manager")&&proof->pid!=1)return -1;
    if(!strcmp(request->role,"system-bus")&&messagebus(&proof->uid,&proof->gid))return -1;
    int length=snprintf(ids,sizeof(ids),"%u\t%u\t%u\t%u",proof->uid,proof->uid,proof->uid,proof->uid);
    if(length<=0||length>=(int)sizeof(ids)||proc_file(proof->pid,"status",text,sizeof(text))<0||line(text,"Uid:\t",ids))return -1;
    length=snprintf(ids,sizeof(ids),"%u\t%u\t%u\t%u",proof->gid,proof->gid,proof->gid,proof->gid);
    if(length<=0||length>=(int)sizeof(ids)||line(text,"Gid:\t",ids)||
        proc_file(proof->pid,"cgroup",text,sizeof(text))<0||strcmp(text,unit(request->role))||
        proc_file(proof->pid,"stat",text,sizeof(text))<0||start_ticks(text,&proof->ticks)||
        hash_executable(proof->pid,request,proof)||live(target)||within(request->deadline))return -1;
    return 0;
}
static int cut_syscalls(void) {
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    struct sock_filter rules[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        ALLOW(poll),ALLOW(ppoll),ALLOW(sendmsg),ALLOW(recvfrom),ALLOW(write),ALLOW(close),
        ALLOW(getpid),ALLOW(clock_gettime),ALLOW(rt_sigreturn),ALLOW(exit),ALLOW(exit_group),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    };
#undef ALLOW
    struct sock_fprog filter={.len=sizeof(rules)/sizeof(rules[0]),.filter=rules};
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter);
}
static int identity(void) {
    char text[16384];
    return getuid()||geteuid()||getgid()||getegid()||
        read_file("/proc/self/attr/current",text,sizeof(text))<0||strcmp(text,"luma-hardware-daemon-observer (enforce)\n")||
        read_file("/proc/self/status",text,sizeof(text))<0||
        line(text,"CapPrm:\t","0000000000080000")||line(text,"CapEff:\t","0000000000080000")||
        line(text,"CapBnd:\t","0000000000080000")||line(text,"CapInh:\t","0000000000000000")||
        line(text,"CapAmb:\t","0000000000000000")||line(text,"NoNewPrivs:\t","1")||line(text,"Seccomp:\t","2");
}
static int run(void) {
    int type=0,controller=-1;socklen_t size=sizeof(type),owner_size=sizeof(struct ucred),pidfd_size=sizeof(controller);
    struct ucred owner;
    if(identity()||getsockopt(0,SOL_SOCKET,SO_TYPE,&type,&size)||size!=sizeof(type)||type!=SOCK_SEQPACKET||
        getsockopt(0,SOL_SOCKET,SO_PEERCRED,&owner,&owner_size)||owner_size!=sizeof(owner)||owner.uid||owner.gid||owner.pid<=1||
        getsockopt(0,SOL_SOCKET,SO_PEERPIDFD,&controller,&pidfd_size)||pidfd_size!=sizeof(controller)||controller<0)return -1;
    char first_stat[8192],last_stat[8192];
    if(peer(owner.pid,controller,first_stat,sizeof(first_stat)))return -1;
    struct pollfd ready={.fd=0,.events=POLLIN};if(poll(&ready,1,500)!=1||ready.revents!=POLLIN)return -1;
    struct request request;int target=receive_request(&request);if(target<0)return -1;
    uint64_t now=boottime();if(!now||request.deadline<=now||request.deadline-now>1000)return -1;
    struct proof before,after;
    if(capture(target,&request,&before)||capture(target,&request,&after)||memcmp(&before,&after,sizeof(before))||
        peer(owner.pid,controller,last_stat,sizeof(last_stat))||same_start(first_stat,last_stat)||within(request.deadline))return -1;
    char reply[4096];
    int length=snprintf(reply,sizeof(reply),"{\"schema_version\":1,\"nonce\":\"%s\",\"boot\":\"%s\",\"deadline_ms\":\"%" PRIu64 "\",\"role\":\"%s\",\"proof\":{\"pid\":%ld,\"start_ticks\":\"%" PRIu64 "\",\"uid\":%u,\"gid\":%u,\"exe_dev\":\"%" PRIu64 "\",\"exe_inode\":\"%" PRIu64 "\",\"exe_sha256\":\"%s\",\"cgroup\":\"%s\",\"boot\":\"%s\"}}",
        request.nonce,request.boot_id,request.deadline,request.role,(long)before.pid,before.ticks,before.uid,before.gid,
        before.device,before.inode,before.sha,escaped_unit(request.role),request.boot_id);
    if(length<=0||length>=(int)sizeof(reply)||descriptors(&target,&controller)||
        prctl(PR_GET_DUMPABLE,0,0,0,0)!=1||restrict_capabilities(0)||live(target)||live(controller)||within(request.deadline)||cut_syscalls())return -1;
    union {struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(struct ucred))];} control;
    struct iovec iov={.iov_base=reply,.iov_len=(size_t)length};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    struct cmsghdr *at=CMSG_FIRSTHDR(&message);at->cmsg_level=SOL_SOCKET;at->cmsg_type=SCM_CREDENTIALS;at->cmsg_len=CMSG_LEN(sizeof(struct ucred));
    struct ucred self={.pid=getpid(),.uid=0,.gid=0};memcpy(CMSG_DATA(at),&self,sizeof(self));
    if(live(target)||live(controller)||within(request.deadline)||sendmsg(0,&message,MSG_NOSIGNAL)!=length)return -1;
    now=boottime();uint64_t remaining=now<request.deadline?request.deadline-now:0;
    if(!remaining)return -1;
    ready.revents=0;
    if(poll(&ready,1,(int)(remaining<250?remaining:250))!=1||ready.revents!=POLLIN)return -1;
    char ack[2];return recv(0,ack,sizeof(ack),MSG_DONTWAIT)==1&&ack[0]=='1'?0:-1;
}
int main(int argc,char **argv) {
    (void)argv;
    if(argc!=1||run()) {
        static const char refused[]="hardware daemon identity observation refused\n";
        ssize_t size=write(2,refused,sizeof(refused)-1);(void)size;_exit(1);
    }
    /* EVP can register libc exit handlers before the syscall cut. Do not
     * execute library cleanup (or reopen resources) after sending the proof. */
    _exit(0);
}
