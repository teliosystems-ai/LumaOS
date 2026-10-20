/* SPDX-License-Identifier: MIT
 * Fixed descriptor-only ASR worker. The parent retains live PAM, signed model
 * custody, resource generations and cancellation. This executable has none.
 */
#include "asr_engine.h"
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <string>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

static bool write_all(int fd,const void *value,std::size_t size) {
    const char *at=static_cast<const char *>(value);
    while(size) { auto n=write(fd,at,size);if(n<0&&errno==EINTR)continue;if(n<=0)return false;at+=n;size-=static_cast<std::size_t>(n); }
    return true;
}
static bool text_file(const char *path,const char *expected) {
    int descriptor=open(path,O_RDONLY|O_CLOEXEC);if(descriptor<0)return false;
    char value[256] {};auto n=read(descriptor,value,sizeof(value));int done=close(descriptor);
    return done==0&&n==static_cast<ssize_t>(strlen(expected))&&!memcmp(value,expected,static_cast<std::size_t>(n));
}
static bool guard() {
    if(getuid()!=988||geteuid()!=988||getgid()!=988||getegid()!=988||getgroups(0,nullptr)!=0)return false;
    const char *raw=getenv("LUMA_SPEECH_PARENT");if(!raw||!*raw||*raw=='0')return false;
    for(const char *at=raw;*at;at++)if(*at<'0'||*at>'9')return false;
    errno=0;char *end=nullptr;long parent=strtol(raw,&end,10);
    if(errno||!end||*end||parent<=1||parent>=INT_MAX||getppid()!=parent||prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=parent)return false;
    if(!text_file("/proc/self/attr/current","luma-speech-asr (enforce)\n")||
       !text_file("/proc/self/cgroup","0::/lumaacquisition.slice/luma-acquisition.service\n"))return false;
    struct __user_cap_header_struct header {_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2] {};
    if(syscall(SYS_capget,&header,caps)||caps[0].effective||caps[0].permitted||caps[0].inheritable||caps[1].effective||caps[1].permitted||caps[1].inheritable||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return false;
    for(int capability=0;capability<64;capability++) {
        int bounding=prctl(PR_CAPBSET_READ,capability,0,0,0);
        if(bounding>0||(bounding<0&&errno!=EINVAL))return false;
        int ambient=prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,capability,0,0);
        if(ambient>0||(ambient<0&&errno!=EINVAL))return false;
    }
    /* Address reservations are not resident allocations. The parent keeps the
     * independently admitted 512MiB physical/no-swap cgroup ceiling unchanged. */
    struct rlimit memory {1024*1024*1024,1024*1024*1024},cpu {18,18},files {32,32},output {16384,16384},zero {0,0};
    if(setrlimit(RLIMIT_AS,&memory)||setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_NOFILE,&files)||
       setrlimit(RLIMIT_CORE,&zero)||setrlimit(RLIMIT_FSIZE,&output)||setrlimit(RLIMIT_MEMLOCK,&zero)||clearenv())return false;
    umask(0077);
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fork,4,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_vfork,3,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_execve,2,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_execveat,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,1,4),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x10000,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program {static_cast<unsigned short>(sizeof(rules)/sizeof(rules[0])),rules};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)==0;
}
int main(int argc,char **argv) {
    (void)argv;
    if(argc!=1||!guard())return 1;
    constexpr int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    struct stat input {},model {},output {};
    if(fstat(0,&input)||fstat(3,&model)||fstat(1,&output)||!S_ISREG(input.st_mode)||!S_ISREG(model.st_mode)||
       !S_ISREG(output.st_mode)||input.st_size<3200||input.st_size>960000||input.st_size%2||
       fcntl(0,F_GET_SEALS)!=seals||model.st_size!=77691713||model.st_uid!=0||model.st_nlink!=1||
       (model.st_mode&022)!=0||(fcntl(3,F_GETFL)&O_ACCMODE)!=O_RDONLY)return 1;
    char input_name[128] {};auto length=readlink("/proc/self/fd/0",input_name,sizeof(input_name));
    const char expected[]="/memfd:luma-speech-pcm (deleted)";
    if(length!=static_cast<ssize_t>(sizeof(expected)-1)||memcmp(input_name,expected,sizeof(expected)-1))return 1;
    std::vector<unsigned char> bytes(static_cast<std::size_t>(input.st_size));
    if(pread(0,bytes.data(),bytes.size(),0)!=static_cast<ssize_t>(bytes.size())||close(0))return 1;
    std::vector<int16_t> pcm(bytes.size()/2);
    for(std::size_t i=0;i<pcm.size();i++)pcm[i]=static_cast<int16_t>(bytes[i*2]|(bytes[i*2+1]<<8));
    std::fill(bytes.begin(),bytes.end(),0);
    luma_asr_result result;
    bool complete=luma_asr_transcribe(3,pcm.data(),pcm.size(),result);
    std::fill(pcm.begin(),pcm.end(),0);
    if(close(3)||!complete)return 2;
    const std::string frame="LUMA_ASR_RESULT_V1 "+std::to_string(result.decoder_tokens)+" "+
        std::to_string(result.audio_samples)+" "+std::to_string(result.text.size())+"\n"+result.text;
    return write_all(1,frame.data(),frame.size())?0:1;
}
