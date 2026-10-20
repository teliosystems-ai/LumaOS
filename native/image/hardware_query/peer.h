/* SPDX-License-Identifier: MIT
 * Shared fixed peer authentication/descriptor routines for two independent,
 * one-request image-owned observers. No test mode or caller-selected path.
 */
#ifndef LUMA_HARDWARE_PEER_H
#define LUMA_HARDWARE_PEER_H
#define _GNU_SOURCE
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

static inline int read_file(const char *path, char *out, size_t bound) {
    int fd = open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t size = read(fd,out,bound);
    int result = close(fd);
    if (size < 0 || (size_t)size >= bound || result) return -1;
    out[size]=0; return (int)size;
}
static inline int proc_file(pid_t pid, const char *name, char *out, size_t bound) {
    char path[128];
    int size = snprintf(path,sizeof(path),"/proc/%ld/%s",(long)pid,name);
    if (size <= 0 || size >= (int)sizeof(path)) return -1;
    return read_file(path,out,bound);
}
static inline int live(int pidfd) {
    struct pollfd fd = {.fd=pidfd,.events=POLLIN};
    return poll(&fd,1,0) == 0 ? 0 : -1;
}
static inline int line(const char *text, const char *key, const char *value) {
    size_t key_size=strlen(key), size=strlen(value);
    const char *at=text; int found=0;
    while (*at) {
        const char *end=strchr(at,'\n');
        if (!end) return -1;
        if ((size_t)(end-at) >= key_size && !memcmp(at,key,key_size)) {
            if (found || (size_t)(end-at) != key_size+size || memcmp(at+key_size,value,size)) return -1;
            found=1;
        }
        at=end+1;
    }
    return found ? 0 : -1;
}
static inline int zero_caps(const char *text) {
    return line(text,"Uid:\t","0\t0\t0\t0") || line(text,"Gid:\t","0\t0\t0\t0") ||
        line(text,"CapInh:\t","0000000000000000") || line(text,"CapPrm:\t","0000000000000000") ||
        line(text,"CapEff:\t","0000000000000000") || line(text,"CapBnd:\t","0000000000000000") ||
        line(text,"CapAmb:\t","0000000000000000") || line(text,"NoNewPrivs:\t","1") ||
        line(text,"Seccomp:\t","2");
}
static inline int generation(const char *value, size_t size) {
    if (size != 32) return -1;
    int nonzero=0;
    for (size_t i=0;i<size;i++) {
        char c=value[i];
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return -1;
        nonzero |= c!='0';
    }
    return nonzero ? 0 : -1;
}
static inline int identifier(const char *value, size_t size, size_t maximum) {
    if (!size || size>maximum || !(value[0]>='a'&&value[0]<='z')) return -1;
    for (size_t i=0;i<size;i++) {
        char c=value[i];
        if (!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-')) return -1;
    }
    return 0;
}
static inline int transaction(const char *value, size_t size) {
    if(!size||size>64||!((value[0]>='a'&&value[0]<='z')||(value[0]>='A'&&value[0]<='Z')))return -1;
    for(size_t i=0;i<size;i++) {
        char c=value[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))return -1;
    }
    return 0;
}
static inline int executable(pid_t pid) {
    char path[64]; struct stat expected,actual;
    int size=snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    if (size<=0 || size>=(int)sizeof(path) ||
        lstat("/usr/libexec/luma-os/luma-platform",&expected) ||
        !S_ISREG(expected.st_mode) || expected.st_uid || expected.st_nlink!=1 ||
        (expected.st_mode&0022) || stat(path,&actual) ||
        expected.st_dev!=actual.st_dev || expected.st_ino!=actual.st_ino) return -1;
    return 0;
}
static inline int peer(pid_t pid, int pidfd, char *original_stat, size_t stat_bound) {
    char text[16384];
    if (live(pidfd) || proc_file(pid,"attr/current",text,sizeof(text)) !=
        (int)strlen("luma-hardware (enforce)\n") || strcmp(text,"luma-hardware (enforce)\n") ||
        proc_file(pid,"status",text,sizeof(text)) < 0 || zero_caps(text) || executable(pid)) return -1;
    int size=proc_file(pid,"cgroup",text,sizeof(text));
    static const char prefix[]="0::/system.slice/luma-hardware-", suffix[]=".service\n";
    if (size!=(int)(strlen(prefix)+32+strlen(suffix)) || memcmp(text,prefix,strlen(prefix)) ||
        generation(text+strlen(prefix),32) || strcmp(text+strlen(prefix)+32,suffix)) return -1;
    size=proc_file(pid,"cmdline",text,sizeof(text));
    if (size<=0 || text[size-1]!=0) return -1;
    /* Native launch fixes argv[0]; arbitrary aliases are not accepted. */
    const char *a=text, *b=memchr(a,0,(size_t)size);
    if (!b || strcmp(a,"/usr/libexec/luma-os/luma-platform")) return -1;
    ++b; size_t rest=(size_t)(text+size-b);
    const char *c=memchr(b,0,rest); if (!c) return -1;
    ++c; size_t argument_size=(size_t)(text+size-c);
    if (!argument_size || strnlen(c,argument_size)!=argument_size-1) return -1;
    if (!strcmp(b,"hardware-console")) {
        if (identifier(c,argument_size-1,32)) return -1;
    } else if (strcmp(b,"hardware-cleanup") || transaction(c,argument_size-1)) return -1;
    if (proc_file(pid,"stat",original_stat,stat_bound)<0 || live(pidfd)) return -1;
    return 0;
}
static inline int same_start(const char *first, const char *second) {
    /* comm can contain spaces/parentheses; the final ')' closes field2. */
    const char *a=strrchr(first,')'), *b=strrchr(second,')');
    if (!a||!b||a[1]!=' '||b[1]!=' ') return -1;
    a+=2;b+=2;
    for (unsigned field=3;field<22;field++) {
        a=strchr(a,' ');b=strchr(b,' ');if(!a||!b)return -1;++a;++b;
    }
    const char *ae=strchr(a,' '), *be=strchr(b,' ');
    if(!ae||!be||ae-a!=be-b||memcmp(a,b,(size_t)(ae-a))) return -1;
    return 0;
}
static inline int boot(char out[33]) {
    char text[64]; int size=read_file("/proc/sys/kernel/random/boot_id",text,sizeof(text));
    if(size!=37 || text[36]!='\n') return -1;
    size_t used=0;
    for(size_t i=0;i<36;i++) {
        if(i==8||i==13||i==18||i==23) {if(text[i]!='-')return -1;}
        else out[used++]=text[i];
    }
    out[used]=0;return generation(out,used);
}
static inline int restrict_capabilities(uint32_t retained) {
    struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
    struct __user_cap_data_struct values[2]={{0},{0}};
    values[0].effective=retained;values[0].permitted=retained;
    if(syscall(SYS_capset,&header,values)||syscall(SYS_capget,&header,values))return -1;
    return values[0].effective!=retained||values[0].permitted!=retained||values[0].inheritable||
        values[1].effective||values[1].permitted||values[1].inheritable ? -1 : 0;
}
static inline int descriptors(int *cgroup_fd,int *peer_fd) {
    int saved_cgroup=fcntl(*cgroup_fd,F_DUPFD_CLOEXEC,5),saved_pid=fcntl(*peer_fd,F_DUPFD_CLOEXEC,5);
    if(saved_cgroup<0||saved_pid<0||dup3(saved_cgroup,3,O_CLOEXEC)!=3||
        dup3(saved_pid,4,O_CLOEXEC)!=4||syscall(SYS_close_range,5,~0U,0))return -1;
    *cgroup_fd=3;*peer_fd=4;return 0;
}
#endif

