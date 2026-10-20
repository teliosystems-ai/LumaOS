/* SPDX-License-Identifier: MIT
 * Fixed daemon-role parsing and genuine pidfd/credential/filter mechanisms.
 * No installed daemon is impersonated and no production helper bypass exists.
 */
#define main production_daemon_observer_entry
#include "../image/hardware_query/daemon.c"
#undef main
#include <sys/wait.h>

static unsigned cases;
#define CHECK(condition) do {++cases;if(!(condition)){fprintf(stderr,"daemon observer case%u failed line%d\n",cases,__LINE__);exit(1);}}while(0)
static void intrinsic(void) {
    if(cut_syscalls())_exit(20);
    if(syscall(SYS_openat,AT_FDCWD,"/etc/passwd",O_RDONLY,0)!=-1||errno!=EPERM)_exit(21);
    if(syscall(SYS_ptrace,0,0,NULL,NULL)!=-1||errno!=EPERM)_exit(22);
    if(syscall(SYS_bpf,BPF_PROG_QUERY,NULL,0)!=-1||errno!=EPERM)_exit(23);
    if(syscall(SYS_socket,AF_UNIX,SOCK_STREAM,0)!=-1||errno!=EPERM)_exit(24);
    if(syscall(SYS_execve,"/nonexistent",NULL,NULL)!=-1||errno!=EPERM)_exit(25);
    if(syscall(SYS_fork)!=-1||errno!=EPERM)_exit(26);
    if(!boottime())_exit(27);
    _exit(0);
}
static int private_bus_hash(void) {
    pid_t child=fork();CHECK(child>=0);
    if(!child) {
        execl("/usr/bin/dbus-daemon","dbus-daemon","--session","--nofork","--nopidfile","--address=unix:tmpdir=/tmp",(char*)NULL);
        _exit(30);
    }
    int handle=(int)syscall(SYS_pidfd_open,child,0);CHECK(handle>=0);
    struct stat expected,actual;CHECK(!stat("/usr/bin/dbus-daemon",&expected));
    char path[64];int length=snprintf(path,sizeof(path),"/proc/%ld/exe",(long)child);
    CHECK(length>0&&length<(int)sizeof(path));
    uint64_t deadline=boottime()+1000;int matched=0;
    do {
        if(!stat(path,&actual)&&actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino){matched=1;break;}
        usleep(1000);
    }while(!live(handle)&&!within(deadline));
    CHECK(matched);
    struct request request={0};strcpy(request.role,"system-bus");request.deadline=boottime()+1000;
    struct proof proof={0};int result=hash_executable(child,&request,&proof);
    int signalled=kill(child,SIGTERM),status=0;pid_t waited=waitpid(child,&status,0);close(handle);
    CHECK(!result);CHECK(!signalled);CHECK(waited==child);
    CHECK(!strcmp(proof.sha,"8c479f1fcddfd6693c736ce541da0955f6752834bdeeef4b928e27f5e974c247"));
    CHECK(proof.device==(uint64_t)expected.st_dev&&proof.inode==(uint64_t)expected.st_ino);
    printf("{\"status\":\"passed\",\"actual_private_dbus_executable_sha256\":\"%s\",\"exact_process_inode_checked\":true,\"host_bus_contacted\":false,\"installed_role_qualified\":false}\n",proof.sha);
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--hash-private-bus"))return private_bus_hash();
    CHECK(argc==1);
    const char *valid="{\"schema_version\":1,\"nonce\":\"2323232323232323232323232323232323232323232323232323232323232323\",\"boot\":\"12121212121212121212121212121212\",\"deadline_ms\":\"90000\",\"role\":\"system-bus\"}";
    struct request request;CHECK(!parse(valid,strlen(valid),&request));CHECK(request.deadline==90000);
    for(size_t size=0;size<strlen(valid);size++)CHECK(parse(valid,size,&request));
    char changed[513];strcpy(changed,valid);strcat(changed,"\n");CHECK(parse(changed,strlen(changed),&request));
    strcpy(changed,valid);*strstr(changed,"90000")='0';CHECK(parse(changed,strlen(changed),&request));
    strcpy(changed,valid);memset(strstr(changed,"232323"),'0',64);CHECK(parse(changed,strlen(changed),&request));
    strcpy(changed,valid);*strstr(changed,"system-bus")='X';CHECK(parse(changed,strlen(changed),&request));
    strcpy(changed,valid);changed[1]=0;CHECK(parse(changed,strlen(valid),&request));
    uint64_t number=0;CHECK(!decimal_value("18446744073709551615",&number)&&number==UINT64_MAX);
    CHECK(decimal_value("18446744073709551616",&number));CHECK(decimal_value("+1",&number));
    CHECK(decimal_value("01",&number));CHECK(decimal_value("0",&number));
    int fd=(int)syscall(SYS_pidfd_open,getpid(),0);CHECK(fd>=0);pid_t actual=0;
    CHECK(!pid_from_fd(fd,&actual)&&actual==getpid());
    int unrelated=(int)syscall(SYS_memfd_create,"not-a-process",1);CHECK(unrelated>=0);
    CHECK(pid_from_fd(unrelated,&actual));close(unrelated);
    char stat_text[8192];uint64_t ticks=0;
    CHECK(proc_file(getpid(),"stat",stat_text,sizeof(stat_text))>0);CHECK(!start_ticks(stat_text,&ticks)&&ticks>0);
    CHECK(start_ticks("not a complete process stat",&ticks));
    CHECK(!strcmp(executable_path("system-bus"),"/usr/bin/dbus-daemon"));
    CHECK(!strcmp(unit("power-profiles"),"0::/system.slice/power-profiles-daemon.service\n"));
    struct proof proof;CHECK(!parse(valid,strlen(valid),&request));request.deadline=boottime()+1000;
    CHECK(capture(fd,&request,&proof)); /* current test executable is NOT dbus */
    close(fd);
    pid_t child=fork();CHECK(child>=0);if(!child)intrinsic();
    int status=0;CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    child=fork();CHECK(child>=0);if(!child){usleep(50000);_exit(0);}
    int dead=(int)syscall(SYS_pidfd_open,child,0);CHECK(dead>=0);
    CHECK(waitpid(child,&status,0)==child);CHECK(pid_from_fd(dead,&actual));close(dead);
    printf("{\"status\":\"passed\",\"assertions\":%u,\"actual_pidfd_generation_checked\":true,\"actual_dead_pidfd_refused\":true,\"actual_syscall_denials\":6,\"installed_daemons_qualified\":false}\n",cases);
    return 0;
}
