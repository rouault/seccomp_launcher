#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    /* fork() is seccomp incompatible */
    syscall( SYS_fork );
    printf("We should never see this message.\n");
    return 0;
}
