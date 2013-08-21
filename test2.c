#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    /* fork() is seccomp incompatible */
    fork();
    printf("We should never see this message");
    return 0;
}
