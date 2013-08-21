#include <stdio.h>

int main(int argc, char* argv[])
{
    FILE* f = fopen("/tmp/out.txt", "wb");
    if( f != NULL )
    {
        fprintf(stderr, "File creation should have failed\n");
        return 1;
    }
    if( mkdir("/tmp/foobar") == 0 )
    {
        fprintf(stderr, "Directory creation should have failed\n");
        return 1;
    }
    return 0;
}

