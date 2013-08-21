#include <stdio.h>

int main(int argc, char* argv[])
{
    FILE* f = fopen(argv[1], "rb");
    char buffer[80];
    while( fgets(buffer, sizeof(buffer), f) != NULL )
    {
        printf("%s", buffer);
    }
    fclose(f);
    return 0;
}
