#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[])
{
    char *policy_file = argv[1];
    char *fname = "/sys/kernel/security/cloudarmor/policy";
    char *symbol = "#";
    unsigned char *policy;
    FILE *fr;
    FILE *fw;
    int size;
    int i = 0;

    if(argc <= 1)
    {
        printf("You need to specify policy file");
        exit(0);
    }

    fr = fopen(policy_file, "r");
    fseek(fr, 0L, SEEK_END);
    size = ftell(fr);
    fseek(fr, 0L, SEEK_SET);

    printf("Policy length is %d",size);
    policy = malloc(size);
    if(!policy)
    {
        printf("error malloc");
        exit(0);
    }
    fread(policy, 1, size, fr);
    fclose(fr);

    fw = fopen(fname, "w");
    fwrite(symbol, 1, 1, fw);
    fflush(fw);
    fwrite(&size, sizeof(int), 1, fw);
    fflush(fw);

    fwrite(policy, 1, size, fw);
    fflush(fw);
    /*
    while(i<size)
    {
        int to_write = size-i;
        if(to_write >= 512)
        {
            fwrite(policy+i, 1, 512, fw);
            i+=512;
        }
        else
        {
            fwrite(policy+i, 1, to_write, fw);
            i+=to_write;
        }
        fflush(fw);
    }
    */
    fclose(fw);
    free(policy);
}
