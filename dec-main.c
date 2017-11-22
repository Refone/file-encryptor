#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>

#include "aes-ni.h"

static unsigned char hvmkey[16] =
{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};


RIJNDAEL_context actx;

int main(int argc, char * argv[])
{
    if (argv[1] && argv[2]) {
        printf("%s %s\n", argv[1], argv[2]);
    } else {
        printf("leak of parameter.\n");
        return 0;
    }

    unsigned long i;

    char *input_file = argv[1];
    char *output_file = argv[2];

    rijndael_setkey(&actx, hvmkey, 16);

    unsigned long filesize = -1;  
    FILE *in_fp = fopen(input_file, "r");
    FILE *out_fp = fopen(output_file, "wb+");
    fseek(in_fp, 0L, SEEK_END);  
    filesize = ftell(in_fp); 

    printf("%s %s\n", input_file, output_file);
    printf("%p %p\n", in_fp, out_fp);
    printf("filesize:%lu\n", filesize);

    printf("%d %d\n", fileno(in_fp), fileno(out_fp));
    //void *out_handler = mmap(0, filesize, PROT_WRITE, MAP_SHARED, fileno(out_fp), 0);
    void *in_handler = mmap(0, filesize, PROT_READ, MAP_SHARED, fileno(in_fp), 0);
    perror("mmap:");

    printf("in_handler: %lx\n", (unsigned long)in_handler);
    //printf("out_handler: %lx\n", (unsigned long)out_handler);

    unsigned char tmp[200]; 
    for (i=0; i<filesize; i+=16) {
//        printf("%d[%lx]\n", i, *((unsigned long *)in_handler+i));
        rijndael_decrypth(&actx, tmp, in_handler+i);
//        printf("tmp[%lx]\n", *((unsigned long *)tmp));
        fwrite(tmp, 16, 1, out_fp);
    }

    fclose(in_fp);
    fclose(out_fp);

    return 0;
}
