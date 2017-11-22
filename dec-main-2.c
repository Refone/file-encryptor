#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>

#include "aes-ni.h"
#include "aes-ni-2.h"


RIJNDAEL_context actx;
AES_KEY enc_key;
AES_KEY dec_key;

void test()
{
    int i;

    do_setkey(&enc_key, &dec_key);

    printf("The Key Schedule:\n");
    for (i=0; i<=16; i++) {
        printf("[0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x]\n", 
                ((unsigned char*)enc_key.KEY)[16*i+0],
                ((unsigned char*)enc_key.KEY)[16*i+1],
                ((unsigned char*)enc_key.KEY)[16*i+2],
                ((unsigned char*)enc_key.KEY)[16*i+3],
                ((unsigned char*)enc_key.KEY)[16*i+4],
                ((unsigned char*)enc_key.KEY)[16*i+5],
                ((unsigned char*)enc_key.KEY)[16*i+6],
                ((unsigned char*)enc_key.KEY)[16*i+7],
                ((unsigned char*)enc_key.KEY)[16*i+8],
                ((unsigned char*)enc_key.KEY)[16*i+9],
                ((unsigned char*)enc_key.KEY)[16*i+10],
                ((unsigned char*)enc_key.KEY)[16*i+11],
                ((unsigned char*)enc_key.KEY)[16*i+12],
                ((unsigned char*)enc_key.KEY)[16*i+13],
                ((unsigned char*)enc_key.KEY)[16*i+14],
                ((unsigned char*)enc_key.KEY)[16*i+15]);
    }
    
    printf("The de-Key Schedule:\n");
    for (i=0; i<=16; i++) {
        printf("[0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x]\n", 
                ((unsigned char*)dec_key.KEY)[16*i+0],
                ((unsigned char*)dec_key.KEY)[16*i+1],
                ((unsigned char*)dec_key.KEY)[16*i+2],
                ((unsigned char*)dec_key.KEY)[16*i+3],
                ((unsigned char*)dec_key.KEY)[16*i+4],
                ((unsigned char*)dec_key.KEY)[16*i+5],
                ((unsigned char*)dec_key.KEY)[16*i+6],
                ((unsigned char*)dec_key.KEY)[16*i+7],
                ((unsigned char*)dec_key.KEY)[16*i+8],
                ((unsigned char*)dec_key.KEY)[16*i+9],
                ((unsigned char*)dec_key.KEY)[16*i+10],
                ((unsigned char*)dec_key.KEY)[16*i+11],
                ((unsigned char*)dec_key.KEY)[16*i+12],
                ((unsigned char*)dec_key.KEY)[16*i+13],
                ((unsigned char*)dec_key.KEY)[16*i+14],
                ((unsigned char*)dec_key.KEY)[16*i+15]);
    }
    char in[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    char out[16];

    aes_ni_enc(&dec_key, in, out, 16);
    for (i=0;i<16;i++)
        printf("0x%x ", out[i]);
    printf("\n");
}

int main(int argc, char * argv[])
{
    if (argv[1] && argv[2]) {
        printf("%s %s\n", argv[1], argv[2]);
    } else {
        printf("leak of parameter.\n");
        return 0;
    }

    unsigned long i;

    //char *input_file = argv[1];
    //char *output_file = argv[2];
    char *input_file = "./ubuntu-macro.img";
    char *output_file = "./ubuntu-aesni.img";

    //rijndael_setkey(&actx, hvmkey, 16);
    do_setkey(&enc_key, &dec_key);

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
        //printf("%d[%lx]\n", i, *((unsigned long *)in_handler+i));
        //rijndael_encrypth(&actx, tmp, in_handler+i);
        //aes_ni_enc(&enc_key, in_handler+i, tmp, 16);
        //printf("tmp[%lx]\n", *((unsigned long *)tmp));
        fwrite(tmp, 16, 1, out_fp);
    
