#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifndef _H_AES_NI_H_
#define _H_AES_NI_H_

#define u64 unsigned long
#define PAGE_SHIFT        12

#define MAXKC			(256/32) /* 8  */
#define MAXROUNDS		14
#define BLOCKSIZE               (128/8)  /* 16 */

typedef struct {
        /* The first fields are the keyschedule arrays.  This is so that
           they are aligned on a 16 byte boundary if using gcc.  This
           alignment is required for the AES-NI code and a good idea in any
           case.  The alignment is guaranteed due to the way cipher.c
           allocates the space for the context.  The PROPERLY_ALIGNED_TYPE
           hack is used to force a minimal alignment if not using gcc of if
           the alignment requirement is higher that 16 bytes.  */
        union {
                unsigned char keyschedule[MAXROUNDS+1][4][4];
        } u1;
        union {
                unsigned char keyschedule[MAXROUNDS+1][4][4];
        } u2;
        int rounds;               /* Key-length-dependent number of rounds.  */
        int decryption_prepared;  /* The decryption key schedule is available.  */
        int key_prepared;
} RIJNDAEL_context;

int rijndael_setkey(void *context, char *key, int keylen);
void rijndael_encrypth (RIJNDAEL_context *context, unsigned char *out, const unsigned char *in);
void rijndael_decrypth (RIJNDAEL_context *context, unsigned char *out, const unsigned char *in);
int aes_cbc_dec(char *ivv, u64 ma, int size, char *key);
int aes_cbc_enc(char *ivv, u64 ma, int size, char *key);

#endif
