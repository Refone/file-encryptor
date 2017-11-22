#ifndef _H_AES_NI_2_H_
#define _H_AES_NI_2_H_

#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__((aligned(16)))
# else
# define ALIGN16 __declspec(align(16))
# endif
#endif

typedef struct KEY_SCHEDULE{
    ALIGN16 unsigned char KEY[16*15];
    unsigned int nr;
}AES_KEY;

extern void do_setkey(AES_KEY *enc_key, AES_KEY *dec_key);
extern void aes_ni_enc(AES_KEY *key, unsigned char *in, unsigned char *out, int len);
extern void aes_ni_dec(AES_KEY *key, unsigned char *in, unsigned char *out, int len);

#endif /* _H_AES_NI_2_H_ */
