#include "aes-ni.h"

#define u32 unsigned int
typedef int m128i_t __attribute__ ((__vector_size__ (16)));

/* Macros defining alias for the keyschedules.  */
#define keyschenc  u1.keyschedule
#define keyschdec  u2.keyschedule

static const unsigned char S[256] = {
    99, 124, 119, 123, 242, 107, 111, 197,
    48,   1, 103,  43, 254, 215, 171, 118,
    202, 130, 201, 125, 250,  89,  71, 240,
    173, 212, 162, 175, 156, 164, 114, 192,
    183, 253, 147,  38,  54,  63, 247, 204,
    52, 165, 229, 241, 113, 216,  49,  21,
    4, 199,  35, 195,  24, 150,   5, 154,
    7,  18, 128, 226, 235,  39, 178, 117,
    9, 131,  44,  26,  27, 110,  90, 160,
    82,  59, 214, 179,  41, 227,  47, 132,
    83, 209,   0, 237,  32, 252, 177,  91,
    106, 203, 190,  57,  74,  76,  88, 207,
    208, 239, 170, 251,  67,  77,  51, 133,
    69, 249,   2, 127,  80,  60, 159, 168,
    81, 163,  64, 143, 146, 157,  56, 245,
    188, 182, 218,  33,  16, 255, 243, 210,
    205,  12,  19, 236,  95, 151,  68,  23,
    196, 167, 126,  61, 100,  93,  25, 115,
    96, 129,  79, 220,  34,  42, 144, 136,
    70, 238, 184,  20, 222,  94,  11, 219,
    224,  50,  58,  10,  73,   6,  36,  92,
    194, 211, 172,  98, 145, 149, 228, 121,
    231, 200,  55, 109, 141, 213,  78, 169,
    108,  86, 244, 234, 101, 122, 174,   8,
    186, 120,  37,  46,  28, 166, 180, 198,
    232, 221, 116,  31,  75, 189, 139, 138,
    112,  62, 181, 102,  72,   3, 246,  14,
    97,  53,  87, 185, 134, 193,  29, 158,
    225, 248, 152,  17, 105, 217, 142, 148,
    155,  30, 135, 233, 206,  85,  40, 223,
    140, 161, 137,  13, 191, 230,  66, 104,
    65, 153,  45,  15, 176,  84, 187,  22
};

static const u32 rcon[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};

/* Perform the key setup.  */
static int do_setkey(RIJNDAEL_context *ctx, const char *key, int keylen)
{
    int rounds;
    int i,j, r, t, rconpointer = 0;
    int KC;
    union {
        unsigned char k[MAXKC][4];
    } k;
#define k k.k
    union {
        unsigned char tk[MAXKC][4];
    } tk;
#define tk tk.tk

    /* The on-the-fly self tests are only run in non-fips mode. In fips
       mode explicit self-tests are required.  Actually the on-the-fly
       self-tests are not fully thread-safe and it might happen that a
       failed self-test won't get noticed in another thread.

FIXME: We might want to have a central registry of succeeded
self-tests. */
    ctx->decryption_prepared = 0;

    if (keylen == 128/8) {
        rounds = 10;
        KC = 4;
    }
    ctx->rounds = rounds;

#define W (ctx->keyschenc)

    for (i = 0; i < keylen; i++) {
        k[i >> 2][i & 3] = key[i];
    }

    for (j = KC-1; j >= 0; j--) {
        *((u32*)tk[j]) = *((u32*)k[j]);
    }
    r = 0;
    t = 0;

    for (j = 0; (j < KC) && (r < rounds + 1); ) {
        for (; (j < KC) && (t < 4); j++, t++) {
            *((u32*)W[r][t]) = *((u32*)tk[j]);
        }
        if (t == 4) {
            r++;
            t = 0;
        }
    }

    while (r < rounds + 1) {
        tk[0][0] ^= S[tk[KC-1][1]];
        tk[0][1] ^= S[tk[KC-1][2]];
        tk[0][2] ^= S[tk[KC-1][3]];
        tk[0][3] ^= S[tk[KC-1][0]];
        tk[0][0] ^= rcon[rconpointer++];

        if (KC != 8) {
            for (j = 1; j < KC; j++) {
                *((u32*)tk[j]) ^= *((u32*)tk[j-1]);
            }
        } else {
            for (j = 1; j < KC/2; j++) {
                *((u32*)tk[j]) ^= *((u32*)tk[j-1]);
            }
            tk[KC/2][0] ^= S[tk[KC/2 - 1][0]];
            tk[KC/2][1] ^= S[tk[KC/2 - 1][1]];
            tk[KC/2][2] ^= S[tk[KC/2 - 1][2]];
            tk[KC/2][3] ^= S[tk[KC/2 - 1][3]];
            for (j = KC/2 + 1; j < KC; j++) {
                *((u32*)tk[j]) ^= *((u32*)tk[j-1]);
            }
        }

        // Copy values into round key array.
        for (j = 0; (j < KC) && (r < rounds + 1); ) {
            for (; (j < KC) && (t < 4); j++, t++) {
                *((u32*)W[r][t]) = *((u32*)tk[j]);
            }
            if (t == 4) {
                r++;
                t = 0;
            }
        }
#undef W
    }

    return 0;
#undef tk
#undef k
}

//# define aesni_prepare() do { } while (0)
//cj-hack: open fpu before do aes-ni
# define aesni_prepare()                                                \
    do {                                  \
    } while (0)
# define aesni_cleanup()                                                \
    do { asm volatile ("pxor %%xmm0, %%xmm0\n\t"                    \
            "pxor %%xmm1, %%xmm1\n" :: );                \
    } while (0)
# define aesni_cleanup_2_4()                                            \
    do { asm volatile ("pxor %%xmm2, %%xmm2\n\t"                    \
            "pxor %%xmm3, %%xmm3\n"                      \
            "pxor %%xmm4, %%xmm4\n":: );                 \
    } while (0)

static void prepare_decryption( RIJNDAEL_context *ctx )
{
    int r;

    /* The AES-NI decrypt instructions use the Equivalent Inverse
       Cipher, thus we can't use the the standard decrypt key
       preparation.  */
    m128i_t *ekey = (m128i_t*)ctx->keyschenc;
    m128i_t *dkey = (m128i_t*)ctx->keyschdec;
    int rr;

    dkey[0] = ekey[ctx->rounds];
    for (r=1, rr=ctx->rounds-1; r < ctx->rounds; r++, rr--) {
        asm volatile ("movdqu %[ekey], %%xmm1\n\t"
                /*"aesimc %%xmm1, %%xmm1\n\t"*/
                ".byte 0x66, 0x0f, 0x38, 0xdb, 0xc9\n\t"
                "movdqu %%xmm1, %[dkey]"
                : [dkey] "=m" (dkey[r])
                : [ekey] "m" (ekey[rr]) );
    }
    dkey[r] = ekey[0];
}

static void do_aesni_enc_aligned (const RIJNDAEL_context *ctx, unsigned char *b, const unsigned char *a)
{
    unsigned char *mkey = (unsigned char *)ctx->keyschenc;

#define aesenc_xmm1_xmm0      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xc1\n\t"
#define aesenclast_xmm1_xmm0  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xc1\n\t"

    asm volatile ("movdqu %[src], %%xmm0\n\t"     /* xmm0 := *a     */
            "movq   %[key], %%rsi\n\t"      /* esi  := keyschenc */
            "movdqa (%%rsi), %%xmm1\n\t"    /* xmm1 := key[0] */
            "pxor   %%xmm1, %%xmm0\n\t"     /* xmm0 ^= key[0] */
            "movdqa 0x10(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x20(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x30(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x40(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x50(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x60(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x70(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x80(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0x90(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0xa0(%%rsi), %%xmm1\n\t"
            "cmp $10, %[rounds]\n\t"
            "jz .Lenclast%=\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0xb0(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0xc0(%%rsi), %%xmm1\n\t"
            "cmp $12, %[rounds]\n\t"
            "jz .Lenclast%=\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0xd0(%%rsi), %%xmm1\n\t"
            aesenc_xmm1_xmm0
            "movdqa 0xe0(%%rsi), %%xmm1\n"

            ".Lenclast%=:\n\t"
            aesenclast_xmm1_xmm0
            "movdqu %%xmm0, %[dst]\n"
            : [dst] "=m" (*b)
            : [src] "m" (*a),
            //[key] "r" (ctx->keyschenc),
            [key] "m" (mkey),
            [rounds] "r" (ctx->rounds)
               : "%esi", "cc", "memory");
#undef aesenc_xmm1_xmm0
#undef aesenclast_xmm1_xmm0
}


static void do_aesni_dec_aligned (const RIJNDAEL_context *ctx,
        unsigned char *b, const unsigned char *a)
{
    char* mkey = (char *)&(ctx->keyschdec);
#define aesdec_xmm1_xmm0      ".byte 0x66, 0x0f, 0x38, 0xde, 0xc1\n\t"
#define aesdeclast_xmm1_xmm0  ".byte 0x66, 0x0f, 0x38, 0xdf, 0xc1\n\t"
    asm volatile ("movdqu %[src], %%xmm0\n\t"     /* xmm0 := *a     */
            "movq   %[key], %%rsi\n\t"
            "movdqa (%%rsi), %%xmm1\n\t"
            "pxor   %%xmm1, %%xmm0\n\t"     /* xmm0 ^= key[0] */
            "movdqa 0x10(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x20(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x30(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x40(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x50(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x60(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x70(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x80(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0x90(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0xa0(%%rsi), %%xmm1\n\t"
            "cmp $10, %[rounds]\n\t"
            "jz .Ldeclast%=\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0xb0(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0xc0(%%rsi), %%xmm1\n\t"
            "cmp $12, %[rounds]\n\t"
            "jz .Ldeclast%=\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0xd0(%%rsi), %%xmm1\n\t"
            aesdec_xmm1_xmm0
            "movdqa 0xe0(%%rsi), %%xmm1\n"

            ".Ldeclast%=:\n\t"
            aesdeclast_xmm1_xmm0
            "movdqu %%xmm0, %[dst]\n"
            : [dst] "=m" (*b)
            : [src] "m" (*a),
            //[key] "r" (ctx->keyschdec),
            [key] "m" (mkey),
            [rounds] "r" (ctx->rounds)
               : "%esi", "cc", "memory");
#undef aesdec_xmm1_xmm0
#undef aesdeclast_xmm1_xmm0
}


static void do_aesni (RIJNDAEL_context *ctx, int decrypt_flag,
        unsigned char *bx, const unsigned char *ax)
{
    if (decrypt_flag) {
        if (!ctx->decryption_prepared) {
            prepare_decryption(ctx);
            ctx->decryption_prepared = 1;
            printf("prepare decryption done.\n");
        }
        do_aesni_dec_aligned(ctx, bx, ax);
    } else {
        do_aesni_enc_aligned(ctx, bx, ax);
    }
}

void rijndael_encrypth (RIJNDAEL_context *context, unsigned char *b, const unsigned char *a)
{
    RIJNDAEL_context *ctx = context;

    aesni_prepare ();
    //fpu begin
    do_aesni (ctx, 0, b, a);
    //fpu end
    aesni_cleanup ();
}

void rijndael_decrypth (RIJNDAEL_context *context, unsigned char *b, const unsigned char *a)
{
    RIJNDAEL_context *ctx = context;

    aesni_prepare();
    //fpu begin
    //clts();
    do_aesni (ctx, 1, b, a);
    //fpu end
    aesni_cleanup();
    //stts();
}

int rijndael_setkey(void *context, char *key, int keylen)
{
    RIJNDAEL_context *ctx = context;
    int rc = 0;
    printf("before do setkey: ctx@%lx key@%lx keylen=%x.\n",
            (unsigned long)ctx, (unsigned long)key, keylen);
    rc = do_setkey (ctx, key, keylen);
    printf("Done.\n");
    ctx->key_prepared = 1;
    return rc;
}

//void _gcry_aes_cbc_enc (void *context, unsigned char *ivv,
//        char *outbuf_arg, const char *inbuf_arg,
//        unsigned int nblocks)
//{
//    RIJNDAEL_context *ctx = context;
//    unsigned char *outbuf = (unsigned char *)outbuf_arg;
//    const unsigned char *inbuf = (const unsigned char *)inbuf_arg;
//    unsigned char *ivp;
//    int i;
//    unsigned char iv[BLOCKSIZE];
//    memcpy(iv,ivv,BLOCKSIZE);
//    aesni_prepare ();
//    clts();
//    for ( ;nblocks; nblocks-- ) {
//        for (ivp=iv, i=0; i < BLOCKSIZE; i++ )
//            outbuf[i] = inbuf[i] ^ *ivp++;
//        do_aesni (ctx, 0, outbuf, outbuf);
//        memcpy (iv, outbuf, BLOCKSIZE);
//        inbuf += BLOCKSIZE;
//        outbuf += BLOCKSIZE;
//    }
//    aesni_cleanup ();
//    stts();
//    _gcry_burn_stack (48 + 2 * sizeof(int));
//}
//
///*
// * Bulk decryption of complete blocks in CBC mode.
// * Caller needs to make sure that IV is aligned on an unsigned long boundary.
// * This function is only intended for the bulk encryption feature of cipher.c.
// */
//void _gcry_aes_cbc_dec (void *context, unsigned char *ivv,
//        char *outbuf_arg, const char *inbuf_arg,
//        unsigned int nblocks)
//{
//    RIJNDAEL_context *ctx = context;
//    unsigned char *outbuf = (unsigned char *)outbuf_arg;
//    const unsigned char *inbuf = (const unsigned char *)inbuf_arg;
//    unsigned char *ivp;
//    int i;
//    unsigned char savebuf[BLOCKSIZE];
//    unsigned char iv[BLOCKSIZE];
//    memcpy(iv, ivv, BLOCKSIZE);
//    aesni_prepare ();
//    clts();
//    for ( ;nblocks; nblocks-- ) {
//        /* We need to save INBUF away because it may be identical to OUTBUF.  */
//        memcpy (savebuf, inbuf, BLOCKSIZE);
//        do_aesni (ctx, 1, outbuf, inbuf);
//        for (ivp=iv, i=0; i < BLOCKSIZE; i++ )
//            outbuf[i] ^= *ivp++;
//        memcpy (iv, savebuf, BLOCKSIZE);
//        inbuf += BLOCKSIZE;
//        outbuf += BLOCKSIZE;
//    }
//    aesni_cleanup ();
//    stts();
//    _gcry_burn_stack (48 + 2 * sizeof(int) + BLOCKSIZE + 4 * sizeof (char*));
//}

/*
 * AES-128 CBC encryption
 * I use a disk sector as a CBC unit with a IV,
 * current disk size is 512 bytes, so the blocks per CBC unit is 32.
 * The IV of every CBC unit is the sha1 hash value of disk sector data.
 * For testing, I will use a stable IV for each CBC unit.
 */
//extern unsigned char *hvmkey;
//extern RIJNDAEL_context actx;
//
//int aes_cbc_enc(char *ivv, u64 ma, int size, char *key)
//{
//    RIJNDAEL_context *ctx = &actx;
//    unsigned char *outbuf;
//    //const unsigned char *inbuf;
//    unsigned char *ivp;
//    int i;
//    unsigned char iv[BLOCKSIZE];
//    u32 nblocks = 0;
//    u64 enc_ma = ma;
//
//    //if (!io_enc_enabled)
//    //    return 0;
//    if (size != 512) {
//        printf("enc ma=%lx size=%x\n", ma, size);
//        BUG();
//    }
//    nblocks = size / BLOCKSIZE;
//    memcpy(iv, ivv, BLOCKSIZE);
//    aesni_prepare ();
//    clts();
//    outbuf = mfn_to_virt(ma >> PAGE_SHIFT) + (ma & 0xfff);
//    //inbuf = outbuf;
//    for ( ; nblocks; nblocks--) {
//        for (ivp = iv, i = 0; i < BLOCKSIZE; i++ )
//            //outbuf[i] = inbuf[i] ^ *ivp++;
//            outbuf[i] ^= *ivp++;
//        do_aesni (ctx, 0, outbuf, outbuf);
//        memcpy (iv, outbuf, BLOCKSIZE);
//        enc_ma += BLOCKSIZE;
//        outbuf = mfn_to_virt(enc_ma >> PAGE_SHIFT) + (enc_ma & 0xfff);
//        //inbuf = outbuf;
//    }
//    aesni_cleanup ();
//    stts();
//    _gcry_burn_stack (48 + 2 * sizeof(int));
//
//    return 0;
//}
//
//int aes_cbc_dec(char *ivv, u64 ma, int size, char *key)
//{
//    RIJNDAEL_context *ctx = &actx;
//    //unsigned char *outbuf;
//    unsigned char *inbuf;
//    unsigned char *ivp;
//    int i;
//    unsigned char savebuf[BLOCKSIZE];
//    unsigned char iv[BLOCKSIZE];
//    u32 nblocks = 0;
//    u64 dec_ma = ma;
//    static int fp = 1;
//
//    //if (!io_enc_enabled)
//    //    return 0;
//    if (size != 512) {
//        printf("enc ma=%lx size=%x\n", ma, size);
//        BUG();
//    }
//    nblocks = size / BLOCKSIZE;
//    if (ctx->key_prepared == 0) {
//        rijndael_setkey(ctx, key, 16);
//        printf("rijndael_setkey done!.\n");
//    }
//    memcpy(iv, ivv, BLOCKSIZE);
//    aesni_prepare ();
//    clts();
//    inbuf = mfn_to_virt(ma >> PAGE_SHIFT) + (ma & 0xfff);
//    //outbuf = inbuf;
//    for ( ; nblocks; nblocks--) {
//        /* We need to save INBUF away because it may be identical to OUTBUF. */
//        memcpy (savebuf, inbuf, BLOCKSIZE);
//        do_aesni (ctx, 1, inbuf, inbuf);
//        for (ivp = iv, i = 0; i < BLOCKSIZE; i++)
//            //outbuf[i] ^= *ivp++;
//            inbuf[i] ^= *ivp++;
//        memcpy (iv, savebuf, BLOCKSIZE);
//        dec_ma += BLOCKSIZE;
//        inbuf = mfn_to_virt(dec_ma >> PAGE_SHIFT) + (dec_ma & 0xfff);
//        //outbuf = inbuf;
//    }
//    aesni_cleanup ();
//    stts();
//    _gcry_burn_stack (48 + 2 * sizeof(int) + BLOCKSIZE + 4 * sizeof (char*));
//    if (fp) {
//        fp = 0;
//        printf("===Dec ma=0x%lx over, size=0x%x.\n", ma, size);
//    }
//    return 0;
//}
