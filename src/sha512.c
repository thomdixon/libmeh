/*
Copyright (c) 2009 Thomas Dixon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "sha512.h"
#include "error.h"
#include "bitwise.h"

static const uint64_t K[80] = {
    UINT64_C(0x428A2F98D728AE22), UINT64_C(0x7137449123EF65CD),
    UINT64_C(0xB5C0FBCFEC4D3B2F), UINT64_C(0xE9B5DBA58189DBBC),
    UINT64_C(0x3956C25BF348B538), UINT64_C(0x59F111F1B605D019),
    UINT64_C(0x923F82A4AF194F9B), UINT64_C(0xAB1C5ED5DA6D8118),
    UINT64_C(0xD807AA98A3030242), UINT64_C(0x12835B0145706FBE),
    UINT64_C(0x243185BE4EE4B28C), UINT64_C(0x550C7DC3D5FFB4E2),
    UINT64_C(0x72BE5D74F27B896F), UINT64_C(0x80DEB1FE3B1696B1),
    UINT64_C(0x9BDC06A725C71235), UINT64_C(0xC19BF174CF692694),
    UINT64_C(0xE49B69C19EF14AD2), UINT64_C(0xEFBE4786384F25E3),
    UINT64_C(0x0FC19DC68B8CD5B5), UINT64_C(0x240CA1CC77AC9C65),
    UINT64_C(0x2DE92C6F592B0275), UINT64_C(0x4A7484AA6EA6E483),
    UINT64_C(0x5CB0A9DCBD41FBD4), UINT64_C(0x76F988DA831153B5),
    UINT64_C(0x983E5152EE66DFAB), UINT64_C(0xA831C66D2DB43210),
    UINT64_C(0xB00327C898FB213F), UINT64_C(0xBF597FC7BEEF0EE4),
    UINT64_C(0xC6E00BF33DA88FC2), UINT64_C(0xD5A79147930AA725),
    UINT64_C(0x06CA6351E003826F), UINT64_C(0x142929670A0E6E70),
    UINT64_C(0x27B70A8546D22FFC), UINT64_C(0x2E1B21385C26C926),
    UINT64_C(0x4D2C6DFC5AC42AED), UINT64_C(0x53380D139D95B3DF),
    UINT64_C(0x650A73548BAF63DE), UINT64_C(0x766A0ABB3C77B2A8),
    UINT64_C(0x81C2C92E47EDAEE6), UINT64_C(0x92722C851482353B),
    UINT64_C(0xA2BFE8A14CF10364), UINT64_C(0xA81A664BBC423001),
    UINT64_C(0xC24B8B70D0F89791), UINT64_C(0xC76C51A30654BE30),
    UINT64_C(0xD192E819D6EF5218), UINT64_C(0xD69906245565A910),
    UINT64_C(0xF40E35855771202A), UINT64_C(0x106AA07032BBD1B8),
    UINT64_C(0x19A4C116B8D2D0C8), UINT64_C(0x1E376C085141AB53),
    UINT64_C(0x2748774CDF8EEB99), UINT64_C(0x34B0BCB5E19B48A8),
    UINT64_C(0x391C0CB3C5C95A63), UINT64_C(0x4ED8AA4AE3418ACB),
    UINT64_C(0x5B9CCA4F7763E373), UINT64_C(0x682E6FF3D6B2B8A3),
    UINT64_C(0x748F82EE5DEFB2FC), UINT64_C(0x78A5636F43172F60),
    UINT64_C(0x84C87814A1F0AB72), UINT64_C(0x8CC702081A6439EC),
    UINT64_C(0x90BEFFFA23631E28), UINT64_C(0xA4506CEBDE82BDE9),
    UINT64_C(0xBEF9A3F7B2C67915), UINT64_C(0xC67178F2E372532B),
    UINT64_C(0xCA273ECEEA26619C), UINT64_C(0xD186B8C721C0C207),
    UINT64_C(0xEADA7DD6CDE0EB1E), UINT64_C(0xF57D4F7FEE6ED178),
    UINT64_C(0x06F067AA72176FBA), UINT64_C(0x0A637DC5A2C898A6),
    UINT64_C(0x113F9804BEF90DAE), UINT64_C(0x1B710B35131C471B),
    UINT64_C(0x28DB77F523047D84), UINT64_C(0x32CAAB7B40C72493),
    UINT64_C(0x3C9EBE0A15C9BEBC), UINT64_C(0x431D67C49C100D4C),
    UINT64_C(0x4CC5D4BECB3E42B6), UINT64_C(0x597F299CFC657E2A),
    UINT64_C(0x5FCB6FAB3AD6FAEC), UINT64_C(0x6C44198C4A475817)
};

MehSHA512 meh_get_sha512(void)
{
    MehSHA512 r = malloc(sizeof (meh_sha512_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_sha512");
        return NULL;
    }
    
    meh_reset_sha512(r);
    
    return r;
}

void meh_reset_sha512(MehSHA512 ctx)
{
    ctx->total[0] = ctx->total[1] = 0;

    ctx->state[0] = UINT64_C(0x6A09E667F3BCC908);
    ctx->state[1] = UINT64_C(0xBB67AE8584CAA73B);
    ctx->state[2] = UINT64_C(0x3C6EF372FE94F82B);
    ctx->state[3] = UINT64_C(0xA54FF53A5F1D36F1);
    ctx->state[4] = UINT64_C(0x510E527FADE682D1);
    ctx->state[5] = UINT64_C(0x9B05688C2B3E6C1F);
    ctx->state[6] = UINT64_C(0x1F83D9ABFB41BD6B);
    ctx->state[7] = UINT64_C(0x5BE0CD19137E2179);
    
    ctx->hash_size = MEH_SHA512_HASH_SIZE;

    memset(ctx->buffer, 0, MEH_SHA512_BLOCK_SIZE);
}

MehSHA384 meh_get_sha384(void)
{
    MehSHA512 r = malloc(sizeof (meh_sha384_state_t));
    
    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_sha384");
        return NULL;
    }
    
    meh_reset_sha384(r);
    
    return r;
}

void meh_reset_sha384(MehSHA384 ctx)
{
    ctx->total[0] = ctx->total[1] = 0;

    ctx->state[0] = UINT64_C(0xCBBB9D5DC1059ED8);
    ctx->state[1] = UINT64_C(0x629A292A367CD507);
    ctx->state[2] = UINT64_C(0x9159015A3070DD17);
    ctx->state[3] = UINT64_C(0x152FECD8F70E5939);
    ctx->state[4] = UINT64_C(0x67332667FFC00B31);
    ctx->state[5] = UINT64_C(0x8EB44A8768581511);
    ctx->state[6] = UINT64_C(0xDB0C2E0D64F98FA7);
    ctx->state[7] = UINT64_C(0x47B5481DBEFA4FA4);
    
    ctx->hash_size = MEH_SHA384_HASH_SIZE;

    memset(ctx->buffer, 0, MEH_SHA512_BLOCK_SIZE);
}

void meh_process_sha512(MehSHA512 ctx, const unsigned char* data)
{
    uint64_t A, B, C, D, E, F, G, H, W[80], t1, t2;

    W[ 0] = U8TO64_BIG(data,   0); W[ 1] = U8TO64_BIG(data,   8);
    W[ 2] = U8TO64_BIG(data,  16); W[ 3] = U8TO64_BIG(data,  24);
    W[ 4] = U8TO64_BIG(data,  32); W[ 5] = U8TO64_BIG(data,  40);
    W[ 6] = U8TO64_BIG(data,  48); W[ 7] = U8TO64_BIG(data,  56);
    W[ 8] = U8TO64_BIG(data,  64); W[ 9] = U8TO64_BIG(data,  72);
    W[10] = U8TO64_BIG(data,  80); W[11] = U8TO64_BIG(data,  88);
    W[12] = U8TO64_BIG(data,  96); W[13] = U8TO64_BIG(data, 104);
    W[14] = U8TO64_BIG(data, 112); W[15] = U8TO64_BIG(data, 120);

#   define THETA0(x) (ROTR64(x,1)^ROTR64(x,8)^(x >> 7))
#   define THETA1(x) (ROTR64(x,19)^ROTR64(x,61)^(x >> 6))
#   define EXPAND(x) W[x]=THETA1(W[x-2])+W[x-7]+THETA0(W[x-15])+W[x-16];

    EXPAND(16); EXPAND(17); EXPAND(18); EXPAND(19);
    EXPAND(20); EXPAND(21); EXPAND(22); EXPAND(23);
    EXPAND(24); EXPAND(25); EXPAND(26); EXPAND(27);
    EXPAND(28); EXPAND(29); EXPAND(30); EXPAND(31);
    EXPAND(32); EXPAND(33); EXPAND(34); EXPAND(35);
    EXPAND(36); EXPAND(37); EXPAND(38); EXPAND(39);
    EXPAND(40); EXPAND(41); EXPAND(42); EXPAND(43);
    EXPAND(44); EXPAND(45); EXPAND(46); EXPAND(47);
    EXPAND(48); EXPAND(49); EXPAND(50); EXPAND(51);
    EXPAND(52); EXPAND(53); EXPAND(54); EXPAND(55);
    EXPAND(56); EXPAND(57); EXPAND(58); EXPAND(59);
    EXPAND(60); EXPAND(61); EXPAND(62); EXPAND(63);
    EXPAND(64); EXPAND(65); EXPAND(66); EXPAND(67);
    EXPAND(68); EXPAND(69); EXPAND(70); EXPAND(71);
    EXPAND(72); EXPAND(73); EXPAND(74); EXPAND(75);
    EXPAND(76); EXPAND(77); EXPAND(78); EXPAND(79);


#   undef EXPAND
#   undef THETA0
#   undef THETA1

#   define SIGMA0(x)  (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#   define SIGMA1(x)  (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#   define MAJ(x,y,z) ((x&y)|(z&(x^y)))
#   define CH(x,y,z)  (z^(x&(y^z)))
#   define T1(x)      (H+SIGMA1(E)+CH(E,F,G)+K[x]+W[x])
#   define T2(x)      (SIGMA0(A)+MAJ(A,B,C))
#   define STEP(n)    t1=T1(n);t2=T2(n);H=G;G=F;F=E;E=D+t1;D=C;C=B;B=A;A=t1+t2

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    STEP( 0); STEP( 1); STEP( 2); STEP( 3);
    STEP( 4); STEP( 5); STEP( 6); STEP( 7);
    STEP( 8); STEP( 9); STEP(10); STEP(11);
    STEP(12); STEP(13); STEP(14); STEP(15);
    STEP(16); STEP(17); STEP(18); STEP(19);
    STEP(20); STEP(21); STEP(22); STEP(23);
    STEP(24); STEP(25); STEP(26); STEP(27);
    STEP(28); STEP(29); STEP(30); STEP(31);
    STEP(32); STEP(33); STEP(34); STEP(35);
    STEP(36); STEP(37); STEP(38); STEP(39);
    STEP(40); STEP(41); STEP(42); STEP(43);
    STEP(44); STEP(45); STEP(46); STEP(47);
    STEP(48); STEP(49); STEP(50); STEP(51);
    STEP(52); STEP(53); STEP(54); STEP(55);
    STEP(56); STEP(57); STEP(58); STEP(59);
    STEP(60); STEP(61); STEP(62); STEP(63);
    STEP(64); STEP(65); STEP(66); STEP(67);
    STEP(68); STEP(69); STEP(70); STEP(71);
    STEP(72); STEP(73); STEP(74); STEP(75);
    STEP(76); STEP(77); STEP(78); STEP(79);
    
#   undef SIGMA0
#   undef SIGMA1
#   undef MAJ
#   undef CH
#   undef T1
#   undef T2
#   undef STEP

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

void meh_update_sha512(MehSHA512 ctx, const unsigned char* data, size_t len)
{
    uint32_t left, fill;

    if (!len)
        return;
    
    left = (ctx->total[0] >> 3) & 0x7f; /* blocksize - 1 */
    fill = MEH_SHA512_BLOCK_SIZE - left;

    ctx->total[0] += len << 3;
    ctx->total[1] += len >> 29;
    ctx->total[1] += ctx->total[0] < (len << 3);
    
    if (left && len >= fill)
    {
        memcpy(ctx->buffer + left, data, fill);
        meh_process_sha512(ctx, ctx->buffer);
        len -= fill;
        data += fill;
        left = 0;
    }

    while (len >= MEH_SHA512_BLOCK_SIZE)
    {
        meh_process_sha512(ctx, data);
        len -= MEH_SHA512_BLOCK_SIZE;
        data += MEH_SHA512_BLOCK_SIZE;
    }

    if (len)
        memcpy(ctx->buffer + left, data, len);
}

static uint8_t meh_sha512_padding[MEH_SHA512_BLOCK_SIZE] = {0x80, 0x00};

void meh_finish_sha512(MehSHA512 ctx, unsigned char* output)
{
    uint32_t last, padlen;
    uint8_t msglen[16] = {0};
    
    U32TO8_BIG(msglen, ctx->total[1], 8);
    U32TO8_BIG(msglen, ctx->total[0], 12);

    last = (ctx->total[0] >> 3) & 0x7f;
    padlen = (112 > last)?
             (112 - last):
             (240 - last);

    meh_update_sha512(ctx, meh_sha512_padding, padlen);
    meh_update_sha512(ctx, msglen, 16);
    
    U64TO8_BIG(output, ctx->state[0],  0);
    U64TO8_BIG(output, ctx->state[1],  8);
    U64TO8_BIG(output, ctx->state[2], 16);
    U64TO8_BIG(output, ctx->state[3], 24);
    U64TO8_BIG(output, ctx->state[4], 32);
    U64TO8_BIG(output, ctx->state[5], 40);
    
    if (MEH_SHA512_HASH_SIZE == ctx->hash_size)
    {
        U64TO8_BIG(output, ctx->state[6], 48);
        U64TO8_BIG(output, ctx->state[7], 56);
    }
}
