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

#include "sha256.h"
#include "error.h"
#include "bitwise.h"

static const uint32_t K[64] ={
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

MehSHA256 meh_get_sha256(void)
{
    MehSHA256 r = malloc(sizeof (meh_sha256_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_sha256");
        return NULL;
    }
    
    meh_reset_sha256(r);
    
    return r;
}

void meh_reset_sha256(MehSHA256 ctx)
{
    ctx->total[0] = ctx->total[1] = 0;
    
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
    
    ctx->hash_size = MEH_SHA256_HASH_SIZE;

    memset(ctx->buffer, 0, MEH_SHA256_BLOCK_SIZE);
}

MehSHA224 meh_get_sha224(void)
{
    MehSHA224 r = malloc(sizeof (meh_sha224_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_sha224");
        return NULL;
    }
    
    meh_reset_sha224(r);
    
    return r;
}

void meh_reset_sha224(MehSHA224 ctx)
{
    ctx->total[0] = ctx->total[1] = 0;
    
    ctx->state[0] = 0xC1059ED8;
    ctx->state[1] = 0x367CD507;
    ctx->state[2] = 0x3070DD17;
    ctx->state[3] = 0xF70E5939;
    ctx->state[4] = 0xFFC00B31;
    ctx->state[5] = 0x68581511;
    ctx->state[6] = 0x64F98FA7;
    ctx->state[7] = 0xBEFA4FA4;
    
    ctx->hash_size = MEH_SHA224_HASH_SIZE;

    memset(ctx->buffer, 0, MEH_SHA256_BLOCK_SIZE);
}

void meh_process_sha256(MehSHA256 ctx, const unsigned char* data)
{
    uint32_t A, B, C, D, E, F, G, H, W[64], t1, t2;

    W[ 0] = U8TO32_BIG(data,  0); W[ 1] = U8TO32_BIG(data,  4);
    W[ 2] = U8TO32_BIG(data,  8); W[ 3] = U8TO32_BIG(data, 12);
    W[ 4] = U8TO32_BIG(data, 16); W[ 5] = U8TO32_BIG(data, 20);
    W[ 6] = U8TO32_BIG(data, 24); W[ 7] = U8TO32_BIG(data, 28);
    W[ 8] = U8TO32_BIG(data, 32); W[ 9] = U8TO32_BIG(data, 36);
    W[10] = U8TO32_BIG(data, 40); W[11] = U8TO32_BIG(data, 44);
    W[12] = U8TO32_BIG(data, 48); W[13] = U8TO32_BIG(data, 52);
    W[14] = U8TO32_BIG(data, 56); W[15] = U8TO32_BIG(data, 60);

#   define THETA0(x) (ROTR32(x,7)^ROTR32(x,18)^(x >> 3))
#   define THETA1(x) (ROTR32(x,17)^ROTR32(x,19)^(x >> 10))
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

#   undef EXPAND
#   undef THETA0
#   undef THETA1

#   define SIGMA0(x)  (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#   define SIGMA1(x)  (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
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

void meh_update_sha256(MehSHA256 ctx, const unsigned char* data, size_t len)
{
    uint32_t left, fill;

    if (!len)
        return;

    left = (ctx->total[0] >> 3) & 0x3F; /* blocksize - 1 */
    fill = MEH_SHA256_BLOCK_SIZE - left;

    ctx->total[0] += len << 3;
    ctx->total[1] += len >> 29;
    ctx->total[1] += ctx->total[0] < (len << 3);

    if (left && len >= fill)
    {
        memcpy(ctx->buffer + left, data, fill);
        meh_process_sha256(ctx, ctx->buffer);
        len -= fill;
        data += fill;
        left = 0;
    }

    while (len >= MEH_SHA256_BLOCK_SIZE)
    {
        meh_process_sha256(ctx, data);
        len -= MEH_SHA256_BLOCK_SIZE;
        data += MEH_SHA256_BLOCK_SIZE;
    }

    if (len)
        memcpy(ctx->buffer + left, data, len);
}

static uint8_t meh_sha256_padding[MEH_SHA256_BLOCK_SIZE] = {0x80, 0x00,};

void meh_finish_sha256(MehSHA256 ctx, unsigned char* output)
{
    uint32_t last, padlen;
    uint8_t msglen[8];
     
    U32TO8_BIG(msglen, ctx->total[1], 0);
    U32TO8_BIG(msglen, ctx->total[0], 4);

    last = (ctx->total[0] >> 3) & 0x3F;
    padlen = ( 56 > last)?
             ( 56 - last):
             (120 - last);

    meh_update_sha256(ctx, meh_sha256_padding, padlen);
    meh_update_sha256(ctx, msglen, 8);

    U32TO8_BIG(output, ctx->state[0],  0);
    U32TO8_BIG(output, ctx->state[1],  4);
    U32TO8_BIG(output, ctx->state[2],  8);
    U32TO8_BIG(output, ctx->state[3], 12);
    U32TO8_BIG(output, ctx->state[4], 16);
    U32TO8_BIG(output, ctx->state[5], 20);
    U32TO8_BIG(output, ctx->state[6], 24);
    
    if (MEH_SHA256_HASH_SIZE == ctx->hash_size)
        U32TO8_BIG(output, ctx->state[7], 28);
}
