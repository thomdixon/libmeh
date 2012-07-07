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

#include "sha1.h"
#include "error.h"
#include "bitwise.h"

MehSHA1 meh_get_sha1(void)
{
    MehSHA1 r = malloc(sizeof (meh_sha1_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_sha1");
        return NULL;
    }
    
    meh_reset_sha1(r);
    
    return r;
}

void meh_reset_sha1(MehSHA1 ctx)
{
    ctx->total[0] = ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    memset(ctx->buffer, 0, MEH_SHA1_BLOCK_SIZE);
}

void meh_process_sha1(MehSHA1 ctx, const unsigned char* data)
{
    uint32_t A, B, C, D, E, W[80];

    W[ 0] = U8TO32_BIG(data,  0); W[ 1] = U8TO32_BIG(data,  4);
    W[ 2] = U8TO32_BIG(data,  8); W[ 3] = U8TO32_BIG(data, 12);
    W[ 4] = U8TO32_BIG(data, 16); W[ 5] = U8TO32_BIG(data, 20);
    W[ 6] = U8TO32_BIG(data, 24); W[ 7] = U8TO32_BIG(data, 28);
    W[ 8] = U8TO32_BIG(data, 32); W[ 9] = U8TO32_BIG(data, 36);
    W[10] = U8TO32_BIG(data, 40); W[11] = U8TO32_BIG(data, 44);
    W[12] = U8TO32_BIG(data, 48); W[13] = U8TO32_BIG(data, 52);
    W[14] = U8TO32_BIG(data, 56); W[15] = U8TO32_BIG(data, 60);

#   define EXPAND(x) W[x]=ROTL32(W[x-3]^W[x-8]^W[x-14]^W[x-16], 1)

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
    
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#   define PERMUTE(a,b,c,d,e,f) a+=ROTL32(b,5)+F(c,d,e)+W[f]; c=ROTL32(c,30)
#   define F(x,y,z) (z^(x&(y^z))) + 0x5A827999

    PERMUTE(E, A, B, C, D,  0); PERMUTE(D, E, A, B, C,  1);
    PERMUTE(C, D, E, A, B,  2); PERMUTE(B, C, D, E, A,  3);
    PERMUTE(A, B, C, D, E,  4); PERMUTE(E, A, B, C, D,  5);
    PERMUTE(D, E, A, B, C,  6); PERMUTE(C, D, E, A, B,  7);
    PERMUTE(B, C, D, E, A,  8); PERMUTE(A, B, C, D, E,  9);
    PERMUTE(E, A, B, C, D, 10); PERMUTE(D, E, A, B, C, 11);
    PERMUTE(C, D, E, A, B, 12); PERMUTE(B, C, D, E, A, 13);
    PERMUTE(A, B, C, D, E, 14); PERMUTE(E, A, B, C, D, 15);
    PERMUTE(D, E, A, B, C, 16); PERMUTE(C, D, E, A, B, 17);
    PERMUTE(B, C, D, E, A, 18); PERMUTE(A, B, C, D, E, 19);

#   undef F
#   define F(x,y,z) (x^y^z) + 0x6ED9EBA1

    PERMUTE(E, A, B, C, D, 20); PERMUTE(D, E, A, B, C, 21);
    PERMUTE(C, D, E, A, B, 22); PERMUTE(B, C, D, E, A, 23);
    PERMUTE(A, B, C, D, E, 24); PERMUTE(E, A, B, C, D, 25);
    PERMUTE(D, E, A, B, C, 26); PERMUTE(C, D, E, A, B, 27);
    PERMUTE(B, C, D, E, A, 28); PERMUTE(A, B, C, D, E, 29);
    PERMUTE(E, A, B, C, D, 30); PERMUTE(D, E, A, B, C, 31);
    PERMUTE(C, D, E, A, B, 32); PERMUTE(B, C, D, E, A, 33);
    PERMUTE(A, B, C, D, E, 34); PERMUTE(E, A, B, C, D, 35);
    PERMUTE(D, E, A, B, C, 36); PERMUTE(C, D, E, A, B, 37);
    PERMUTE(B, C, D, E, A, 38); PERMUTE(A, B, C, D, E, 39);

#   undef F
#   define F(x,y,z) ((x&y)|(z&(x|y))) + 0x8F1BBCDC

    PERMUTE(E, A, B, C, D, 40); PERMUTE(D, E, A, B, C, 41);
    PERMUTE(C, D, E, A, B, 42); PERMUTE(B, C, D, E, A, 43);
    PERMUTE(A, B, C, D, E, 44); PERMUTE(E, A, B, C, D, 45);
    PERMUTE(D, E, A, B, C, 46); PERMUTE(C, D, E, A, B, 47);
    PERMUTE(B, C, D, E, A, 48); PERMUTE(A, B, C, D, E, 49);
    PERMUTE(E, A, B, C, D, 50); PERMUTE(D, E, A, B, C, 51);
    PERMUTE(C, D, E, A, B, 52); PERMUTE(B, C, D, E, A, 53);
    PERMUTE(A, B, C, D, E, 54); PERMUTE(E, A, B, C, D, 55);
    PERMUTE(D, E, A, B, C, 56); PERMUTE(C, D, E, A, B, 57);
    PERMUTE(B, C, D, E, A, 58); PERMUTE(A, B, C, D, E, 59);

#   undef F
#   define F(x,y,z) (x^y^z) + 0xCA62C1D6

    PERMUTE(E, A, B, C, D, 60); PERMUTE(D, E, A, B, C, 61);
    PERMUTE(C, D, E, A, B, 62); PERMUTE(B, C, D, E, A, 63);
    PERMUTE(A, B, C, D, E, 64); PERMUTE(E, A, B, C, D, 65);
    PERMUTE(D, E, A, B, C, 66); PERMUTE(C, D, E, A, B, 67);
    PERMUTE(B, C, D, E, A, 68); PERMUTE(A, B, C, D, E, 69);
    PERMUTE(E, A, B, C, D, 70); PERMUTE(D, E, A, B, C, 71);
    PERMUTE(C, D, E, A, B, 72); PERMUTE(B, C, D, E, A, 73);
    PERMUTE(A, B, C, D, E, 74); PERMUTE(E, A, B, C, D, 75);
    PERMUTE(D, E, A, B, C, 76); PERMUTE(C, D, E, A, B, 77);
    PERMUTE(B, C, D, E, A, 78); PERMUTE(A, B, C, D, E, 79);

#   undef F
#   undef PERMUTE    

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

void meh_update_sha1(MehSHA1 ctx, const unsigned char* data, size_t len)
{
    uint32_t left, fill;

    if(!len)
        return;

    left = (ctx->total[0] >> 3) & 0x3F;
    fill = MEH_SHA1_BLOCK_SIZE - left;

    ctx->total[0] += len << 3;
    ctx->total[1] += len >> 29;
    ctx->total[1] += ctx->total[0] < (len << 3);

    if(left && len >= fill)
    {
        memcpy(ctx->buffer + left, data, fill);
        meh_process_sha1(ctx, ctx->buffer);
        len -= fill;
        data += fill;
        left = 0;
    }

    while(len >= MEH_SHA1_BLOCK_SIZE)
    {
        meh_process_sha1(ctx, data);
        len -= MEH_SHA1_BLOCK_SIZE;
        data += MEH_SHA1_BLOCK_SIZE;
    }

    if(len)
        memcpy(ctx->buffer + left, data, len);
}

static uint8_t meh_sha1_padding[MEH_SHA1_BLOCK_SIZE] = {0x80, 0x00,};

void meh_finish_sha1(MehSHA1 ctx, unsigned char* output)
{
    uint32_t last, padlen;
    uint8_t msglen[8];
    
    U32TO8_BIG(msglen, ctx->total[1], 0);
    U32TO8_BIG(msglen, ctx->total[0], 4);

    last = (ctx->total[0] >> 3) & 0x3F;
    padlen = ( 56 > last)?
             ( 56 - last):
             (120 - last);

    meh_update_sha1(ctx, meh_sha1_padding, padlen);
    meh_update_sha1(ctx, msglen, 8);

    U32TO8_BIG(output, ctx->state[0],  0);
    U32TO8_BIG(output, ctx->state[1],  4);
    U32TO8_BIG(output, ctx->state[2],  8);
    U32TO8_BIG(output, ctx->state[3], 12);
    U32TO8_BIG(output, ctx->state[4], 16);
}
