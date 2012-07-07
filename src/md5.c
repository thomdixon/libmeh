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

#include "md5.h"
#include "error.h"
#include "bitwise.h"

MehMD5 meh_get_md5(void)
{
    MehMD5 r = malloc(sizeof (meh_md5_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_md5");
        return NULL;
    }
    
    meh_reset_md5(r);
    
    return r;
}

void meh_reset_md5(MehMD5 ctx)
{
    ctx->total[0] = ctx->total[1] = 0;
    
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;

    memset(ctx->buffer, 0, MEH_MD5_BLOCK_SIZE);
}

void meh_process_md5(MehMD5 ctx, const unsigned char* data)
{
    uint32_t A, B, C, D, X[16];

    X[ 0] = U8TO32_LITTLE(data,  0); X[ 1] = U8TO32_LITTLE(data,  4);
    X[ 2] = U8TO32_LITTLE(data,  8); X[ 3] = U8TO32_LITTLE(data, 12);
    X[ 4] = U8TO32_LITTLE(data, 16); X[ 5] = U8TO32_LITTLE(data, 20);
    X[ 6] = U8TO32_LITTLE(data, 24); X[ 7] = U8TO32_LITTLE(data, 28);
    X[ 8] = U8TO32_LITTLE(data, 32); X[ 9] = U8TO32_LITTLE(data, 36);
    X[10] = U8TO32_LITTLE(data, 40); X[11] = U8TO32_LITTLE(data, 44);
    X[12] = U8TO32_LITTLE(data, 48); X[13] = U8TO32_LITTLE(data, 52);
    X[14] = U8TO32_LITTLE(data, 56); X[15] = U8TO32_LITTLE(data, 60);

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    
#   define P(a,b,c,d,k,s,t) a+=F(b,c,d)+X[k]+t; a=ROTL32(a,s)+b
#   define F(x,y,z) (z^(x&(y^z)))

    P(A, B, C, D,  0,  7, 0xD76AA478); P(D, A, B, C,  1, 12, 0xE8C7B756);
    P(C, D, A, B,  2, 17, 0x242070DB); P(B, C, D, A,  3, 22, 0xC1BDCEEE);
    P(A, B, C, D,  4,  7, 0xF57C0FAF); P(D, A, B, C,  5, 12, 0x4787C62A);
    P(C, D, A, B,  6, 17, 0xA8304613); P(B, C, D, A,  7, 22, 0xFD469501);
    P(A, B, C, D,  8,  7, 0x698098D8); P(D, A, B, C,  9, 12, 0x8B44F7AF);
    P(C, D, A, B, 10, 17, 0xFFFF5BB1); P(B, C, D, A, 11, 22, 0x895CD7BE);
    P(A, B, C, D, 12,  7, 0x6B901122); P(D, A, B, C, 13, 12, 0xFD987193);
    P(C, D, A, B, 14, 17, 0xA679438E); P(B, C, D, A, 15, 22, 0x49B40821);

#   undef F
#   define F(x,y,z) (y^(z&(x^y)))

    P(A, B, C, D,  1,  5, 0xF61E2562); P(D, A, B, C,  6,  9, 0xC040B340);
    P(C, D, A, B, 11, 14, 0x265E5A51); P(B, C, D, A,  0, 20, 0xE9B6C7AA);
    P(A, B, C, D,  5,  5, 0xD62F105D); P(D, A, B, C, 10,  9, 0x02441453);
    P(C, D, A, B, 15, 14, 0xD8A1E681); P(B, C, D, A,  4, 20, 0xE7D3FBC8);
    P(A, B, C, D,  9,  5, 0x21E1CDE6); P(D, A, B, C, 14,  9, 0xC33707D6);
    P(C, D, A, B,  3, 14, 0xF4D50D87); P(B, C, D, A,  8, 20, 0x455A14ED);
    P(A, B, C, D, 13,  5, 0xA9E3E905); P(D, A, B, C,  2,  9, 0xFCEFA3F8);
    P(C, D, A, B,  7, 14, 0x676F02D9); P(B, C, D, A, 12, 20, 0x8D2A4C8A);

#   undef F
#   define F(x,y,z) (x^y^z)

    P(A, B, C, D,  5,  4, 0xFFFA3942); P(D, A, B, C,  8, 11, 0x8771F681);
    P(C, D, A, B, 11, 16, 0x6D9D6122); P(B, C, D, A, 14, 23, 0xFDE5380C);
    P(A, B, C, D,  1,  4, 0xA4BEEA44); P(D, A, B, C,  4, 11, 0x4BDECFA9);
    P(C, D, A, B,  7, 16, 0xF6BB4B60); P(B, C, D, A, 10, 23, 0xBEBFBC70);
    P(A, B, C, D, 13,  4, 0x289B7EC6); P(D, A, B, C,  0, 11, 0xEAA127FA);
    P(C, D, A, B,  3, 16, 0xD4EF3085); P(B, C, D, A,  6, 23, 0x04881D05);
    P(A, B, C, D,  9,  4, 0xD9D4D039); P(D, A, B, C, 12, 11, 0xE6DB99E5);
    P(C, D, A, B, 15, 16, 0x1FA27CF8); P(B, C, D, A,  2, 23, 0xC4AC5665);

#   undef F
#   define F(x,y,z) (y^(x|~z))

    P(A, B, C, D,  0,  6, 0xF4292244); P(D, A, B, C,  7, 10, 0x432AFF97);
    P(C, D, A, B, 14, 15, 0xAB9423A7); P(B, C, D, A,  5, 21, 0xFC93A039);
    P(A, B, C, D, 12,  6, 0x655B59C3); P(D, A, B, C,  3, 10, 0x8F0CCC92);
    P(C, D, A, B, 10, 15, 0xFFEFF47D); P(B, C, D, A,  1, 21, 0x85845DD1);
    P(A, B, C, D,  8,  6, 0x6FA87E4F); P(D, A, B, C, 15, 10, 0xFE2CE6E0);
    P(C, D, A, B,  6, 15, 0xA3014314); P(B, C, D, A, 13, 21, 0x4E0811A1);
    P(A, B, C, D,  4,  6, 0xF7537E82); P(D, A, B, C, 11, 10, 0xBD3AF235);
    P(C, D, A, B,  2, 15, 0x2AD7D2BB); P(B, C, D, A,  9, 21, 0xEB86D391);

#   undef F
#   undef P    

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}

void meh_update_md5(MehMD5 ctx, const unsigned char* data, size_t len)
{
    uint32_t left, fill;

    if (!len)
        return;

    left = (ctx->total[0] >> 3) & 0x3F;
    fill = MEH_MD5_BLOCK_SIZE - left;
 
    ctx->total[0] += len << 3;
    ctx->total[1] += len >> 29;
    ctx->total[1] += ctx->total[0] < (len << 3);
    
    if (left && len >= fill)
    {
        memcpy(ctx->buffer + left, data, fill);
        meh_process_md5(ctx, ctx->buffer);
        len -= fill;
        data += fill;
        left = 0;
    }

    while (len >= MEH_MD5_BLOCK_SIZE)
    {
        meh_process_md5(ctx, data);
        len -= MEH_MD5_BLOCK_SIZE;
        data += MEH_MD5_BLOCK_SIZE;
    }

    if (len)
        memcpy(ctx->buffer + left, data, len);  
}

static uint8_t meh_md5_padding[MEH_MD5_BLOCK_SIZE] = {0x80, 0x00,};

void meh_finish_md5(MehMD5 ctx, unsigned char* output)
{
    uint32_t last, padlen;
    uint8_t msglen[8];

    U32TO8_LITTLE(msglen, ctx->total[0], 0);
    U32TO8_LITTLE(msglen, ctx->total[1], 4);

    last = (ctx->total[0] >> 3) & 0x3F;
    padlen = ( 56 > last)?
             ( 56 - last):
             (120 - last);

    meh_update_md5(ctx, meh_md5_padding, padlen);
    meh_update_md5(ctx, msglen, 8);

    U32TO8_LITTLE(output, ctx->state[0],  0);
    U32TO8_LITTLE(output, ctx->state[1],  4);
    U32TO8_LITTLE(output, ctx->state[2],  8);
    U32TO8_LITTLE(output, ctx->state[3], 12);
}
