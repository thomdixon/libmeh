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

#ifndef MEH_SHA256_H
#define MEH_SHA256_H

#include "include.h"

#define MEH_SHA256_HASH_SIZE   32
#define MEH_SHA224_HASH_SIZE   28
#define MEH_SHA256_BLOCK_SIZE  64
#define MEH_SHA224_BLOCK_SIZE  64

typedef struct meh_sha256_state_s
{
    uint32_t total[2],
             state[8],
             hash_size;
    
    uint8_t buffer[MEH_SHA256_BLOCK_SIZE];
} meh_sha256_state_t;

typedef meh_sha256_state_t meh_sha224_state_t;
typedef meh_sha256_state_t* MehSHA256;
typedef MehSHA256 MehSHA224;

MehSHA256 meh_get_sha256(void);
void meh_reset_sha256(MehSHA256);
void meh_update_sha256(MehSHA256, const unsigned char*, size_t);
void meh_finish_sha256(MehSHA256, unsigned char*);
#define meh_destroy_sha256(x) free(x)

MehSHA224 meh_get_sha224(void);
void meh_reset_sha224(MehSHA224);
#define meh_update_sha224(x, y, z) meh_update_sha256((x), (y), (z))
#define meh_finish_sha224(x, y) meh_finish_sha256((x), (y))
#define meh_destroy_sha224(x) free(x)

#endif

