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

#ifndef MEH_SHA512_H
#define MEH_SHA512_H

#include "include.h"

#define MEH_SHA512_HASH_SIZE   64
#define MEH_SHA384_HASH_SIZE   48
#define MEH_SHA512_BLOCK_SIZE  128
#define MEH_SHA384_BLOCK_SIZE  128

typedef struct meh_sha512_state_s
{
    uint32_t total[2],
             hash_size;
    
    uint64_t state[8];
    
    uint8_t buffer[MEH_SHA512_BLOCK_SIZE];
} meh_sha512_state_t;

typedef meh_sha512_state_t meh_sha384_state_t;
typedef meh_sha512_state_t* MehSHA512;
typedef MehSHA512 MehSHA384;

MehSHA512 meh_get_sha512(void);
void meh_reset_sha512(MehSHA512);
void meh_update_sha512(MehSHA512, const unsigned char*, size_t);
void meh_finish_sha512(MehSHA512, unsigned char*);
#define meh_destroy_sha512(x) free(x)

MehSHA384 meh_get_sha384(void);
void meh_reset_sha384(MehSHA384);
#define meh_update_sha384(x, y, z) meh_update_sha512((x), (y), (z))
#define meh_finish_sha384(x, y) meh_finish_sha512((x), (y))
#define meh_destroy_sha384(x) free(x)

#endif

