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

#ifndef MEH_SHA1_H
#define MEH_SHA1_H

#include "include.h"

#define MEH_SHA1_HASH_SIZE   20
#define MEH_SHA1_BLOCK_SIZE  64

typedef struct meh_sha1_state_s
{
    uint32_t total[2],
             state[5];
    
    uint8_t buffer[MEH_SHA1_BLOCK_SIZE];
} meh_sha1_state_t;

typedef meh_sha1_state_t* MehSHA1;

MehSHA1 meh_get_sha1(void);
void meh_reset_sha1(MehSHA1);
void meh_update_sha1(MehSHA1, const unsigned char*, size_t);
void meh_finish_sha1(MehSHA1, unsigned char*);
#define meh_destroy_sha1(x) free(x)

#endif
