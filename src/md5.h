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

#ifndef MEH_MD5_H
#define MEH_MD5_H

#include "include.h"

#define MEH_MD5_HASH_SIZE   16
#define MEH_MD5_BLOCK_SIZE  64

typedef struct meh_md5_state_s
{
    uint32_t total[2],
             state[4];
    
    uint8_t buffer[MEH_MD5_BLOCK_SIZE];
} meh_md5_state_t;

typedef meh_md5_state_t* MehMD5;

MehMD5 meh_get_md5(void);
void meh_reset_md5(MehMD5);
void meh_update_md5(MehMD5, const unsigned char*, size_t);
void meh_finish_md5(MehMD5, unsigned char*);
#define meh_destroy_md5(x) free(x)

#endif
