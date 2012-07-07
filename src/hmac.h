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

#ifndef MEH_HMAC_H
#define MEH_HMAC_H

#include "hash.h"

typedef struct meh_hmac_s
{
    MehHash inner, outer;
    
    uint8_t* opad,
           * ipad,
           * tmp;
    
    size_t output_size, block_size;
    
    meh_hash_id id;
} meh_hmac_t;

typedef meh_hmac_t* MehHMAC;

MehHMAC meh_get_hmac(const meh_hash_id, const unsigned char*, size_t);
meh_error_t meh_reset_hmac(MehHMAC, const unsigned char*, size_t);
meh_error_t meh_update_hmac(MehHMAC, const unsigned char*, size_t);
meh_error_t meh_finish_hmac(MehHMAC, unsigned char*);
meh_error_t meh_hmac(const meh_hash_id, const unsigned char*, size_t,
                     const unsigned char*, size_t, unsigned char*);
meh_error_t meh_hmac_file(MehHMAC, FILE*);
void meh_destroy_hmac(MehHMAC);

#endif
