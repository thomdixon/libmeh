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

#ifndef MEH_PBKDF2_H
#define MEH_PBKDF2_H

#include "hmac.h"
#include "include.h"

typedef struct meh_pbkdf2_state_s
{
    MehHMAC hmac;
    
    unsigned char* salt,
                 * password;

    size_t salt_len,
           pass_len;

    unsigned char* buffer,
                 * tmp;
    
    uint8_t  block_count[4];
    
    int iterations, index;
} meh_pbkdf2_state_t;

typedef meh_pbkdf2_state_t* MehPBKDF2;

MehPBKDF2 meh_get_pbkdf2(const meh_hash_id, const unsigned char*,
                         size_t, const unsigned char*, size_t, unsigned int);
meh_error_t meh_reset_pbkdf2(MehPBKDF2, const unsigned char*, size_t,
                             const unsigned char*, size_t, unsigned int);
meh_error_t meh_update_pbkdf2(MehPBKDF2, unsigned char*, size_t, size_t*);
#define meh_finish_pbkdf2(x) MEH_OK
void meh_destroy_pbkdf2(MehPBKDF2);

#endif
