/*
Copyright (c) 2010 Thomas Dixon

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

#ifndef MEH_CIPHER_H
#define MEH_CIPHER_H

#include "include.h"
#include "error.h"
#include "rc4.h"
#include "salsa20.h"

typedef enum
{
    MEH_RC4,
    MEH_SALSA20
} meh_cipher_id;

typedef union meh_cipher_state_u
{
    MehRC4 rc4;
    MehSalsa20 salsa20;
    
} meh_cipher_state_t;

typedef struct meh_cipher_s
{
    meh_cipher_state_t state;
    meh_cipher_id id;
} meh_cipher_t;

typedef meh_cipher_t* MehCipher;

typedef union meh_cipher_args_u
{
    meh_rc4_args_t rc4;
    meh_salsa20_args_t salsa20;
} meh_cipher_args_t;

MehCipher meh_get_cipher(const meh_cipher_id, ...);
meh_error_t meh_reset_cipher(MehCipher, ...);
meh_error_t meh_update_cipher(MehCipher, const unsigned char*, unsigned char*,
                              size_t, size_t*);
meh_error_t meh_finish_cipher(MehCipher, unsigned char*, size_t*);
void meh_destroy_cipher(MehCipher);

#endif
