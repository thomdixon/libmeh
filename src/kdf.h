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

#ifndef MEH_KDF_H
#define MEH_KDF_H

#include "include.h"
#include "error.h"
#include "pbkdf2.h"

typedef enum
{
    MEH_PBKDF2
} meh_kdf_id;

typedef union meh_kdf_state_u
{
    MehPBKDF2 pbkdf2;
} meh_kdf_state_t;

typedef struct meh_kdf_s
{
    meh_kdf_state_t state;
    meh_kdf_id id;
} meh_kdf_t;

typedef meh_kdf_t* MehKDF;

MehKDF meh_get_kdf(const meh_kdf_id, ...);
meh_error_t meh_reset_kdf(MehKDF, ...);
meh_error_t meh_update_kdf(MehKDF, unsigned char*, size_t, size_t*);
meh_error_t meh_finish_kdf(MehKDF);
void meh_destroy_kdf(MehKDF);
meh_error_t meh_kdf(const meh_kdf_id, ...);

#endif
