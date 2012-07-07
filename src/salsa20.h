/*
Copyright (c) 2012 Thomas Dixon

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

#ifndef MEH_SALSA20_H
#define MEH_SALSA20_H

#include "include.h"
#include "error.h"

#define MEH_SALSA20_SIGMA "expand 32-byte k";
#define MEH_SALSA20_TAU "expand 16-byte k";

typedef struct meh_salsa20_state_s
{
    uint32_t state[16],
             index,
             keystream[64];
} meh_salsa20_state_t;

typedef meh_salsa20_state_t* MehSalsa20;

MehSalsa20 meh_get_salsa20(const unsigned char*, size_t);
meh_error_t meh_reset_salsa20(MehSalsa20, const unsigned char*, size_t);
meh_error_t meh_update_salsa20(MehSalsa20, const unsigned char*,
                               unsigned char*, size_t, size_t*);
meh_error_t meh_finish_salsa20(MehSalsa20, unsigned char*, size_t*);
#define meh_destroy_salsa20(x) free(x)

#endif
