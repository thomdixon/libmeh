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

#ifndef MEH_HASH_H
#define MEH_HASH_H

#include "include.h"
#include "error.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

typedef enum
{
    MEH_MD5,
    MEH_SHA1,
    MEH_SHA224,
    MEH_SHA256,
    MEH_SHA384,
    MEH_SHA512
} meh_hash_id;

typedef union meh_hash_state_u
{
    MehMD5 md5;
    MehSHA1 sha1;
    MehSHA256 sha256;
    MehSHA224 sha224;
    MehSHA384 sha384;
    MehSHA512 sha512;

} meh_hash_state_t;

typedef struct meh_hash_s
{
    meh_hash_state_t state;
    
    meh_hash_id id;

    size_t output_size,
           block_size;
} meh_hash_t;

typedef meh_hash_t* MehHash;

MehHash meh_get_hash(const meh_hash_id);
meh_error_t meh_reset_hash(MehHash);
meh_error_t meh_update_hash(MehHash, const unsigned char*, size_t);
meh_error_t meh_finish_hash(MehHash, unsigned char*);
void meh_destroy_hash(MehHash);
meh_error_t meh_hash(meh_hash_id, const unsigned char*, size_t, unsigned char*);
meh_error_t meh_hash_file(MehHash, FILE*);
size_t meh_hash_output_size(MehHash);
size_t meh_hash_block_size(MehHash);

#endif
