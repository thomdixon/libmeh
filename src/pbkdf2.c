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

#include "pbkdf2.h"
#include "bitwise.h"

void _increment_counter(uint8_t* in, size_t len)
{
    int i;

    if (len <= 0) /* shouldn't happen, but to prevent weird shit */
    {
        meh_warn("negative length passed to _increment_counter in pbkdf2");
        return;
    }
    
    for (i = len-1; i >= 0; i--)
        if (++in[i])
            break;
}

MehPBKDF2 meh_get_pbkdf2(const meh_hash_id hash_id,
                         const unsigned char* password, size_t pass_len,
                         const unsigned char* salt, size_t salt_len,
                         unsigned int iterations)
{
    meh_error_t error;
    MehPBKDF2 r = malloc(sizeof (meh_pbkdf2_state_t));

    if (NULL == r)
        goto meh_get_pbkdf2_allocation_failure;

    r->hmac = meh_get_hmac(hash_id, password, pass_len);

    if (NULL == r->hmac)
        goto meh_get_pbkdf2_hmac_allocation_failure;
    
    r->buffer = malloc(r->hmac->output_size);

    if (NULL == r->buffer)
        goto meh_get_pbkdf2_buffer_allocation_failure;

    r->tmp = malloc(r->hmac->output_size);

    if (NULL == r->tmp)
        goto meh_get_pbkdf2_tmp_allocation_failure;

    r->password = r->salt = NULL;
    
    if ((error = meh_reset_pbkdf2(r, password, pass_len,
                                  salt, salt_len, iterations)) != MEH_OK)
        goto meh_get_pbkdf2_reset_failure;
    
    return r;

meh_get_pbkdf2_reset_failure:
    free(r->tmp);
meh_get_pbkdf2_tmp_allocation_failure:
    free(r->buffer);
meh_get_pbkdf2_buffer_allocation_failure:
    meh_destroy_hmac(r->hmac);
meh_get_pbkdf2_hmac_allocation_failure:
    free(r);
meh_get_pbkdf2_allocation_failure:
    return NULL;
}   

meh_error_t meh_reset_pbkdf2(MehPBKDF2 kdf,
                             const unsigned char* password, size_t pass_len,
                             const unsigned char* salt, size_t salt_len,
                             unsigned int iterations)
{
    
    if (NULL == password || NULL == salt)
        return meh_error("invalid argument passed to meh_reset_pbkdf2",
                         MEH_INVALID_ARGUMENT);

    if (NULL == kdf->password)
    {
        kdf->password = malloc(pass_len);
        kdf->pass_len = pass_len;
    }
    else
        if (kdf->pass_len < pass_len)
            kdf->password = realloc(kdf->password, pass_len);

    if (NULL == kdf->password)
        return MEH_OUT_OF_MEMORY;

    memcpy(kdf->password, password, pass_len);

    if (NULL == kdf->salt)
    {
        kdf->salt = malloc(salt_len);
        kdf->salt_len = salt_len;
    }
    else
        if (kdf->salt_len < salt_len)
            kdf->salt = realloc(kdf->salt, salt_len);

    if (NULL == kdf->salt)
    {
        free(kdf->password);
        return MEH_OUT_OF_MEMORY;
    }

    memcpy(kdf->salt, salt, salt_len);

    kdf->iterations = iterations;

    kdf->index = kdf->hmac->output_size;
    
    memset(kdf->block_count, 0, sizeof (uint32_t));
    
    return meh_reset_hmac(kdf->hmac, kdf->password, kdf->pass_len);
}

meh_error_t meh_update_pbkdf2(MehPBKDF2 kdf, unsigned char* output,
                              size_t want_len, size_t* get_len)
{
    meh_error_t error;
    int i, j, k;

    *get_len = 0;
    error = MEH_OK;
    
    for (i = 0; i < want_len; i++)
    {
        if (kdf->index == kdf->hmac->output_size)
        {
            _increment_counter(kdf->block_count, sizeof (uint32_t));
            if (0 == U8TO32_BIG(kdf->block_count, 0))
            {
                /* little hacky but prevents reuse */
                memset(kdf->block_count, 0xff, sizeof (uint32_t));
                
                return meh_error("source exhausted in meh_update_pbkdf2",
                                 MEH_SOURCE_EXHAUSTED);
            }

            memset(kdf->buffer, 0, kdf->hmac->output_size);

            /* forego "real" error checking for speed */
            for (j = 0; j < kdf->iterations; j++)
            {
                error = meh_reset_hmac(kdf->hmac, kdf->password, kdf->pass_len);
                
                if (0 != j)
                    error = meh_update_hmac(kdf->hmac, kdf->tmp, kdf->hmac->output_size);
                else
                {
                    error = meh_update_hmac(kdf->hmac, kdf->salt, kdf->salt_len);
                    error = meh_update_hmac(kdf->hmac,
                                            kdf->block_count, sizeof (uint32_t));
                }
                
                error = meh_finish_hmac(kdf->hmac, kdf->tmp);

                for (k = 0; k < kdf->hmac->output_size; k++)
                    kdf->buffer[k] ^= kdf->tmp[k];
            }

            kdf->index = 0;
        }

        output[i] = kdf->buffer[kdf->index++];
        (*get_len)++;
    }

    return error; /* Yeah, this blows. I'll fix it later--maybe. */
}

void meh_destroy_pbkdf2(MehPBKDF2 kdf)
{
    if (NULL == kdf)
    {
        meh_warn("invalid argument passed to meh_destroy_pbkdf2");
        return;
    }
    
    meh_destroy_hmac(kdf->hmac);
    free(kdf->salt);
    free(kdf->password);
    free(kdf->buffer);
    free(kdf->tmp);
    free(kdf);
}
