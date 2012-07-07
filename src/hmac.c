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

#include "hmac.h"

MehHMAC meh_get_hmac(const meh_hash_id hash_id,
                     const unsigned char* key, size_t len)
{
    meh_error_t error;
    MehHMAC r = malloc(sizeof (meh_hmac_t));
    
    if (NULL == r)
        goto meh_get_hmac_allocation_failure;
    
    r->inner = meh_get_hash(hash_id);

    if (NULL == r->inner)
        goto meh_get_hmac_inner_allocation_failure;
    
    r->outer = meh_get_hash(hash_id);

    if (NULL == r->outer)
        goto meh_get_hmac_outer_allocation_failure;

    r->block_size = r->inner->block_size;
    r->output_size = r->inner->output_size;
    r->id = r->inner->id;
    
    r->opad = malloc(r->block_size);
    
    if (NULL == r->opad)
        goto meh_get_hmac_opad_allocation_failure;

    r->ipad = malloc(r->block_size);

    if (NULL == r->ipad)
        goto meh_get_hmac_ipad_allocation_failure;

    r->tmp = malloc(r->output_size);

    if (NULL == r->tmp)
        goto meh_get_hmac_tmp_allocation_failure;

    if ((error = meh_reset_hmac(r, key, len)) != MEH_OK)
        goto meh_get_hmac_reset_failure;

    return r;
    
meh_get_hmac_reset_failure:
    free(r->tmp);
meh_get_hmac_tmp_allocation_failure:
    free(r->ipad);
meh_get_hmac_ipad_allocation_failure:
    free(r->opad);
meh_get_hmac_opad_allocation_failure:
    meh_destroy_hash(r->outer);
meh_get_hmac_outer_allocation_failure:
    meh_destroy_hash(r->inner);
meh_get_hmac_inner_allocation_failure:
    free(r);
meh_get_hmac_allocation_failure:
    meh_warn("allocation failure in meh_get_hmac");
    return NULL;
    
}

meh_error_t meh_reset_hmac(MehHMAC hmac, const unsigned char* key, size_t len)
{
    int i;
    meh_error_t error;
    
    if (NULL == hmac || NULL == key)
        return meh_error("invalid argument passed to meh_reset_hmac",
                         MEH_INVALID_ARGUMENT);
    
    memset(hmac->ipad, 0, hmac->block_size);

    if (len > hmac->block_size)
        meh_hash(hmac->id, key, len, hmac->ipad);
    else
        memcpy(hmac->ipad, key, len);

    memcpy(hmac->opad, hmac->ipad, hmac->block_size);

    for (i = 0; i < hmac->block_size; i++)
    {
        hmac->ipad[i] ^= 0x36;
        hmac->opad[i] ^= 0x5c;
    }

    if ((error = meh_reset_hash(hmac->inner)) != MEH_OK)
        return error;

    if ((error = meh_reset_hash(hmac->outer)) != MEH_OK)
        return error;
    
    error = meh_update_hash(hmac->inner, hmac->ipad, hmac->block_size);
    return error;
}

meh_error_t meh_update_hmac(MehHMAC hmac, const unsigned char* data, size_t len)
{
    if (NULL == hmac)
        return meh_error("invalid argument passed to meh_update_hmac",
                         MEH_INVALID_ARGUMENT);

    return meh_update_hash(hmac->inner, data, len);
}

meh_error_t meh_finish_hmac(MehHMAC hmac, unsigned char* output)
{
    meh_error_t error;
    
    if (NULL == hmac)
        return meh_error("invalid argument passed to meh_update_hmac",
                         MEH_INVALID_ARGUMENT);
    
    if ((error = meh_finish_hash(hmac->inner, hmac->tmp)) != MEH_OK)
        return error;

    if ((error = meh_update_hash(hmac->outer,
                                 hmac->opad, hmac->block_size)) != MEH_OK)
        return error;

    if ((error = meh_update_hash(hmac->outer,
                                 hmac->tmp, hmac->output_size)) != MEH_OK)
        return error;

    if ((error = meh_finish_hash(hmac->outer, output)) != MEH_OK)
        return error;

    return MEH_OK;
}

void meh_destroy_hmac(MehHMAC hmac)
{
    if (NULL == hmac)
    {
        meh_warn("invalid argument passed to meh_destroy_hmac");
        return;
    }
    
    free(hmac->tmp);
    free(hmac->ipad);
    free(hmac->opad);
    meh_destroy_hash(hmac->outer);
    meh_destroy_hash(hmac->inner);
    free(hmac);
}

meh_error_t meh_hmac(const meh_hash_id hash_id, const unsigned char* data,
                     size_t data_len, const unsigned char* key, size_t key_len,
                     unsigned char* output)
{
    meh_error_t error;
    MehHMAC t = meh_get_hmac(hash_id, key, key_len);
    
    if (NULL == t)
        return MEH_ERROR;
    
    if ((error = meh_update_hmac(t, data, data_len)) != MEH_OK)
    {
        meh_destroy_hmac(t);
        return error;
    }
    
    if ((error = meh_finish_hmac(t, output)) != MEH_OK)
    {
        meh_destroy_hmac(t);
        return error;
    }
    
    meh_destroy_hmac(t);
    
    return MEH_OK;
}

meh_error_t meh_hmac_file(MehHMAC hmac, FILE* fd)
{
    int count;
    meh_error_t error;
    unsigned char buffer[8192];

    if (NULL == fd || NULL == hmac)
        return MEH_INVALID_ARGUMENT;

    while ((count = fread(buffer, sizeof (unsigned char), 8192, fd)) != 0)
    {
        if ((error = meh_update_hmac(hmac, buffer, count)) != MEH_OK)
            return error;
    }
    
    return MEH_OK;
}

    
