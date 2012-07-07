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

#include "hash.h"

/* Is there a better way to do this?
   Macros are hideous, but an option. */

MehHash meh_get_hash(const meh_hash_id hash_id)
{   
    MehHash r = malloc(sizeof (meh_hash_t));
    
    if (NULL == r)
    {
        meh_warn("could not allocate hash context in meh_get_hash");
        return NULL;
    }
    
    r->id = hash_id;
    
    switch (hash_id)
    {
        case MEH_MD5:
            r->state.md5 = meh_get_md5();
            if (NULL == r->state.md5)
                goto meh_get_hash_allocation_failure;
            break;
        case MEH_SHA1:
            r->state.sha1 = meh_get_sha1();
            if (NULL == r->state.sha1)
                goto meh_get_hash_allocation_failure;
            break;
        case MEH_SHA224:
            r->state.sha224 = meh_get_sha224();
            if (NULL == r->state.sha224)
                goto meh_get_hash_allocation_failure;
            break;
        case MEH_SHA256:
            r->state.sha256 = meh_get_sha256();
            if (NULL == r->state.sha256)
                goto meh_get_hash_allocation_failure;
            break;
        case MEH_SHA384:
            r->state.sha384 = meh_get_sha384();
            if (NULL == r->state.sha384)
                goto meh_get_hash_allocation_failure;
            break;
        case MEH_SHA512:
            r->state.sha512 = meh_get_sha512();
            if (NULL == r->state.sha512)
                goto meh_get_hash_allocation_failure;
            break;
        default:
            meh_warn("invalid hash id passed to meh_get_hash");
            goto meh_get_hash_allocation_failure;
    }

    r->output_size = meh_hash_output_size(r);
    r->block_size = meh_hash_block_size(r);
    
    return r;

meh_get_hash_allocation_failure:
    free(r);
    return NULL;
}

meh_error_t meh_reset_hash(MehHash hash)
{
    if (NULL == hash)
        return meh_error("invalid argument passed to meh_reset_hash",
                         MEH_INVALID_ARGUMENT);
    
    switch (hash->id)
    {
        case MEH_MD5: meh_reset_md5(hash->state.md5); break;
        case MEH_SHA1: meh_reset_sha1(hash->state.sha1); break;
        case MEH_SHA224: meh_reset_sha224(hash->state.sha224); break;
        case MEH_SHA256: meh_reset_sha256(hash->state.sha256); break;
        case MEH_SHA384: meh_reset_sha384(hash->state.sha384); break;
        case MEH_SHA512: meh_reset_sha512(hash->state.sha512); break;
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid hash id passed to meh_reset_hash",
                             MEH_INVALID_HASH);
    }

    return MEH_OK;
}

meh_error_t meh_update_hash(MehHash hash, const unsigned char* data, size_t len)
{
    if (NULL == hash || NULL == data)
        return meh_error("invalid argument passed to meh_update_hash",
                         MEH_INVALID_ARGUMENT);

    if (0 == len)
        return MEH_OK;
    
    switch (hash->id)
    {
        case MEH_MD5: meh_update_md5(hash->state.md5, data, len); break;
        case MEH_SHA1: meh_update_sha1(hash->state.sha1, data, len); break;
        case MEH_SHA224:
            meh_update_sha224(hash->state.sha224, data, len); break;
        case MEH_SHA256:
            meh_update_sha256(hash->state.sha256, data, len); break;
        case MEH_SHA384:
            meh_update_sha384(hash->state.sha384, data, len); break;
        case MEH_SHA512:
            meh_update_sha512(hash->state.sha512, data, len); break;
        default:
            return meh_error("invalid hash id passed to meh_update_hash",
                             MEH_INVALID_HASH);
    }
    
    return MEH_OK;
}

meh_error_t meh_finish_hash(MehHash hash, unsigned char* output)
{
    if (NULL == hash || NULL == output)
        return meh_error("invalid argument passed to meh_finish_hash",
                         MEH_INVALID_ARGUMENT);
    
    switch (hash->id)
    {
        case MEH_MD5: meh_finish_md5(hash->state.md5, output); break;
        case MEH_SHA1: meh_finish_sha1(hash->state.sha1, output); break;
        case MEH_SHA224: meh_finish_sha224(hash->state.sha224, output); break;
        case MEH_SHA256: meh_finish_sha256(hash->state.sha256, output); break;
        case MEH_SHA384: meh_finish_sha384(hash->state.sha384, output); break;
        case MEH_SHA512: meh_finish_sha512(hash->state.sha512, output); break;
        default:
            return meh_error("invalid hash id passed to meh_finish_hash",
                             MEH_INVALID_HASH);
    }

    return MEH_OK;
}

void meh_destroy_hash(MehHash hash)
{
    if (NULL == hash)
    {
        meh_warn("invalid argument passed to meh_destroy_hash");
        return;
    }
    
    switch (hash->id)
    {
        case MEH_MD5: meh_destroy_md5(hash->state.md5); break;
        case MEH_SHA1: meh_destroy_sha1(hash->state.sha1); break;
        case MEH_SHA224: meh_destroy_sha224(hash->state.sha224); break;
        case MEH_SHA256: meh_destroy_sha256(hash->state.sha256); break;
        case MEH_SHA384: meh_destroy_sha384(hash->state.sha384); break;
        case MEH_SHA512: meh_destroy_sha512(hash->state.sha512); break;
        default:
            meh_warn("invalid hash id passed to meh_destroy_hash");
    }
    
    free(hash);
}

meh_error_t meh_hash(meh_hash_id hash_id, const unsigned char* data,
                     size_t len, unsigned char* output)
{
    meh_error_t error;
    MehHash t;

    t = meh_get_hash(hash_id);
    
    if (NULL == t)
        return MEH_ERROR; /* ran out of memory, invalid hash, something */
    
    if ((error = meh_update_hash(t, data, len)) != MEH_OK)
    {
        meh_destroy_hash(t);
        return error;
    }
    
    if ((error = meh_finish_hash(t, output)) != MEH_OK)
    {
        meh_destroy_hash(t);
        return error;
    }
    
    meh_destroy_hash(t);

    return MEH_OK;
}

meh_error_t meh_hash_file(MehHash hash, FILE* fd)
{
    int count;
    meh_error_t error;
    unsigned char buffer[8192];

    if (NULL == fd || NULL == hash)
        return MEH_INVALID_ARGUMENT;

    while ((count = fread(buffer, sizeof (unsigned char), 8192, fd)) != 0)
    {
        if ((error = meh_update_hash(hash, buffer, count)) != MEH_OK)
            return error;
    }
    
    return MEH_OK;
}

size_t meh_hash_output_size(MehHash hash)
{
    switch (hash->id)
    {
        case MEH_MD5: return MEH_MD5_HASH_SIZE;
        case MEH_SHA1: return MEH_SHA1_HASH_SIZE;
        case MEH_SHA224: return MEH_SHA224_HASH_SIZE;
        case MEH_SHA256: return MEH_SHA256_HASH_SIZE;
        case MEH_SHA384: return MEH_SHA384_HASH_SIZE;
        case MEH_SHA512: return MEH_SHA512_HASH_SIZE;
        default: /* shouldn't happen, but just in case */
            return meh_error(
                "invalid hash id passed to meh_hash_output_size", -1);
    }

    return -1;
}

size_t meh_hash_block_size(MehHash hash)
{
    switch (hash->id)
    {
        case MEH_MD5: return MEH_MD5_BLOCK_SIZE;
        case MEH_SHA1: return MEH_SHA1_BLOCK_SIZE;
        case MEH_SHA224: return MEH_SHA224_BLOCK_SIZE;
        case MEH_SHA256: return MEH_SHA256_BLOCK_SIZE;
        case MEH_SHA384: return MEH_SHA384_BLOCK_SIZE;
        case MEH_SHA512: return MEH_SHA512_BLOCK_SIZE;
        default: /* shouldn't happen, but just in case */
            return meh_error(
                "invalid hash id passed to meh_hash_block_size", -1);
    }

    return -1;
}
