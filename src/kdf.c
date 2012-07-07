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

#include "kdf.h"

typedef struct meh_pbkdf2_args_s
{
    meh_hash_id prf;
    unsigned char* password,
                 * salt;
    size_t pass_len,
           salt_len;
    unsigned int iterations;
} meh_pbkdf2_args_t;

typedef union meh_kdf_args_u
{
    meh_pbkdf2_args_t pbkdf2;
} meh_kdf_args_t;

MehKDF _meh_get_kdf(const meh_kdf_id kdf_id, va_list args)
{
    meh_kdf_args_t kdf_args;
    MehKDF r = malloc(sizeof (meh_kdf_t));

    if (NULL == r)
    {
        meh_warn("could not allocate KDF context in meh_get_kdf");
        return NULL;
    }

    r->id = kdf_id;
    
    switch (kdf_id)
    {
        case MEH_PBKDF2:
            kdf_args.pbkdf2.prf = va_arg(args, meh_hash_id);
            kdf_args.pbkdf2.password = va_arg(args, unsigned char*);
            kdf_args.pbkdf2.pass_len = va_arg(args, size_t);
            kdf_args.pbkdf2.salt = va_arg(args, unsigned char*);
            kdf_args.pbkdf2.salt_len = va_arg(args, size_t);
            kdf_args.pbkdf2.iterations = va_arg(args, unsigned int);
            r->state.pbkdf2 = meh_get_pbkdf2(kdf_args.pbkdf2.prf,
                                             kdf_args.pbkdf2.password,
                                             kdf_args.pbkdf2.pass_len,
                                             kdf_args.pbkdf2.salt,
                                             kdf_args.pbkdf2.salt_len,
                                             kdf_args.pbkdf2.iterations);
            break;
            
        default: /* shouldn't happen, but just in case */
            free(r);
            meh_warn("invalid KDF id passed to _meh_get_kdf");
            return NULL;
    }

    return r;
}

MehKDF meh_get_kdf(const meh_kdf_id kdf_id, ...)
{
    MehKDF r;
    va_list args;
    
    va_start(args, kdf_id);
    r = _meh_get_kdf(kdf_id, args);
    va_end(args);
    
    return r;
}

meh_error_t _meh_reset_kdf(MehKDF kdf, va_list args)
{
    meh_kdf_args_t kdf_args;
    meh_error_t error;
    
    switch (kdf->id)
    {
        case MEH_PBKDF2:
            kdf_args.pbkdf2.password = va_arg(args, unsigned char*);
            kdf_args.pbkdf2.pass_len = va_arg(args, size_t);
            kdf_args.pbkdf2.salt = va_arg(args, unsigned char*);
            kdf_args.pbkdf2.salt_len = va_arg(args, size_t);
            kdf_args.pbkdf2.iterations = va_arg(args, unsigned int);
            error = meh_reset_pbkdf2(kdf->state.pbkdf2,
                                     kdf_args.pbkdf2.password,
                                     kdf_args.pbkdf2.pass_len,
                                     kdf_args.pbkdf2.salt,
                                     kdf_args.pbkdf2.salt_len,
                                     kdf_args.pbkdf2.iterations);
            break;
            
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid KDF id passed to _meh_reset_kdf",
                             MEH_INVALID_KDF);    
    }

    return error;
}

meh_error_t meh_reset_kdf(MehKDF kdf, ...)
{
    va_list args;
    meh_error_t error;
    
    va_start(args, kdf);
    error = _meh_reset_kdf(kdf, args);
    va_end(args);

    return error;
}

meh_error_t meh_update_kdf(MehKDF kdf, unsigned char* output,
                           size_t want_len, size_t* get_len)
{
    meh_error_t error;
    
    switch (kdf->id)
    {
        case MEH_PBKDF2:
            error = meh_update_pbkdf2(kdf->state.pbkdf2,
                                      output, want_len, get_len);
            break;
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid KDF id passed to meh_update_kdf",
                             MEH_INVALID_KDF);
    }
    
    return error;
}

meh_error_t meh_finish_kdf(MehKDF kdf)
{
    meh_error_t error;
    
    switch (kdf->id)
    {
        case MEH_PBKDF2:
            error = meh_finish_pbkdf2(kdf);
            break;
            
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid KDF id passed to meh_finish_kdf",
                             MEH_INVALID_KDF);
    }
    
    return error;
}

meh_error_t meh_kdf(meh_kdf_id kdf_id, ...)
{
    va_list args;
    meh_error_t error;
    size_t want;
    size_t* got;
    unsigned char* output;
    MehKDF t;
    
    va_start(args, kdf_id);
    t = _meh_get_kdf(kdf_id, args);
    output = va_arg(args, unsigned char*);
    want = va_arg(args, size_t);
    got = va_arg(args, size_t*);
    va_end(args);
    
    if (NULL == t)
        return MEH_ERROR;
    
    if ((error = meh_update_kdf(t, output, want, got)) != MEH_OK)
    {
        meh_destroy_kdf(t);
        return error;
    }
    
    if ((error = meh_finish_kdf(t)) != MEH_OK)
    {
        meh_destroy_kdf(t);
        return error;
    }
    
    meh_destroy_kdf(t);
    
    return MEH_OK;
}

void meh_destroy_kdf(MehKDF kdf)
{
    if (NULL == kdf)
    {
        meh_warn("invalid argument passed to meh_destroy_kdf");
        return;
    }
    
    switch(kdf->id)
    {
        case MEH_PBKDF2:
            meh_destroy_pbkdf2(kdf->state.pbkdf2); break;
        default:
            meh_warn("invalid kdf id passed to meh_destroy_kdf");
    }

    free(kdf);
}
