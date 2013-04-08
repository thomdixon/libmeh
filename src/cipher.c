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

#include "cipher.h"

MehCipher _meh_get_cipher(const meh_cipher_id cipher_id, va_list args)
{
    meh_cipher_args_t cipher_args;
    MehCipher r = malloc(sizeof (meh_cipher_t));

    if (NULL == r)
    {
        meh_warn("could not allocate cipher context in meh_get_cipher");
        return NULL;
    }

    r->id = cipher_id;
    
    switch (cipher_id)
    {
        case MEH_RC4:
            cipher_args.rc4.key = va_arg(args, unsigned char*);
            cipher_args.rc4.key_size = va_arg(args, size_t);
            r->state.rc4 = meh_get_rc4(cipher_args.rc4.key,
                                       cipher_args.rc4.key_size);
            break;

        case MEH_SALSA20:
            cipher_args.salsa20.key = va_arg(args, unsigned char*);
            cipher_args.salsa20.iv = va_arg(args, unsigned char*);
            cipher_args.salsa20.key_size = va_arg(args, size_t);
            r->state.salsa20 = meh_get_salsa20(cipher_args.salsa20.key,
                                               cipher_args.salsa20.iv,
                                               cipher_args.salsa20.key_size);
            break;
            
        default: /* shouldn't happen, but just in case */
            free(r);
            meh_warn("invalid cipher id passed to _meh_get_cipher");
            return NULL;
    }

    return r;
}

MehCipher meh_get_cipher(const meh_cipher_id cipher_id, ...)
{
    MehCipher r;
    va_list args;
    
    va_start(args, cipher_id);
    r = _meh_get_cipher(cipher_id, args);
    va_end(args);
    
    return r;
}

meh_error_t _meh_reset_cipher(MehCipher cipher, va_list args)
{
    meh_cipher_args_t cipher_args;
    meh_error_t error;
    
    switch (cipher->id)
    {
        case MEH_RC4:
            cipher_args.rc4.key = va_arg(args, unsigned char*);
            cipher_args.rc4.key_size = va_arg(args, size_t);
            error = meh_reset_rc4(cipher->state.rc4,
                                  cipher_args.rc4.key,
                                  cipher_args.rc4.key_size);
            break;

        case MEH_SALSA20:
            cipher_args.salsa20.key = va_arg(args, unsigned char*);
            cipher_args.salsa20.iv = va_arg(args, unsigned char*);
            cipher_args.salsa20.key_size = va_arg(args, size_t);
            error = meh_reset_salsa20(cipher->state.salsa20,
                                      cipher_args.salsa20.key,
                                      cipher_args.salsa20.iv,
                                      cipher_args.salsa20.key_size);
            break;
            
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid cipher id passed to _meh_reset_cipher",
                             MEH_INVALID_CIPHER);    
    }

    return error;
}

meh_error_t meh_reset_cipher(MehCipher cipher, ...)
{
    va_list args;
    meh_error_t error;
    
    va_start(args, cipher);
    error = _meh_reset_cipher(cipher, args);
    va_end(args);

    return error;
}

meh_error_t meh_update_cipher(MehCipher cipher, const unsigned char* in,
                              unsigned char* out, size_t len, size_t* got)
{
    meh_error_t error;
    
    switch (cipher->id)
    {
        case MEH_RC4:
            error = meh_update_rc4(cipher->state.rc4, in, out, len, got);
            break;

        case MEH_SALSA20:
            error = meh_update_salsa20(cipher->state.salsa20,
                                       in,
                                       out,
                                       len,
                                       got);
            break;
            
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid cipher id passed to meh_update_cipher",
                             MEH_INVALID_CIPHER);
    }
    
    return error;
}

meh_error_t meh_finish_cipher(MehCipher cipher, unsigned char* out, size_t* got)
{
    meh_error_t error;
    
    switch (cipher->id)
    {
        case MEH_RC4:
            error = meh_finish_rc4(cipher->state.rc4, out, got);
            break;

        case MEH_SALSA20:
            error = meh_finish_salsa20(cipher->state.salsa20, out, got);
            break;
            
        default: /* shouldn't happen, but just in case */
            return meh_error("invalid cipher id passed to meh_finish_cipher",
                             MEH_INVALID_CIPHER);
    }
    
    return error;
}

meh_error_t meh_cipher(meh_cipher_id cipher_id, ...)
{
    va_list args;
    meh_error_t error;
    const unsigned char* in;
    unsigned char* out;
    size_t len;
    size_t* got;
    MehCipher t;
    
    va_start(args, cipher_id);
    t = _meh_get_cipher(cipher_id, args);
    in = va_arg(args, const unsigned char*);
    out = va_arg(args, unsigned char*);
    len = va_arg(args, size_t);
    got = va_arg(args, size_t*);
    va_end(args);
    
    if (NULL == t)
        return MEH_ERROR;
    
    if ((error = meh_update_cipher(t, in, out, len, got)) != MEH_OK)
    {
        meh_destroy_cipher(t);
        return error;
    }
    
    if ((error = meh_finish_cipher(t, (out+*got), got)) != MEH_OK)
    {
        meh_destroy_cipher(t);
        return error;
    }
    
    meh_destroy_cipher(t);
    
    return MEH_OK;
}

void meh_destroy_cipher(MehCipher cipher)
{
    if (NULL == cipher)
    {
        meh_warn("invalid argument passed to meh_destroy_cipher");
        return;
    }
    
    switch(cipher->id)
    {
        case MEH_RC4:
            meh_destroy_rc4(cipher->state.rc4); break;
        default:
            meh_warn("invalid cipher id passed to meh_destroy_cipher");
    }

    free(cipher);
}
