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

#include "rc4.h"

MehRC4 meh_get_rc4(const unsigned char* key, size_t key_size)
{
    MehRC4 r = malloc(sizeof (meh_rc4_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate cipher context in meh_get_rc4");
        return NULL;
    }

    meh_reset_rc4(r, key, key_size);

    return r;
}

meh_error_t meh_reset_rc4(MehRC4 rc4,
                          const unsigned char* key, size_t key_size)
{
    uint32_t i;
    uint8_t* state;
    uint8_t j, tmp;

    if (NULL == key || NULL == rc4)
        return meh_error("null reference passed to meh_reset_rc4",
                         MEH_INVALID_ARGUMENT);

    if (key_size < 1 || key_size > 256)
        return meh_error("invalid key size passed to meh_reset_rc4",
                         MEH_INVALID_KEY_SIZE);

    state = rc4->state;

    for (i = 0; i < MEH_RC4_STATE_SIZE; i++)
        state[i] = i;

    for (i = j = 0; i < MEH_RC4_STATE_SIZE; i++)
    {
        j += key[i % key_size] + state[i];

        tmp = state[i];
        rc4->state[i] = state[j];
        rc4->state[j] = tmp;
    }

    rc4->x = rc4->y = 0;

    return MEH_OK;
}

meh_error_t meh_update_rc4(MehRC4 rc4, const unsigned char* in,
                           unsigned char* out, size_t len, size_t* got)
{
    uint32_t i;
    uint8_t* state;
    uint8_t x, y, tmp;

    if (NULL == in || NULL == got ||  NULL == out || NULL == rc4)
        return meh_error("null reference passed to meh_update_rc4",
                         MEH_INVALID_ARGUMENT);

    x = rc4->x;
    y = rc4->y;
    state = rc4->state;

    for (i = 0; i < len; i++)
    {
        y += state[++x];
        tmp = state[x];
        state[x] = state[y];
        state[y] = tmp;

        out[i] = in[i]^state[(uint8_t)(state[x]+state[y])];
    }

    rc4->x = x;
    rc4->y = y;

    *got = len;

    return MEH_OK;
}

meh_error_t meh_finish_rc4(MehRC4 rc4, unsigned char* out, size_t* got)
{
    /* This is a dummy function for consistency. */
    *got = 0;

    return MEH_OK;
}
