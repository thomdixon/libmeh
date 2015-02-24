/*
Copyright (c) 2012 Thomas Dixon

Adapted from Daniel J. Berstein's reference implementation.

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

#include "salsa20.h"

MehSalsa20 meh_get_salsa20(const unsigned char* key,
			   const unsigned char* iv,
			   size_t key_size)
{
    MehSalsa20 r = malloc(sizeof (meh_salsa20_state_t));

    if (NULL == r)
    {
        meh_warn("could not allocate cipher context in meh_get_salsa20");
        return NULL;
    }

    meh_reset_salsa20(r, key, iv, key_size);

    return r;
}

meh_error_t meh_reset_salsa20(MehSalsa20 s20,
			      const unsigned char* key,
			      const unsigned char* iv,
			      size_t key_size)
{
    uint32_t* state;
    const char* constants;

    if (NULL == key || NULL == iv || NULL == s20)
        return meh_error("null reference passed to meh_reset_salsa20",
                         MEH_INVALID_ARGUMENT);

    if (key_size != 16 && key_size != 32)
        return meh_error("invalid key size passed to meh_reset_salsa20",
                         MEH_INVALID_KEY_SIZE);

    /* Key setup */
    state = s20->state;

    state[1] = U8TO32_LITTLE(key, 0);
    state[2] = U8TO32_LITTLE(key, 4);
    state[3] = U8TO32_LITTLE(key, 8);
    state[4] = U8TO32_LITTLE(key, 12);

    if (key_size == 32)
    {
        key += 16;
        constants = MEH_SALSA20_SIGMA;
    }
    else
    {

        constants = MEH_SALSA20_TAU;
    }

    state[11] = U8TO32_LITTLE(key, 0);
    state[12] = U8TO32_LITTLE(key, 4);
    state[13] = U8TO32_LITTLE(key, 8);
    state[14] = U8TO32_LITTLE(key, 12);
    state[0] = U8TO32_LITTLE(constants, 0);
    state[5] = U8TO32_LITTLE(constants, 4);
    state[10] = U8TO32_LITTLE(constants, 8);
    state[15] = U8TO32_LITTLE(constants, 12);

    /* IV setup */
    state[6] = U8TO32_LITTLE(iv, 0);
    state[7] = U8TO32_LITTLE(iv, 4);
    state[8] = 0;
    state[9] = 0;

    /* Force the core to be called */
    s20->index = 64;

    return MEH_OK;
}

static void meh_salsa20_core(uint8_t* output, const uint32_t* input)
{
  uint32_t x[16];
  int i;

  for (i = 0; i < 16; ++i)
      x[i] = input[i];

  for (i = 20; i > 0; i -= 2)
  {
      x[ 4] = XOR(x[ 4], ROTATE(PLUS(x[ 0], x[12]),  7));
      x[ 8] = XOR(x[ 8], ROTATE(PLUS(x[ 4], x[ 0]),  9));
      x[12] = XOR(x[12], ROTATE(PLUS(x[ 8], x[ 4]), 13));
      x[ 0] = XOR(x[ 0], ROTATE(PLUS(x[12], x[ 8]), 18));
      x[ 9] = XOR(x[ 9], ROTATE(PLUS(x[ 5], x[ 1]),  7));
      x[13] = XOR(x[13], ROTATE(PLUS(x[ 9], x[ 5]),  9));
      x[ 1] = XOR(x[ 1], ROTATE(PLUS(x[13], x[ 9]), 13));
      x[ 5] = XOR(x[ 5], ROTATE(PLUS(x[ 1], x[13]), 18));
      x[14] = XOR(x[14], ROTATE(PLUS(x[10], x[ 6]),  7));
      x[ 2] = XOR(x[ 2], ROTATE(PLUS(x[14], x[10]),  9));
      x[ 6] = XOR(x[ 6], ROTATE(PLUS(x[ 2], x[14]), 13));
      x[10] = XOR(x[10], ROTATE(PLUS(x[ 6], x[ 2]), 18));
      x[ 3] = XOR(x[ 3], ROTATE(PLUS(x[15], x[11]),  7));
      x[ 7] = XOR(x[ 7], ROTATE(PLUS(x[ 3], x[15]),  9));
      x[11] = XOR(x[11], ROTATE(PLUS(x[ 7], x[ 3]), 13));
      x[15] = XOR(x[15], ROTATE(PLUS(x[11], x[ 7]), 18));
      x[ 1] = XOR(x[ 1], ROTATE(PLUS(x[ 0], x[ 3]),  7));
      x[ 2] = XOR(x[ 2], ROTATE(PLUS(x[ 1], x[ 0]),  9));
      x[ 3] = XOR(x[ 3], ROTATE(PLUS(x[ 2], x[ 1]), 13));
      x[ 0] = XOR(x[ 0], ROTATE(PLUS(x[ 3], x[ 2]), 18));
      x[ 6] = XOR(x[ 6], ROTATE(PLUS(x[ 5], x[ 4]),  7));
      x[ 7] = XOR(x[ 7], ROTATE(PLUS(x[ 6], x[ 5]),  9));
      x[ 4] = XOR(x[ 4], ROTATE(PLUS(x[ 7], x[ 6]), 13));
      x[ 5] = XOR(x[ 5], ROTATE(PLUS(x[ 4], x[ 7]), 18));
      x[11] = XOR(x[11], ROTATE(PLUS(x[10], x[ 9]),  7));
      x[ 8] = XOR(x[ 8], ROTATE(PLUS(x[11], x[10]),  9));
      x[ 9] = XOR(x[ 9], ROTATE(PLUS(x[ 8], x[11]), 13));
      x[10] = XOR(x[10], ROTATE(PLUS(x[ 9], x[ 8]), 18));
      x[12] = XOR(x[12], ROTATE(PLUS(x[15], x[14]),  7));
      x[13] = XOR(x[13], ROTATE(PLUS(x[12], x[15]),  9));
      x[14] = XOR(x[14], ROTATE(PLUS(x[13], x[12]), 13));
      x[15] = XOR(x[15], ROTATE(PLUS(x[14], x[13]), 18));
  }

  for (i = 0; i < 16; ++i)
      x[i] = PLUS(x[i], input[i]);

  for (i = 0; i < 16; ++i)
      U32TO8_LITTLE(output, x[i], 4*i);
}

meh_error_t meh_update_salsa20(MehSalsa20 s20, const unsigned char* in,
                               unsigned char* out, size_t len, size_t* got)
{
    uint32_t i;
    uint32_t index;
    uint32_t* state;
    uint8_t* keystream;

    if (NULL == in || NULL == got ||  NULL == out || NULL == s20)
        return meh_error("null reference passed to meh_update_salsa20",
                         MEH_INVALID_ARGUMENT);

    state = s20->state;
    keystream = s20->keystream;

    index = s20->index;
    for (i = 0; i < len; i++, index++)
    {
        if (64 == index)
        {
            meh_salsa20_core(keystream, state);
            index = 0;
        }

        out[i] = in[i] ^ keystream[index];
    }

    s20->index = index;

    *got = len;

    return MEH_OK;
}

meh_error_t meh_finish_salsa20(MehSalsa20 s20, unsigned char* out, size_t* got)
{
    /* This is a dummy function for consistency. */
    *got = 0;

    return MEH_OK;
}
