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

#ifndef MEH_ERROR_H
#define MEH_ERROR_H

typedef enum
{
    MEH_FILE_NOT_FOUND = -16,
    MEH_READ_ERROR,       /* Reading file */
    MEH_WRITE_ERROR,      /* Writing file */
    
    MEH_SOURCE_EXHAUSTED, /* Maximum output of the primitive reached */
    
    MEH_INVALID_PRNG,     /* These are not the cryptos you're looking for */
    MEH_INVALID_KDF,
    MEH_INVALID_HASH,
    MEH_INVALID_CIPHER,
    MEH_INVALID_KEY_SIZE,
    MEH_INVALID_IV_SIZE,
    MEH_INVALID_ROUNDS,
    MEH_INVALID_ARGUMENT, /* One or more invalid arguments were passed */
    
    MEH_OUT_OF_MEMORY,    /* Ran out of RAM */
    MEH_BUFFER_UNDERFLOW, /* Input buffer is too small */
    MEH_BUFFER_OVERFLOW,  /* Output buffer ^ */
    
    MEH_ERROR,            /* Something bad happened */
    MEH_OK                /* Everything is awwwwwwwwright */
} meh_error_t;

meh_error_t meh_error(const char*, meh_error_t);
void meh_warn(const char*);

#endif

