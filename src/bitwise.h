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

#include <stdint.h>

#ifndef MEH_BITWISE_H
#    define MEH_BITWISE_H

#    define U8TO16_LITTLE(p, i) \
      (((uint16_t)((p)[(i)])         ) | \
       ((uint16_t)((p)[(i)+1]) <<  8))

#    define U8TO32_LITTLE(p, i) \
      (((uint32_t)((p)[(i)])        ) | \
       ((uint32_t)((p)[(i)+1]) <<  8) | \
       ((uint32_t)((p)[(i)+2]) << 16) | \
       ((uint32_t)((p)[(i)+3]) << 24))

#   define U8TO64_LITTLE(p, i) \
     (((uint64_t)((p)[(i)])        ) | \
      ((uint64_t)((p)[(i)+1]) <<  8) | \
      ((uint64_t)((p)[(i)+2]) << 16) | \
      ((uint64_t)((p)[(i)+3]) << 24) | \
      ((uint64_t)((p)[(i)+4]) << 32) | \
      ((uint64_t)((p)[(i)+5]) << 40) | \
      ((uint64_t)((p)[(i)+6]) << 48) | \
      ((uint64_t)((p)[(i)+7]) << 56))

#   define U8TO16_BIG(p, i) \
     (((uint16_t)((p)[(i)]) <<  8) | \
      ((uint16_t)((p)[(i)+1])    ))

#   define U8TO32_BIG(p, i) \
     (((uint32_t)((p)[(i)])   << 24) | \
      ((uint32_t)((p)[(i)+1]) << 16) | \
      ((uint32_t)((p)[(i)+2]) <<  8) | \
      ((uint32_t)((p)[(i)+3])      ))

#   define U8TO64_BIG(p, i) \
     (((uint64_t)((p)[(i)])   << 56) | \
      ((uint64_t)((p)[(i)+1]) << 48) | \
      ((uint64_t)((p)[(i)+2]) << 40) | \
      ((uint64_t)((p)[(i)+3]) << 32) | \
      ((uint64_t)((p)[(i)+4]) << 24) | \
      ((uint64_t)((p)[(i)+5]) << 16) | \
      ((uint64_t)((p)[(i)+6]) <<  8) | \
      ((uint64_t)((p)[(i)+7])      ))

#   define U16TO8_LITTLE(p, v, i) \
     do { \
         (p)[(i)  ] = (uint8_t)((v)      ); \
         (p)[(i)+1] = (uint8_t)((v) >>  8); \
     } while (0)

#   define U32TO8_LITTLE(p, v, i) \
     do { \
         (p)[(i)  ] = (uint8_t)((v)      ); \
         (p)[(i)+1] = (uint8_t)((v) >>  8); \
         (p)[(i)+2] = (uint8_t)((v) >> 16); \
         (p)[(i)+3] = (uint8_t)((v) >> 24); \
     } while (0)

#   define U64TO8_LITTLE(p, v, i) \
     do { \
         (p)[(i)  ] = (uint8_t)((v)      ); \
         (p)[(i)+1] = (uint8_t)((v) >>  8); \
         (p)[(i)+2] = (uint8_t)((v) >> 16); \
         (p)[(i)+3] = (uint8_t)((v) >> 24); \
         (p)[(i)+4] = (uint8_t)((v) >> 32); \
         (p)[(i)+5] = (uint8_t)((v) >> 40); \
         (p)[(i)+6] = (uint8_t)((v) >> 48); \
         (p)[(i)+7] = (uint8_t)((v) >> 56); \
     } while (0)

#   define U16TO8_BIG(p, v, i) \
     do { \
         (p)[(i)  ] = (uint8_t)((v)      ); \
         (p)[(i)+1] = (uint8_t)((v) >>  8); \
     } while (0)

#   define U32TO8_BIG(p, v, i) \
     do { \
         (p)[(i)  ] = (uint8_t)((v) >> 24); \
         (p)[(i)+1] = (uint8_t)((v) >> 16); \
         (p)[(i)+2] = (uint8_t)((v) >>  8); \
         (p)[(i)+3] = (uint8_t)((v)      ); \
     } while (0)

#   define U64TO8_BIG(p, v, i) \
     do { \
         (p)[(i)  ] = (uint8_t)((v) >> 56); \
         (p)[(i)+1] = (uint8_t)((v) >> 48); \
         (p)[(i)+2] = (uint8_t)((v) >> 40); \
         (p)[(i)+3] = (uint8_t)((v) >> 32); \
         (p)[(i)+4] = (uint8_t)((v) >> 24); \
         (p)[(i)+5] = (uint8_t)((v) >> 16); \
         (p)[(i)+6] = (uint8_t)((v) >>  8); \
         (p)[(i)+7] = (uint8_t)((v)      ); \
     } while (0)

#    define ROTL32(x, y) ((x) << (y) | (x) >> (32-(y)))
#    define ROTR32(x, y) ((x) >> (y) | (x) << (32-(y)))

#    define ROTL64(x, y) ((x) << (y) | (x) >> (64-(y)))
#    define ROTR64(x, y) ((x) >> (y) | (x) << (64-(y)))

#endif 
