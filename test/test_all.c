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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <check.h>
#include "../src/meh.h"

/**
 * Compare the raw byte array to the expected hex string and
 * return true if they are equal, false otherwise.
 */
bool raw_equals_hex(unsigned char* raw, char* hex, size_t len_raw)
{
  int number_written,
      result;
  char* raw_hex = malloc(2*len_raw+1),
      * raw_hex_ptr = raw_hex;

  if (NULL == raw_hex) {
    fprintf(stderr, "!! ERROR: Could not allocate space to convert raw to hex.\n");
    return false;
  }

  for (int i = 0; i < len_raw; i++) {
    number_written = sprintf(raw_hex_ptr, "%02x", raw[i]);

    if (number_written < 0)
      return false;

    raw_hex_ptr += number_written;
  }

  *raw_hex_ptr = '\0';

  result = (strncmp(raw_hex, hex, 2*len_raw) == 0);
  
  free(raw_hex);

  return result;
}

#include "test_hashes.c"
#include "test_stream_ciphers.c"

int main(void) {
    Suite* test_hashes,
         * test_stream_ciphers;

    SRunner* sr_test_hashes,
           * sr_test_stream_ciphers;

  test_hashes = hash_suite();
  sr_test_hashes = srunner_create(test_hashes);
  srunner_run_all(sr_test_hashes, CK_NORMAL);
  srunner_free(sr_test_hashes);

  test_stream_ciphers = stream_cipher_suite();
  sr_test_stream_ciphers = srunner_create(test_stream_ciphers);
  srunner_run_all(sr_test_stream_ciphers, CK_NORMAL);
  srunner_free(sr_test_stream_ciphers);

  return EXIT_SUCCESS;
}
