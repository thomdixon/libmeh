/*
Copyright (c) 2013 Thomas Dixon

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

START_TEST (test_rc4)
{
    MehCipher c;
    meh_error_t result;
    unsigned char* data;
    size_t got;
    
    data = malloc(512);
    fail_if(NULL == data, "Could not allocate cipher buffer.");
    
    c = meh_get_cipher(MEH_RC4, (const unsigned char *)"\0\0\0\0\0\0\0\0", 8);
    fail_if(NULL == c, "Could not allocate cipher context.");
    
    /* Empty string */
    result = meh_update_cipher(c, (const unsigned char *)"0", data, 0, &got);
    fail_unless(MEH_OK == result, NULL);
    fail_unless(got == 0, NULL);
    
    /* All zeros */
    result = meh_update_cipher(c, (const unsigned char *)"\0\0\0\0\0\0\0\0", data, 8, &got);
    fail_unless(MEH_OK == result, NULL);
    fail_unless(got == 8, NULL);
    fail_unless(raw_equals_hex(data, "de188941a3375d3a", 8), NULL);
    
    /* Larger than state length ciphertext */
    memset(data, 0x01, 512);
    meh_reset_cipher(c, (const unsigned char *)"\x01\x23\x45\x67\x89\xab\xcd\xef", 8);
    result = meh_update_cipher(c, data, data, 512, &got);
    fail_unless(MEH_OK == result, NULL);
    fail_unless(got == 512, NULL);
    fail_unless(raw_equals_hex(data,
                               "7595c3e6114a09780c4ad452338e1ffd9a1be9498f813d76533449b6778dcad8"
                               "c78a8d2ba9ac66085d0e53d59c26c2d1c490c1ebbe0ce66d1b6b1b13b6b919b8"
                               "47c25a91447a95e75e4ef16779cde8bf0a95850e32af9689444fd377108f98fd"
                               "cbd4e726567500990bcc7e0ca3c4aaa304a387d20f3b8fbbcd42a1bd311d7a43"
                               "03dda5ab078896ae80c18b0af66dff319616eb784e495ad2ce90d7f772a81747"
                               "b65f62093b1e0db9e5ba532fafec47508323e671327df9444432cb7367cec82f"
                               "5d44c0d00b67d650a075cd4b70dedd77eb9b10231b6b5b741347396d62897421"
                               "d43df9b42e446e358e9c11a9b2184ecbef0cd8e7a877ef968f1390ec9b3d35a5"
                               "585cb009290e2fcde7b5ec66d9084be44055a619d9dd7fc3166f9487f7cb2729" 
                               "12426445998514c15d53a18c864ce3a2b7555793988126520eacf2e3066e230c"  
                               "91bee4dd5304f5fd0405b35bd99c73135d3d9bc335ee049ef69b3867bf2d7bd1"
                               "eaa595d8bfc0066ff8d31509eb0c6caa006c807a623ef84c3d33c195d23ee320"
                               "c40de0558157c822d4b8c569d849aed59d4e0fd7f379586b4b7ff684ed6a189f"
                               "7486d49b9c4bad9ba24b96abf924372c8a8fffb10d55354900a77a3db5f205e1"
                               "b99fcd8660863a159ad4abe40fa48934163ddde542a6585540fd683cbfd8c00f"
                               "12129a284deacc4cdefe58be7137541c047126c8d49e2755ab181ab7e940b0c0",
                               512), NULL);
    free(data);
}
END_TEST

START_TEST (test_salsa20)
{
    MehCipher c;
    meh_error_t result;
    unsigned char* data;
    size_t got;
 
    data = malloc(64);
    fail_if(NULL == data, "Could not allocate cipher buffer.");

    c = meh_get_cipher(MEH_SALSA20,
                       (const unsigned char *)"\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                       (const unsigned char *)"\0\0\0\0\0\0\0\0",
                       16);
    fail_if(NULL == c, "Could not allocate cipher context.");

    /* Empty string */
    result = meh_update_cipher(c, (const unsigned char *)"0", data, 0, &got);
    fail_unless(MEH_OK == result, NULL);
    fail_unless(got == 0, NULL);
    
    /* All zeros, 128 bit key */
    memset(data, 0, 64);
    result = meh_update_cipher(c, data, data, 64, &got);
    fail_unless(MEH_OK == result, NULL);
    fail_unless(got == 64, NULL);
    fail_unless(raw_equals_hex(data,
                               "4dfa5e481da23ea09a31022050859936da52fcee218005164f267cb65f5cfd7f"
                               "2b4f97e0ff16924a52df269515110a07f9e460bc65ef95da58f740b7d1dbb0aa",
                               64), NULL);

    /* All zeros, 256 bit key */
    memset(data, 0, 64);
    result = meh_reset_cipher(c,
                              (const unsigned char *)"\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                              (const unsigned char *)"\0\0\0\0\0\0\0\0",
                              32);
    fail_unless(MEH_OK == result, NULL);
    result = meh_update_cipher(c, data, data, 64, &got);
    fail_unless(MEH_OK == result, NULL);
    fail_unless(got == 64, NULL);
    fail_unless(raw_equals_hex(data,
                               "c29ba0da9ebebfacdebbdd1d16e5f5987e1cb12e9083d437eaaaa4ba0cdc909e"
                               "53d052ac387d86acda8d956ba9e6f6543065f6912a7df710b4b57f27809bafe3",
                               64), NULL);

    free(data);
    
}
END_TEST

Suite* stream_cipher_suite(void)
{
  Suite* test_stream_ciphers;
  TCase* tcase_rc4,
       * tcase_salsa20;

  test_stream_ciphers = suite_create("Stream Ciphers");

  tcase_rc4 = tcase_create("RC4");
  tcase_add_test(tcase_rc4, test_rc4);

  tcase_salsa20 = tcase_create("Salsa20");
  tcase_add_test(tcase_salsa20, test_salsa20);

  suite_add_tcase(test_stream_ciphers, tcase_rc4);
  suite_add_tcase(test_stream_ciphers, tcase_salsa20);

  return test_stream_ciphers;
}
