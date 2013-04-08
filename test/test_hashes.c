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

/**
 * Vectors taken from RFC 1321.
 */
START_TEST (test_md5_standard_vectors)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
 
  hash = malloc(MEH_MD5_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_MD5);
  fail_if(NULL == h, "Could not allocate hash context.");

  /* Empty string */
  result = meh_update_hash(h, (const unsigned char*)"", 0);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "d41d8cd98f00b204e9800998ecf8427e", MEH_MD5_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* a */
  result = meh_update_hash(h, (const unsigned char*)"a", 1);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "0cc175b9c0f1b6a831c399e269772661", MEH_MD5_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* abc */
  result = meh_update_hash(h, (const unsigned char*)"abc", 3);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "900150983cd24fb0d6963f7d28e17f72", MEH_MD5_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* message digest */
  result = meh_update_hash(h, (const unsigned char*)"message digest", 14);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "f96b697d7cb7938d525a2f31aaf161d0", MEH_MD5_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* alphabet */
  result = meh_update_hash(h, (const unsigned char*)"abcdefghijklmnopqrstuvwxyz", 26);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "c3fcd3d76192e4007dfb496cca67e13b", MEH_MD5_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Hash an input consisting of several blocks.
 */
START_TEST (test_md5_large_input_vector)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
  int i;
 
  hash = malloc(MEH_MD5_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_MD5);
  fail_if(NULL == h, "Could not allocate hash context.");

  for (i = 0; i < 100000; i++) {
    result = meh_update_hash(h, (const unsigned char*)"aaaaaaaaaa", 10);
    fail_unless(MEH_OK == result, NULL);
  }

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);
  
  fail_unless(raw_equals_hex(hash, "7707d6ae4e027c70eea2a935c2296f21", MEH_MD5_HASH_SIZE), NULL);
  
  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Vectors taken from RFC 1321.
 */
START_TEST (test_sha1_standard_vectors)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
 
  hash = malloc(MEH_SHA1_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA1);
  fail_if(NULL == h, "Could not allocate hash context.");

  /* Empty string */
  result = meh_update_hash(h, (const unsigned char*)"", 0);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709", MEH_SHA1_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* a */
  result = meh_update_hash(h, (const unsigned char*)"a", 1);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", MEH_SHA1_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* abc */
  result = meh_update_hash(h, (const unsigned char*)"abc", 3);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "a9993e364706816aba3e25717850c26c9cd0d89d", MEH_SHA1_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* message digest */
  result = meh_update_hash(h, (const unsigned char*)"message digest", 14);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "c12252ceda8be8994d5fa0290a47231c1d16aae3", MEH_SHA1_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* alphabet */
  result = meh_update_hash(h, (const unsigned char*)"abcdefghijklmnopqrstuvwxyz", 26);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, "32d10c7b8cf96570ca04ce37f2a19d84240d3a89", MEH_SHA1_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Hash an input consisting of several blocks.
 */
START_TEST (test_sha1_large_input_vector)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
  int i;
 
  hash = malloc(MEH_SHA1_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA1);
  fail_if(NULL == h, "Could not allocate hash context.");

  for (i = 0; i < 100000; i++) {
    result = meh_update_hash(h, (const unsigned char*)"aaaaaaaaaa", 10);
    fail_unless(MEH_OK == result, NULL);
  }

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);
  
  fail_unless(raw_equals_hex(hash, "34aa973cd4c4daa4f61eeb2bdbad27316534016f", MEH_SHA1_HASH_SIZE), NULL);
  
  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Vectors taken from RFC 1321.
 */
START_TEST (test_sha224_standard_vectors)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
 
  hash = malloc(MEH_SHA224_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA224);
  fail_if(NULL == h, "Could not allocate hash context.");

  /* Empty string */
  result = meh_update_hash(h, (const unsigned char*)"", 0);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
			     MEH_SHA224_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* a */
  result = meh_update_hash(h, (const unsigned char*)"a", 1);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
			     MEH_SHA224_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* abc */
  result = meh_update_hash(h, (const unsigned char*)"abc", 3);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", 
			     MEH_SHA224_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* message digest */
  result = meh_update_hash(h, (const unsigned char*)"message digest", 14);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
			     MEH_SHA224_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* alphabet */
  result = meh_update_hash(h, (const unsigned char*)"abcdefghijklmnopqrstuvwxyz", 26);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
			     MEH_SHA224_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Hash an input consisting of several blocks.
 */
START_TEST (test_sha224_large_input_vector)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
  int i;
 
  hash = malloc(MEH_SHA224_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA224);
  fail_if(NULL == h, "Could not allocate hash context.");

  for (i = 0; i < 100000; i++) {
    result = meh_update_hash(h, (const unsigned char*)"aaaaaaaaaa", 10);
    fail_unless(MEH_OK == result, NULL);
  }

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);
  
  fail_unless(raw_equals_hex(hash, 
			     "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
			     MEH_SHA224_HASH_SIZE), NULL);
  
  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Vectors taken from RFC 1321.
 */
START_TEST (test_sha256_standard_vectors)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
 
  hash = malloc(MEH_SHA256_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA256);
  fail_if(NULL == h, "Could not allocate hash context.");

  /* Empty string */
  result = meh_update_hash(h, (const unsigned char*)"", 0);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			     MEH_SHA256_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* a */
  result = meh_update_hash(h, (const unsigned char*)"a", 1);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
			     MEH_SHA256_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* abc */
  result = meh_update_hash(h, (const unsigned char*)"abc", 3);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 
			     MEH_SHA256_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* message digest */
  result = meh_update_hash(h, (const unsigned char*)"message digest", 14);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
			     MEH_SHA256_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* alphabet */
  result = meh_update_hash(h, (const unsigned char*)"abcdefghijklmnopqrstuvwxyz", 26);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
			     MEH_SHA256_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Hash an input consisting of several blocks.
 */
START_TEST (test_sha256_large_input_vector)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
  int i;
 
  hash = malloc(MEH_SHA256_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA256);
  fail_if(NULL == h, "Could not allocate hash context.");

  for (i = 0; i < 100000; i++) {
    result = meh_update_hash(h, (const unsigned char*)"aaaaaaaaaa", 10);
    fail_unless(MEH_OK == result, NULL);
  }

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);
  
  fail_unless(raw_equals_hex(hash, 
			     "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
			     MEH_SHA256_HASH_SIZE), NULL);
  
  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Vectors taken from RFC 1321.
 */
START_TEST (test_sha384_standard_vectors)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
 
  hash = malloc(MEH_SHA384_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA384);
  fail_if(NULL == h, "Could not allocate hash context.");

  /* Empty string */
  result = meh_update_hash(h, (const unsigned char*)"", 0);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
			     "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
			     MEH_SHA384_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* a */
  result = meh_update_hash(h, (const unsigned char*)"a", 1);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035d"
			     "ce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
			     MEH_SHA384_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* abc */
  result = meh_update_hash(h, (const unsigned char*)"abc", 3);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
			     "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", 
			     MEH_SHA384_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* message digest */
  result = meh_update_hash(h, (const unsigned char*)"message digest", 14);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "473ed35167ec1f5d8e550368a3db39be54639f828868e945"
			     "4c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
			     MEH_SHA384_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* alphabet */
  result = meh_update_hash(h, (const unsigned char*)"abcdefghijklmnopqrstuvwxyz", 26);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "feb67349df3db6f5924815d6c3dc133f091809213731fe5c"
			     "7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
			     MEH_SHA384_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Hash an input consisting of several blocks.
 */
START_TEST (test_sha384_large_input_vector)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
  int i;
 
  hash = malloc(MEH_SHA384_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA384);
  fail_if(NULL == h, "Could not allocate hash context.");

  for (i = 0; i < 100000; i++) {
    result = meh_update_hash(h, (const unsigned char*)"aaaaaaaaaa", 10);
    fail_unless(MEH_OK == result, NULL);
  }

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);
  
  fail_unless(raw_equals_hex(hash, 
			     "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
			     "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
			     MEH_SHA384_HASH_SIZE), NULL);
  
  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Vectors taken from RFC 1321.
 */
START_TEST (test_sha512_standard_vectors)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
 
  hash = malloc(MEH_SHA512_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA512);
  fail_if(NULL == h, "Could not allocate hash context.");

  /* Empty string */
  result = meh_update_hash(h, (const unsigned char*)"", 0);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
			     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			     MEH_SHA512_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* a */
  result = meh_update_hash(h, (const unsigned char*)"a", 1);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f53"
			     "02860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
			     MEH_SHA512_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* abc */
  result = meh_update_hash(h, (const unsigned char*)"abc", 3);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
			     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 
			     MEH_SHA512_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* message digest */
  result = meh_update_hash(h, (const unsigned char*)"message digest", 14);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
			     "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
			     MEH_SHA512_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  /* alphabet */
  result = meh_update_hash(h, (const unsigned char*)"abcdefghijklmnopqrstuvwxyz", 26);
  fail_unless(MEH_OK == result, NULL);

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);

  fail_unless(raw_equals_hex(hash, 
			     "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429"
			     "955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
			     MEH_SHA512_HASH_SIZE), NULL);

  result = meh_reset_hash(h);
  fail_unless(MEH_OK == result, NULL);

  meh_destroy_hash(h);
  free(hash);
}
END_TEST

/**
 * Hash an input consisting of several blocks.
 */
START_TEST (test_sha512_large_input_vector)
{
  MehHash h;
  meh_error_t result;
  unsigned char* hash;
  int i;
 
  hash = malloc(MEH_SHA512_HASH_SIZE);
  fail_if(NULL == hash, "Could not allocate hash buffer.");

  h = meh_get_hash(MEH_SHA512);
  fail_if(NULL == h, "Could not allocate hash context.");

  for (i = 0; i < 100000; i++) {
    result = meh_update_hash(h, (const unsigned char*)"aaaaaaaaaa", 10);
    fail_unless(MEH_OK == result, NULL);
  }

  result = meh_finish_hash(h, hash);
  fail_unless(MEH_OK == result, NULL);
  
  fail_unless(raw_equals_hex(hash, 
			     "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
			     "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
			     MEH_SHA512_HASH_SIZE), NULL);
  
  meh_destroy_hash(h);
  free(hash);
}
END_TEST

Suite* hash_suite(void) {
  Suite* test_hashes;
  TCase* test_md5,
       * test_sha1,
       * test_sha224,
       * test_sha256,
       * test_sha384,
       * test_sha512;

  test_hashes = suite_create("Hashes");

  test_md5 = tcase_create("MD5");
  tcase_add_test(test_md5, test_md5_standard_vectors);
  tcase_add_test(test_md5, test_md5_large_input_vector);

  test_sha1 = tcase_create("SHA1");
  tcase_add_test(test_sha1, test_sha1_standard_vectors);
  tcase_add_test(test_sha1, test_sha1_large_input_vector);

  test_sha224 = tcase_create("SHA224");
  tcase_add_test(test_sha224, test_sha224_standard_vectors);
  tcase_add_test(test_sha224, test_sha224_large_input_vector);

  test_sha256 = tcase_create("SHA256");
  tcase_add_test(test_sha256, test_sha256_standard_vectors);
  tcase_add_test(test_sha256, test_sha256_large_input_vector);

  test_sha384 = tcase_create("SHA384");
  tcase_add_test(test_sha384, test_sha384_standard_vectors);
  tcase_add_test(test_sha384, test_sha384_large_input_vector);

  test_sha512 = tcase_create("SHA512");
  tcase_add_test(test_sha512, test_sha512_standard_vectors);
  tcase_add_test(test_sha512, test_sha512_large_input_vector);

  suite_add_tcase(test_hashes, test_md5);
  suite_add_tcase(test_hashes, test_sha1);
  suite_add_tcase(test_hashes, test_sha224);
  suite_add_tcase(test_hashes, test_sha256);
  suite_add_tcase(test_hashes, test_sha384);
  suite_add_tcase(test_hashes, test_sha512);

  return test_hashes;
}
