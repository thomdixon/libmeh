
=====================================
libmeh - cryptography for lazy people
=====================================

About 
======

libmeh is a small cryptographic library written in C99 that has been
in very, very slow development since 2009. After being horrified by
OpenSSL's API back around 2004 or 2005, I decided to eventually create
a cryptographic library in C that was relatively simple to use. This
is what I have so far.

Installation
============

libmeh uses Check for its unit tests, so you'll need to have that
installed if you want to run ``make`` from the root directory
(``aptitude install check`` on Debian systems). Otherwise, you can run
``make`` from the ``src`` directory and still compile
successfully. You'll end up with ``libmeh.so``, which you can
subsequently link against. There is no ``make install`` for reasons
outlined below.

Usage
=====

Don't. libmeh is a tiny project being semi-maintained by one person
and has virtually no documentation, which is the last thing you want
in a cryptographic library. Just for fun though, I'll detail how to
run the unit tests that currently exist and include some examples of
working code below, so you can get a feel for the ideas behind the
project.

Testing
-------

After running ``make`` in the root directory, ``cd`` into the ``test``
directory and run::

    ./test

You should see some output hopefully specifying zero failures. The
unit tests aren't currently comprehensive (they test hashes only, not
key derivation functions, message authentication codes, or ciphers).

Example
-------

libmeh organizes primitives into various categories and provides a
unified API for each category. For example, every hash is a
``MehHash``, and every ``MehHash`` supports ``meh_update_hash`` and
``meh_finish_hash``. This means, as an example, that you can pass
around hash contexts without worrying about precisely which hash
function you're given.

Here's some example code for encrypting a string with RC4 (which you
should probably never use)::

    #include <stdlib.h>
    #include "meh.h"

    int main(void) {
        unsigned char output[9]; 
        size_t got;
        int i;

        MehCipher r = meh_get_cipher(MEH_RC4, "Key", 3);
        meh_update_cipher(r, "Plaintext", output, 9, &got);

        for (i = 0; i < got; i++)
            printf("%02x", output[i]);
        printf("\n");

        meh_reset_cipher(r, "Key", 3);
        meh_update_cipher(r, "Plaintext", output, 9, &got);
        meh_destroy_cipher(r);
    
        for (i = 0; i < got; i++)
            printf("%02x", output[i]);
        printf("\n");

        return EXIT_SUCCESS;
    }

Not particularly pretty, but C rarely ever is. It's also possible to
use a key derivation function, such as PBKDF2, in order to generate a
key for a cipher::

    #include <stdlib.h>
    #include "meh.h"

    int main(void) {

        unsigned char output[32];
        size_t got;
        int i;

        MehKDF k = meh_get_kdf(MEH_PBKDF2, MEH_SHA1,
                               "password", 8,
                               "ATHENA.MIT.EDUraeburn", 21,
                               1200);
        meh_update_kdf(k, output, OUTPUT_SIZE, &got);
        meh_finish_kdf(k);
        meh_destroy_kdf(k);
    
        for (i = 0; i < OUTPUT_SIZE; i++)
            printf("%02x", output[i]);
        printf("\n");
 
        return EXIT_SUCCESS;
    }

As you can see, the code for these vastly different primitives follows
a very similar structure.

The ``meh_get_*`` functions allocate a context for you based on the
primitive you specify. In the case of ``meh_get_kdf`` and
``meh_get_cipher``, these functions are variadic so that different
specific key derivation functions and ciphers which expect different
parameters may be supported. A good example is that of stream ciphers
versus block ciphers. The latter requires a mode of operation. The
former does not. This means block ciphers require at least one extra
parameter, but both are supported through the same interface.

As you would expect, ``meh_update_*`` will update the given
primitive's context with the information you specify. For example, in
the case of a cipher, this information must be the context, the input,
the output, the input's length, and then a pointer to a ``size_t``
where the number of ciphertext bytes written to the output will be
given.

In order to finalize an operation, you may need to call
``meh_finish_*``. In the case of a cipher or hash, this may result in
all necessary padding being applied and the final block being
written. Since RC4 is a stream cipher, this does nothing, and so the
line was omitted in the example above.

Finally, a call to ``meh_destroy_*`` will deallocate the given
primitive's context. Sometimes this is as simple as calling ``free``
on the supplied context, but in the case of more complex primtives,
such as HMAC and PBKDF2, there may be a more complicated chain of
internal calls to ``free`` which must first take place.
