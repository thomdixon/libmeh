CC = gcc
CFLAGS = -std=c99 -pedantic -Wall -fPIC
LDFLAGS = -lc -lcheck
CORE_FILES = ../src/error.c ../src/md5.c ../src/sha1.c ../src/sha256.c \
             ../src/sha512.c ../src/hash.c ../src/hmac.c ../src/pbkdf2.c \
             ../src/kdf.c ../src/rc4.c ../src/salsa20.c ../src/cipher.c \
	     test_all.c
CORE_OBJS := $(patsubst %.c,%.o,$(CORE_FILES))

all: $(CORE_OBJS)
	$(CC) -o test $(CORE_OBJS) $(LDFLAGS)

%.o : %.cc
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o