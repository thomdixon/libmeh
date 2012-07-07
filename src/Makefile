CC = gcc
CFLAGS = -std=c99 -pedantic -Wall -fPIC
LDFLAGS = -lc
CORE_FILES = error.c md5.c sha1.c sha256.c sha512.c hash.c hmac.c	\
pbkdf2.c kdf.c rc4.c cipher.c
CORE_OBJS := $(patsubst %.c,%.o,$(CORE_FILES))

all: $(CORE_OBJS)
	 $(CC) -shared -o libmeh.so $(CORE_OBJS)

%.o : %.cc
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o

like-it-never-even-happened:
	rm -rf *.so *.o