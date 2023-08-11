CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = lib/kex.c lib/kem.c lib/indcpa.c lib/polyvec.c lib/poly.c lib/ntt.c lib/cbd.c lib/reduce.c lib/verify.c
SOURCESKECCAK = $(SOURCES) lib/fips202.c lib/symmetric-shake.c
SOURCESNINETIES = $(SOURCES) lib/sha256.c lib/sha512.c lib/aes256ctr.c lib/symmetric-aes.c
HEADERS = lib/params.h lib/kex.h lib/kem.h lib/indcpa.h lib/polyvec.h lib/poly.h lib/ntt.h lib/cbd.h lib/reduce.c lib/verify.h lib/symmetric.h
HEADERSKECCAK = $(HEADERS) lib/fips202.h
HEADERSNINETIES = $(HEADERS) lib/aes256ctr.h lib/sha2.h

.PHONY: all speed shared clean

all: \
  test_kex1024 \

test_kex1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kex.c lib/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) lib/randombytes.c test_kex.c -o test_kex1024
  
clean:
	-$(RM) -rf test_kex1024
