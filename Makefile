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
  kyber_client1024 \
  kyber_server1024 \
  kyber_client1024-90s \
  kyber_server1024-90s

kyber_client1024: $(SOURCESKECCAK) $(HEADERSKECCAK) kyber_client.c lib/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) lib/randombytes.c kyber_client.c -o kyber_client1024

kyber_server1024: $(SOURCESKECCAK) $(HEADERSKECCAK) kyber_server.c lib/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) lib/randombytes.c kyber_server.c -o kyber_server1024

kyber_client1024-90s:$(SOURCESNINETIES) $(HEADERSNINETIES) kyber_client.c lib/randombytes.c
	$(CC) $(CFLAGS) -D KYBER_90S -DKYBER_K=4 $(SOURCESNINETIES) lib/randombytes.c kyber_client.c -o kyber_client1024-90s

kyber_server1024-90s: $(SOURCESNINETIES) $(HEADERSNINETIES) kyber_server.c lib/randombytes.c
	$(CC) $(CFLAGS) -D KYBER_90S -DKYBER_K=4 $(SOURCESNINETIES) lib/randombytes.c kyber_server.c -o kyber_server1024-90s

clean:
	-$(RM) -rf kyber_client1024
	-$(RM) -rf kyber_server1024
	-$(RM) -rf kyber_client1024-90s
	-$(RM) -rf kyber_server1024-90s

