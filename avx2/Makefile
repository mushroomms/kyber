CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -maes \
  -march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS += -Wno-unused-result -mavx2 -mbmi2 -mpopcnt -maes \
  -march=native -mtune=native -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = lib/kem.c lib/indcpa.c lib/polyvec.c lib/poly.c lib/fq.S lib/shuffle.S lib/ntt.S lib/invntt.S \
  lib/basemul.S lib/consts.c lib/rejsample.c lib/cbd.c lib/verify.c
SOURCESKECCAK   = $(SOURCES) lib/fips202.c lib/fips202x4.c lib/symmetric-shake.c \
  lib/keccak4x/KeccakP-1600-times4-SIMD256.o
SOURCESNINETIES = $(SOURCES) lib/aes256ctr.c
HEADERS = lib/params.h lib/align.h lib/kem.h lib/indcpa.h lib/polyvec.h lib/poly.h lib/reduce.h fq.inc shuffle.inc \
  lib/ntt.h lib/consts.h lib/rejsample.h lib/cbd.h lib/verify.h lib/symmetric.h lib/randombytes.h
HEADERSKECCAK   = $(HEADERS) lib/fips202.h lib/fips202x4.h
HEADERSNINETIES = $(HEADERS) lib/sha2.h lib/aes256ctr.h

.PHONY: all shared clean

all: \
  kyber_client1024 \
  kyber_server1024 \


shared: \
  libpqcrystals_kyber512_avx2.so \
  libpqcrystals_kyber768_avx2.so \
  libpqcrystals_kyber1024_avx2.so \
  libpqcrystals_kyber512-90s_avx2.so \
  libpqcrystals_kyber768-90s_avx2.so \
  libpqcrystals_kyber1024-90s_avx2.so \
  libpqcrystals_fips202_ref.so \
  libpqcrystals_fips202x4_avx2.so \
  libpqcrystals_aes256ctr_avx2.so

keccak4x/KeccakP-1600-times4-SIMD256.o: \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/KeccakP-SIMD256-config.h \
  keccak4x/KeccakP-align.h \
  keccak4x/KeccakP-brg_endian.h
	$(CC) $(CFLAGS) -c $< -o $@

libpqcrystals_fips202_ref.so: fips202.c fips202.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

libpqcrystals_fips202x4_avx2.so: fips202x4.c fips202x4.h \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/KeccakP-SIMD256-config.h \
  keccak4x/KeccakP-align.h \
  keccak4x/KeccakP-brg_endian.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $< keccak4x/KeccakP-1600-times4-SIMD256.c


kyber_client1024: $(SOURCESKECCAK) $(HEADERSKECCAK) kyber_client.c lib/randombytes.c lib/kex.c lib/kex.h
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) lib/randombytes.c lib/kex.c kyber_client.c -o kyber_client1024

kyber_server1024: $(SOURCESKECCAK) $(HEADERSKECCAK) kyber_server.c lib/randombytes.c lib/kex.c lib/kex.h
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) lib/randombytes.c lib/kex.c kyber_server.c -o kyber_server1024


clean:
	-$(RM) -rf *.o *.a *.so
	-$(RM) -rf kyber_client1024
	-$(RM) -rf kyber_server1024
	-$(RM) -rf keccak4x/KeccakP-1600-times4-SIMD256.o
