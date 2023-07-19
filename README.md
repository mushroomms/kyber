# Kyber
CRYSTALS-KYBER (Lattice + LWE) - Key EXchange Mechanism (KEX)

Kyber comes in three security levels. The size vs. security tradeoffs are shown in the following table with RSA as a pre-quantum comparison.

| Version | Security Level | Private Key Size | Public Key Size | Ciphertext Size | 
| --- | --- | --- | --- | --- |
| Kyber512 | AES128 | 1632 | 800 | 768 |
| Kyber768 | AES192 | 2400 | 1184 | 1088 |
| Kyber1024 | AES256 | 3168 | 1568 | 1568 |
| RSA3072 | AES128 | 384 | 384 | 384 |
| RSA15360 | AES256 | 1920 | 1920 | 1920 |

`$ALG` ranges over the parameter sets 512, 768, 1024.

* `test_kyber$ALG` tests 1000 times to generate keys, encapsulate a random key and correctly decapsulate it again. Also, the program tests that the keys cannot correctly be decapsulated using a random secret key or a ciphertext where a single random byte was randomly distorted in order to test for trivial failures of the CCA security. The program will abort with an error message and return 1 if there was an error. Otherwise it will output the key and ciphertext sizes and return 0.
* `test_kex$ALG` tests the authenticated key exchange schemes derived from the Kyber KEM
