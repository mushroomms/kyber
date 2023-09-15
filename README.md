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

## Key Encapsulation Method (KEM) using Mutually Authenticated Key EXchange (KEX)
- Both ALICE & BOB are required to share their respective public key
- The public keys allow ALICE & BOB to decapsulate correctly using their respective private key
- This ensures that ALICE & BOB are authenticated

![image](https://github.com/mushroomms/kyber/assets/98047682/75f36154-d3c8-4592-8742-9e87774101c8)

## To run
Run the following make files in Alice & Bob folders to run.
<br><br>
Alice:
```
./test_kex1024 <Bob IP Address> <Bob Port>
```
Bob:
```
./test_kex1024 <Listening Port> <Alice Machine Name>
```




