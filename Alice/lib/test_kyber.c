#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kem.h"
#include "randombytes.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8888


char *showhex(uint8_t a[], int size) ;

char *showhex(uint8_t a[], int size) {
    char *s = malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return(s);
}

int main(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  
  int rtn;
  int status, valread, client_fd;
  struct sockaddr_in serv_addr;

  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, "192.168.10.1", &serv_addr.sin_addr)
          <= 0) {
          printf("\nInvalid address/ Address not supported \n");
          return -1;
  }

  if ((status
          = connect(client_fd, (struct sockaddr*)&serv_addr,
                          sizeof(serv_addr)))
          < 0) {
          printf("\nConnection Failed \n");
          return -1;
  }

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  char buffer[2048] = { 0 };

  send(client_fd, pk, sizeof(pk), 0);
  printf("Public key sent to Bob\n");

  valread = read(client_fd, buffer, 2048);
  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, buffer, sk);
  printf("Bob response received\n");

  // closing the connected socket
  close(client_fd);

  // printf("Public key size: %d\nSecret key size: %d\nCiphertext  size: %d\n",CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_CIPHERTEXTBYTES);
  printf("Public key (only showing 1/8 of key): %s\n",showhex(pk,CRYPTO_PUBLICKEYBYTES/8));
  // printf("Secret key (only showing 1/8 of key): %s\n",showhex(sk,CRYPTO_SECRETKEYBYTES/8));
  printf("Cipher text (only showing 1/8 of ciphertext): %s\n",showhex(buffer,CRYPTO_CIPHERTEXTBYTES/8));
  printf("Key (A): %s\n",showhex(key_a,CRYPTO_BYTES));  
  // printf("Key (B): %s\n",showhex(key_b,CRYPTO_BYTES));

  // rtn=memcmp(key_a, key_b, CRYPTO_BYTES);
  // if (rtn==0) { printf("Keys are the same\n");}
  // else printf("Error in the keys!");

  return 0;
}
