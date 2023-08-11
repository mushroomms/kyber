#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kem.h"
#include "randombytes.h"

#include <netinet/in.h>
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

  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  char buffer[2048] = { 0 };


  //Alice generates a public key
  // crypto_kem_keypair(pk, sk);

  //Alice uses Bobs response to get her shared key
  // crypto_kem_dec(key_a, ct, sk);

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
          perror("socket failed");
          exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 8080
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
          perror("setsockopt");
          exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8080
  if (bind(server_fd, (struct sockaddr*)&address,
                  sizeof(address))
          < 0) {
          perror("bind failed");
          exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 3) < 0) {
          perror("listen");
          exit(EXIT_FAILURE);
  }
  if ((new_socket
          = accept(server_fd, (struct sockaddr*)&address,
                          (socklen_t*)&addrlen))
          < 0) {
          perror("accept");
          exit(EXIT_FAILURE);
  }

  // Alice will receivev public key here
  valread = read(new_socket, buffer, 2048);
  printf("Alice public key received\n");

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, buffer);

  send(new_socket, ct, sizeof(ct), 0);
  printf("Bob response sent\n");

  // closing the connected socket
  close(new_socket);
  // closing the listening socket
  shutdown(server_fd, SHUT_RDWR);

  // printf("Public key size: %d\nSecret key size: %d\nCiphertext  size: %d\n",CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_CIPHERTEXTBYTES);
  printf("Public key (only showing 1/8 of key): %s\n",showhex(buffer,CRYPTO_PUBLICKEYBYTES/8));
  // printf("Secret key (only showing 1/8 of key): %s\n",showhex(sk,CRYPTO_SECRETKEYBYTES/8));
  printf("Cipher text (only showing 1/8 of ciphertext): %s\n",showhex(ct,CRYPTO_CIPHERTEXTBYTES/8));
  // printf("Key (A): %s\n",showhex(key_a,CRYPTO_BYTES));  
  printf("Key (B): %s\n",showhex(key_b,CRYPTO_BYTES));

  return 0;
}
