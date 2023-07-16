#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kem.h"
#include "kex.h"

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
  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
  uint8_t skb[CRYPTO_SECRETKEYBYTES];

  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];

  uint8_t eska[CRYPTO_SECRETKEYBYTES];

  uint8_t uake_senda[KEX_UAKE_SENDABYTES];
  uint8_t uake_sendb[KEX_UAKE_SENDBBYTES];

  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

  uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];
  uint8_t kb[KEX_SSBYTES];
  uint8_t zero[KEX_SSBYTES];

  int i;

  int rtn;
  int status, valread, client_fd;
  struct sockaddr_in serv_addr;
  char buffer_ake_sendb[3137] = { 0 };
  char buffer_pkb[2048] = { 0 };

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

  for(i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;

  crypto_kem_keypair(pka, ska); // Generate static key for Alice
  
  // Sending Alice Public Key
  printf("\nSending Alice Public key...\n");
  send(client_fd, pka, sizeof(pka), 0);

  // Receiving Bob Public Key
  valread = read(client_fd, buffer_pkb, 2048);
  printf("[] Received Bob Public key\n");

  kex_ake_initA(ake_senda, tk, eska, buffer_pkb); // Run by Alice
  
  // Sending Alice AKE
  printf("----AKE of Alice sent----\n");
  send(client_fd, ake_senda, sizeof(ake_senda), 0);

  // Receiving Bob AKE
  valread = read(client_fd, buffer_ake_sendb, 3137);
  printf("[] AKE of Bob Received\n");
  kex_ake_sharedA(ka, buffer_ake_sendb, tk, eska, ska); // Run by Alice

  printf("\nKEX_AKE_SENDABYTES: %d\n",KEX_AKE_SENDABYTES);
  printf("KEX_AKE_SENDBBYTES: %d\n",KEX_AKE_SENDBBYTES);

  // Printing the AKE shared between Alice and Bob
  printf("Alice AKE key (only showing 1/8 of key): %s\n",showhex(ake_senda,KEX_AKE_SENDABYTES/8));
  printf("Bob AKE key (only showing 1/8 of key): %s\n",showhex(buffer_ake_sendb,KEX_AKE_SENDBBYTES/8));

  // Printing the Public keys shared between Alice and Bob
  printf("Alice Public key (only showing 1/8 of key): %s\n",showhex(pka,CRYPTO_PUBLICKEYBYTES/8));
  printf("Bob Public key (only showing 1/8 of key): %s\n",showhex(buffer_pkb,CRYPTO_PUBLICKEYBYTES/8));

  // Printing the derived secret key by Alice
  printf("Key (A): %s\n",showhex(ka,CRYPTO_BYTES));  

  return 0;
}

