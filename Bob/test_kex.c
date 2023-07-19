#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kem.h"
#include "kex.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8888

char *showhex(uint8_t a[], int size);

char *showhex(uint8_t a[], int size) {

    char *s = malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return(s);
}

int main(void)
{
  uint8_t pka[CRYPTO_PUBLICKEYBYTES];

  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
  uint8_t skb[CRYPTO_SECRETKEYBYTES];

  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

  uint8_t kb[KEX_SSBYTES];
  uint8_t zero[KEX_SSBYTES];
  int i;

  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  
  for(i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;
  
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
  if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 3) < 0) {
        printf("listen");
        exit(EXIT_FAILURE);
  }
  if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen))< 0) {
        perror("accept");
        exit(EXIT_FAILURE);
  }

  // Receiving Alice public key first
  valread = read(new_socket, pka, CRYPTO_PUBLICKEYBYTES);
  printf("\n[] Received Alice Public Key----\n");

  crypto_kem_keypair(pkb, skb); // Generate static key for Bob

  send(new_socket, pkb, sizeof(pkb), 0); // Sending Bob public key
  printf("Sending Bob Public key...\n");

  // Bob will receive AKE
  valread = read(new_socket, ake_senda, KEX_AKE_SENDABYTES);
  printf("[] AKE of Alice received...\n");

  kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob

  // Bob will send AKE
  send(new_socket, ake_sendb, sizeof(ake_sendb), 0);
  printf("Sending AKE of Bob\n");

  printf("\nKEX_AKE_SENDABYTES: %d\n",KEX_AKE_SENDABYTES);
  printf("KEX_AKE_SENDBBYTES: %d\n",KEX_AKE_SENDBBYTES);

  // Printing the AKE shared between Alice and Bob
  printf("Alice AKE key (only showing 1/8 of key): %s\n",showhex(ake_senda,KEX_AKE_SENDABYTES/8));
  printf("Bob AKE key (only showing 1/8 of key): %s\n",showhex(ake_sendb,KEX_AKE_SENDBBYTES/8));


  // Printing Public Key shared between Alice and Bob
  printf("Alice Public key (only showing 1/8 of key): %s\n",showhex(pka,CRYPTO_PUBLICKEYBYTES/8));
  printf("Bob Public key (only showing 1/8 of key): %s\n",showhex(pkb,CRYPTO_PUBLICKEYBYTES/8));

  // printf("Key (A): %s\n",showhex(ka,CRYPTO_BYTES));  
  printf("Key (B): %s\n",showhex(kb,CRYPTO_BYTES));

  return 0;
}

