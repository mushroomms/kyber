#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

#include "lib/kem.h"
#include "lib/kex.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8888

#define cpucycles(cycles) cycles = __rdtsc()
#define cpucycles_reset() cpucycles_sum = 0
#define cpucycles_start() cpucycles(cpucycles_before)
#define cpucycles_stop()                                         \
      do                                                         \
      {                                                          \
            cpucycles(cpucycles_after);                          \
            cpucycles_sum += cpucycles_after - cpucycles_before; \
      } while (0)

#define cpucycles_result() cpucycles_sum

unsigned long long cpucycles_before, cpucycles_after, cpucycles_sum;

char *showhex(uint8_t a[], int size) {

      char *s = malloc(size * 2 + 1);

      for (int i = 0; i < size; i++)
            sprintf(s + i * 2, "%02x", a[i]);

      return (s);
}

int main(void) {
      struct timespec begin_kyber_cpu, end_kyber_cpu, begin_kyber_wall, end_kyber_wall;

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

      for (i = 0; i < KEX_SSBYTES; i++)
            zero[i] = 0;

      // Creating socket file descriptor
      if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      {
            perror("socket failed");
            exit(EXIT_FAILURE);
      }

      // Forcefully attaching socket to the port 8080
      if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
      {
            perror("setsockopt");
            exit(EXIT_FAILURE);
      }

      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons(PORT);

      printf("\n[*] Waiting for Alice Public Key...\n");

      // Forcefully attaching socket to the port 8080
      if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
      }
      if (listen(server_fd, 3) < 0) {
            printf("listen");
            exit(EXIT_FAILURE);
      }
      if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
      }

      // Receiving Alice public key first
      valread = read(new_socket, pka, CRYPTO_PUBLICKEYBYTES);
      printf("\n[+] Received Alice Public Key\n");

      clock_gettime(CLOCK_REALTIME, &begin_kyber_wall);
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin_kyber_cpu);

      cpucycles_reset();
      cpucycles_start();
      crypto_kem_keypair(pkb, skb); // Generate static key for Bob
      cpucycles_stop();
      unsigned int crypto_kem_keypair_cycles = cpucycles_result();

      printf("[*] Sending Bob Public key...\n");
      send(new_socket, pkb, sizeof(pkb), 0); // Sending Bob public key

      // Bob will receive AKE
      valread = read(new_socket, ake_senda, KEX_AKE_SENDABYTES);
      printf("\n[+] Received Alice AKE\n");

      cpucycles_reset();
      cpucycles_start();
      kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
      cpucycles_stop();
      unsigned int ake_shared_cycles = cpucycles_result();

      clock_gettime(CLOCK_REALTIME, &end_kyber_wall);
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_kyber_cpu);

      double kyber_wall = (end_kyber_wall.tv_sec - begin_kyber_wall.tv_sec) + (end_kyber_wall.tv_nsec - begin_kyber_wall.tv_nsec) / 1000000000.0 * 1000.0;
      double kyber_cpu = (end_kyber_cpu.tv_sec - begin_kyber_cpu.tv_sec) + (end_kyber_cpu.tv_nsec - begin_kyber_cpu.tv_nsec) / 1000000000.0 * 1000.0;

      // Bob will send AKE
      printf("[*] Sending Bob AKE...\n");
      send(new_socket, ake_sendb, sizeof(ake_sendb), 0);

      printf("\nKEX_AKE_SENDABYTES: %d\n", KEX_AKE_SENDABYTES);
      printf("KEX_AKE_SENDBBYTES: %d\n", KEX_AKE_SENDBBYTES);

      // Printing the AKE shared between Alice and Bob
      printf("\nAlice AKE key (only showing 1/8 of key): %s\n", showhex(ake_senda, KEX_AKE_SENDABYTES / 8));
      printf("Bob AKE key (only showing 1/8 of key): %s\n", showhex(ake_sendb, KEX_AKE_SENDBBYTES / 8));

      // Printing Public Key shared between Alice and Bob
      printf("\nAlice Public key (only showing 1/8 of key): %s\n", showhex(pka, CRYPTO_PUBLICKEYBYTES / 8));
      printf("Bob Public key (only showing 1/8 of key): %s\n", showhex(pkb, CRYPTO_PUBLICKEYBYTES / 8));

      // printf("Key (A): %s\n",showhex(ka,CRYPTO_BYTES));
      printf("\nKey (B): %s\n", showhex(kb, CRYPTO_BYTES));

      printf("\nTotal CPU Cycles: %d\n", crypto_kem_keypair_cycles + ake_shared_cycles);
      printf("Total Wall time: %f milliseconds\n", kyber_wall);
      printf("Total CPU time: %f milliseconds\n", kyber_cpu);  

      return 0;
}
