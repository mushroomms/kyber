#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

#include "lib/kem.h"
#include "lib/kex.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "192.168.10.1"

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

char *showhex(uint8_t a[], int size);

char *showhex(uint8_t a[], int size) {

      char *s = malloc(size * 2 + 1);

      for (int i = 0; i < size; i++)
            sprintf(s + i * 2, "%02x", a[i]);

      return (s);
}

int main(int argc, char* argv[]) {
      struct timespec begin_kyber_cpu, end_kyber_cpu;
      struct timespec public_key_begin, public_key_end;
      struct timespec ake_begin, ake_end;

      uint8_t pka[CRYPTO_PUBLICKEYBYTES];

      uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
      uint8_t skb[CRYPTO_SECRETKEYBYTES];

      uint8_t ake_senda[KEX_AKE_SENDABYTES];
      uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

      uint8_t kb[KEX_SSBYTES];

      int server_fd, new_socket, valread;
      struct sockaddr_in address;
      int opt = 1;
      int addrlen = sizeof(address);

      if (argc != 3) {
            printf("Usage: %s <LISTENING PORT> <PEER NAME>\n", argv[0]);
            return 1;
      }
      int PORT = atoi(argv[1]);
      char *SERVER_NAME = argv[2];

      // Creating socket file descriptor
      if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
      }

      // Forcefully attaching socket
      if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            perror("setsockopt");
            exit(EXIT_FAILURE);
      }

      address.sin_family = AF_INET;
      address.sin_port = htons(PORT);

      printf("[SOCK] Starting up on %s:%i\n", SERVER_IP, PORT);
      printf("[SOCK] Listening for %s machine\n", SERVER_NAME);

      // Forcefully attaching socket to the port 8080 to SERVER_IP
      if (inet_pton(AF_INET, SERVER_IP, &address.sin_addr) <= 0) {
          printf("\nInvalid address/ Address not supported \n");
          return -1;
      }
      if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
      }
      
      printf("\n[*] Waiting for Alice Public Key...\n");

      if (listen(server_fd, 3) < 0) {
            exit(EXIT_FAILURE);
      }
      if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
      }

      // Receiving Alice public key first
      valread = read(new_socket, pka, CRYPTO_PUBLICKEYBYTES);
      if (valread == -1) {
            perror("read error");
            exit(EXIT_FAILURE);
      }
      printf("\n[+] Received Alice Public Key\n");
      clock_gettime(CLOCK_REALTIME, &public_key_begin);
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin_kyber_cpu);

      // Taking CPU cycles to generate static keys
      cpucycles_reset();
      cpucycles_start();
      crypto_kem_keypair(pkb, skb); // Generate static key for Alice
      cpucycles_stop();
      unsigned int crypto_kem_keypair_cycles = cpucycles_result();

      // Sending Bob public key
      printf("[*] Sending Bob Public key...\n");
      send(new_socket, pkb, sizeof(pkb), 0);
      clock_gettime(CLOCK_REALTIME, &public_key_end);
      
      // Calculating time taken to send PKB to Alice
      double pk_time = (public_key_end.tv_sec - public_key_begin.tv_sec) + (public_key_end.tv_nsec - public_key_begin.tv_nsec) / 1000000000.0 * 1000.0;
      printf("\nTime taken to send PKB (WALL TIME): %f milliseconds\n", pk_time);

      // Bob will receive AKE
      valread = read(new_socket, ake_senda, KEX_AKE_SENDABYTES);
      if (valread == -1) {
            perror("read error");
            exit(EXIT_FAILURE);
      }
      printf("\n[+] Received Alice AKE\n");
      clock_gettime(CLOCK_REALTIME, &ake_begin);

      // Calculate CPU cyckes to generate ake_sendb ciphertext
      cpucycles_reset();
      cpucycles_start();
      kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
      cpucycles_stop();
      unsigned int ake_shared_cycles = cpucycles_result();

      // Bob will send AKE
      printf("[*] Sending Bob AKE...\n");
      send(new_socket, ake_sendb, sizeof(ake_sendb), 0);
      clock_gettime(CLOCK_REALTIME, &ake_end);
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_kyber_cpu);

      // Calculating time taken to send ake_sendb ciphertext to Alice
      double ake_time = (ake_end.tv_sec - ake_begin.tv_sec) + (ake_end.tv_nsec - ake_begin.tv_nsec) / 1000000000.0 * 1000.0;
      printf("\nTime taken to send ake_sendb (WALL TIME): %f milliseconds\n", ake_time);

      // Calculating total timing
      double kyber_wall = (ake_end.tv_sec - public_key_begin.tv_sec) + (ake_end.tv_nsec - public_key_begin.tv_nsec) / 1000000000.0 * 1000.0;
      double kyber_cpu = (end_kyber_cpu.tv_sec - begin_kyber_cpu.tv_sec) + (end_kyber_cpu.tv_nsec - begin_kyber_cpu.tv_nsec) / 1000000000.0 * 1000.0;

      printf("\nKEX_AKE_SENDABYTES: %d\n", KEX_AKE_SENDABYTES);
      printf("KEX_AKE_SENDBBYTES: %d\n", KEX_AKE_SENDBBYTES);

      // Printing the AKE shared between Alice and Bob
      printf("\nAlice AKE key (only showing 1/32 of key): %s\n", showhex(ake_senda, KEX_AKE_SENDABYTES / 32));
      printf("Bob AKE key (only showing 1/32 of key): %s\n", showhex(ake_sendb, KEX_AKE_SENDBBYTES / 32));

      // Printing Public Key shared between Alice and Bob   
      printf("\nAlice Public key (only showing 1/32 of key): %s\n", showhex(pka, CRYPTO_PUBLICKEYBYTES / 32));
      printf("Bob Public key (only showing 1/32 of key): %s\n", showhex(pkb, CRYPTO_PUBLICKEYBYTES / 32));

      // printf("Key (A): %s\n",showhex(ka,CRYPTO_BYTES));
      printf("\nKey (B): %s\n", showhex(kb, CRYPTO_BYTES));

      printf("\nKEM keypair:    %d CPU Cycles\n", crypto_kem_keypair_cycles);
      printf("Derive Shared:  %d CPU Cycles\n", ake_shared_cycles);
      printf("Total:          %d CPU Cycles\n", crypto_kem_keypair_cycles + ake_shared_cycles);

      printf("\nTotal Wall time: %f milliseconds\n", kyber_wall);
      printf("Total CPU time: %f milliseconds\n", kyber_cpu);

      // Create a buffer to hold the concatenated string
      char filename[128];

      strcpy(filename, SERVER_NAME); // Copy SERVER_NAME to filename
      strcat(filename, "_pmk.key");  // Concatenate "_pmk.key" to filename

      FILE *sharedsecret = fopen(filename, "wb");
      fwrite(kb, 1, CRYPTO_BYTES, sharedsecret);
      return 0;
}
