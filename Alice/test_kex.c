#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

#include "lib/kem.h"
#include "lib/kex.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define cpucycles(cycles) cycles = __rdtsc()
#define cpucycles_reset() cpucycles_sum = 0
#define cpucycles_start() cpucycles(cpucycles_before)
#define cpucycles_stop()                                 \
  do                                                     \
  {                                                      \
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

    return(s);
}

int main(int argc, char* argv[]) {
  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];

  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];

  uint8_t eska[CRYPTO_SECRETKEYBYTES];

  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

  uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];

  int status, valread, client_fd;
  struct sockaddr_in serv_addr;
  struct timespec begin_sending_PKA, end_receiving_PKB, begin_sending_AKE, end_receiving_AKE;
  struct timespec begin_kyber_cpu, end_kyber_cpu, begin_kyber_wall, end_kyber_wall;
  
  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  char *SERVER_IP = argv[1];
  int PORT = atoi(argv[2]);

  memset(&serv_addr, 0, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  printf("[SOCK] Connecting to %s:%d\n", SERVER_IP, PORT);

  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
          printf("\nInvalid address/ Address not supported \n");
          return -1;
  }
  if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
          printf("\nConnection Failed \n");
          return -1;
  }

  // Start timer
  clock_gettime(CLOCK_REALTIME, &begin_kyber_wall);
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin_kyber_cpu);

  // Taking CPU cycles to generate static keys
  cpucycles_reset();
  cpucycles_start();
  crypto_kem_keypair(pka, ska); // Generate static key for Alice
  cpucycles_stop();
  unsigned int crypto_kem_keypair_cycles = cpucycles_result();

  // Sending Alice Public Key
  printf("\n[*] Sending Alice Public key...\n");
  clock_gettime(CLOCK_REALTIME, &begin_sending_PKA);
  send(client_fd, pka, sizeof(pka), 0);
  
  // Receiving Bob Public Key
  valread = read(client_fd, pkb, CRYPTO_PUBLICKEYBYTES);
  clock_gettime(CLOCK_REALTIME, &end_receiving_PKB);
  printf("[+] Received Bob Public key\n");

  // Calculating RTT for sending and receiving Public Keys
  double RTT_PK = (end_receiving_PKB.tv_sec - begin_sending_PKA.tv_sec) + (end_receiving_PKB.tv_nsec - begin_sending_PKA.tv_nsec) / 1000000000.0 * 1000.0;
  printf("\nRound Trip Time for Public Key (WALL TIME): %f milliseconds\n", RTT_PK);

  // Taking CPU cycles to generate ake_senda ciphertext
  cpucycles_reset();
  cpucycles_start();
  kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice
  cpucycles_stop();
  unsigned int ake_init_cycles = cpucycles_result();

  // Sending Alice AKE
  printf("\n[*] Sending Alice AKE...\n");
  clock_gettime(CLOCK_REALTIME, &begin_sending_AKE);
  send(client_fd, ake_senda, sizeof(ake_senda), 0);

  // Receiving Bob AKE
  valread = read(client_fd, ake_sendb, KEX_AKE_SENDBBYTES);
  clock_gettime(CLOCK_REALTIME, &end_receiving_AKE);
  if (valread == -1) {
    perror("read error");
  }
  printf("[+] Received Bob AKE\n");

  // Calculating RTT for sending and receiving AKEs
  double RTT_AKE = (end_receiving_AKE.tv_sec - begin_sending_AKE.tv_sec) + (end_receiving_AKE.tv_nsec - begin_sending_AKE.tv_nsec) / 1000000000.0 * 1000.0;
  printf("\nRound Trip Time for AKE (WALL TIME): %f milliseconds\n", RTT_AKE);
  
  // Taking CPU cycles to generate shared key
  cpucycles_reset();
  cpucycles_start();
  kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
  cpucycles_stop();
  unsigned int sharedA_cycles = cpucycles_result();

  // End timer
  clock_gettime(CLOCK_REALTIME, &end_kyber_wall);
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_kyber_cpu);

  double kyber_wall = (end_kyber_wall.tv_sec - begin_kyber_wall.tv_sec) + (end_kyber_wall.tv_nsec - begin_kyber_wall.tv_nsec) / 1000000000.0 * 1000.0;
  double kyber_cpu = (end_kyber_cpu.tv_sec - begin_kyber_cpu.tv_sec) + (end_kyber_cpu.tv_nsec - begin_kyber_cpu.tv_nsec) / 1000000000.0 * 1000.0;

  printf("\nKEX_AKE_SENDABYTES: %d\n",KEX_AKE_SENDABYTES);
  printf("KEX_AKE_SENDBBYTES: %d\n",KEX_AKE_SENDBBYTES);

  // Printing the AKE shared between Alice and Bob
  printf("\nAlice AKE key (only showing 1/32 of key): %s\n",showhex(ake_senda,KEX_AKE_SENDABYTES/32));
  printf("Bob AKE key (only showing 1/32 of key): %s\n",showhex(ake_sendb,KEX_AKE_SENDBBYTES/32));

  // Printing the Public keys shared between Alice and Bob
  printf("\nAlice Public key (only showing 1/32 of key): %s\n",showhex(pka,CRYPTO_PUBLICKEYBYTES/32));
  printf("Bob Public key (only showing 1/32 of key): %s\n",showhex(pkb,CRYPTO_PUBLICKEYBYTES/32));

  // Printing the derived secret key by Alice
  printf("\nKey (A): %s\n",showhex(ka,CRYPTO_BYTES));

  printf("\nKEM Keypair:    %d CPU Cycles\n", crypto_kem_keypair_cycles);
  printf("AKE Init:       %d CPU Cycles\n", ake_init_cycles);
  printf("Derive Shared:  %d CPU Cycles\n", sharedA_cycles);
  printf("Total:          %d CPU Cycles\n", crypto_kem_keypair_cycles + ake_init_cycles + sharedA_cycles);

  printf("\nTotal Wall time: %f milliseconds\n", kyber_wall);
  printf("Total CPU time: %f milliseconds\n", kyber_cpu);  

  FILE *sharedsecret = fopen("pmk.key", "wb");
  fwrite(ka, 1, CRYPTO_BYTES, sharedsecret); 

  return 0;
}

