#include <stdio.h>
#include <stdlib.h>
 
#include "rijndael.h"
 
/*
 * print_block: print the 16 bytes of a block in flat sequential order.
 *
 * The AES state is stored column-major internally, but for display we
 * print the raw bytes [0..15] left-to-right, 4 per line.  This matches
 * the order boppreh/aes uses when it prints list(ct).
 */
void print_block(unsigned char *block, aes_block_size_t block_size) {
  size_t len = 16; /* 128-bit block */
  for (size_t i = 0; i < len; i++) {
    printf("%4d", block[i]);
    if ((i + 1) % 4 == 0) printf("\n");
  }
}
 
int main() {
  unsigned char plaintext[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4,  8, 6,  99};
 
  unsigned char *ciphertext = aes_encrypt_block(plaintext, key, AES_BLOCK_128);
  unsigned char *recovered_plaintext = aes_decrypt_block(ciphertext, key, AES_BLOCK_128);
 
  printf("############ ORIGINAL PLAINTEXT ###########\n");
  print_block(plaintext, AES_BLOCK_128);
 
  printf("\n\n################ CIPHERTEXT ###############\n");
  print_block(ciphertext, AES_BLOCK_128);
 
  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_block(recovered_plaintext, AES_BLOCK_128);
 
  free(ciphertext);
  free(recovered_plaintext);
 
  return 0;
}