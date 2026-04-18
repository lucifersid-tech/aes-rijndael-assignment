#include <stdio.h>
#include <stdlib.h>
 
#include "rijndael.h"
 
/*
 * print_block: display a block as a 4-row state matrix.
 *
 * State is stored column-major: block[col * 4 + row].
 * Iterating row-outer, col-inner prints one state row per line,
 * matching the standard AES state diagram and boppreh/aes output.
 */
void print_block(unsigned char *block, aes_block_size_t block_size) {
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      unsigned char value = block_access(block, row, col, block_size);
      printf("%4d", value);   /* fixed-width field: right-aligned in 4 chars */
    }
    printf("\n");
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
