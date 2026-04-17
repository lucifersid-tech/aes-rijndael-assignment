/*
 * rijndael.c
 * AES (Rijndael) block cipher implementation for 128, 256 and 512-bit blocks.
 *
 * Implements:
 *   - SubBytes / InvSubBytes       (S-box and inverse S-box substitution)
 *   - ShiftRows / InvShiftRows     (row rotation)
 *   - MixColumns / InvMixColumns   (column mixing via GF(2^8) arithmetic)
 *   - AddRoundKey                  (XOR with round key)
 *   - KeyExpansion                 (Rijndael key schedule)
 *   - aes_encrypt_block            (public API: encrypt one block)
 *   - aes_decrypt_block            (public API: decrypt one block)
 *
 * Block-size mapping used throughout:
 *   AES_BLOCK_128  => 16 bytes, 4 columns,  10 rounds
 *   AES_BLOCK_256  => 32 bytes, 8 columns,  14 rounds
 *   AES_BLOCK_512  => 64 bytes, 16 columns, 22 rounds
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include "rijndael.h"
 
/* -------------------------------------------------------------------------
 * Forward S-box (AES standard)
 * ------------------------------------------------------------------------- */
static const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
 
/* -------------------------------------------------------------------------
 * Inverse S-box
 * ------------------------------------------------------------------------- */
static const unsigned char inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
 
/* -------------------------------------------------------------------------
 * Rijndael round constants (Rcon), indices 0..29 cover all key schedules
 * ------------------------------------------------------------------------- */
static const unsigned char rcon[30] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
    0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,0x91
};
 
/* -------------------------------------------------------------------------
 * Helper: derive column count and round count from block_size enum
 * ------------------------------------------------------------------------- */
static size_t block_size_to_bytes(aes_block_size_t block_size) {
    switch (block_size) {
        case AES_BLOCK_128: return 16;
        case AES_BLOCK_256: return 32;
        case AES_BLOCK_512: return 64;
        default:
            fprintf(stderr, "Invalid block size %d\n", block_size);
            exit(1);
    }
}
 
static int block_size_to_cols(aes_block_size_t block_size) {
    switch (block_size) {
        case AES_BLOCK_128: return 4;
        case AES_BLOCK_256: return 8;
        case AES_BLOCK_512: return 16;
        default: return 4;
    }
}
 
/* Number of rounds: Nr = 6 + Nb  (standard Rijndael formula for Nk==Nb) */
static int block_size_to_rounds(aes_block_size_t block_size) {
    switch (block_size) {
        case AES_BLOCK_128: return 10;
        case AES_BLOCK_256: return 14;
        case AES_BLOCK_512: return 22;
        default: return 10;
    }
}
 
/* -------------------------------------------------------------------------
 * block_access: read byte at (row, col) from a block stored in row-major order
 * The block state is 4 rows x Nb columns.
 * ------------------------------------------------------------------------- */
unsigned char block_access(unsigned char *block,
                           size_t row, size_t col,
                           aes_block_size_t block_size) {
    int nb = block_size_to_cols(block_size);
    return block[row * nb + col];
}
 
/* Convenience write macro */
static inline void block_set(unsigned char *block,
                              size_t row, size_t col,
                              aes_block_size_t block_size,
                              unsigned char val) {
    int nb = block_size_to_cols(block_size);
    block[row * nb + col] = val;
}
 
/* -------------------------------------------------------------------------
 * GF(2^8) multiplication used by MixColumns
 * Multiply by 2 (xtime), then build higher multiples.
 * ------------------------------------------------------------------------- */
static unsigned char xtime(unsigned char a) {
    /* Left-shift; XOR with 0x1b if high bit was set (reduce mod x^8+x^4+x^3+x+1) */
    return (unsigned char)((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00));
}
 
static unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    unsigned char hi;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return result;
}
 
/* -------------------------------------------------------------------------
 * SubBytes: replace every byte with its S-box value
 * ------------------------------------------------------------------------- */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
    size_t len = block_size_to_bytes(block_size);
    for (size_t i = 0; i < len; i++) {
        block[i] = sbox[block[i]];
    }
}

void shift_rows(unsigned char *block, aes_block_size_t block_size) {
   int nb = block_size_to_cols(block_size);
    unsigned char tmp[64]; /* max block size */
 
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < nb; col++) {
            /* read source column with wrap: (col + row) % nb */
            tmp[row * nb + col] = block[row * nb + ((col + row) % nb)];
        }
    }
    memcpy(block, tmp, 4 * nb);
}

void mix_columns(unsigned char *block, aes_block_size_t block_size) {
   int nb = block_size_to_cols(block_size);
 
    for (int col = 0; col < nb; col++) {
        unsigned char s0 = block[0 * nb + col];
        unsigned char s1 = block[1 * nb + col];
        unsigned char s2 = block[2 * nb + col];
        unsigned char s3 = block[3 * nb + col];
 
        block[0 * nb + col] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        block[1 * nb + col] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        block[2 * nb + col] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        block[3 * nb + col] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
    for (size_t i = 0; i < len; i++) {
        block[i] = inv_sbox[block[i]];
    }
}

void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int nb = block_size_to_cols(block_size);
    unsigned char tmp[64];
 
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < nb; col++) {
            /* shift right: source column is (col - row + nb) % nb */
            tmp[row * nb + col] = block[row * nb + ((col - row + nb) % nb)];
        }
    }
    memcpy(block, tmp, 4 * nb);
}

void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int nb = block_size_to_cols(block_size);
 
    for (int col = 0; col < nb; col++) {
        unsigned char s0 = block[0 * nb + col];
        unsigned char s1 = block[1 * nb + col];
        unsigned char s2 = block[2 * nb + col];
        unsigned char s3 = block[3 * nb + col];
 
        block[0 * nb + col] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        block[1 * nb + col] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        block[2 * nb + col] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        block[3 * nb + col] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
    for (size_t i = 0; i < len; i++) {
        block[i] ^= round_key[i];
    }
}

static void sub_word(unsigned char *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = sbox[word[i]];
    }
}

static void rot_word(unsigned char *word) {
    unsigned char tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
      int nb     = block_size_to_cols(block_size); 
    int nk     = nb;                             
    int nr     = block_size_to_rounds(block_size);
    int total  = nb * (nr + 1);                 
    size_t len = total * 4;                      
 
    unsigned char *w = (unsigned char *)malloc(len);
    if (!w) { perror("malloc"); exit(1); }

    memcpy(w, cipher_key, nk * 4);
 
    unsigned char temp[4];
 
    for (int i = nk; i < total; i++) {
       
        memcpy(temp, &w[(i - 1) * 4], 4);
 
        if (i % nk == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= rcon[(i / nk) - 1];
        } else if (nk > 6 && (i % nk) == 4) {
         
            sub_word(temp);
        }
 
        /* w[i] = w[i-Nk] XOR temp */
        for (int j = 0; j < 4; j++) {
            w[i * 4 + j] = w[(i - nk) * 4 + j] ^ temp[j];
        }
    }
 
    size_t block_bytes = block_size_to_bytes(block_size);
    unsigned char *rk = (unsigned char *)malloc(len);
    if (!rk) { perror("malloc"); exit(1); }
 
    for (int rnd = 0; rnd <= nr; rnd++) {
       
        unsigned char *src = &w[rnd * nb * 4];
        unsigned char *dst = &rk[rnd * block_bytes];
 
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < nb; col++) {
                dst[row * nb + col] = src[col * 4 + row];
            }
        }
    }
 
    free(w);
    return rk;
  return 0;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
                                  size_t bytes = block_size_to_bytes(block_size);
    int nr = block_size_to_rounds(block_size);
 
    /* Allocate working state and output */
    unsigned char *state = (unsigned char *)malloc(bytes);
    if (!state) { perror("malloc"); exit(1); }
    memcpy(state, plaintext, bytes);
 
    /* Expand key */
    unsigned char *round_keys = expand_key(key, block_size);
 
    /* Initial round key addition */
    add_round_key(state, &round_keys[0], block_size);
 
    /* Main rounds */
    for (int round = 1; round < nr; round++) {
        sub_bytes(state, block_size);
        shift_rows(state, block_size);
        mix_columns(state, block_size);
        add_round_key(state, &round_keys[round * bytes], block_size);
    }
 
    /* Final round (no MixColumns) */
    sub_bytes(state, block_size);
    shift_rows(state, block_size);
    add_round_key(state, &round_keys[nr * bytes], block_size);
 
    free(round_keys);
    return state; /* caller frees */
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
      size_t bytes = block_size_to_bytes(block_size);
    int nr = block_size_to_rounds(block_size);
 
    unsigned char *state = (unsigned char *)malloc(bytes);
    if (!state) { perror("malloc"); exit(1); }
    memcpy(state, ciphertext, bytes);
 
    unsigned char *round_keys = expand_key(key, block_size);
 
    /* Start with last round key */
    add_round_key(state, &round_keys[nr * bytes], block_size);
 
    /* Middle rounds in reverse */
    for (int round = nr - 1; round >= 1; round--) {
        invert_shift_rows(state, block_size);
        invert_sub_bytes(state, block_size);
        add_round_key(state, &round_keys[round * bytes], block_size);
        invert_mix_columns(state, block_size);
    }
 
    /* Final (initial) round */
    invert_shift_rows(state, block_size);
    invert_sub_bytes(state, block_size);
    add_round_key(state, &round_keys[0], block_size);
 
    free(round_keys);
    return state; /* caller frees */
}
