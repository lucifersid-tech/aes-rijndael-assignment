"""
test_rijndael.py
Unit tests for the C AES implementation via Python ctypes.
 
Compares each stage of the C implementation against the reference Python
implementation (boppreh/aes, added as a git submodule under aes/).
 
Run:  python test_rijndael.py
"""
 
import ctypes
import os
import random
import sys
import unittest
 
# ---------------------------------------------------------------------------
# Load the shared library
# ---------------------------------------------------------------------------
LIB_PATH = os.path.join(os.path.dirname(__file__), "rijndael.so")
if not os.path.exists(LIB_PATH):
    sys.exit(f"ERROR: {LIB_PATH} not found – run 'make' first.")
 
lib = ctypes.CDLL(LIB_PATH)
 
# Block size enum values (must match rijndael.h)
AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2
 
# ---------------------------------------------------------------------------
# ctypes return / argument types
# ---------------------------------------------------------------------------
lib.sub_bytes.argtypes         = [ctypes.c_char_p, ctypes.c_int]
lib.sub_bytes.restype          = None
lib.invert_sub_bytes.argtypes  = [ctypes.c_char_p, ctypes.c_int]
lib.invert_sub_bytes.restype   = None
lib.shift_rows.argtypes        = [ctypes.c_char_p, ctypes.c_int]
lib.shift_rows.restype         = None
lib.invert_shift_rows.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.invert_shift_rows.restype  = None
lib.mix_columns.argtypes       = [ctypes.c_char_p, ctypes.c_int]
lib.mix_columns.restype        = None
lib.invert_mix_columns.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.invert_mix_columns.restype  = None
lib.add_round_key.argtypes     = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
lib.add_round_key.restype      = None
lib.expand_key.argtypes        = [ctypes.c_char_p, ctypes.c_int]
lib.expand_key.restype         = ctypes.c_void_p
lib.aes_encrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
lib.aes_encrypt_block.restype  = ctypes.c_void_p
lib.aes_decrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
lib.aes_decrypt_block.restype  = ctypes.c_void_p
 
# ---------------------------------------------------------------------------
# Reference AES S-box / inverse (Python reference values)
# ---------------------------------------------------------------------------
SBOX = [
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
 
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
 
# ---------------------------------------------------------------------------
# reference implementations
# ---------------------------------------------------------------------------
 
def py_sub_bytes(block):
    return bytes(SBOX[b] for b in block)

def py_inv_sub_bytes(block):
    return bytes(INV_SBOX[b] for b in block)

def py_shift_rows(block, nb):
    """block is bytes, nb is number of columns."""
    state = list(block)
    out = [0] * len(state)
    for row in range(4):
        for col in range(nb):
            out[row * nb + col] = state[row * nb + (col + row) % nb]
    return bytes(out)

def py_inv_shift_rows(block, nb):
    state = list(block)
    out = [0] * len(state)
    for row in range(4):
        for col in range(nb):
            out[row * nb + col] = state[row * nb + (col - row) % nb]
    return bytes(out)

def gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return result

def py_mix_columns(block, nb):
    state = list(block)
    for col in range(nb):
        s = [state[row * nb + col] for row in range(4)]
        state[0 * nb + col] = gf_mul(2, s[0]) ^ gf_mul(3, s[1]) ^ s[2] ^ s[3]
        state[1 * nb + col] = s[0] ^ gf_mul(2, s[1]) ^ gf_mul(3, s[2]) ^ s[3]
        state[2 * nb + col] = s[0] ^ s[1] ^ gf_mul(2, s[2]) ^ gf_mul(3, s[3])
        state[3 * nb + col] = gf_mul(3, s[0]) ^ s[1] ^ s[2] ^ gf_mul(2, s[3])
    return bytes(state)

def c_sub_bytes(block, bs):
    buf = ctypes.create_string_buffer(bytes(block), len(block))
    lib.sub_bytes(buf, bs)
    return bytes(buf)

def c_inv_sub_bytes(block, bs):
    buf = ctypes.create_string_buffer(bytes(block), len(block))
    lib.invert_sub_bytes(buf, bs)
    return bytes(buf)

def c_shift_rows(block, bs):
    buf = ctypes.create_string_buffer(bytes(block), len(block))
    lib.shift_rows(buf, bs)
    return bytes(buf)

def c_inv_shift_rows(block, bs):
    buf = ctypes.create_string_buffer(bytes(block), len(block))
    lib.invert_shift_rows(buf, bs)
    return bytes(buf)

def c_mix_columns(block, bs):
    buf = ctypes.create_string_buffer(bytes(block), len(block))
    lib.mix_columns(buf, bs)
    return bytes(buf)

def rand_block(n):
    return bytes(random.randint(0, 255) for _ in range(n))

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
 
BS_SIZES = [
    (AES_BLOCK_128, 16, 4),
    (AES_BLOCK_256, 32, 8),
    (AES_BLOCK_512, 64, 16),
]
 
class TestSubBytes(unittest.TestCase):
    def test_sub_bytes_matches_reference(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                self.assertEqual(c_sub_bytes(block, bs), py_sub_bytes(block),
                                 f"sub_bytes mismatch for block_size={sz}")
                
    def test_inv_sub_bytes_matches_reference(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                self.assertEqual(c_inv_sub_bytes(block, bs), py_inv_sub_bytes(block),
                                 f"inv_sub_bytes mismatch for block_size={sz}")
 
    def test_sub_bytes_invertible(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                sub = c_sub_bytes(block, bs)
                recovered = c_inv_sub_bytes(sub, bs)
                self.assertEqual(recovered, block,
                                 "sub_bytes -> inv_sub_bytes should return original")
                
class TestShiftRows(unittest.TestCase):
    def test_shift_rows_matches_reference(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                self.assertEqual(c_shift_rows(block, bs), py_shift_rows(block, nb),
                                 f"shift_rows mismatch for block_size={sz}")
                
    def test_inv_shift_rows_matches_reference(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                self.assertEqual(c_inv_shift_rows(block, bs), py_inv_shift_rows(block, nb),
                                 f"inv_shift_rows mismatch for block_size={sz}")
 
    def test_shift_rows_invertible(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                shifted   = c_shift_rows(block, bs)
                recovered = c_inv_shift_rows(shifted, bs)
                self.assertEqual(recovered, block,
                                 "shift_rows -> inv_shift_rows should return original")
                
class TestMixColumns(unittest.TestCase):
    def test_mix_columns_matches_reference(self):
        for bs, sz, nb in BS_SIZES:
            for _ in range(3):
                block = rand_block(sz)
                self.assertEqual(c_mix_columns(block, bs), py_mix_columns(block, nb),
                                 f"mix_columns mismatch for block_size={sz}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

