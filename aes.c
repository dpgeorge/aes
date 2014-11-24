#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"

/****************************************************************/
// discrete arithmetic routines, mostly from a precomputed table

// non-linear, invertible, substitution box
static const byte aes_s_box_table[256] = {
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
};

// multiplication of polynomials modulo x^8 + x^4 + x^3 + x + 1 = 0x11b
static byte aes_gf8_mul_2(byte x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}
static byte aes_gf8_mul_3(byte x) {
    return x ^ aes_gf8_mul_2(x);
}

// non-linear, invertible, substitution box
static byte aes_s_box(byte a) {
    return aes_s_box_table[a & 0xff];
}

// return 0x02^(a-1) in GF(2^8)
static uint32_t aes_r_con(uint32_t a) {
    uint32_t ans = 1;
    for (; a > 1; --a) {
        ans <<= 1;
        if (ans & 0x100 != 0) {
            ans ^= 0x11b;
        }
    }
    return ans;
}

/****************************************************************/
// basic AES algorithm; see FIPS-197
//
// Think of it as a pseudo random number generator, with each
// symbol in the sequence being a 16 byte block (the state).  The
// key is a parameter of the algorithm and tells which particular
// sequence of random symbols you want.  The initial vector, IV,
// sets the start of the sequence.  The idea of a strong cipher
// is that it's very difficult to guess the key even if you know
// a large part of the sequence.  The basic AES algorithm simply
// provides such a sequence.  En/de-cryption is implemented here
// using OCB, where the sequence is xored against the plaintext.
// Care must be taken to (almost) always choose a different IV.

// all inputs must be size AES_ST_NBYTE
static void aes_add_round_key(byte *state, const byte *w) {
    for (unsigned int i = 0; i < AES_ST_NBYTE; ++i) {
        state[i] ^= w[i];
    }
}

// combined sub_bytes, shift_rows, mix_columns, add_round_key
// all inputs must be size AES_ST_NBYTE
static void aes_sb_sr_mc_ark(byte *state, const byte *w, byte *temp) {
    for (unsigned int i = 0; i < AES_ST_NCOL; ++i, temp += AES_ST_NROW, w += AES_ST_NROW) {
        byte x0 = aes_s_box_table[state[0 + i * AES_ST_NROW]];
        byte x1 = aes_s_box_table[state[1 + ((i + 1) & 3) * AES_ST_NROW]];
        byte x2 = aes_s_box_table[state[2 + ((i + 2) & 3) * AES_ST_NROW]];
        byte x3 = aes_s_box_table[state[3 + ((i + 3) & 3) * AES_ST_NROW]];
        temp[0] = aes_gf8_mul_2(x0) ^ aes_gf8_mul_3(x1) ^ x2 ^ x3 ^ w[0];
        temp[1] = x0 ^ aes_gf8_mul_2(x1) ^ aes_gf8_mul_3(x2) ^ x3 ^ w[1];
        temp[2] = x0 ^ x1 ^ aes_gf8_mul_2(x2) ^ aes_gf8_mul_3(x3) ^ w[2];
        temp[3] = aes_gf8_mul_3(x0) ^ x1 ^ x2 ^ aes_gf8_mul_2(x3) ^ w[3];
    }
    memcpy(state, temp - AES_ST_NBYTE, AES_ST_NBYTE);
}

// combined sub_bytes, shift_rows, add_round_key
// all inputs must be size AES_ST_NBYTE
static void aes_sb_sr_ark(byte *state, const byte *w, byte *temp) {
    for (unsigned int i = 0; i < AES_ST_NCOL; ++i, temp += AES_ST_NROW, w += AES_ST_NROW) {
        byte x0 = aes_s_box_table[state[0 + i * AES_ST_NROW]];
        byte x1 = aes_s_box_table[state[1 + ((i + 1) & 3) * AES_ST_NROW]];
        byte x2 = aes_s_box_table[state[2 + ((i + 2) & 3) * AES_ST_NROW]];
        byte x3 = aes_s_box_table[state[3 + ((i + 3) & 3) * AES_ST_NROW]];
        temp[0] = x0 ^ w[0];
        temp[1] = x1 ^ w[1];
        temp[2] = x2 ^ w[2];
        temp[3] = x3 ^ w[3];
    }
    memcpy(state, temp - AES_ST_NBYTE, AES_ST_NBYTE);
}

// take state as input and change it to the next state in the sequence
// state and temp have size AES_ST_NBYTE, w has size AES_ST_NBYTE * (AES_NR + 1), AES_NR >= 1
static void aes_state(byte *state, const byte *w, byte *temp) {
    aes_add_round_key(state, w);
    w += AES_ST_NBYTE;
    for (unsigned int i = AES_NR - 1; i > 0; i--) {
        aes_sb_sr_mc_ark(state, w, temp);
        w += AES_ST_NBYTE;
    }
    aes_sb_sr_ark(state, w, temp);
}

// expand 'key' to 'w' for use with aes_state
// key has size AES_ST_NROW * AES_NK, w hase size AES_ST_NBYTE * (AES_NR + 1), temp has size AES_ST_NBYTE
static void aes_key_expansion(const byte *key, byte *w, byte *temp) {
    memcpy(w, key, AES_ST_NROW * AES_NK);
    w += AES_ST_NROW * AES_NK;
    for (uint32_t i = AES_NK; i < AES_ST_NCOL * (AES_NR + 1); ++i, w += AES_ST_NROW) {
        byte *wp = &w[-AES_ST_NROW];
        byte *t = temp;
        if (i % AES_NK == 0) {
            t[0] = aes_s_box(wp[1]) ^ aes_r_con(i / AES_NK);
            for (unsigned int j = 1; j < AES_ST_NROW; ++j) {
                t[j] = aes_s_box(wp[(j + 1) % AES_ST_NROW]);
            }
        } else if (AES_NK > 6 && i % AES_NK == 4) {
            for (unsigned int j = 0; j < AES_ST_NROW; ++j) {
                t[j] = aes_s_box(wp[j]);
            }
        } else {
            t = wp;
        }
        for (unsigned int j = 0; j < AES_ST_NROW; ++j) {
            w[j] = w[j - AES_ST_NROW * AES_NK] ^ t[j];
        }
    }
}

/****************************************************************/
// simple use of AES algorithm, using output feedback (OFB) mode

void aes_set_key(aes_t *aes, const byte *key) {
    aes_key_expansion(key, aes->w, aes->temp);
    aes->state_pos = AES_ST_NBYTE;
}

void aes_set_iv(aes_t *aes, const byte *iv) {
    memcpy(aes->state, iv, AES_ST_NBYTE);
    aes->state_pos = AES_ST_NBYTE;
}

void aes_get_some_state(aes_t *aes, uint32_t n_needed, const byte **state, uint32_t *len) {
    if (aes->state_pos >= AES_ST_NBYTE) {
        aes_state(aes->state, aes->w, aes->temp);
        aes->state_pos = 0;
    }
    uint32_t n = AES_ST_NBYTE - aes->state_pos;

    if (n > n_needed) {
        n = n_needed;
    }
    *state = &aes->state[aes->state_pos];
    aes->state_pos += n;
    *len = n;
}

void aes_apply_to(aes_t *aes, byte *data, unsigned int n) {
    while (n > 0) {
        uint32_t len;
        const byte *cipher;
        aes_get_some_state(aes, n, &cipher, &len);
        n -= len;
        for (; len > 0; --len, ++data, ++cipher) {
            *data ^= *cipher;
        }
    }
}
