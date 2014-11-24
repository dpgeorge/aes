// AES 128
#define AES_NK (4)
#define AES_NR (10)

/*
// AES 192
#define AES_NK (6)
#define AES_NR (12)
*/

/*
// AES 256
#define AES_NK (8)
#define AES_NR (14)
*/

// size of the state
// a lot of the code relies on these constants being what they are
#define AES_ST_NROW (4)
#define AES_ST_NCOL (4) // Nb in FIPS standard
#define AES_ST_NBYTE (AES_ST_NROW * AES_ST_NCOL)

typedef unsigned char byte;

typedef struct _aes_t {
    byte state[AES_ST_NBYTE];
    byte w[AES_ST_NBYTE * (AES_NR + 1)];
    byte temp[AES_ST_NBYTE];
    uint32_t state_pos;
} aes_t;

void aes_set_key(aes_t *aes, const byte *key);
void aes_set_iv(aes_t *aes, const byte *iv);
void aes_get_some_state(aes_t *aes, uint32_t n_needed, const byte **state, uint32_t *len);
void aes_apply_to(aes_t *aes, byte *data, unsigned int n);
