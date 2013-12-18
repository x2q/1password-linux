#ifndef _INCL_AES_H_
#define _INCL_AES_H_

#include <stdint.h>

// AES-128 only supports Nb=4
#define aesNb 4			// number of columns in the state & expanded key
#define aesNk 4			// number of columns in a key
#define aesNr 10			// number of rounds in encryption

#define aesExpandedKeySize (4 * aesNb * (aesNr + 1))
void aesExpandKey(const uint8_t *key, uint8_t *expkey);

// these do one 128-bit block at a time.
void aesEncrypt (uint8_t *in, uint8_t *expkey, uint8_t *out);
void aesDecrypt (uint8_t *in, uint8_t *expkey, uint8_t *out);

#endif
