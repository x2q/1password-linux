#ifndef _INCL_PKCS5_PBKDF2_H_
#define _INCL_PKCS5_PBKDF2_H_

#include <stdint.h>

int pkcs5_pbkdf2(const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, uint8_t *key, size_t key_len, unsigned int rounds);

#endif

// end of pkcs5_pbkdf2.h ...

