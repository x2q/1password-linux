#ifndef _INCL_MD5_H_
#define _INCL_MD5_H_

#include <stdint.h>

typedef struct MD5_CTX
{
    uint32_t count[2];
    uint32_t abcd[4];
    uint8_t buf[64];
} MD5_CTX;

void MD5_init(MD5_CTX *pms);
void MD5_append(MD5_CTX *pms, const uint8_t *data, int nbytes);
void MD5_finish(MD5_CTX *pms, uint8_t digest[16]);

#endif

// end of md5.h ...
