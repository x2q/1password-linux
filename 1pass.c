#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "pkcs5_pbkdf2.h"
#include "aes.h"
#include "base64.h"
#include "md5.h"

#define STATICARRAYLEN(x) ( (sizeof ((x))) / (sizeof ((x)[0])) )

static lua_State *luaState = NULL;
static const uint8_t zero16[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
static const char saltprefix[] = { 'S', 'a', 'l', 't', 'e', 'd', '_', '_' };

static inline int retvalStringBytes(lua_State *L, const uint8_t *str, size_t len)
{
    if (str != NULL)
        lua_pushlstring(L, (const char *) str, len);
    else
        lua_pushnil(L);
    return 1;
} // retvalStringBytes

static inline void xorBlock(uint8_t *dst, const uint8_t *src)
{
    int i;
    for (i = 0; i < 16; i++, dst++, src++)
        *dst ^= *src;
} // xorBlock

static int decryptUsingKeyAndIvec(uint8_t *data, size_t *datalen, const uint8_t *key, const uint8_t *iv)
{
    const size_t blocks = *datalen / 16;
    uint8_t *block = data + ((blocks-1) * 16);   // start at final block, work backwards
    const uint8_t *padding = &block[15];
    uint8_t expkey[aesExpandedKeySize];
    size_t i;

    if (blocks == 0)
        return 1;  // nothing to do.

	aesExpandKey(key, expkey);

    for (i = 0; i < blocks-1; i++)
    {
        aesDecrypt(block, expkey, block);   // decrypt in place.
        xorBlock(block, block-16);
        block -= 16;
    }
    aesDecrypt(block, expkey, block);   // decrypt in place.
    xorBlock(block, iv);   // xor against initial vector for final block.

    if (*padding > 16)
        return 0;  // bad data?

    *datalen -= *padding;

    return 1;
} // decryptBinaryUsingKeyAndIvec


static inline int isSalted(const uint8_t *data, const size_t datalen)
{
    return ( (datalen > sizeof (saltprefix)) &&
             (memcmp(data, saltprefix, sizeof (saltprefix)) == 0) );
} // isSalted


static int decryptUsingPBKDF2(lua_State *L)
{
    const char *base64 = luaL_checkstring(L, 1);
    const char *password = luaL_checkstring(L, 2);
    const int iterations = luaL_checkinteger(L, 3);
    size_t datalen = strlen(base64);
    uint8_t *dataptr = (uint8_t *) malloc(datalen);
    uint8_t *data = dataptr;
    base64_decodestate base64state;

    base64_init_decodestate(&base64state);
    datalen = base64_decode_block(base64, (int) datalen, data, &base64state);

    const uint8_t *salt = zero16;
    int saltlen = sizeof (zero16);
    if (isSalted(data, datalen))
    {
        salt = data + 8;
        saltlen = 8;
        data += 16;
        datalen -= 16;
    } // if

    uint8_t output[32];
    pkcs5_pbkdf2(password, strlen(password), salt, saltlen, output, sizeof (output), (unsigned int) iterations);

    const uint8_t *aeskey = &output[0];
    const uint8_t *aesiv = &output[16];
	if (decryptUsingKeyAndIvec(data, &datalen, aeskey, aesiv))
        retvalStringBytes(L, data, datalen);
    else
        lua_pushnil(L);

    free(dataptr);
    return 1;
} // decryptUsingPBKDF2


static int decryptBase64UsingKey(lua_State *L)
{
    size_t keylen = 0;
    const char *base64 = luaL_checkstring(L, 1);
    const uint8_t *key = (const uint8_t *) luaL_checklstring(L, 2, &keylen);
    size_t datalen = strlen(base64);
    uint8_t *dataptr = (uint8_t *) malloc(datalen);
    uint8_t *data = dataptr;
    base64_decodestate base64state;

    base64_init_decodestate(&base64state);
    datalen = base64_decode_block(base64, (int) datalen, data, &base64state);

    uint8_t aeskey[16];
    uint8_t aesiv[16];
    MD5_CTX md5;

    if (isSalted(data, datalen))
    {
        const uint8_t *salt = data + 8;
        const size_t saltlen = 8;
        data += 16;
        datalen -= 16;

        assert(aesNr == 10);  // AES-256 needs more rounds.
        assert(aesNk == 4);   // hashing size is hardcoded later.
        uint8_t hashing[32];

        MD5_init(&md5);
        MD5_append(&md5, key, keylen);
        MD5_append(&md5, salt, saltlen);
        MD5_finish(&md5, hashing);

        MD5_init(&md5);
        MD5_append(&md5, hashing, 16);
        MD5_append(&md5, key, keylen);
        MD5_append(&md5, salt, saltlen);
        MD5_finish(&md5, &hashing[16]);

        memcpy(aeskey, hashing, 4 * aesNk);
        memcpy(aesiv, &hashing[4 * aesNk], 16);
    } // if
    else
    {
        MD5_init(&md5);
        MD5_append(&md5, key, keylen);
        MD5_finish(&md5, aeskey);
        memset(aesiv, '\0', sizeof (aesiv));
    } // else

	if (decryptUsingKeyAndIvec(data, &datalen, aeskey, aesiv))
        retvalStringBytes(L, data, datalen);
    else
        lua_pushnil(L);

    free(dataptr);
    return 1;
} // decryptBase64UsingKey


static void *luaAlloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    if (nsize == 0)
    {
        free(ptr);
        return NULL;
    } // if
    return realloc(ptr, nsize);
} // luaAlloc


static inline void luaSetCFunc(lua_State *L, lua_CFunction f, const char *sym)
{
    lua_pushcfunction(L, f);
    lua_setglobal(luaState, sym);
} // luaSetCFunc


static int luaFatal(lua_State *L)
{
    const char *errstr = lua_tostring(L, -1);
    fprintf(stderr, "Lua panic: %s\n", errstr ? errstr : "(?)");
    fflush(stderr);
    exit(1);
} // luaFatal


static int initLua(void)
{
    assert(luaState == NULL);
    luaState = lua_newstate(luaAlloc, NULL);

    lua_atpanic(luaState, luaFatal);
    assert(lua_checkstack(luaState, 20));  // Just in case.
    luaL_openlibs(luaState);

    // Set up initial C functions, etc we want to expose to Lua code...
    luaSetCFunc(luaState, decryptUsingPBKDF2, "decryptUsingPBKDF2");
    luaSetCFunc(luaState, decryptBase64UsingKey, "decryptBase64UsingKey");

    // Transfer control to Lua...
    if (luaL_dofile(luaState, "1pass.lua") != 0)
    {
        const char *msg = lua_tostring(luaState, -1);
        fprintf(stderr, "1pass.lua didn't run: %s\n", msg);
        lua_pop(luaState, 1);
        return 0;
    } // if

    return 1;
} // initLua


static void deinitLua(void)
{
    if (luaState != NULL)
    {
        lua_close(luaState);
        luaState = NULL;
    } // if
} // deinitLua


int main(int argc, char **argv)
{
    atexit(deinitLua);

    if (!initLua())  // this will move control to 1pass.lua
        return 1;

    return 0;
} // main

// end of 1pass.c ...

