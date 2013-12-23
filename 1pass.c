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
#include <gtk/gtk.h>

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

static inline int retvalString(lua_State *L, const char *str)
{
    return retvalStringBytes(L, (const uint8_t *) str, strlen(str));
} // retvalString

static inline int retvalPointer(lua_State *L, void *ptr)
{
    if (ptr != NULL)
        lua_pushlightuserdata(L, ptr);
    else
        lua_pushnil(L);
    return 1;
} // retvalPointer

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


static int runGuiPasswordPrompt(lua_State *L)
{
    const char *hintstr = lua_tostring(L, 1);
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
                            "Master Password", NULL, GTK_DIALOG_MODAL,
                            GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
                            GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
                            NULL);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    if (hintstr != NULL)
    {
        GtkWidget *label = gtk_label_new(hintstr);
        gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_CENTER);
        gtk_container_add(GTK_CONTAINER(content_area), label);
    } // if

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    gtk_container_add(GTK_CONTAINER(content_area), entry);

    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_MOUSE);
    gtk_widget_show_all(dialog);
    const int ok = (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT);
    retvalString(L, ok ? (const char *) gtk_entry_get_text(GTK_ENTRY(entry)) : NULL);
    gtk_widget_destroy(dialog);

    return 1;
} // runGuiPasswordPrompt


static int copyToClipboard(lua_State *L)
{
    const char *str = luaL_checkstring(L, 1);
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY), str, -1);
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), str, -1);
} // copyToClipboard


static int makeGuiMenu(lua_State *L)
{
    return retvalPointer(L, gtk_menu_new());
} // makeGuiMenu


static void clickedMenuItem(void *arg)
{
    // This is the callback from GTK+; now call into our actual Lua callback!
    const int callback = (int) ((size_t)arg);
    lua_rawgeti(luaState, LUA_REGISTRYINDEX, callback);
    lua_call(luaState, 0, 0);
} // clickedMenuItem

#if 0  // !!! FIXME: figure out how to fire this.
static void deletedMenuItem(void *arg)
{
    // Clean up the Lua function we referenced in the Registry.
    const int callback = (int) ((size_t)arg);
printf("unref callback %d\n", callback);
    luaL_unref(luaState, LUA_REGISTRYINDEX, callback);
} // deletedMenuItem
#endif

static int appendGuiMenuItem(lua_State *L)
{
    const int argc = lua_gettop(L);
    GtkWidget *menu = (GtkWidget *) lua_touserdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    GtkWidget *item = gtk_menu_item_new_with_label(label);

    if ((argc >= 3) && (!lua_isnil(L, 3)))
    {
        assert(lua_isfunction(L, 3));
        lua_pushvalue(L, 3);  // copy the Lua callback (luaL_ref() pops it).
        const int callback = luaL_ref(L, LUA_REGISTRYINDEX);
        gtk_signal_connect_object(GTK_OBJECT(item), "activate", GTK_SIGNAL_FUNC(clickedMenuItem), (gpointer) ((size_t)callback));
    } // if

    gtk_widget_show(item);
    gtk_menu_append(menu, item);
    return retvalPointer(L, item);
} // appendGuiMenuItem


static int setGuiMenuItemSubmenu(lua_State *L)
{
    GtkMenuItem *item = (GtkMenuItem *) lua_touserdata(L, 1);
    GtkWidget *submenu = (GtkWidget *) lua_touserdata(L, 2);
    gtk_menu_item_set_submenu(item, submenu);
    return 0;
} // setGuiMenuItemSubmenu


static int popupGuiMenu(lua_State *L)
{
    GtkMenu *menu = (GtkMenu *) lua_touserdata(L, 1);
    gtk_menu_popup(menu, NULL, NULL, NULL, NULL, 0, gtk_get_current_event_time());
    return 0;
} // popupGuiMenu


static int giveControlToGui(lua_State *L)
{
    gtk_main();
    return 0;
} // giveControlToGui


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


static void deinitLua(void)
{
    if (luaState != NULL)
    {
        lua_close(luaState);
        luaState = NULL;
    } // if
} // deinitLua


static int initLua(const int argc, char **argv)
{
    atexit(deinitLua);

    assert(luaState == NULL);
    luaState = lua_newstate(luaAlloc, NULL);

    lua_atpanic(luaState, luaFatal);
    assert(lua_checkstack(luaState, 20));  // Just in case.
    luaL_openlibs(luaState);

    // Set up initial C functions, etc we want to expose to Lua code...
    luaSetCFunc(luaState, decryptUsingPBKDF2, "decryptUsingPBKDF2");
    luaSetCFunc(luaState, decryptBase64UsingKey, "decryptBase64UsingKey");
    luaSetCFunc(luaState, makeGuiMenu, "makeGuiMenu");
    luaSetCFunc(luaState, appendGuiMenuItem, "appendGuiMenuItem");
    luaSetCFunc(luaState, setGuiMenuItemSubmenu, "setGuiMenuItemSubmenu");
    luaSetCFunc(luaState, popupGuiMenu, "popupGuiMenu");
    luaSetCFunc(luaState, giveControlToGui, "giveControlToGui");
    luaSetCFunc(luaState, runGuiPasswordPrompt, "runGuiPasswordPrompt");
    luaSetCFunc(luaState, copyToClipboard, "copyToClipboard");

    // Set up argv table...
    lua_newtable(luaState);
    int i;
    for (i = 0; i < argc; i++)
    {
        lua_pushinteger(luaState, i+1);
        lua_pushstring(luaState, argv[i]);
        lua_settable(luaState, -3);
    } // for
    lua_setglobal(luaState, "argv");

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


int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);

    if (!initLua(argc, argv))  // this will move control to 1pass.lua
        return 1;

    return 0;
} // main

// end of 1pass.c ...

