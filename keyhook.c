// !!! FIXME: this is X11 specific.  :(

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <X11/Xlib.h>
#include <X11/Xlibint.h>
#include <X11/extensions/record.h>

#include "keyhook.h"

static volatile int keyPressFlags = 0;
static volatile int sawKeyCombo = 0;
static void keyhookCallback(XPointer priv, XRecordInterceptData *data)
{
    const xEvent *xev = (const xEvent *) data->data;
    if (data->category == XRecordFromServer)
    {
        const BYTE keycode = xev->u.u.detail;
        if (xev->u.u.type == KeyPress)
        {
            // !!! FIXME: don't hardcode these keycodes.
            if ((keycode == 64) && (keyPressFlags == 0))
                keyPressFlags++;
            else if ((keycode == 133) && (keyPressFlags == 1))
                keyPressFlags++;
            else if ((keycode == 51) && (keyPressFlags == 2))
            {
                sawKeyCombo = 1;
                keyPressFlags = 0;
            } // else if
            else
                keyPressFlags = 0;
        } // if
        else if (xev->u.u.type == KeyRelease)
        {
            keyPressFlags = 0;
        } // else if
    } // if

    XRecordFreeData(data);
} // keyhookCallback


// every example I've seen needs two Display connections...one for the
//  keyhook, and one to control it.
static Display *ctrldpy = NULL;
static Display *datadpy = NULL;
static XRecordContext xrc = 0;

int initKeyHook(void)
{
    int major = 0;
    int minor = 0;
    XRecordRange *xrr = NULL;
    XRecordClientSpec xrcs = XRecordAllClients;

    if (ctrldpy)
        return 0;  // already initialized.

    ctrldpy = XOpenDisplay(NULL);
    if (!ctrldpy)
        goto failed;

    XSynchronize(ctrldpy, True);

    datadpy = XOpenDisplay(NULL);
    if (!datadpy)
        goto failed;
    else if (!XRecordQueryVersion(ctrldpy, &major, &minor))
        goto failed;
    else if ((xrr = XRecordAllocRange()) == NULL)
        goto failed;

    memset(xrr, '\0', sizeof (*xrr));
    xrr->device_events.first = KeyPress;
    xrr->device_events.last = KeyPress;

    if ((xrc = XRecordCreateContext(ctrldpy, 0, &xrcs, 1, &xrr, 1)) == 0)
        goto failed;
    else if (!XRecordEnableContextAsync(datadpy, xrc, keyhookCallback, NULL))
        goto failed;

    XFree(xrr);
    xrr = NULL;

    return 1;

failed:
    deinitKeyHook();
    if (xrr) XFree(xrr);

    return 0;
} // initKeyHook


void deinitKeyHook(void)
{
    if (ctrldpy)
    {
        if (xrc)
        {
            XRecordDisableContext(ctrldpy, xrc);
            XRecordFreeContext(ctrldpy, xrc);
        } // if
        XCloseDisplay(ctrldpy);
    } // if

    if (datadpy)
        XCloseDisplay(datadpy);

    ctrldpy = NULL;
    datadpy = NULL;
    xrc = 0;
    sawKeyCombo = 0;
    keyPressFlags = 0;
} // deinitKeyHook


int pumpKeyHook(void)
{
    if (!datadpy)
        return 0;

    sawKeyCombo = 0;
    XRecordProcessReplies(datadpy);
    return sawKeyCombo;
} // pumpKeyHook

// end of keyhook.c ...

