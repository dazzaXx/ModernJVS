#include "ffb/ffb.h"
#include "console/debug.h"
#include "controller/threading.h"

void *ffbThread(void *_args);

FFBStatus initFFB(FFBState *state, FFBEmulationType type, char *serialPath)
{
    debug(0, "Init ffb %s\n", serialPath);
    state->type = type;
    state->serial = -1;
    state->controller = -1;

    /* NOTE: `state` is passed directly to the FFB thread and must remain valid
     * for the entire lifetime of that thread.  The caller must not free or
     * re-use `state` until after stopAllThreads() has returned.  When the FFB
     * thread body is fully implemented it should either receive a malloc'd copy
     * (like deviceThread does) or the caller must guarantee the lifetime above. */
    if (createThread(ffbThread, state) != THREAD_STATUS_SUCCESS)
        return FFB_STATUS_ERROR;

    return FFB_STATUS_SUCCESS;
}

FFBStatus closeFFB(FFBState *state)
{
    state->serial = -1;
    return FFB_STATUS_SUCCESS;
}

FFBStatus bindController(FFBState *state, int controller)
{
    if (state->controller > -1)
        return FFB_STATUS_ERROR_CONTROLLED_ALREADY_BOUND;

    state->controller = controller;

    return FFB_STATUS_SUCCESS;
}

void *ffbThread(void *_args)
{
    FFBState *args = (FFBState *)_args;

    debug(1, "FFB thread started (serial fd: %d)\n", args->serial);

    return NULL;
}
