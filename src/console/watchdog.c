#include "console/watchdog.h"
#include "console/debug.h"
#include "controller/threading.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "controller/input.h"

typedef struct
{
    volatile int *running;

} WatchdogThreadArguments;

static void *watchdogThread(void *_args)
{
    WatchdogThreadArguments *args = (WatchdogThreadArguments *)_args;

    int originalDevicesCount = getNumberOfDevices();

    while (getThreadsRunning())
    {
        /* Break the 1-second poll period into 100 ms intervals so that
         * stopAllThreads() can wake this thread within ~100 ms instead
         * of waiting up to a full second for sleep() to return. */
        const struct timespec ts = {0, 100 * 1000 * 1000L}; /* 100 ms */
        for (int tick = 0; tick < 10 && getThreadsRunning(); tick++)
        {
            nanosleep(&ts, NULL);
        }

        if (!getThreadsRunning())
            break;

        // Check if device count has changed or if we can't enumerate devices:
        // - currentDeviceCount == -1: error accessing /dev/input → restart
        // - currentDeviceCount != originalDevicesCount: device added/removed → restart
        // This allows detection of controllers being plugged in or unplugged
        int currentDeviceCount = getNumberOfDevices();
        if (currentDeviceCount == -1)
        {
            debug(1, "Watchdog: Error accessing /dev/input, triggering reinitialization\n");
            *args->running = 0;
            break;
        }
        else if (currentDeviceCount != originalDevicesCount)
        {
            if (currentDeviceCount > originalDevicesCount)
            {
                debug(1, "Watchdog: Device connected (%d -> %d), triggering reinitialization\n", 
                      originalDevicesCount, currentDeviceCount);
            }
            else
            {
                debug(1, "Watchdog: Device disconnected (%d -> %d), triggering reinitialization\n", 
                      originalDevicesCount, currentDeviceCount);
            }
            *args->running = 0;
            break;
        }
    }

    free(_args);

    return 0;
}

WatchdogStatus initWatchdog(volatile int *running)
{
    WatchdogThreadArguments *args = malloc(sizeof(WatchdogThreadArguments));
    if (args == NULL)
    {
        debug(0, "Error: Failed to malloc watchdog arguments\n");
        return WATCHDOG_STATUS_ERROR;
    }
    
    args->running = running;

    if (THREAD_STATUS_SUCCESS != createThread(watchdogThread, args))
    {
        free(args);
        args = NULL;
        return WATCHDOG_STATUS_ERROR;
    }

    return WATCHDOG_STATUS_SUCCESS;
}
