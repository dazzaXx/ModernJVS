#include "console/watchdog.h"
#include "console/debug.h"
#include "controller/threading.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "controller/input.h"

// Poll devices every one second
#define TIME_POLL_DEVICES 1

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
        /* Sleep in short increments so that when setThreadsRunning(0) is
         * called by a device thread the watchdog wakes within ~100 ms and
         * immediately signals the main loop, rather than blocking for the
         * full TIME_POLL_DEVICES second. */
        for (int tick = 0; tick < TIME_POLL_DEVICES * 10 && getThreadsRunning(); tick++)
            usleep(100 * 1000);
    }

    // If an input thread detected a device error (e.g. ENODEV/EIO on Bluetooth
    // disconnect) and called setThreadsRunning(0), the loop above exits without
    // having set *args->running.  Ensure the main loop is signaled to
    // reinitialize, unless the main loop is already stopping (running != 1).
    if (*args->running == 1)
    {
        debug(1, "Watchdog: Input thread signaled stop, triggering reinitialization\n");
        *args->running = 0;
    }

    if (_args != NULL)
    {
        free(_args);
        _args = NULL;
    }

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
        return WATCHDOG_STATUS_ERROR;
    }

    return WATCHDOG_STATUS_SUCCESS;
}
