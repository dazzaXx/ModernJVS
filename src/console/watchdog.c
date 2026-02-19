#include "console/watchdog.h"
#include "console/debug.h"
#include "controller/threading.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "controller/input.h"

// Poll rotary every one second
#define TIME_POLL_ROTARY 1

typedef struct
{
    volatile int *running;
    JVSRotaryStatus rotaryStatus;

} WatchdogThreadArguments;

static void *watchdogThread(void *_args)
{
    WatchdogThreadArguments *args = (WatchdogThreadArguments *)_args;

    int originalDevicesCount = getNumberOfDevices();

    int rotaryValue = -1;

    if (args->rotaryStatus == JVS_ROTARY_STATUS_SUCCESS)
    {
        rotaryValue = getRotaryValue();
    }

    while (getThreadsRunning())
    {
        if ((args->rotaryStatus == JVS_ROTARY_STATUS_SUCCESS) && (rotaryValue != getRotaryValue()))
        {
            *args->running = 0;
            break;
        }

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
        sleep(TIME_POLL_ROTARY);
    }

    if (_args != NULL)
    {
        free(_args);
        _args = NULL;
    }

    return 0;
}

WatchdogStatus initWatchdog(volatile int *running, JVSRotaryStatus rotaryStatus)
{
    WatchdogThreadArguments *args = malloc(sizeof(WatchdogThreadArguments));
    if (args == NULL)
    {
        debug(0, "Error: Failed to malloc watchdog arguments\n");
        return WATCHDOG_STATUS_ERROR;
    }
    
    args->running = running;
    args->rotaryStatus = rotaryStatus;

    if (THREAD_STATUS_SUCCESS != createThread(watchdogThread, args))
    {
        free(args);
        return WATCHDOG_STATUS_ERROR;
    }

    return WATCHDOG_STATUS_SUCCESS;
}
