#ifndef WATCHDOG_H_
#define WATCHDOG_H_

#include <signal.h>

typedef enum
{
    WATCHDOG_STATUS_SUCCESS,
    WATCHDOG_STATUS_ERROR
} WatchdogStatus;

WatchdogStatus initWatchdog(volatile sig_atomic_t *running);

#endif // WATCHDOG_H_
