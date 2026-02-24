#ifndef WATCHDOG_H_
#define WATCHDOG_H_

typedef enum
{
    WATCHDOG_STATUS_SUCCESS,
    WATCHDOG_STATUS_ERROR
} WatchdogStatus;

WatchdogStatus initWatchdog(volatile int *running);

#endif // WATCHDOG_H_
