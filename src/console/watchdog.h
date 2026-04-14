#ifndef WATCHDOG_H_
#define WATCHDOG_H_

typedef enum
{
    WATCHDOG_STATUS_SUCCESS,
    WATCHDOG_STATUS_ERROR
} WatchdogStatus;

/**
 * Start the watchdog background thread.
 *
 * The thread polls /dev/input for device-count changes.  When a change is
 * detected (or /dev/input becomes inaccessible) it sets *reinit = 1 so the
 * main loop can reinitialise the controller threads without interrupting JVS
 * packet processing.
 *
 * @param reinit Pointer to the volatile flag that the watchdog sets when
 *               controller reinitialization is required.
 * @returns WATCHDOG_STATUS_SUCCESS or WATCHDOG_STATUS_ERROR
 */
WatchdogStatus initWatchdog(volatile int *reinit);

#endif // WATCHDOG_H_
