#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

#include "console/cli.h"
#include "console/config.h"
#include "console/debug.h"
#include "controller/input.h"
#include "controller/threading.h"
#include "console/watchdog.h"
#include "hardware/device.h"
#include "jvs/io.h"
#include "jvs/jvs.h"
#include "ffb/ffb.h"
#include "version.h"

/* Time between reinit in ms */
#define TIME_REINIT (200 * 1000)

/* Runtime state file: records the current testButtonActive value (0 or 1)
 * so the WebUI can read it without relying on signal bookkeeping. */
#define TESTMODE_STATE_PATH "/run/modernjvs/testmode"

void cleanup(void);
void handleSignal(int signal);

volatile int running = 1;
volatile int testButtonActive = 0;

static void writeTestModeState(int active)
{
    FILE *f = fopen(TESTMODE_STATE_PATH, "w");
    if (!f)
    {
        debug(1, "Warning: Could not write test mode state file: %s\n", TESTMODE_STATE_PATH);
        return;
    }
    fprintf(f, "%d", active);
    fclose(f);
}

typedef struct
{
    volatile int *running;
    JVSIO *io;
} JVSThreadArguments;

/**
 * Persistent JVS packet processing thread
 *
 * Runs independently of the controller hot-plug lifecycle so that
 * JVS communication with the arcade machine is never interrupted
 * while input threads are being stopped and restarted.
 *
 * @param _args Pointer to a heap-allocated JVSThreadArguments struct
 *              (ownership is transferred; this thread frees it on exit).
 * @returns NULL
 */
static void *jvsThread(void *_args)
{
    JVSThreadArguments *args = (JVSThreadArguments *)_args;
    int lastTestButtonActive = 0;

    while (*args->running != -1)
    {
        JVSStatus processingStatus = processPacket(args->io);

        /* Apply software test-button state.
         * Snapshot the volatile once so both the comparison and the
         * setSwitch call operate on the same consistent value.
         * When active, re-assert on every iteration so that a controller
         * button mapped to BUTTON_TEST cannot override the software latch
         * via its key-up event. */
        int activeSnapshot = testButtonActive;
        if (activeSnapshot != lastTestButtonActive)
        {
            lastTestButtonActive = activeSnapshot;
            setSwitch(args->io, SYSTEM, BUTTON_TEST, activeSnapshot);
            writeTestModeState(activeSnapshot);
        }
        else if (activeSnapshot)
        {
            setSwitch(args->io, SYSTEM, BUTTON_TEST, 1);
        }

        switch (processingStatus)
        {
        case JVS_STATUS_ERROR_CHECKSUM:
            debug(0, "Error: A checksum error occurred (Expected if controllers hot-plugged)\n");
            break;
        case JVS_STATUS_ERROR_WRITE_FAIL:
            debug(0, "Error: A write failure occurred\n");
            break;
        case JVS_STATUS_ERROR:
            debug(0, "Error: A generic error occurred\n");
            break;
        default:
            break;
        }
    }

    free(args);
    return NULL;
}

int main(int argc, char **argv)
{
    signal(SIGINT, handleSignal);
    signal(SIGUSR1, handleSignal);

    /* Read the initial config */
    JVSConfig config;
    getDefaultConfig(&config);
    if (parseConfig(DEFAULT_CONFIG_PATH, &config) != JVS_CONFIG_STATUS_SUCCESS)
    {
        debug(0, "Warning: No valid config file found, defaults are being used\n");
    }

    /* Initialise the debug output */
    initDebug(config.debugLevel);

    /* Get the correct game output mapping */
    JVSCLIStatus argumentsStatus = parseArguments(argc, argv, config.defaultGamePath);
    switch (argumentsStatus)
    {
    case JVS_CLI_STATUS_ERROR:
        return EXIT_FAILURE;
        break;
    case JVS_CLI_STATUS_SUCCESS_CLOSE:
        return EXIT_SUCCESS;
        break;
    case JVS_CLI_STATUS_SUCCESS_CONTINUE:
        break;
    default:
        break;
    }

    debug(0, "ModernJVS Version %s\n\n", PROJECT_VER);

    /* Create runtime directory and write initial test-mode state.
     * mkdir() is a no-op if the directory already exists (errno == EEXIST). */
    if (mkdir("/run/modernjvs", 0755) != 0 && errno != EEXIST)
        debug(0, "Warning: Could not create /run/modernjvs directory: %s\n", strerror(errno));
    writeTestModeState(0);

    /* Init the thread manager */
    ThreadStatus threadStatus = initThreadManager();
    if (threadStatus != THREAD_STATUS_SUCCESS)
    {
        debug(0, "Critical: Could not initialise the thread manager.\n");
        return EXIT_FAILURE;
    }

    /* Init the connection to the Naomi */
    if (!initDevice(config.devicePath, config.senseLineType, config.senseLinePin))
    {
        debug(0, "Critical: Failed to init the RS485 device at %s, you must be root.\n", config.devicePath);
        return EXIT_FAILURE;
    }

    // Create the JVSIO structure outside the loop so it persists across controller changes.
    // This allows controllers to be hot-plugged without resetting the JVS connection,
    // which would cause the arcade machine to lose communication and require a system reset.
    // Only input threads are reinitialized when controllers change; the JVS protocol
    // state (device address, capabilities, etc.) remains intact.
    JVSIO io = {0};
    io.deviceID = -1;          // -1 indicates no device ID assigned yet
    io.chainedIO = NULL;       // No chained device initially
    JVSIO secondIO = {0};
    secondIO.deviceID = -1;    // -1 indicates no device ID assigned yet
    int jvsInitialized = 0;

    /* The JVS processing thread runs for the lifetime of the program so that
     * packet handling is never interrupted by controller hot-plug reinit.
     * It is started once after initJVS() succeeds and joined on exit. */
    pthread_t jvsThreadID;
    int jvsThreadStarted = 0;

    JVSInputStatus lastInputState = JVS_INPUT_STATUS_SUCCESS;
    while (running != -1)
    {
        /* Init the watchdog to check inputs */
        debug(1, "Init watchdog\n");
        running = 1;
        setThreadsRunning(1);
        initWatchdog(&running);

        debug(1, "Init inputs\n");
        JVSInputStatus inputStatus = initInputs(config.defaultGamePath, config.capabilitiesPath, config.secondCapabilitiesPath, &io, config.autoControllerDetection, config.analogDeadzonePlayer1, config.analogDeadzonePlayer2, config.analogDeadzonePlayer3, config.analogDeadzonePlayer4, config.wiiIRScale);

        // Only report these errors if the status has changed
        // from the last run. Since we restart this thread every 200ms
        // on errors, we could end up spamming the logs extremely quickly
        // when a controller just isn't plugged in.
        if (inputStatus != lastInputState)
        {
            switch (inputStatus)
            {
            case JVS_INPUT_STATUS_MALLOC_ERROR:
                debug(0, "Error: Failed to malloc\n");
                break;
            case JVS_INPUT_STATUS_DEVICE_OPEN_ERROR:
                debug(0, "Warning: No controllers detected, waiting for input devices...\n");
                break;
            case JVS_INPUT_STATUS_OUTPUT_MAPPING_ERROR:
                debug(0, "Error: Cannot find an output mapping\n");
                break;
            default:
                break;
            }
        }

        // Critical errors that prevent JVS operation (not including missing controllers)
        if (inputStatus == JVS_INPUT_STATUS_MALLOC_ERROR || inputStatus == JVS_INPUT_STATUS_OUTPUT_MAPPING_ERROR)
        {
            // Cleanup then wait before reconnecting
            lastInputState = inputStatus;
            cleanup();
            continue;
        }

        debug(0, "  Output:          %s\n", config.defaultGamePath);

        // Report controller status
        if (inputStatus == JVS_INPUT_STATUS_SUCCESS)
        {
            debug(0, "  Controllers:     Connected\n");
        }
        else if (inputStatus == JVS_INPUT_STATUS_DEVICE_OPEN_ERROR)
        {
            debug(0, "  Controllers:     None (waiting for devices)\n");
        }

        // Only initialize IO and JVS once at startup, not on every controller change
        if (!jvsInitialized)
        {
            debug(1, "Parse IO\n");
            JVSConfigStatus ioStatus = parseIO(config.capabilitiesPath, &io.capabilities);
            if (ioStatus != JVS_CONFIG_STATUS_SUCCESS)
            {
                switch (ioStatus)
                {
                case JVS_CONFIG_STATUS_FILE_NOT_FOUND:
                    debug(0, "Critical: Could not find IO definition named %s\n", config.capabilitiesPath);
                    break;
                default:
                    debug(0, "Critical: Failed to parse an IO file.\n");
                }
                return EXIT_FAILURE;
            }

            debug(1, "ABOUT TO PARSE Second IO\n");

            if (config.secondCapabilitiesPath[0] != 0x00)
            {
                debug(1, "Parse Second IO\n");
                ioStatus = parseIO(config.secondCapabilitiesPath, &secondIO.capabilities);
                if (ioStatus != JVS_CONFIG_STATUS_SUCCESS)
                {
                    switch (ioStatus)
                    {
                    case JVS_CONFIG_STATUS_FILE_NOT_FOUND:
                        debug(0, "Critical: Could not find IO definition named %s\n", config.secondCapabilitiesPath);
                        break;
                    default:
                        debug(0, "Critical: Failed to parse an IO file.\n");
                    }
                    return EXIT_FAILURE;
                }
                else
                {
                    io.chainedIO = &secondIO;
                }
            }

            /* Init the Virtual IO */
            debug(1, "Init IO\n");
            if (!initIO(&io))
            {
                debug(0, "Critical: Failed to init IO\n");
                return EXIT_FAILURE;
            }

            if (io.chainedIO != NULL)
            {
                debug(1, "Init Second IO\n");
                if (!initIO(io.chainedIO))
                {
                    debug(0, "Critical: Failed to init second IO\n");
                    return EXIT_FAILURE;
                }
            }

            /* Setup the JVS Emulator with the RS485 path and capabilities */
            debug(1, "Init JVS\n");
            if (!initJVS(&io))
            {
                debug(0, "Critical: Could not initialise JVS\n");
                return EXIT_FAILURE;
            }

            /* Print out what is being emulated */
            debug(0, "\nYou are currently emulating a \033[0;31m%s\033[0m ", io.capabilities.displayName);
            if (io.chainedIO != NULL)
            {
                debug(0, "chained to a \033[0;31m%s\033[0m ", io.chainedIO->capabilities.displayName);
            }
            debug(0, "on %s.\n\n", config.devicePath);

            jvsInitialized = 1;

            /* Start the persistent JVS processing thread now that the
             * connection is initialised.  This thread runs for the entire
             * lifetime of the program and is never stopped on hot-plug. */
            JVSThreadArguments *jvsArgs = malloc(sizeof(JVSThreadArguments));
            if (!jvsArgs)
            {
                debug(0, "Critical: Failed to malloc JVS thread arguments\n");
                return EXIT_FAILURE;
            }
            jvsArgs->running = &running;
            jvsArgs->io = &io;
            if (pthread_create(&jvsThreadID, NULL, jvsThread, jvsArgs) != 0)
            {
                debug(0, "Critical: Could not start JVS processing thread\n");
                free(jvsArgs);
                return EXIT_FAILURE;
            }
            jvsThreadStarted = 1;
        }
        else
        {
            debug(1, "Reinitializing inputs while maintaining JVS connection...\n");
        }

        /* Wait for a hot-plug event or shutdown signal.
         * JVS packet processing continues uninterrupted in jvsThread. */
        while (running == 1)
            usleep(10 * 1000);

        lastInputState = inputStatus;
        cleanup();
    }

    /* Remove the runtime state file now that the daemon is stopping. */
    unlink(TESTMODE_STATE_PATH);

    /* Wait for the JVS processing thread to finish. */
    if (jvsThreadStarted)
        pthread_join(jvsThreadID, NULL);

    /* Release mutex resources for both IO boards. */
    destroyIO(&io);
    if (io.chainedIO != NULL)
        destroyIO(io.chainedIO);

    /* Close the file pointer */
    if (!disconnectJVS())
    {
        debug(0, "Critical: Could not disconnect from serial\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void cleanup(void)
{
    /* Stop threads managed by ThreadManager */
    stopAllThreads();

    /* Take a short break on reinit to reduce load */
    usleep(TIME_REINIT);
}

void handleSignal(int signal)
{
    if (signal == SIGINT)
    {
        /* Write a literal newline+message using write() which is async-signal-safe.
         * debug()/printf() are NOT safe to call from a signal handler. */
        const char msg[] = "\nModernJVS is stopping...\n";
        write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        running = -1;
    }
    else if (signal == SIGUSR1)
    {
        /* Atomic toggle: safe to call from both signal handler and controller
         * threads without a mutex (which is not async-signal-safe). */
        __sync_fetch_and_xor(&testButtonActive, 1);
    }
}
