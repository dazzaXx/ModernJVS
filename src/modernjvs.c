#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

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

/* Delay (µs) before retrying after a critical controller-init error.
 * Intentionally short so the JVS loop only pauses briefly on retries. */
#define TIME_REINIT_CRITICAL_US (200 * 1000)

/* Runtime state file: records the current testButtonActive value (0 or 1)
 * so the WebUI can read it without relying on signal bookkeeping. */
#define TESTMODE_STATE_PATH "/run/modernjvs/testmode"

void handleSignal(int signal);

volatile int running = 1;
volatile int testButtonActive = 0;

/* Set to 1 by the watchdog thread when a controller device is added or
 * removed.  Checked inside the JVS processing loop so that controller
 * threads can be restarted without ever interrupting JVS packet flow. */
volatile int controllersNeedReinit = 0;

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

/**
 * (Re)start the watchdog and controller threads.
 *
 * Stops any existing threads, clears the reinit flag, then starts a fresh
 * watchdog and calls initInputs().  Returns the initInputs() status so the
 * caller can log/handle errors.  Does NOT touch the JVS protocol state.
 *
 * @param config         The current JVS configuration
 * @param jvsIO          The JVSIO structure shared with the JVS loop
 * @returns The JVSInputStatus returned by initInputs()
 */
static JVSInputStatus restartControllers(JVSConfig *config, JVSIO *jvsIO)
{
    stopAllThreads();

    controllersNeedReinit = 0;
    setThreadsRunning(1);
    initWatchdog(&controllersNeedReinit);

    return initInputs(
        config->defaultGamePath,
        config->capabilitiesPath,
        config->secondCapabilitiesPath,
        jvsIO,
        config->autoControllerDetection,
        config->analogDeadzonePlayer1,
        config->analogDeadzonePlayer2,
        config->analogDeadzonePlayer3,
        config->analogDeadzonePlayer4,
        config->wiiIRScale);
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

    /* Create the JVSIO structure outside the loop so it persists across
     * controller changes.  This allows controllers to be hot-plugged without
     * resetting the JVS connection; the arcade machine never loses the
     * device address or capabilities state. */
    JVSIO io = {0};
    io.deviceID  = -1;
    io.chainedIO = NULL;
    JVSIO secondIO = {0};
    secondIO.deviceID = -1;

    /* ── One-time JVS / IO-board initialisation ───────────────────────── */
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

    debug(1, "Init JVS\n");
    if (!initJVS(&io))
    {
        debug(0, "Critical: Could not initialise JVS\n");
        return EXIT_FAILURE;
    }

    debug(0, "\nYou are currently emulating a \033[0;31m%s\033[0m ", io.capabilities.displayName);
    if (io.chainedIO != NULL)
        debug(0, "chained to a \033[0;31m%s\033[0m ", io.chainedIO->capabilities.displayName);
    debug(0, "on %s.\n\n", config.devicePath);

    /* ── Initial controller and watchdog startup ──────────────────────── */
    debug(1, "Init watchdog\n");
    setThreadsRunning(1);
    initWatchdog(&controllersNeedReinit);

    debug(1, "Init inputs\n");
    JVSInputStatus lastInputState = JVS_INPUT_STATUS_SUCCESS;
    JVSInputStatus inputStatus = initInputs(
        config.defaultGamePath, config.capabilitiesPath, config.secondCapabilitiesPath,
        &io, config.autoControllerDetection,
        config.analogDeadzonePlayer1, config.analogDeadzonePlayer2,
        config.analogDeadzonePlayer3, config.analogDeadzonePlayer4,
        config.wiiIRScale);
    lastInputState = inputStatus;

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

    debug(0, "  Output:          %s\n", config.defaultGamePath);
    if (inputStatus == JVS_INPUT_STATUS_SUCCESS)
        debug(0, "  Controllers:     Connected\n");
    else if (inputStatus == JVS_INPUT_STATUS_DEVICE_OPEN_ERROR)
        debug(0, "  Controllers:     None (waiting for devices)\n");

    /* ── Main JVS processing loop ─────────────────────────────────────── *
     *                                                                      *
     * This loop runs until SIGINT.  Controller hot-plug reinit is handled  *
     * inline so that processPacket() is called on every iteration and JVS  *
     * packet transmission is never interrupted for more than the time it   *
     * takes to join the old threads and start new ones (~50 ms maximum     *
     * thanks to the watchdog's short-slice sleep).                         */
    JVSStatus processingStatus;
    int lastTestButtonActive = 0;
    while (running != -1)
    {
        /* ── Controller hot-plug reinitialization ───────────────────────── *
         * When the watchdog detects a device-count change it sets           *
         * controllersNeedReinit = 1.  We handle it here between two         *
         * processPacket() calls so the JVS loop is never stopped.           */
        if (controllersNeedReinit)
        {
            debug(1, "Reinitializing controllers while maintaining JVS connection...\n");
            inputStatus = restartControllers(&config, &io);

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
                lastInputState = inputStatus;
            }

            /* Critical errors (malloc, bad mapping): pause briefly then
             * re-trigger reinit so we keep trying without spinning. */
            if (inputStatus == JVS_INPUT_STATUS_MALLOC_ERROR ||
                inputStatus == JVS_INPUT_STATUS_OUTPUT_MAPPING_ERROR)
            {
                stopAllThreads();
                usleep(TIME_REINIT_CRITICAL_US);
                setThreadsRunning(1);
                controllersNeedReinit = 1;
            }
        }

        /* ── Process the next JVS packet ─────────────────────────────────── */
        processingStatus = processPacket(&io);

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
            setSwitch(&io, SYSTEM, BUTTON_TEST, activeSnapshot);
            writeTestModeState(activeSnapshot);
        }
        else if (activeSnapshot)
        {
            setSwitch(&io, SYSTEM, BUTTON_TEST, 1);
        }

        switch (processingStatus)
        {
        case JVS_STATUS_ERROR_CHECKSUM:
            debug(0, "Error: A checksum error occurred\n");
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

    /* ── Shutdown ─────────────────────────────────────────────────────── */
    stopAllThreads();

    /* Remove the runtime state file now that the daemon is stopping. */
    unlink(TESTMODE_STATE_PATH);

    /* Close the file pointer */
    if (!disconnectJVS())
    {
        debug(0, "Critical: Could not disconnect from serial\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void handleSignal(int signal)
{
    if (signal == SIGINT)
    {
        debug(0, "\nModernJVS is stopping...\n");
        running = -1;
    }
    else if (signal == SIGUSR1)
    {
        /* Atomic toggle: safe to call from both signal handler and controller
         * threads without a mutex (which is not async-signal-safe). */
        __sync_fetch_and_xor(&testButtonActive, 1);
    }
}

