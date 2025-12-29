/**
 * OpenJVS Input Controller
 * Authors: Bobby Dilley, Redone, Fred 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <linux/input.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/select.h>
#include <math.h>

#include "controller/input.h"
#include "console/debug.h"
#include "console/config.h"
#include "controller/threading.h"

#define BITS_PER_LONG (sizeof(long) * 8)
#define NBITS(x) ((((x)-1) / BITS_PER_LONG) + 1)
#define OFF(x) ((x) % BITS_PER_LONG)
#define LONG(x) ((x) / BITS_PER_LONG)
#define test_bit_diff(bit, array) ((array[LONG(bit)] >> OFF(bit)) & 1)

#define DEV_INPUT_EVENT "/dev/input"
#define test_bit(bit, array) (array[bit / 8] & (1 << (bit % 8)))

/* Bus type constants from linux/input.h for device sorting */
#define BUS_TYPE_USB 0x03
#define BUS_TYPE_BLUETOOTH 0x05

// Device name patterns to filter out (non-controller devices)
// These patterns match device names that should not be treated as game controllers
static const char *FILTERED_DEVICE_PATTERNS[] = {
    // Audio/HDMI devices
    "vc4-hdmi",           // Raspberry Pi HDMI/CEC interface
    "HDMI",               // Generic HDMI devices
    "hdmi",               // Lowercase HDMI variants
    "headphone",          // Headphone jack detection
    "Headphone",          // Headphone jack detection (capitalized)
    
    // Sound devices (specific ALSA devices)
    "snd_bcm2835",        // Raspberry Pi audio
    "snd_hda",            // HD Audio devices
    "snd_usb",            // USB audio devices
    "pcspkr",             // PC Speaker
    "PC Speaker",         // PC Speaker (capitalized)
    
    // Power management
    "Power Button",       // Power buttons
    "power-button",       // Power buttons (lowercase)
    "Sleep Button",       // Sleep buttons
    "Lid Switch",         // Lid switches
    
    // Video/Camera devices (specific patterns)
    "Video Bus",          // Video4Linux bus devices
    
    NULL  // Sentinel value to mark end of array
};

typedef struct
{
    ThreadSharedData *sharedData_p;
    JVSIO *jvsIO;
    char devicePath[MAX_PATH_LENGTH];
    EVInputs inputs;
    int player;
    double deadzone;
    DeviceType deviceType;
} MappingThreadArguments;

static void *wiiDeviceThread(void *_args)
{
    MappingThreadArguments *args = (MappingThreadArguments *)_args;

    int fd = open(args->devicePath, O_RDONLY);
    if (fd < 0)
    {
        debug(0, "Warning: Failed to open Wii Remote device.");
        return 0;
    }

    struct input_event event;
    fd_set file_descriptor;
    struct timeval tv;

    /* Wii Remote Variables */
    int x0 = 0, x1 = 0, y0 = 0, y1 = 0;

    while (getThreadsRunning())
    {
        FD_ZERO(&file_descriptor);
        FD_SET(fd, &file_descriptor);

        tv.tv_sec = 0;
        tv.tv_usec = 2 * 1000;

        if (select(fd + 1, &file_descriptor, NULL, NULL, &tv) < 1)
            continue;

        if (read(fd, &event, sizeof(event)) == sizeof(event))
        {
            switch (event.type)
            {
            case EV_ABS:
            {
                bool outOfBounds = true;
                if (event.type == EV_ABS)
                {
                    switch (event.code)
                    {
                    case 16:
                        x0 = event.value;
                        break;
                    case 17:
                        y0 = event.value;
                        break;
                    case 18:
                        x1 = event.value;
                        break;
                    case 19:
                        y1 = event.value;
                        break;
                    }
                }

                if ((x0 != 1023) && (x1 != 1023) && (y0 != 1023) && (y1 != 1023))
                {
                    /* Set screen in player 1 */
                    setSwitch(args->jvsIO, args->player, args->inputs.key[KEY_O].output, 0);
                    int oneX, oneY, twoX, twoY;
                    if (x0 > x1)
                    {
                        oneY = y0;
                        oneX = x0;
                        twoY = y1;
                        twoX = x1;
                    }
                    else
                    {
                        oneY = y1;
                        oneX = x1;
                        twoY = y0;
                        twoX = x0;
                    }

                    /* Use some fancy maths that I don't understand fully */
                    double valuex = 512 + cos(atan2(twoY - oneY, twoX - oneX) * -1) * (((oneX - twoX) / 2 + twoX) - 512) - sin(atan2(twoY - oneY, twoX - oneX) * -1) * (((oneY - twoY) / 2 + twoY) - 384);
                    double valuey = 384 + sin(atan2(twoY - oneY, twoX - oneX) * -1) * (((oneX - twoX) / 2 + twoX) - 512) + cos(atan2(twoY - oneY, twoX - oneX) * -1) * (((oneY - twoY) / 2 + twoY) - 384);

                    double finalX = (((double)valuex / (double)1023) * 1.0);
                    double finalY = 1.0f - ((double)valuey / (double)1023);

                    // check for out-of-bound after rotation ..
                    if ((!(finalX > 1.0f) || (finalY > 1.0f) || (finalX < 0) || (finalY < 0)))
                    {
                        setAnalogue(args->jvsIO, args->inputs.abs[ABS_X].output, args->inputs.abs[ABS_X].reverse ? 1 - finalX : finalX);
                        setAnalogue(args->jvsIO, args->inputs.abs[ABS_Y].output, args->inputs.abs[ABS_Y].reverse ? 1 - finalY : finalY);
                        setGun(args->jvsIO, args->inputs.abs[ABS_X].output, args->inputs.abs[ABS_X].reverse ? 1 - finalX : finalX);
                        setGun(args->jvsIO, args->inputs.abs[ABS_Y].output, args->inputs.abs[ABS_Y].reverse ? 1 - finalY : finalY);

                        outOfBounds = false;
                    }
                }

                if (outOfBounds)
                {
                    /* Set screen out player 1 */
                    setSwitch(args->jvsIO, args->player, args->inputs.key[KEY_O].output, 1);

                    setAnalogue(args->jvsIO, args->inputs.abs[ABS_X].output, 0);
                    setAnalogue(args->jvsIO, args->inputs.abs[ABS_Y].output, 0);

                    setGun(args->jvsIO, args->inputs.abs[ABS_X].output, 0);
                    setGun(args->jvsIO, args->inputs.abs[ABS_Y].output, 0);
                }
                continue;
            }
            break;
            }
        }
    }

    close(fd);
    free(args);

    return 0;
}

/**
 * Apply circular deadzone to analog stick values
 * @param x The X axis value (0.0 to 1.0, where 0.5 is center)
 * @param y The Y axis value (0.0 to 1.0, where 0.5 is center)
 * @param deadzone The deadzone radius (0.0 to 1.0)
 * @param outX Pointer to store the processed X value
 * @param outY Pointer to store the processed Y value
 */
static void applyDeadzone(double x, double y, double deadzone, double *outX, double *outY)
{
    /* Clamp deadzone to valid range to prevent division by zero */
    if (deadzone >= 1.0)
    {
        *outX = 0.5;
        *outY = 0.5;
        return;
    }
    
    if (deadzone < 0.0)
        deadzone = 0.0;
    
    /* Convert from 0.0-1.0 range to -1.0 to 1.0 range (center at 0) */
    double dx = (x - 0.5) * 2.0;
    double dy = (y - 0.5) * 2.0;
    
    /* Calculate magnitude */
    double magnitude = sqrt(dx * dx + dy * dy);
    
    /* If within deadzone, set to center */
    if (magnitude < deadzone)
    {
        *outX = 0.5;
        *outY = 0.5;
        return;
    }
    
    /* Scale the input to account for deadzone */
    double scale = (magnitude - deadzone) / (1.0 - deadzone);
    if (scale > 1.0) scale = 1.0;
    
    /* Normalize and apply scale */
    double nx = (magnitude > 0.0) ? (dx / magnitude) : 0.0;
    double ny = (magnitude > 0.0) ? (dy / magnitude) : 0.0;
    
    /* Convert back to 0.0-1.0 range */
    *outX = (nx * scale + 1.0) * 0.5;
    *outY = (ny * scale + 1.0) * 0.5;
}

static void *deviceThread(void *_args)
{
    MappingThreadArguments *args = (MappingThreadArguments *)_args;

    int fd = open(args->devicePath, O_RDONLY);
    if (fd < 0)
    {
        debug(0, "Critical: Failed to open device file descriptor %d \n", fd);
        free(args);
        return 0;
    }

    struct input_event event;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    uint8_t absoluteBitmask[ABS_MAX / 8 + 1];
    struct input_absinfo absoluteFeatures;

    memset(absoluteBitmask, 0, sizeof(absoluteBitmask));
    if (ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absoluteBitmask)), absoluteBitmask) < 0)
        perror("Error: Failed to get bit mask for analogue values");

    for (int axisIndex = 0; axisIndex < ABS_MAX; ++axisIndex)
    {
        if (test_bit(axisIndex, absoluteBitmask))
        {
            if (ioctl(fd, EVIOCGABS(axisIndex), &absoluteFeatures))
                perror("Error: Failed to get device analogue limits");

            args->inputs.absMax[axisIndex] = (double)absoluteFeatures.maximum;
            args->inputs.absMin[axisIndex] = (double)absoluteFeatures.minimum;
        }
    }

    fd_set file_descriptor;
    struct timeval tv;

    /* Track current analog stick values for deadzone processing */
    double leftStickX = 0.5;  /* Center position */
    double leftStickY = 0.5;
    double rightStickX = 0.5;
    double rightStickY = 0.5;

    while (getThreadsRunning())
    {

        FD_ZERO(&file_descriptor);
        FD_SET(fd, &file_descriptor);

        tv.tv_sec = 0;
        tv.tv_usec = 2 * 1000;

        if (select(fd + 1, &file_descriptor, NULL, NULL, &tv) < 1)
            continue;

        if (read(fd, &event, sizeof(event)) == sizeof(event))
        {
            switch (event.type)
            {

            case EV_KEY:
            {
                JVSIO *io = args->jvsIO;
                if (args->inputs.key[event.code].secondaryIO)
                {
                    io = args->jvsIO->chainedIO;
                }

                /* Check if the coin button has been pressed */
                if (args->inputs.key[event.code].output == COIN)
                {
                    if (event.value == 1)
                        incrementCoin(io, args->inputs.key[event.code].jvsPlayer, 1);

                    continue;
                }

                setSwitch(io, args->inputs.key[event.code].jvsPlayer, args->inputs.key[event.code].output, event.value == 0 ? 0 : 1);

                if (args->inputs.key[event.code].outputSecondary != NONE)
                    setSwitch(io, args->inputs.key[event.code].jvsPlayer, args->inputs.key[event.code].outputSecondary, event.value == 0 ? 0 : 1);
            }
            break;

            case EV_REL:
            {
                JVSIO *io = args->jvsIO;

                if (!args->inputs.relEnabled[event.code])
                    continue;

                if (args->inputs.rel[event.code].secondaryIO && args->jvsIO->chainedIO != NULL)
                    io = args->jvsIO->chainedIO;

                int reverse = args->inputs.rel[event.code].reverse;

                int oldRotaryValue = getRotary(io, args->inputs.rel[event.code].output);
                setRotary(io, args->inputs.rel[event.code].output, oldRotaryValue + (reverse ? event.value * -1 : event.value));
            }
            break;

            case EV_ABS:
            {
                /* Support HAT Controlls */
                if (args->inputs.abs[event.code].type == HAT)
                {

                    if (event.value == args->inputs.absMin[event.code])
                    {
                        setSwitch(args->jvsIO, args->inputs.abs[event.code].jvsPlayer, args->inputs.abs[event.code].output, 1);
                    }
                    else if (event.value == args->inputs.absMax[event.code])
                    {
                        setSwitch(args->jvsIO, args->inputs.abs[event.code].jvsPlayer, args->inputs.abs[event.code].outputSecondary, 1);
                    }
                    else
                    {
                        setSwitch(args->jvsIO, args->inputs.abs[event.code].jvsPlayer, args->inputs.abs[event.code].output, 0);
                        setSwitch(args->jvsIO, args->inputs.abs[event.code].jvsPlayer, args->inputs.abs[event.code].outputSecondary, 0);
                    }
                    continue;
                }

                // Useful for mapping analogue buttons to digital buttons,
                // for example the triggers on a gamepad.
                if (args->inputs.abs[event.code].type == SWITCH)
                {
                    // Allows mapping an axis button to a coin
                    if (args->inputs.key[event.code].output == COIN)
                    {
                        if (event.value == args->inputs.absMax[event.code])
                        {
                            incrementCoin(args->jvsIO, args->inputs.key[event.code].jvsPlayer, 1);
                        }
                        continue;
                    }
                    else if (event.value == args->inputs.absMin[event.code])
                    {
                        setSwitch(args->jvsIO, args->inputs.key[event.code].jvsPlayer, args->inputs.key[event.code].output, 0);
                    }
                    else
                    {
                        setSwitch(args->jvsIO, args->inputs.key[event.code].jvsPlayer, args->inputs.key[event.code].output, 1);
                    }
                    continue;
                }

                /* Handle normally mapped analogue controls */
                if (args->inputs.absEnabled[event.code])
                {
                    double scaled = ((double)((double)event.value * (double)args->inputs.absMultiplier[event.code]) - args->inputs.absMin[event.code]) / (args->inputs.absMax[event.code] - args->inputs.absMin[event.code]);

                    /* Make sure it doesn't go over 1 or below 0 if its multiplied */
                    scaled = scaled > 1 ? 1 : scaled;
                    scaled = scaled < 0 ? 0 : scaled;

                    /* Determine which stick this axis belongs to and apply deadzone.
                     * Only ABS_X/ABS_Y (left stick) and ABS_RX/ABS_RY (right stick) get deadzone.
                     * ABS_Z and ABS_RZ are excluded as they are commonly used for triggers
                     * (L2/R2 on PlayStation controllers, LT/RT on some Xbox controllers),
                     * and should maintain full pressure sensitivity without deadzone.
                     * Controllers with non-standard mappings should use custom device mappings.
                     */
                    int isLeftStick = (event.code == ABS_X || event.code == ABS_Y);
                    int isRightStick = (event.code == ABS_RX || event.code == ABS_RY);
                    int shouldApplyDeadzone = (args->deviceType == DEVICE_TYPE_JOYSTICK && args->deadzone > 0.0);
                    
                    double finalValue = scaled;  /* Default to unprocessed value */
                    
                    /* Only apply deadzone to joystick devices with analog sticks */
                    if (shouldApplyDeadzone && isLeftStick)
                    {
                        /* Update the appropriate axis value */
                        if (event.code == ABS_X)
                            leftStickX = scaled;
                        else if (event.code == ABS_Y)
                            leftStickY = scaled;
                        
                        /* Apply deadzone to both axes */
                        double processedX, processedY;
                        applyDeadzone(leftStickX, leftStickY, args->deadzone, &processedX, &processedY);
                        
                        /* Set the processed value for the axis that just changed */
                        if (event.code == ABS_X)
                        {
                            finalValue = processedX;
                            setAnalogue(args->jvsIO, args->inputs.abs[event.code].output, args->inputs.abs[event.code].reverse ? 1 - processedX : processedX);
                        }
                        else if (event.code == ABS_Y)
                        {
                            finalValue = processedY;
                            setAnalogue(args->jvsIO, args->inputs.abs[event.code].output, args->inputs.abs[event.code].reverse ? 1 - processedY : processedY);
                        }
                    }
                    else if (shouldApplyDeadzone && isRightStick)
                    {
                        /* Update the appropriate axis value */
                        if (event.code == ABS_RX)
                            rightStickX = scaled;
                        else if (event.code == ABS_RY)
                            rightStickY = scaled;
                        
                        /* Apply deadzone to both axes */
                        double processedX, processedY;
                        applyDeadzone(rightStickX, rightStickY, args->deadzone, &processedX, &processedY);
                        
                        /* Set the processed value for the axis that just changed */
                        if (event.code == ABS_RX)
                        {
                            finalValue = processedX;
                            setAnalogue(args->jvsIO, args->inputs.abs[event.code].output, args->inputs.abs[event.code].reverse ? 1 - processedX : processedX);
                        }
                        else if (event.code == ABS_RY)
                        {
                            finalValue = processedY;
                            setAnalogue(args->jvsIO, args->inputs.abs[event.code].output, args->inputs.abs[event.code].reverse ? 1 - processedY : processedY);
                        }
                    }
                    else
                    {
                        /* No deadzone or not a joystick device - pass through directly.
                         * This path handles all other analog inputs including trigger axes
                         * (ABS_Z, ABS_RZ, ABS_THROTTLE, ABS_BRAKE, etc.) that should not
                         * have circular deadzone applied.
                         */
                        setAnalogue(args->jvsIO, args->inputs.abs[event.code].output, args->inputs.abs[event.code].reverse ? 1 - scaled : scaled);
                    }
                    
                    /* Gun controls - use processed value if deadzone was applied, otherwise use scaled */
                    setGun(args->jvsIO, args->inputs.abs[event.code].output, args->inputs.abs[event.code].reverse ? 1 - finalValue : finalValue);
                }
            }
            break;

            case EV_MSC:
            {
                if (args->inputs.key[event.code].output == COIN)
                {
                    // The event's value is passed through, allowing the
                    // source of the event to define how many coins to
                    // insert at once.
                    if (event.value > 0)
                        incrementCoin(args->jvsIO, args->inputs.key[event.code].jvsPlayer, event.value);

                    continue;
                }
            }
            break;
            }
        }
    }

    close(fd);
    free(args);

    return 0;
}
static void startThread(EVInputs *inputs, char *devicePath, int wiiMode, int player, JVSIO *jvsIO, double deadzone, DeviceType deviceType)
{
    MappingThreadArguments *args = malloc(sizeof(MappingThreadArguments));
    if (args == NULL)
    {
        debug(0, "Error: Failed to malloc mapping thread arguments\n");
        return;
    }
    
    strcpy(args->devicePath, devicePath);
    memcpy(&args->inputs, inputs, sizeof(EVInputs));
    args->player = player;
    args->jvsIO = jvsIO;
    args->deadzone = deadzone;
    args->deviceType = deviceType;

    if (wiiMode)
    {
        if (createThread(wiiDeviceThread, args) != THREAD_STATUS_SUCCESS)
        {
            free(args);
        }
    }
    else
    {
        if (createThread(deviceThread, args) != THREAD_STATUS_SUCCESS)
        {
            free(args);
        }
    }
}

int evDevFromString(char *evDevString)
{
    for (long unsigned int i = 0; i < sizeof(evDevConversion) / sizeof(evDevConversion[0]); i++)
    {
        if (strcmp(evDevConversion[i].string, evDevString) == 0)
        {
            return evDevConversion[i].number;
        }
    }
    debug(0, "Error: Could not find the EV DEV string specified for %s\n", evDevString);
    return -1;
}

ControllerInput controllerInputFromString(char *controllerInputString)
{
    for (long unsigned int i = 0; i < sizeof(controllerInputConversion) / sizeof(controllerInputConversion[0]); i++)
    {
        if (strcmp(controllerInputConversion[i].string, controllerInputString) == 0)
            return controllerInputConversion[i].input;
    }
    debug(0, "Error: Could not find the CONTROLLER INPUT string specified for %s\n", controllerInputString);
    return -1;
}

ControllerPlayer controllerPlayerFromString(char *controllerPlayerString)
{
    for (long unsigned int i = 0; i < sizeof(controllerPlayerConversion) / sizeof(controllerPlayerConversion[0]); i++)
    {
        if (strcmp(controllerPlayerConversion[i].string, controllerPlayerString) == 0)
            return controllerPlayerConversion[i].player;
    }
    debug(0, "Error: Could not find the CONTROLLER PLAYER string specified for %s\n", controllerPlayerString);
    return -1;
}

static const char *stringFromControllerInput(ControllerInput controllerInput)
{
    for (long unsigned int i = 0; i < sizeof(controllerInputConversion) / sizeof(controllerInputConversion[0]); i++)
    {
        if (controllerInputConversion[i].input == controllerInput)
            return controllerInputConversion[i].string;
    }
    debug(0, "Error: Could not find the CONTROLLER INPUT string specified for controller input\n");
    return NULL;
}

static int processMappings(InputMappings *inputMappings, OutputMappings *outputMappings, EVInputs *evInputs, ControllerPlayer player)
{
    for (int i = 0; i < inputMappings->length; i++)
    {
        int found = 0;
        double multiplier = 1;
        OutputMapping tempMapping;
        for (int j = outputMappings->length - 1; j >= 0; j--)
        {

            if ((outputMappings->mappings[j].input == inputMappings->mappings[i].input) && (outputMappings->mappings[j].controllerPlayer == player))
            {
                tempMapping = outputMappings->mappings[j];

                /* Find the second mapping if needed*/
                if (inputMappings->mappings[i].type == HAT)
                {
                    int foundSecondaryMapping = 0;
                    for (int p = outputMappings->length - 1; p >= 0; p--)
                    {
                        if (outputMappings->mappings[p].input == inputMappings->mappings[i].inputSecondary && outputMappings->mappings[p].controllerPlayer == player)
                        {
                            tempMapping.outputSecondary = outputMappings->mappings[p].output;
                            tempMapping.type = HAT;
                            found = 1;
                            break;
                        }
                    }
                    if (!foundSecondaryMapping)
                    {
                        debug(1, "Warning: No outside secondary mapping found for HAT\n");
                        continue;
                    }
                }

                tempMapping.reverse ^= inputMappings->mappings[i].reverse;
                multiplier = inputMappings->mappings[i].multiplier;
                found = 1;
                break;
            }
        }

        if (!found)
        {
            debug(1, "Warning: No outside mapping found for %s\n", stringFromControllerInput(inputMappings->mappings[i].input));
            continue;
        }

        if (inputMappings->mappings[i].type == HAT)
        {
            evInputs->abs[inputMappings->mappings[i].code] = tempMapping;
            evInputs->abs[inputMappings->mappings[i].code].type = HAT;
            evInputs->absEnabled[inputMappings->mappings[i].code] = 1;
        }

        if (inputMappings->mappings[i].type == ANALOGUE && tempMapping.type == ANALOGUE)
        {
            evInputs->abs[inputMappings->mappings[i].code] = tempMapping;
            evInputs->abs[inputMappings->mappings[i].code].type = ANALOGUE;
            evInputs->absEnabled[inputMappings->mappings[i].code] = 1;
            evInputs->absMultiplier[inputMappings->mappings[i].code] = multiplier;
        }
        else if (inputMappings->mappings[i].type == ROTARY && tempMapping.type == ROTARY)
        {
            evInputs->rel[inputMappings->mappings[i].code] = tempMapping;
            evInputs->rel[inputMappings->mappings[i].code].type = ROTARY;
            evInputs->relEnabled[inputMappings->mappings[i].code] = 1;
            evInputs->relMultiplier[inputMappings->mappings[i].code] = multiplier;
        }
        else if (inputMappings->mappings[i].type == SWITCH || tempMapping.type == SWITCH)
        {
            evInputs->key[inputMappings->mappings[i].code] = tempMapping;
            evInputs->abs[inputMappings->mappings[i].code].type = SWITCH;
            evInputs->absEnabled[inputMappings->mappings[i].code] = 1;
        }

        if (inputMappings->mappings[i].type == CARD)
        {
            evInputs->key[inputMappings->mappings[i].code] = tempMapping;
            evInputs->abs[inputMappings->mappings[i].code].type = (InputType)COIN;
            evInputs->absEnabled[inputMappings->mappings[i].code] = 1;
        }
    }
    return 1;
}

static int isEventDevice(const struct dirent *dir)
{
    return strncmp("event", dir->d_name, 5) == 0;
}

static int shouldFilterDevice(const char *deviceName)
{
    for (int i = 0; FILTERED_DEVICE_PATTERNS[i] != NULL; i++)
    {
        if (strstr(deviceName, FILTERED_DEVICE_PATTERNS[i]) != NULL)
            return 1;
    }
    return 0;
}

int getNumberOfDevices(void)
{
    struct dirent **namelist;
    return scandir(DEV_INPUT_EVENT, &namelist, isEventDevice, NULL);
}

JVSInputStatus getInputs(DeviceList *deviceList)
{
    memset(deviceList, 0, sizeof(DeviceList));
    struct dirent **namelist;

    int scannedCount = scandir(DEV_INPUT_EVENT, &namelist, isEventDevice, alphasort);

    if (scannedCount == 0)
        return JVS_INPUT_STATUS_NO_DEVICE_ERROR;

    char aimtrakRemap[3][32] = {
        AIMTRAK_DEVICE_NAME_REMAP_JOYSTICK,
        AIMTRAK_DEVICE_NAME_REMAP_OUT_SCREEN,
        AIMTRAK_DEVICE_NAME_REMAP_IN_SCREEN};
    int aimtrakCount = 0;

    int validDeviceIndex = 0;
    for (int i = 0; i < scannedCount; i++)
    {
        char tempPath[MAX_PATH];
        snprintf(tempPath, sizeof(tempPath), "%s/%s", DEV_INPUT_EVENT, namelist[i]->d_name);
        free(namelist[i]);

        int device = open(tempPath, O_RDONLY);
        if (device < 0)
            continue;

        char tempFullName[MAX_PATH] = "Unknown";
        
        // Get the name string first to check if we should filter this device
        ioctl(device, EVIOCGNAME(sizeof(tempFullName)), tempFullName);

        // Filter out non-controller devices (HDMI, sound cards, etc.)
        if (shouldFilterDevice(tempFullName))
        {
            close(device);
            continue;
        }

        // This is a valid device, so add it to our list
        Device *dev = &deviceList->devices[validDeviceIndex];
        strcpy(dev->path, tempPath);
        strcpy(dev->fullName, tempFullName);
        strcpy(dev->name, "unknown");
        dev->type = DEVICE_TYPE_UNKNOWN;

        // Get product vendor and ID information
        struct input_id device_info;
        ioctl(device, EVIOCGID, &device_info);
        dev->vendorID = device_info.vendor;
        dev->productID = device_info.product;
        dev->version = device_info.version;
        dev->bus = device_info.bustype;

        // Get the physical location string
        ioctl(device, EVIOCGPHYS(sizeof(dev->physicalLocation)), dev->physicalLocation);
        for (size_t j = 0; j < strlen(dev->physicalLocation); j++)
        {
            if (dev->physicalLocation[j] == '/')
            {
                dev->physicalLocation[j] = 0;
                break;
            }
        }

        // Make it lower case and replace letters
        for (size_t j = 0; j < strlen(dev->fullName); j++)
        {
            dev->name[j] = tolower(dev->fullName[j]);
            if (dev->name[j] == ' ' ||
                dev->name[j] == '/' ||
                dev->name[j] == '(' ||
                dev->name[j] == ')')
            {
                dev->name[j] = '-';
            }
        }

        // Assign the correct names for the aimtracks
        if (strcmp(dev->name, AIMTRAK_DEVICE_NAME) == 0)
        {
            strcpy(dev->name, aimtrakRemap[aimtrakCount++]);
            if (aimtrakCount == 3)
                aimtrakCount = 0;
        }

        // Attempt to work out the device type
        unsigned long bit[EV_MAX][NBITS(KEY_MAX)];
        memset(bit, 0, sizeof(bit));
        ioctl(device, EVIOCGBIT(0, EV_MAX), bit[0]);

        // If it does repeating events and key events, it's probably a keyboard.
        if (!test_bit_diff(EV_ABS, bit[0]) && test_bit_diff(EV_REP, bit[0]) && test_bit_diff(EV_KEY, bit[0]))
            dev->type = DEVICE_TYPE_KEYBOARD;

        // Relative events means its a mouse!
        if (test_bit_diff(EV_REL, bit[0]))
        {
            dev->type = DEVICE_TYPE_MOUSE;
        }

        // If it has a start button then it's probably a joystick!
        if (test_bit_diff(EV_KEY, bit[0]))
        {
            ioctl(device, EVIOCGBIT(EV_KEY, KEY_MAX), bit[EV_KEY]);
            if (test_bit_diff(BTN_START, bit[EV_KEY]))
                dev->type = DEVICE_TYPE_JOYSTICK;
        }

        close(device);
        validDeviceIndex++;
    }

    free(namelist);

    deviceList->length = validDeviceIndex;

    /* Sort devices to ensure consistent player slot assignment.
     * Primary sort: bus type (USB before Bluetooth for predictable ordering)
     * Secondary sort: physical location (USB port path or Bluetooth MAC)
     * This ensures USB controllers get player 1, 2, etc., and Bluetooth
     * controllers get subsequent player slots in a stable order.
     */
    for (int i = 0; i < deviceList->length - 1; i++)
    {
        for (int j = 0; j < deviceList->length - 1 - i; j++)
        {
            Device tmp;
            int shouldSwap = 0;
            
            /* Compare bus types first - lower bus type numbers come first */
            if (deviceList->devices[j].bus > deviceList->devices[j + 1].bus)
            {
                shouldSwap = 1;
            }
            /* If same bus type, sort by physical location */
            else if (deviceList->devices[j].bus == deviceList->devices[j + 1].bus)
            {
                if (strcmp(deviceList->devices[j].physicalLocation, deviceList->devices[j + 1].physicalLocation) > 0)
                {
                    shouldSwap = 1;
                }
            }
            
            if (shouldSwap)
            {
                tmp = deviceList->devices[j];
                deviceList->devices[j] = deviceList->devices[j + 1];
                deviceList->devices[j + 1] = tmp;
            }
        }
    }

    /* Debug output: show detected devices in order after sorting */
    if (deviceList->length > 0)
    {
        debug(1, "Detected %d input device%s after filtering and sorting:\n", 
              deviceList->length, 
              deviceList->length == 1 ? "" : "s");
        for (int i = 0; i < deviceList->length; i++)
        {
            const char *busType = "Unknown";
            if (deviceList->devices[i].bus == BUS_TYPE_USB) busType = "USB";
            else if (deviceList->devices[i].bus == BUS_TYPE_BLUETOOTH) busType = "Bluetooth";
            
            debug(1, "  [%d] %s (%s, %s)\n", i, 
                  deviceList->devices[i].name,
                  busType,
                  deviceList->devices[i].physicalLocation);
        }
    }

    return JVS_INPUT_STATUS_SUCCESS;
}

/**
 * Initialise all of the input devices and start the threads
 * 
 * This function initialises all the input devices that have mappings and
 * starts all of the appropriate threads.
 * 
 * @param outputMappingPath The path of the game mapping file
 * @param configPath The path to the configuration file
 * @param jvsIO The JVS IO object that we will send inputs to
 * @param autoDetect If we should automatically map controllers without mappings
 * @returns The status of the operation
 **/
JVSInputStatus initInputs(char *outputMappingPath, char *configPath, char *secondConfigPath, JVSIO *jvsIO, int autoDetect, double dzP1, double dzP2)
{
    OutputMappings outputMappings = {0};
    DeviceList *deviceList = (DeviceList *)malloc(sizeof(DeviceList));

    if (deviceList == NULL)
        return JVS_INPUT_STATUS_MALLOC_ERROR;

    if (getInputs(deviceList) != JVS_INPUT_STATUS_SUCCESS)
    {
        free(deviceList);
        return JVS_INPUT_STATUS_DEVICE_OPEN_ERROR;
    }

    if (parseOutputMapping(outputMappingPath, &outputMappings, configPath, secondConfigPath) != JVS_CONFIG_STATUS_SUCCESS)
    {
        free(deviceList);
        return JVS_INPUT_STATUS_OUTPUT_MAPPING_ERROR;
    }

    int playerNumber = 1;

    for (int i = 0; i < deviceList->length; i++)
    {
        Device *device = &deviceList->devices[i];

        char disabledPath[MAX_PATH_LENGTH];
        int ret = snprintf(disabledPath, sizeof(disabledPath), "%s%s.disabled", DEFAULT_DEVICE_MAPPING_PATH, device->name);
        if (ret < 0 || ret >= (int)sizeof(disabledPath))
            continue;
        FILE *file = fopen(disabledPath, "r");
        if (file != NULL)
        {
            fclose(file);
            continue;
        }

        /* Attempt to do a generic map */
        char specialMap[256] = "";
        InputMappings inputMappings = {0};

        // Put the device name into a temp variable so it can be changed
        char deviceName[MAX_PATH_LENGTH];
        strcpy(deviceName, device->name);

        // Use the standard nintendo-wii-remote mapping file for the IR Version too
        if (strcmp(deviceName, WIIMOTE_DEVICE_NAME_IR) == 0)
            strcpy(deviceName, WIIMOTE_DEVICE_NAME);

        // Use the standard ultimarc-aimtrak mapping file for both screen events
        if (strcmp(deviceName, AIMTRAK_DEVICE_NAME_REMAP_JOYSTICK) == 0 || strcmp(deviceName, AIMTRAK_DEVICE_NAME_REMAP_OUT_SCREEN) == 0 || strcmp(deviceName, AIMTRAK_DEVICE_NAME_REMAP_IN_SCREEN) == 0)
            strcpy(deviceName, AIMTRAK_DEVICE_MAPPING_NAME);

        if (parseInputMapping(deviceName, &inputMappings) != JVS_CONFIG_STATUS_SUCCESS || inputMappings.length == 0)
        {
            if (autoDetect)
            {
                switch (deviceList->devices[i].type)
                {
                case DEVICE_TYPE_JOYSTICK:
                    if (parseInputMapping("generic-joystick", &inputMappings) != JVS_CONFIG_STATUS_SUCCESS || inputMappings.length == 0)
                        continue;
                    strcpy(specialMap, " (Generic Joystick Map)");
                    break;
                case DEVICE_TYPE_KEYBOARD:
                    if (parseInputMapping("generic-keyboard", &inputMappings) != JVS_CONFIG_STATUS_SUCCESS || inputMappings.length == 0)
                        continue;
                    strcpy(specialMap, " (Generic Keyboard Map)");
                    break;
                case DEVICE_TYPE_MOUSE:
                    if (parseInputMapping("generic-mouse", &inputMappings) != JVS_CONFIG_STATUS_SUCCESS || inputMappings.length == 0)
                        continue;
                    strcpy(specialMap, " (Generic Mouse Map)");
                    break;
                default:
                    continue;
                }
            }
        }

        EVInputs evInputs = {0};
        if (!processMappings(&inputMappings, &outputMappings, &evInputs, (ControllerPlayer)playerNumber))
        {
            debug(0, "Error: Failed to process the mapping for %s\n", deviceList->devices[i].name);
            continue;
        }

        if (inputMappings.player != -1)
        {
            double dz = (inputMappings.player == 1) ? dzP1 : dzP2;
            startThread(&evInputs, device->path, strcmp(device->name, WIIMOTE_DEVICE_NAME_IR) == 0, inputMappings.player, jvsIO, dz, deviceList->devices[i].type);
            debug(0, "  Player %d (Fixed via config):\t\t%s%s\n", inputMappings.player, deviceList->devices[i].name, specialMap);
        }
        else
        {
            double dz = (playerNumber == 1) ? dzP1 : dzP2;
            startThread(&evInputs, device->path, strcmp(device->name, WIIMOTE_DEVICE_NAME_IR) == 0, playerNumber, jvsIO, dz, deviceList->devices[i].type);
            if (strcmp(deviceList->devices[i].name, AIMTRAK_DEVICE_NAME_REMAP_OUT_SCREEN) != 0 && strcmp(deviceList->devices[i].name, AIMTRAK_DEVICE_NAME_REMAP_JOYSTICK) != 0 && strcmp(deviceList->devices[i].name, WIIMOTE_DEVICE_NAME_IR) != 0)
            {
                debug(0, "  Player %d:\t\t%s%s\n", playerNumber, deviceName, specialMap);
                playerNumber++;
            }
        }
    }

    free(deviceList);
    deviceList = NULL;

    return JVS_INPUT_STATUS_SUCCESS;
}
