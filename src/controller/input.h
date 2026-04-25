#ifndef INPUT_H_
#define INPUT_H_

#include <linux/input.h>

#include "jvs/io.h"

#define WIIMOTE_DEVICE_NAME "nintendo-wii-remote"
#define WIIMOTE_DEVICE_NAME_IR "nintendo-wii-remote-ir"
#define WIIMOTE_DEVICE_NAME_NUNCHUK "nintendo-wii-remote-nunchuk"
#define WIIMOTE_DEVICE_NAME_PLUS_NUNCHUK "nintendo-wii-remote-plus-nunchuk"

#define AIMTRAK_DEVICE_NAME "ultimarc-ultimarc"
#define AIMTRAK_DEVICE_NAME_REMAP_JOYSTICK "ultimarc-ultimarc-joystick"
#define AIMTRAK_DEVICE_NAME_REMAP_OUT_SCREEN "ultimarc-ultimarc-screen-out"
#define AIMTRAK_DEVICE_NAME_REMAP_IN_SCREEN "ultimarc-ultimarc-screen-in"
#define AIMTRAK_DEVICE_MAPPING_NAME "ultimarc-aimtrak"

#define MAX_MAPPING 1024
#define MAX_PATH 1024
#define MAX_DEVICES 255
#define MAX_EV_ITEMS 1024

typedef enum
{
    DEVICE_TYPE_JOYSTICK,
    DEVICE_TYPE_KEYBOARD,
    DEVICE_TYPE_MOUSE,
    DEVICE_TYPE_UNKNOWN
} DeviceType;

typedef struct
{
    DeviceType type;
    char fullName[MAX_PATH];
    char name[MAX_PATH];
    char path[MAX_PATH];
    char physicalLocation[MAX_PATH];
    int bus;
    int productID;
    int vendorID;
    int version;
} Device;

typedef struct
{
    Device devices[MAX_DEVICES];
    int length;
} DeviceList;

typedef enum
{
    ANALOGUE,
    SWITCH,
    ROTARY,
    HAT,
    CARD,
} InputType;

typedef enum
{
    CONTROLLER_BUTTON_TEST,
    CONTROLLER_BUTTON_TILT,
    CONTROLLER_BUTTON_COIN,
    CONTROLLER_BUTTON_START,
    CONTROLLER_BUTTON_SERVICE,
    CONTROLLER_BUTTON_UP,
    CONTROLLER_BUTTON_DOWN,
    CONTROLLER_BUTTON_LEFT,
    CONTROLLER_BUTTON_LEFT_BUMPER,
    CONTROLLER_BUTTON_RIGHT,
    CONTROLLER_BUTTON_RIGHT_BUMPER,
    CONTROLLER_BUTTON_A,
    CONTROLLER_BUTTON_B,
    CONTROLLER_BUTTON_C,
    CONTROLLER_BUTTON_D,
    CONTROLLER_BUTTON_E,
    CONTROLLER_BUTTON_F,
    CONTROLLER_BUTTON_G,
    CONTROLLER_BUTTON_H,
    CONTROLLER_BUTTON_I,
    CONTROLLER_BUTTON_J,
    CONTROLLER_ANALOGUE_X,
    CONTROLLER_ANALOGUE_Y,
    CONTROLLER_ANALOGUE_Z,
    CONTROLLER_ANALOGUE_R,
    CONTROLLER_ANALOGUE_L,
    CONTROLLER_ANALOGUE_T,
    CONTROLLER_ROTARY_X,
    CONTROLLER_ROTARY_Y,
    CONTROLLER_ROTARY_Z,
    CONTROLLER_ROTARY_R,
    CONTROLLER_ROTARY_L,
    CONTROLLER_ROTARY_T
} ControllerInput;

typedef enum
{
    CONTROLLER_1 = 1,
    CONTROLLER_2,
    CONTROLLER_3,
    CONTROLLER_4,
} ControllerPlayer;

typedef struct
{
    InputType type;
    ControllerInput input;
    ControllerInput inputSecondary;
    int code;
    int reverse;
    double multiplier;
} InputMapping;

typedef struct
{
    int enabled;
    InputType type;
    ControllerInput input;
    ControllerPlayer controllerPlayer;
    JVSInput output;
    JVSInput outputSecondary;
    JVSPlayer jvsPlayer;
    int reverse;
    double multiplier;
    int secondaryIO;
} OutputMapping;

typedef struct
{
    int length;
    InputMapping mappings[MAX_MAPPING];
    int player;
    char name[MAX_PATH];
} InputMappings;

typedef struct
{
    int length;
    OutputMapping mappings[MAX_MAPPING];
} OutputMappings;

typedef struct
{
    int relEnabled[MAX_EV_ITEMS];
    int absEnabled[MAX_EV_ITEMS];
    double absMultiplier[MAX_EV_ITEMS];
    double relMultiplier[MAX_EV_ITEMS];
    int absMin[MAX_EV_ITEMS];
    int absMax[MAX_EV_ITEMS];
    OutputMapping abs[MAX_EV_ITEMS];
    OutputMapping rel[MAX_EV_ITEMS];
    OutputMapping key[MAX_EV_ITEMS];
} EVInputs;

typedef enum
{
    JVS_INPUT_STATUS_NO_DEVICE_ERROR,
    JVS_INPUT_STATUS_MALLOC_ERROR,
    JVS_INPUT_STATUS_DEVICE_OPEN_ERROR,
    JVS_INPUT_STATUS_OUTPUT_MAPPING_ERROR,
    JVS_INPUT_STATUS_SUCCESS
} JVSInputStatus;

JVSInputStatus initInputs(char *outputMappingPath, char *configPath, char *secondConfigPath, JVSIO *jvsIO, int autoDetect, double analogDeadzoneP1, double analogDeadzoneP2, double analogDeadzoneP3, double analogDeadzoneP4, double wiiIRScale);
int evDevFromString(char *evDevString);
JVSInputStatus getInputs(DeviceList *deviceList);
ControllerInput controllerInputFromString(char *controllerInputString);
ControllerPlayer controllerPlayerFromString(char *controllerPlayerString);
int getNumberOfDevices(void);

#endif // INPUT_H_
