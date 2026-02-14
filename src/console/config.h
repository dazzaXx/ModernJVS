#ifndef CONFIG_H_
#define CONFIG_H_

#include "controller/input.h"

/* Default config values */
#define DEFAULT_CONFIG_PATH "/etc/modernjvs/config"
#define DEFAULT_DEBUG_LEVEL 0
#define DEFAULT_DEVICE_MAPPING_PATH "/etc/modernjvs/devices/"
#define DEFAULT_DEVICE_PATH "/dev/ttyUSB0"
#define DEFAULT_GAME "generic"
#define DEFAULT_GAME_MAPPING_PATH "/etc/modernjvs/games/"
#define DEFAULT_IO "namco-FCA1"
#define DEFAULT_IO_PATH "/etc/modernjvs/ios/"
#define DEFAULT_ROTARY_PATH "/etc/modernjvs/rotary"
#define DEFAULT_SENSE_LINE_PIN 26
#define DEFAULT_SENSE_LINE_TYPE 1
#define DEFAULT_AUTO_CONTROLLER_DETECTION 1
#define DEFAULT_PLAYER -1
#define DEFAULT_ANALOG_DEADZONE 0.2
#define MAX_ANALOG_DEADZONE 0.5
#define DEADZONE_CLAMP_OFFSET 0.01

#define MAX_PATH_LENGTH 1024
#define MAX_LINE_LENGTH 1024
#define MAX_ROTARY_POSITIONS 16  /* Rotary encoder supports 16 positions (0-15) */

typedef struct
{
    int senseLineType;
    int senseLinePin;
    char defaultGamePath[MAX_PATH_LENGTH];
    char devicePath[MAX_PATH_LENGTH];
    int debugLevel;
    char capabilitiesPath[MAX_PATH_LENGTH];
    char secondCapabilitiesPath[MAX_PATH_LENGTH];
    int autoControllerDetection;
    double analogDeadzonePlayer1;
    double analogDeadzonePlayer2;
    double analogDeadzonePlayer3;
    double analogDeadzonePlayer4;
} JVSConfig;

typedef enum
{
    JVS_CONFIG_STATUS_ERROR = 0,
    JVS_CONFIG_STATUS_SUCCESS = 1,
    JVS_CONFIG_STATUS_FILE_NOT_FOUND,
    JVS_CONFIG_STATUS_PARSE_ERROR,
} JVSConfigStatus;

JVSConfigStatus getDefaultConfig(JVSConfig *config);
JVSConfigStatus parseConfig(char *path, JVSConfig *config);
JVSConfigStatus parseInputMapping(char *path, InputMappings *inputMappings);
JVSConfigStatus parseOutputMapping(char *path, OutputMappings *outputMappings, char *configPath, char* secondConfigPath);
JVSConfigStatus parseRotary(char *path, int rotary, char *output);
JVSConfigStatus parseIO(char *path, JVSCapabilities *capabilities);

#endif // CONFIG_H_
