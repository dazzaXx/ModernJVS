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
#define DEFAULT_SENSE_LINE_PIN 26
#define DEFAULT_SENSE_LINE_TYPE 1
#define DEFAULT_AUTO_CONTROLLER_DETECTION 1
#define DEFAULT_PLAYER -1
#define DEFAULT_ANALOG_DEADZONE 0.2
#define MAX_ANALOG_DEADZONE 0.5
#define DEADZONE_CLAMP_OFFSET 0.01
#define DEFAULT_WII_IR_SCALE 1.0
#define MIN_WII_IR_SCALE 0.1
#define MAX_WII_IR_SCALE 5.0

#define MAX_PATH_LENGTH 1024
#define MAX_LINE_LENGTH 1024

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
    double wiiIRScale;
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
/**
 * Parse a game output-mapping file.
 *
 * @param path            Filename of the game mapping (relative to DEFAULT_GAME_MAPPING_PATH).
 * @param outputMappings  Populated with the parsed button/axis mappings.
 * @param configPath      Buffer (MAX_PATH_LENGTH) that receives the IO board path when the
 *                        mapping file contains an EMULATE directive.  **The buffer is written
 *                        in-place** — on entry it holds the current default; on return it may
 *                        have been overwritten with a game-specific override.
 * @param secondConfigPath Buffer (MAX_PATH_LENGTH) for an optional second IO board path
 *                        (EMULATE_SECOND directive).  Same in-place mutation semantics.
 */
JVSConfigStatus parseOutputMapping(char *path, OutputMappings *outputMappings, char *configPath, char* secondConfigPath);
JVSConfigStatus parseIO(char *path, JVSCapabilities *capabilities);

#endif // CONFIG_H_
