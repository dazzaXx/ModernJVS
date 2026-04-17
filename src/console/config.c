#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jvs/io.h"
#include "console/debug.h"

/* Delimiter set used by getNextToken: split on spaces and tabs so that
 * config files written with tab indentation parse identically to
 * space-separated ones. */
#define TOKEN_SEPARATOR " \t"

static char *getNextToken(char *buffer, char *separator, char **saveptr)
{
    char *token = strtok_r(buffer, separator, saveptr);
    if (token == NULL)
        return NULL;

    /* Cache strlen result to avoid recalculating in loop */
    int token_len = (int)strlen(token);
    for (int i = 0; i < token_len; i++)
    {
        if ((token[i] == '\n') || (token[i] == '\r'))
        {
            token[i] = 0;
        }
    }
    return token;
}

static double clampDeadzone(double deadzone)
{
    /* Clamp deadzone to valid range [0.0, MAX_ANALOG_DEADZONE) to prevent division by zero */
    if (deadzone < 0.0)
        return 0.0;
    else if (deadzone >= MAX_ANALOG_DEADZONE)
        return MAX_ANALOG_DEADZONE - DEADZONE_CLAMP_OFFSET;
    return deadzone;
}

/**
 * Parse an integer from a config token, warning on invalid input.
 *
 * @param token   The string to parse (must not be NULL).
 * @param fallback Value returned when the token is not a valid integer.
 * @returns The parsed integer, or fallback on error.
 */
static int parseConfigInt(const char *token, int fallback)
{
    char *end;
    long val = strtol(token, &end, 10);
    /* end must advance past at least one digit and reach NUL or whitespace */
    if (end == token || (*end != '\0' && *end != '\n' && *end != '\r'))
    {
        debug(0, "Warning: Config value '%s' is not a valid integer, using default %d\n", token, fallback);
        return fallback;
    }
    return (int)val;
}

/**
 * Parse a double from a config token, warning on invalid input.
 *
 * @param token   The string to parse (must not be NULL).
 * @param fallback Value returned when the token is not a valid number.
 * @returns The parsed double, or fallback on error.
 */
static double parseConfigDouble(const char *token, double fallback)
{
    char *end;
    double val = strtod(token, &end);
    if (end == token || (*end != '\0' && *end != '\n' && *end != '\r'))
    {
        debug(0, "Warning: Config value '%s' is not a valid number, using default %g\n", token, fallback);
        return fallback;
    }
    return val;
}

/* Helper function to check if adding a new mapping would exceed the maximum limit */
static int checkMappingLimit(int currentLength, const char *mappingType)
{
    if (currentLength >= MAX_MAPPING)
    {
        debug(0, "Error: Maximum number of %s mappings (%d) exceeded\n", mappingType, MAX_MAPPING);
        return 0; /* Failed - limit exceeded */
    }
    return 1; /* Success - can add mapping */
}

JVSConfigStatus getDefaultConfig(JVSConfig *config)
{
    config->senseLineType = DEFAULT_SENSE_LINE_TYPE;
    config->senseLinePin = DEFAULT_SENSE_LINE_PIN;
    config->debugLevel = DEFAULT_DEBUG_LEVEL;
    config->autoControllerDetection = DEFAULT_AUTO_CONTROLLER_DETECTION;
    config->analogDeadzonePlayer1 = DEFAULT_ANALOG_DEADZONE;
    config->analogDeadzonePlayer2 = DEFAULT_ANALOG_DEADZONE;
    config->analogDeadzonePlayer3 = DEFAULT_ANALOG_DEADZONE;
    config->analogDeadzonePlayer4 = DEFAULT_ANALOG_DEADZONE;
    config->wiiIRScale  = DEFAULT_WII_IR_SCALE;
    strncpy(config->defaultGamePath, DEFAULT_GAME, MAX_PATH_LENGTH - 1);
    config->defaultGamePath[MAX_PATH_LENGTH - 1] = '\0';
    strncpy(config->devicePath, DEFAULT_DEVICE_PATH, MAX_PATH_LENGTH - 1);
    config->devicePath[MAX_PATH_LENGTH - 1] = '\0';
    strncpy(config->capabilitiesPath, DEFAULT_IO, MAX_PATH_LENGTH - 1);
    config->capabilitiesPath[MAX_PATH_LENGTH - 1] = '\0';
    config->secondCapabilitiesPath[0] = 0x00;
    return JVS_CONFIG_STATUS_SUCCESS;
}

/* Maximum INCLUDE nesting depth to prevent infinite recursion on self-referential files */
#define MAX_INCLUDE_DEPTH 10

/* Forward declarations for internal recursive helpers */
static JVSConfigStatus parseConfigInternal(char *path, JVSConfig *config, int depth);
static JVSConfigStatus parseInputMappingInternal(char *path, InputMappings *inputMappings, int depth);
static JVSConfigStatus parseOutputMappingInternal(char *path, OutputMappings *outputMappings, char *configPath, char *secondConfigPath, int depth);

/* Internal implementation that tracks recursion depth via a parameter */
static JVSConfigStatus parseConfigInternal(char *path, JVSConfig *config, int depth)
{
    FILE *file;
    char buffer[MAX_LINE_LENGTH];
    char *saveptr = NULL;

    if ((file = fopen(path, "r")) == NULL)
        return JVS_CONFIG_STATUS_FILE_NOT_FOUND;

    while (fgets(buffer, MAX_LINE_LENGTH, file))
    {

        /* Check for comments */
        if (buffer[0] == '#' || buffer[0] == 0 || buffer[0] == ' ' || buffer[0] == '\r' || buffer[0] == '\n')
            continue;

        char *command = getNextToken(buffer, TOKEN_SEPARATOR, &saveptr);
        if (!command || command[0] == '#' || command[0] == '\0')
            continue;

        /* Recursively parse an included config file, inheriting all settings parsed so far */
        if (strcmp(command, "INCLUDE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token && depth < MAX_INCLUDE_DEPTH)
                parseConfigInternal(token, config, depth + 1);
            else if (token)
                debug(0, "Error: Maximum INCLUDE depth (%d) exceeded, skipping '%s'\n", MAX_INCLUDE_DEPTH, token);
        }
        else if (strcmp(command, "SENSE_LINE_TYPE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->senseLineType = parseConfigInt(token, config->senseLineType);
        }
        else if (strcmp(command, "EMULATE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                strncpy(config->capabilitiesPath, token, MAX_PATH_LENGTH - 1);
                config->capabilitiesPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "EMULATE_SECOND") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                strncpy(config->secondCapabilitiesPath, token, MAX_PATH_LENGTH - 1);
                config->secondCapabilitiesPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "SENSE_LINE_PIN") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->senseLinePin = parseConfigInt(token, config->senseLinePin);
        }
        else if (strcmp(command, "DEFAULT_GAME") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                strncpy(config->defaultGamePath, token, MAX_PATH_LENGTH - 1);
                config->defaultGamePath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "DEBUG_MODE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->debugLevel = parseConfigInt(token, config->debugLevel);
        }
        else if (strcmp(command, "DEVICE_PATH") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                strncpy(config->devicePath, token, MAX_PATH_LENGTH - 1);
                config->devicePath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "AUTO_CONTROLLER_DETECTION") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->autoControllerDetection = parseConfigInt(token, config->autoControllerDetection);
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_1") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->analogDeadzonePlayer1 = clampDeadzone(parseConfigDouble(token, config->analogDeadzonePlayer1));
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_2") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->analogDeadzonePlayer2 = clampDeadzone(parseConfigDouble(token, config->analogDeadzonePlayer2));
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_3") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->analogDeadzonePlayer3 = clampDeadzone(parseConfigDouble(token, config->analogDeadzonePlayer3));
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_4") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                config->analogDeadzonePlayer4 = clampDeadzone(parseConfigDouble(token, config->analogDeadzonePlayer4));
        }
        else if (strcmp(command, "WII_IR_SCALE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                double val = parseConfigDouble(token, config->wiiIRScale);
                if (val < MIN_WII_IR_SCALE)
                    val = MIN_WII_IR_SCALE;
                else if (val > MAX_WII_IR_SCALE)
                    val = MAX_WII_IR_SCALE;
                config->wiiIRScale = val;
            }
        }
        else
            debug(0, "Error: Unknown configuration command %s\n", command);
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseConfig(char *path, JVSConfig *config)
{
    return parseConfigInternal(path, config, 0);
}

/* Internal implementation that tracks recursion depth via a parameter */
static JVSConfigStatus parseInputMappingInternal(char *path, InputMappings *inputMappings, int depth)
{
    FILE *file;
    char buffer[MAX_LINE_LENGTH];
    char *saveptr = NULL;

    char gamePath[MAX_PATH_LENGTH];
    int ret = snprintf(gamePath, sizeof(gamePath), "%s%s", DEFAULT_DEVICE_MAPPING_PATH, path);
    if (ret < 0 || ret >= (int)sizeof(gamePath))
        return JVS_CONFIG_STATUS_ERROR;

    if ((file = fopen(gamePath, "r")) == NULL)
        return JVS_CONFIG_STATUS_FILE_NOT_FOUND;

    inputMappings->player = DEFAULT_PLAYER;
    inputMappings->length = 0;

    while (fgets(buffer, MAX_LINE_LENGTH, file))
    {

        /* Check for comments */
        if (buffer[0] == '#' || buffer[0] == 0 || buffer[0] == ' ' || buffer[0] == '\r' || buffer[0] == '\n')
            continue;

        char *command = getNextToken(buffer, TOKEN_SEPARATOR, &saveptr);
        if (!command || command[0] == '#' || command[0] == '\0')
            continue;

        if (strcmp(command, "INCLUDE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token && depth < MAX_INCLUDE_DEPTH)
            {
                InputMappings tempInputMappings = {0};
                JVSConfigStatus status = parseInputMappingInternal(token, &tempInputMappings, depth + 1);
                if (status == JVS_CONFIG_STATUS_SUCCESS)
                {
                    /* Merge: append included mappings to any already parsed in
                     * this file rather than replacing them.  Mappings defined
                     * before INCLUDE are preserved; the included file's player
                     * number is only inherited when the current file hasn't set
                     * one yet. */
                    int spaceLeft = MAX_MAPPING - inputMappings->length;
                    int toAdd = tempInputMappings.length < spaceLeft ? tempInputMappings.length : spaceLeft;
                    if (toAdd < tempInputMappings.length)
                        debug(0, "Warning: Mapping array full, %d input entr%s from '%s' dropped\n",
                              tempInputMappings.length - toAdd,
                              (tempInputMappings.length - toAdd == 1) ? "y" : "ies",
                              token);
                    memcpy(&inputMappings->mappings[inputMappings->length],
                           tempInputMappings.mappings,
                           toAdd * sizeof(InputMapping));
                    inputMappings->length += toAdd;
                    if (inputMappings->player == DEFAULT_PLAYER &&
                        tempInputMappings.player != DEFAULT_PLAYER)
                        inputMappings->player = tempInputMappings.player;
                }
            }
            else if (token)
            {
                debug(0, "Error: Maximum INCLUDE depth (%d) exceeded, skipping '%s'\n", MAX_INCLUDE_DEPTH, token);
            }
        }
        else if (strcmp(command, "PLAYER") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                int player = parseConfigInt(token, inputMappings->player);
                inputMappings->player = player;
            }
        }
        else if (command[0] == 'K' || command[0] == 'B' || command[0] == 'C')
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                if (!checkMappingLimit(inputMappings->length, "input"))
                {
                    fclose(file);
                    return JVS_CONFIG_STATUS_ERROR;
                }
                
                int code = evDevFromString(command);
                ControllerInput input = controllerInputFromString(token);

                InputMapping mapping = {
                    .type = SWITCH,
                    .code = code,
                    .input = input};

                inputMappings->mappings[inputMappings->length] = mapping;
                inputMappings->length++;
            }
        }
        else if (command[0] == 'A')
        {
            char *firstArgument = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!firstArgument)
                continue;
            InputMapping mapping;

            if (strlen(firstArgument) > 11 && firstArgument[11] == 'B')
            {
                // This suggests we are doing it as a hat!
                char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
                if (!token)
                    continue;
                InputMapping hatMapping = {
                    .type = HAT,
                    .code = evDevFromString(command),
                    .input = controllerInputFromString(firstArgument),
                    .inputSecondary = controllerInputFromString(token),
                };
                mapping = hatMapping;
            }
            else
            {
                // Normal Analogue Mapping
                InputMapping analogueMapping = {
                    .type = ANALOGUE,
                    .code = evDevFromString(command),
                    .input = controllerInputFromString(firstArgument),
                    .reverse = 0,
                    .multiplier = 1,
                };

                /* Check to see if we should reverse */
                char *extra = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
                while (extra != NULL)
                {
                    if (strcmp(extra, "REVERSE") == 0)
                    {
                        analogueMapping.reverse = 1;
                    }
                    else if (strcmp(extra, "SENSITIVITY") == 0)
                    {
                        char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
                        if (token)
                            analogueMapping.multiplier = atof(token);
                    }
                    extra = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
                }

                mapping = analogueMapping;
            }

            if (!checkMappingLimit(inputMappings->length, "input"))
            {
                fclose(file);
                return JVS_CONFIG_STATUS_ERROR;
            }
            
            inputMappings->mappings[inputMappings->length] = mapping;
            inputMappings->length++;
        }
        else if (command[0] == 'R')
        {
            char *firstArgument = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!firstArgument)
                continue;
            InputMapping mapping;

            // Normal Relative Mapping
            InputMapping analogueMapping = {
                .type = ROTARY,
                .code = evDevFromString(command),
                .input = controllerInputFromString(firstArgument),
                .reverse = 0,
                .multiplier = 1,
            };

            /* Check to see if we should reverse */
            char *extra = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            while (extra != NULL)
            {
                if (strcmp(extra, "REVERSE") == 0)
                {
                    analogueMapping.reverse = 1;
                }
                else if (strcmp(extra, "SENSITIVITY") == 0)
                {
                    char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
                    if (token)
                        analogueMapping.multiplier = atof(token);
                }
                extra = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            }

            mapping = analogueMapping;

            if (!checkMappingLimit(inputMappings->length, "input"))
            {
                fclose(file);
                return JVS_CONFIG_STATUS_ERROR;
            }
            
            inputMappings->mappings[inputMappings->length] = mapping;
            inputMappings->length++;
        }
        else if (command[0] == 'M')
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                if (!checkMappingLimit(inputMappings->length, "input"))
                {
                    fclose(file);
                    return JVS_CONFIG_STATUS_ERROR;
                }
                
                int code = evDevFromString(command);
                ControllerInput input = controllerInputFromString(token);

                InputMapping mapping = {
                    .type = CARD,
                    .code = code,
                    .input = input};

                inputMappings->mappings[inputMappings->length] = mapping;
                inputMappings->length++;
            }
        }
        else
        {
            debug(0, "Error: Unknown mapping command %s\n", command);
        }
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseInputMapping(char *path, InputMappings *inputMappings)
{
    return parseInputMappingInternal(path, inputMappings, 0);
}

/* Internal implementation that tracks recursion depth via a parameter */
static JVSConfigStatus parseOutputMappingInternal(char *path, OutputMappings *outputMappings, char *configPath, char *secondConfigPath, int depth)
{
    FILE *file;
    char buffer[MAX_LINE_LENGTH];
    char *saveptr = NULL;

    char gamePath[MAX_PATH_LENGTH];
    int ret = snprintf(gamePath, sizeof(gamePath), "%s%s", DEFAULT_GAME_MAPPING_PATH, path);
    if (ret < 0 || ret >= (int)sizeof(gamePath))
        return JVS_CONFIG_STATUS_ERROR;

    if ((file = fopen(gamePath, "r")) == NULL)
        return JVS_CONFIG_STATUS_FILE_NOT_FOUND;

    outputMappings->length = 0;

    while (fgets(buffer, MAX_LINE_LENGTH, file))
    {

        /* Check for comments */
        if (buffer[0] == '#' || buffer[0] == 0 || buffer[0] == ' ' || buffer[0] == '\r' || buffer[0] == '\n')
            continue;

        char *command = getNextToken(buffer, TOKEN_SEPARATOR, &saveptr);
        if (!command || command[0] == '#' || command[0] == '\0')
            continue;
        int analogueToDigital = 0;
        if (strcmp(command, "DIGITAL") == 0)
        {
            analogueToDigital = 1;
            // DIGITAL is the first token for these, coming before the
            // axis name; if we found DIGITAL, we need to read the next
            // token for the actual axis.
            command = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!command)
                continue;
        }

        /* Move the next mapping onto the secondary IO */
        int secondaryIO = 0;
        if (strcmp(command, "SECONDARY") == 0)
        {
            secondaryIO = 1;
            command = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!command)
                continue;
        }

        if (strcmp(command, "INCLUDE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token && depth < MAX_INCLUDE_DEPTH)
            {
                OutputMappings tempOutputMappings = {0};
                JVSConfigStatus status = parseOutputMappingInternal(token, &tempOutputMappings, configPath, secondConfigPath, depth + 1);
                if (status == JVS_CONFIG_STATUS_SUCCESS)
                {
                    /* Merge: append included mappings to any already parsed in
                     * this file rather than replacing them. */
                    int spaceLeft = MAX_MAPPING - outputMappings->length;
                    int toAdd = tempOutputMappings.length < spaceLeft ? tempOutputMappings.length : spaceLeft;
                    if (toAdd < tempOutputMappings.length)
                        debug(0, "Warning: Mapping array full, %d output entr%s from '%s' dropped\n",
                              tempOutputMappings.length - toAdd,
                              (tempOutputMappings.length - toAdd == 1) ? "y" : "ies",
                              token);
                    memcpy(&outputMappings->mappings[outputMappings->length],
                           tempOutputMappings.mappings,
                           toAdd * sizeof(OutputMapping));
                    outputMappings->length += toAdd;
                }
            }
            else if (token)
            {
                debug(0, "Error: Maximum INCLUDE depth (%d) exceeded, skipping '%s'\n", MAX_INCLUDE_DEPTH, token);
            }
        }
        else if (strcmp(command, "EMULATE") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                strncpy(configPath, token, MAX_PATH_LENGTH - 1);
                configPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "EMULATE_SECOND") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
            {
                strncpy(secondConfigPath, token, MAX_PATH_LENGTH - 1);
                secondConfigPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if ((strlen(command) > 11 && command[11] == 'B') || analogueToDigital)
        {
            char *token1 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            char *token2 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            char *token3 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!token1 || !token2 || !token3)
                continue;
            ControllerPlayer controllerPlayer = controllerPlayerFromString(token1);
            OutputMapping mapping = {
                .type = SWITCH,
                .input = controllerInputFromString(command),
                .controllerPlayer = controllerPlayer,
                .output = jvsInputFromString(token2),
                .outputSecondary = NONE,
                .jvsPlayer = jvsPlayerFromString(token3),
                .secondaryIO = secondaryIO};

            /* Check to see if we have a secondary output */
            char *secondaryOutput = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (secondaryOutput != NULL)
            {
                mapping.outputSecondary = jvsInputFromString(secondaryOutput);
            }

            if (!checkMappingLimit(outputMappings->length, "output"))
            {
                fclose(file);
                return JVS_CONFIG_STATUS_ERROR;
            }
            
            outputMappings->mappings[outputMappings->length] = mapping;
            outputMappings->length++;
        }
        else if (strlen(command) > 11 && command[11] == 'A')
        {
            char *token1 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            char *token2 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!token1 || !token2)
                continue;
            OutputMapping mapping = {
                .type = ANALOGUE,
                .input = controllerInputFromString(command),
                .controllerPlayer = controllerPlayerFromString(token1),
                .output = jvsInputFromString(token2),
                .secondaryIO = secondaryIO};

            /* Check to see if we should reverse */
            char *reverse = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (reverse != NULL && strcmp(reverse, "REVERSE") == 0)
            {
                mapping.reverse = 1;
            }

            if (!checkMappingLimit(outputMappings->length, "output"))
            {
                fclose(file);
                return JVS_CONFIG_STATUS_ERROR;
            }
            
            outputMappings->mappings[outputMappings->length] = mapping;
            outputMappings->length++;
        }
        else if (strlen(command) > 11 && command[11] == 'R')
        {
            char *token1 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            char *token2 = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (!token1 || !token2)
                continue;
            OutputMapping mapping = {
                .type = ROTARY,
                .input = controllerInputFromString(command),
                .controllerPlayer = controllerPlayerFromString(token1),
                .output = jvsInputFromString(token2),
                .secondaryIO = secondaryIO};

            /* Check to see if we should reverse */
            char *reverse = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (reverse != NULL && strcmp(reverse, "REVERSE") == 0)
            {
                mapping.reverse = 1;
            }

            if (!checkMappingLimit(outputMappings->length, "output"))
            {
                fclose(file);
                return JVS_CONFIG_STATUS_ERROR;
            }
            
            outputMappings->mappings[outputMappings->length] = mapping;
            outputMappings->length++;
        }
        else
        {
            debug(0, "Error: Unknown mapping command %s\n", command);
        }
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseOutputMapping(char *path, OutputMappings *outputMappings, char *configPath, char *secondConfigPath)
{
    return parseOutputMappingInternal(path, outputMappings, configPath, secondConfigPath, 0);
}

JVSConfigStatus parseIO(char *path, JVSCapabilities *capabilities)
{
    FILE *file;
    char buffer[MAX_LINE_LENGTH];
    char *saveptr = NULL;

    char ioPath[MAX_PATH_LENGTH];
    int ret = snprintf(ioPath, sizeof(ioPath), "%s%s", DEFAULT_IO_PATH, path);
    if (ret < 0 || ret >= (int)sizeof(ioPath))
        return JVS_CONFIG_STATUS_ERROR;

    if ((file = fopen(ioPath, "r")) == NULL)
        return JVS_CONFIG_STATUS_FILE_NOT_FOUND;

    while (fgets(buffer, MAX_LINE_LENGTH, file))
    {

        /* Check for comments */
        if (buffer[0] == '#' || buffer[0] == 0 || buffer[0] == ' ' || buffer[0] == '\r' || buffer[0] == '\n')
            continue;

        char *command = getNextToken(buffer, TOKEN_SEPARATOR, &saveptr);
        if (!command || command[0] == '#' || command[0] == '\0')
            continue;

        if (strcmp(command, "DISPLAY_NAME") == 0)
        {
            char *token = getNextToken(NULL, "\n", &saveptr);
            if (token)
            {
                strncpy(capabilities->displayName, token, MAX_JVS_NAME_SIZE - 1);
                capabilities->displayName[MAX_JVS_NAME_SIZE - 1] = '\0';
            }
        }
        else if (strcmp(command, "NAME") == 0)
        {
            char *token = getNextToken(NULL, "\n", &saveptr);
            if (token)
            {
                strncpy(capabilities->name, token, MAX_JVS_NAME_SIZE - 1);
                capabilities->name[MAX_JVS_NAME_SIZE - 1] = '\0';
            }
        }
        else if (strcmp(command, "COMMAND_VERSION") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->commandVersion = (unsigned char)parseConfigInt(token, capabilities->commandVersion);
        }
        else if (strcmp(command, "JVS_VERSION") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->jvsVersion = (unsigned char)parseConfigInt(token, capabilities->jvsVersion);
        }
        else if (strcmp(command, "COMMS_VERSION") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->commsVersion = (unsigned char)parseConfigInt(token, capabilities->commsVersion);
        }

        else if (strcmp(command, "PLAYERS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->players = (unsigned char)parseConfigInt(token, capabilities->players);
        }
        else if (strcmp(command, "SWITCHES") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->switches = (unsigned char)parseConfigInt(token, capabilities->switches);
        }
        else if (strcmp(command, "COINS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->coins = (unsigned char)parseConfigInt(token, capabilities->coins);
        }
        else if (strcmp(command, "ANALOGUE_IN_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->analogueInChannels = (unsigned char)parseConfigInt(token, capabilities->analogueInChannels);
        }
        else if (strcmp(command, "ANALOGUE_IN_BITS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->analogueInBits = (unsigned char)parseConfigInt(token, capabilities->analogueInBits);
        }
        else if (strcmp(command, "ROTARY_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->rotaryChannels = (unsigned char)parseConfigInt(token, capabilities->rotaryChannels);
        }
        else if (strcmp(command, "KEYPAD") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->keypad = (unsigned char)parseConfigInt(token, capabilities->keypad);
        }
        else if (strcmp(command, "GUN_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->gunChannels = (unsigned char)parseConfigInt(token, capabilities->gunChannels);
        }
        else if (strcmp(command, "GUN_X_BITS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->gunXBits = (unsigned char)parseConfigInt(token, capabilities->gunXBits);
        }
        else if (strcmp(command, "GUN_Y_BITS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->gunYBits = (unsigned char)parseConfigInt(token, capabilities->gunYBits);
        }
        else if (strcmp(command, "GENERAL_PURPOSE_INPUTS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->generalPurposeInputs = (unsigned char)parseConfigInt(token, capabilities->generalPurposeInputs);
        }
        else if (strcmp(command, "CARD") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->card = (unsigned char)parseConfigInt(token, capabilities->card);
        }
        else if (strcmp(command, "HOPPER") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->hopper = (unsigned char)parseConfigInt(token, capabilities->hopper);
        }
        else if (strcmp(command, "GENERAL_PURPOSE_OUTPUTS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->generalPurposeOutputs = (unsigned char)parseConfigInt(token, capabilities->generalPurposeOutputs);
        }
        else if (strcmp(command, "ANALOGUE_OUT_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->analogueOutChannels = (unsigned char)parseConfigInt(token, capabilities->analogueOutChannels);
        }
        else if (strcmp(command, "DISPLAY_OUT_ROWS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->displayOutRows = (unsigned char)parseConfigInt(token, capabilities->displayOutRows);
        }
        else if (strcmp(command, "DISPLAY_OUT_COLUMNS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->displayOutColumns = (unsigned char)parseConfigInt(token, capabilities->displayOutColumns);
        }
        else if (strcmp(command, "DISPLAY_OUT_ENCODINGS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->displayOutEncodings = (unsigned char)parseConfigInt(token, capabilities->displayOutEncodings);
        }
        else if (strcmp(command, "BACKUP") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->backup = (unsigned char)parseConfigInt(token, capabilities->backup);
        }
        else if (strcmp(command, "RIGHT_ALIGN_BITS") == 0)
        {
            char *token = getNextToken(NULL, TOKEN_SEPARATOR, &saveptr);
            if (token)
                capabilities->rightAlignBits = (unsigned char)parseConfigInt(token, capabilities->rightAlignBits);
        }

        else
            debug(0, "Error: Unknown IO configuration command %s\n", command);
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}
