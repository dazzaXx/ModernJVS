#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jvs/io.h"

static char *getNextToken(char *buffer, char *separator, char **saveptr)
{
    char *token = strtok_r(buffer, separator, saveptr);
    if (token == NULL)
        return NULL;

    for (int i = 0; i < (int)strlen(token); i++)
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
    strncpy(config->defaultGamePath, DEFAULT_GAME, MAX_PATH_LENGTH - 1);
    config->defaultGamePath[MAX_PATH_LENGTH - 1] = '\0';
    strncpy(config->devicePath, DEFAULT_DEVICE_PATH, MAX_PATH_LENGTH - 1);
    config->devicePath[MAX_PATH_LENGTH - 1] = '\0';
    strncpy(config->capabilitiesPath, DEFAULT_IO, MAX_PATH_LENGTH - 1);
    config->capabilitiesPath[MAX_PATH_LENGTH - 1] = '\0';
    config->secondCapabilitiesPath[0] = 0x00;
    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseConfig(char *path, JVSConfig *config)
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

        char *command = getNextToken(buffer, " ", &saveptr);
        if (!command)
            continue;

        /* This will get overwritten! Need to do defaults somewhere else */
        if (strcmp(command, "INCLUDE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                parseConfig(token, config);
        }
        else if (strcmp(command, "SENSE_LINE_TYPE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->senseLineType = atoi(token);
        }
        else if (strcmp(command, "EMULATE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                strncpy(config->capabilitiesPath, token, MAX_PATH_LENGTH - 1);
                config->capabilitiesPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "EMULATE_SECOND") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                strncpy(config->secondCapabilitiesPath, token, MAX_PATH_LENGTH - 1);
                config->secondCapabilitiesPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "SENSE_LINE_PIN") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->senseLinePin = atoi(token);
        }
        else if (strcmp(command, "DEFAULT_GAME") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                strncpy(config->defaultGamePath, token, MAX_PATH_LENGTH - 1);
                config->defaultGamePath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "DEBUG_MODE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->debugLevel = atoi(token);
        }
        else if (strcmp(command, "DEVICE_PATH") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                strncpy(config->devicePath, token, MAX_PATH_LENGTH - 1);
                config->devicePath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "AUTO_CONTROLLER_DETECTION") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->autoControllerDetection = atoi(token);
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_1") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->analogDeadzonePlayer1 = clampDeadzone(atof(token));
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_2") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->analogDeadzonePlayer2 = clampDeadzone(atof(token));
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_3") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->analogDeadzonePlayer3 = clampDeadzone(atof(token));
        }
        else if (strcmp(command, "ANALOG_DEADZONE_PLAYER_4") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                config->analogDeadzonePlayer4 = clampDeadzone(atof(token));
        }
        else
            printf("Error: Unknown configuration command %s\n", command);
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseInputMapping(char *path, InputMappings *inputMappings)
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

    while (fgets(buffer, MAX_LINE_LENGTH, file))
    {

        /* Check for comments */
        if (buffer[0] == '#' || buffer[0] == 0 || buffer[0] == ' ' || buffer[0] == '\r' || buffer[0] == '\n')
            continue;

        char *command = getNextToken(buffer, " ", &saveptr);
        if (!command)
            continue;

        if (strcmp(command, "INCLUDE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                InputMappings tempInputMappings;
                JVSConfigStatus status = parseInputMapping(token, &tempInputMappings);
                if (status == JVS_CONFIG_STATUS_SUCCESS)
                    memcpy(inputMappings, &tempInputMappings, sizeof(InputMappings));
            }
        }
        else if (strcmp(command, "PLAYER") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                int player = atoi(token);
                inputMappings->player = player;
            }
        }
        else if (command[0] == 'K' || command[0] == 'B' || command[0] == 'C')
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
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
            char *firstArgument = getNextToken(NULL, " ", &saveptr);
            if (!firstArgument)
                continue;
            InputMapping mapping;

            if (strlen(firstArgument) > 11 && firstArgument[11] == 'B')
            {
                // This suggests we are doing it as a hat!
                char *token = getNextToken(NULL, " ", &saveptr);
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
                char *extra = getNextToken(NULL, " ", &saveptr);
                while (extra != NULL)
                {
                    if (strcmp(extra, "REVERSE") == 0)
                    {
                        analogueMapping.reverse = 1;
                    }
                    else if (strcmp(extra, "SENSITIVITY") == 0)
                    {
                        char *token = getNextToken(NULL, " ", &saveptr);
                        if (token)
                            analogueMapping.multiplier = atof(token);
                    }
                    extra = getNextToken(NULL, " ", &saveptr);
                }

                mapping = analogueMapping;
            }

            inputMappings->mappings[inputMappings->length] = mapping;
            inputMappings->length++;
        }
        else if (command[0] == 'R')
        {
            char *firstArgument = getNextToken(NULL, " ", &saveptr);
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
            char *extra = getNextToken(NULL, " ", &saveptr);
            while (extra != NULL)
            {
                if (strcmp(extra, "REVERSE") == 0)
                {
                    analogueMapping.reverse = 1;
                }
                else if (strcmp(extra, "SENSITIVITY") == 0)
                {
                    char *token = getNextToken(NULL, " ", &saveptr);
                    if (token)
                        analogueMapping.multiplier = atof(token);
                }
                extra = getNextToken(NULL, " ", &saveptr);
            }

            mapping = analogueMapping;

            inputMappings->mappings[inputMappings->length] = mapping;
            inputMappings->length++;
        }
        else if (command[0] == 'M')
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
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
            printf("Error: Unknown mapping command %s\n", command);
        }
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseOutputMapping(char *path, OutputMappings *outputMappings, char *configPath, char *secondConfigPath)
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

    while (fgets(buffer, MAX_LINE_LENGTH, file))
    {

        /* Check for comments */
        if (buffer[0] == '#' || buffer[0] == 0 || buffer[0] == ' ' || buffer[0] == '\r' || buffer[0] == '\n')
            continue;

        char *command = getNextToken(buffer, " ", &saveptr);
        if (!command)
            continue;
        int analogueToDigital = 0;
        if (strcmp(command, "DIGITAL") == 0)
        {
            analogueToDigital = 1;
            // DIGITAL is the first token for these, coming before the
            // axis name; if we found DIGITAL, we need to read the next
            // token for the actual axis.
            command = getNextToken(NULL, " ", &saveptr);
            if (!command)
                continue;
        }

        /* Move the next mapping onto the secondary IO */
        int secondaryIO = 0;
        if (strcmp(command, "SECONDARY") == 0)
        {
            secondaryIO = 1;
            command = getNextToken(NULL, " ", &saveptr);
            if (!command)
                continue;
        }

        if (strcmp(command, "INCLUDE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                OutputMappings tempOutputMappings;
                JVSConfigStatus status = parseOutputMapping(token, &tempOutputMappings, configPath, secondConfigPath);
                if (status == JVS_CONFIG_STATUS_SUCCESS)
                    memcpy(outputMappings, &tempOutputMappings, sizeof(OutputMappings));
            }
        }
        else if (strcmp(command, "EMULATE") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                strncpy(configPath, token, MAX_PATH_LENGTH - 1);
                configPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (strcmp(command, "EMULATE_SECOND") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
            {
                strncpy(secondConfigPath, token, MAX_PATH_LENGTH - 1);
                secondConfigPath[MAX_PATH_LENGTH - 1] = '\0';
            }
        }
        else if (command[11] == 'B' || analogueToDigital)
        {
            char *token1 = getNextToken(NULL, " ", &saveptr);
            char *token2 = getNextToken(NULL, " ", &saveptr);
            char *token3 = getNextToken(NULL, " ", &saveptr);
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
            char *secondaryOutput = getNextToken(NULL, " ", &saveptr);
            if (secondaryOutput != NULL)
            {
                mapping.outputSecondary = jvsInputFromString(secondaryOutput);
            }

            outputMappings->mappings[outputMappings->length] = mapping;
            outputMappings->length++;
        }
        else if (command[11] == 'A')
        {
            char *token1 = getNextToken(NULL, " ", &saveptr);
            char *token2 = getNextToken(NULL, " ", &saveptr);
            if (!token1 || !token2)
                continue;
            OutputMapping mapping = {
                .type = ANALOGUE,
                .input = controllerInputFromString(command),
                .controllerPlayer = controllerPlayerFromString(token1),
                .output = jvsInputFromString(token2),
                .secondaryIO = secondaryIO};

            /* Check to see if we should reverse */
            char *reverse = getNextToken(NULL, " ", &saveptr);
            if (reverse != NULL && strcmp(reverse, "REVERSE") == 0)
            {
                mapping.reverse = 1;
            }

            outputMappings->mappings[outputMappings->length] = mapping;
            outputMappings->length++;
        }
        else if (command[11] == 'R')
        {
            char *token1 = getNextToken(NULL, " ", &saveptr);
            char *token2 = getNextToken(NULL, " ", &saveptr);
            if (!token1 || !token2)
                continue;
            OutputMapping mapping = {
                .type = ROTARY,
                .input = controllerInputFromString(command),
                .controllerPlayer = controllerPlayerFromString(token1),
                .output = jvsInputFromString(token2),
                .secondaryIO = secondaryIO};

            /* Check to see if we should reverse */
            char *reverse = getNextToken(NULL, " ", &saveptr);
            if (reverse != NULL && strcmp(reverse, "REVERSE") == 0)
            {
                mapping.reverse = 1;
            }

            outputMappings->mappings[outputMappings->length] = mapping;
            outputMappings->length++;
        }
        else
        {
            printf("Error: Unknown mapping command %s\n", command);
        }
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}

JVSConfigStatus parseRotary(char *path, int rotary, char *output)
{
    FILE *file;

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    if ((file = fopen(path, "r")) == NULL)
        return JVS_CONFIG_STATUS_FILE_NOT_FOUND;

    int counter = 0;
    char rotaryGames[16][MAX_LINE_LENGTH];

    for (int i = 0; i < 16; i++)
    {
        strncpy(rotaryGames[i], "generic", MAX_LINE_LENGTH - 1);
        rotaryGames[i][MAX_LINE_LENGTH - 1] = '\0';
    }

    while ((read = getline(&line, &len, file)) != -1 && counter < 16)
    {
        strncpy(rotaryGames[counter], line, MAX_LINE_LENGTH - 1);
        rotaryGames[counter][MAX_LINE_LENGTH - 1] = '\0';
        for (size_t i = 0; i < strlen(line); i++)
        {
            if (rotaryGames[counter][i] == '\n' || rotaryGames[counter][i] == '\r')
            {
                rotaryGames[counter][i] = 0;
            }
        }
        counter++;

        if (line)
        {
            free(line);
            line = NULL;
            len = 0;
        }
    }

    fclose(file);

    strncpy(output, rotaryGames[rotary], MAX_PATH_LENGTH - 1);
    output[MAX_PATH_LENGTH - 1] = '\0';

    return JVS_CONFIG_STATUS_SUCCESS;
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

        char *command = getNextToken(buffer, " ", &saveptr);
        if (!command)
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
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->commandVersion = atoi(token);
        }
        else if (strcmp(command, "JVS_VERSION") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->jvsVersion = atoi(token);
        }
        else if (strcmp(command, "COMMS_VERSION") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->commsVersion = atoi(token);
        }

        else if (strcmp(command, "PLAYERS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->players = atoi(token);
        }
        else if (strcmp(command, "SWITCHES") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->switches = atoi(token);
        }
        else if (strcmp(command, "COINS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->coins = atoi(token);
        }
        else if (strcmp(command, "ANALOGUE_IN_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->analogueInChannels = atoi(token);
        }
        else if (strcmp(command, "ANALOGUE_IN_BITS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->analogueInBits = atoi(token);
        }
        else if (strcmp(command, "ROTARY_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->rotaryChannels = atoi(token);
        }
        else if (strcmp(command, "KEYPAD") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->keypad = atoi(token);
        }
        else if (strcmp(command, "GUN_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->gunChannels = atoi(token);
        }
        else if (strcmp(command, "GUN_X_BITS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->gunXBits = atoi(token);
        }
        else if (strcmp(command, "GUN_Y_BITS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->gunYBits = atoi(token);
        }
        else if (strcmp(command, "GENERAL_PURPOSE_INPUTS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->generalPurposeInputs = atoi(token);
        }
        else if (strcmp(command, "CARD") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->card = atoi(token);
        }
        else if (strcmp(command, "HOPPER") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->hopper = atoi(token);
        }
        else if (strcmp(command, "GENERAL_PURPOSE_OUTPUTS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->generalPurposeOutputs = atoi(token);
        }
        else if (strcmp(command, "ANALOGUE_OUT_CHANNELS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->analogueOutChannels = atoi(token);
        }
        else if (strcmp(command, "DISPLAY_OUT_ROWS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->displayOutRows = atoi(token);
        }
        else if (strcmp(command, "DISPLAY_OUT_COLUMNS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->displayOutColumns = atoi(token);
        }
        else if (strcmp(command, "DISPLAY_OUT_ENCODINGS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->displayOutEncodings = atoi(token);
        }
        else if (strcmp(command, "BACKUP") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->backup = atoi(token);
        }
        else if (strcmp(command, "RIGHT_ALIGN_BITS") == 0)
        {
            char *token = getNextToken(NULL, " ", &saveptr);
            if (token)
                capabilities->rightAlignBits = atoi(token);
        }

        else
            printf("Error: Unknown IO configuration command %s\n", command);
    }

    fclose(file);

    return JVS_CONFIG_STATUS_SUCCESS;
}
