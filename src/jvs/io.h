#ifndef IO_H_
#define IO_H_

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define JVS_MAX_STATE_SIZE 100
#define MAX_JVS_NAME_SIZE 2048

typedef enum
{
    BUTTON_TEST = 1 << 7, // System Buttons
    BUTTON_TILT_1 = 1 << 6,
    BUTTON_TILT_2 = 1 << 5,
    BUTTON_TILT_3 = 1 << 4,
    BUTTON_TILT_4 = 1 << 3,
    BUTTON_TILT_5 = 1 << 2,
    BUTTON_TILT_6 = 1 << 1,
    BUTTON_TILT_7 = 1 << 0,
    BUTTON_START = 1 << 15, // Player Buttons
    BUTTON_SERVICE = 1 << 14,
    BUTTON_UP = 1 << 13,
    BUTTON_DOWN = 1 << 12,
    BUTTON_LEFT = 1 << 11,
    BUTTON_RIGHT = 1 << 10,
    BUTTON_1 = 1 << 9,
    BUTTON_2 = 1 << 8,
    BUTTON_3 = 1 << 7,
    BUTTON_4 = 1 << 6,
    BUTTON_5 = 1 << 5,
    BUTTON_6 = 1 << 4,
    BUTTON_7 = 1 << 3,
    BUTTON_8 = 1 << 2,
    BUTTON_9 = 1 << 1,
    BUTTON_10 = 1 << 0,
    ANALOGUE_1 = 0, // Analogue Inputs
    ANALOGUE_2 = 1,
    ANALOGUE_3 = 2,
    ANALOGUE_4 = 3,
    ANALOGUE_5 = 4,
    ANALOGUE_6 = 5,
    ANALOGUE_7 = 6,
    ANALOGUE_8 = 7,
    ANALOGUE_9 = 8,
    ANALOGUE_10 = 9,
    ROTARY_1 = 0, // Rotary Inputs
    ROTARY_2 = 1,
    ROTARY_3 = 2,
    ROTARY_4 = 3,
    ROTARY_5 = 4,
    ROTARY_6 = 5,
    ROTARY_7 = 6,
    ROTARY_8 = 7,
    ROTARY_9 = 8,
    ROTARY_10 = 9,

    /* Things that aren't actually doable */
    COIN = 98,
    NONE = 99,
} JVSInput;


typedef enum
{
    SYSTEM = 0,
    PLAYER_1 = 1,
    PLAYER_2 = 2,
    PLAYER_3 = 3,
    PLAYER_4 = 4,
} JVSPlayer;


typedef struct
{
    int coinCount[JVS_MAX_STATE_SIZE];
    int inputSwitch[JVS_MAX_STATE_SIZE];
    int analogueChannel[JVS_MAX_STATE_SIZE];
    int gunChannel[JVS_MAX_STATE_SIZE];
    int rotaryChannel[JVS_MAX_STATE_SIZE];
} JVSState;

typedef struct
{
    char name[MAX_JVS_NAME_SIZE];
    unsigned char commandVersion;
    unsigned char jvsVersion;
    unsigned char commsVersion;
    unsigned char players;
    unsigned char switches;
    unsigned char coins;
    unsigned char analogueInChannels;
    unsigned char analogueInBits;
    unsigned char rotaryChannels;
    unsigned char keypad;
    unsigned char gunChannels;
    unsigned char gunXBits;
    unsigned char gunYBits;
    unsigned char generalPurposeInputs;
    unsigned char card;
    unsigned char hopper;
    unsigned char generalPurposeOutputs;
    unsigned char analogueOutChannels;
    unsigned char displayOutRows;
    unsigned char displayOutColumns;
    unsigned char displayOutEncodings;
    unsigned char backup;
    unsigned char rightAlignBits;
    char displayName[MAX_JVS_NAME_SIZE];
} JVSCapabilities;

typedef struct JVSIO
{
    int deviceID;
    /* Set to 1 by initIO after the first pthread_mutex_init call so that
     * subsequent initIO calls can safely call pthread_mutex_destroy first.
     * Checked with == 1 (not just != 0) so that a struct poisoned with
     * memset(0xFF) skips the destroy, which is the correct safe behaviour. */
    int mutexInitialized;
    int analogueRestBits;
    int gunXRestBits;
    int gunYRestBits;
    int analogueMax;
    int gunXMax;
    int gunYMax;
    JVSState state;
    pthread_mutex_t state_mutex;
    JVSCapabilities capabilities;
    struct JVSIO *chainedIO;
} JVSIO;

JVSCapabilities *getCapabilities(void);
JVSState *getState(void);

int initIO(JVSIO *io);
int setSwitch(JVSIO *io, JVSPlayer player, JVSInput switchNumber, int value);
int incrementCoin(JVSIO *io, JVSPlayer player, int amount);
int setAnalogue(JVSIO *io, JVSInput channel, double value);
int setGun(JVSIO *io, JVSInput channel, double value);
int setRotary(JVSIO *io, JVSInput channel, int value);
int getRotary(JVSIO *io, JVSInput channel);
int incrementRotary(JVSIO *io, JVSInput channel, int delta);

JVSInput jvsInputFromString(char *jvsInputString);
JVSPlayer jvsPlayerFromString(char *jvsPlayerString);
#endif // IO_H_
