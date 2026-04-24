/**
 * ModernJVS Comprehensive Test Suite
 *
 * Tests the following modules with no hardware required:
 *   - jvs/io.c      – IO state management (pure logic)
 *   - jvs/jvs.c     – JVS packet framing + processPacket (via socketpair)
 *   - console/config.c – config / IO file parsing
 *   - console/debug.c  – debug level filtering
 *
 * JVS wire protocol emulation uses socketpair(AF_UNIX, SOCK_STREAM).
 * The "arcade machine" side writes command packets to sv[1]; processPacket()
 * reads from sv[0] (serialIO) and writes the response back to sv[0]; the test
 * then reads the response from sv[1].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>
#include <math.h>
#include <time.h>

/* Pull in the modules under test */
#include "jvs/io.h"
#include "jvs/jvs.h"
#include "console/config.h"
#include "console/debug.h"

/* Access the serial-port fd exported by hardware/device.c */
extern int serialIO;

/*
 * input.c references testButtonActive (normally defined in modernjvs.c).
 * In the real daemon this flag is set when the test button is held to
 * activate test mode; controller threads read it to suppress normal input.
 * Provide a stub here so the test binary links cleanly without needing
 * modernjvs.c (which defines main()).
 */
volatile int testButtonActive = 0;

/* =========================================================================
 * Minimal test framework
 * ========================================================================= */

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

/* Each test function is void and uses ASSERT_* to report failures. */
static const char *g_current_test = "unknown";

#define TEST_BEGIN(name)                                                       \
    do {                                                                       \
        g_current_test = #name;                                                \
        g_tests_run++;                                                         \
    } while (0)

#define TEST_PASS()                                                            \
    do {                                                                       \
        g_tests_passed++;                                                      \
        printf("  PASS  %s\n", g_current_test);                               \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        g_tests_failed++;                                                      \
        printf("  FAIL  %s – %s (line %d)\n",                                 \
               g_current_test, (msg), __LINE__);                              \
        return;                                                                \
    } while (0)

#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); } } while (0)

#define ASSERT_EQ_INT(a, b, msg)                                               \
    do {                                                                       \
        long long _a = (long long)(a), _b = (long long)(b);                   \
        if (_a != _b) {                                                        \
            printf("    expected %lld, got %lld\n", _b, _a);                  \
            FAIL(msg);                                                         \
        }                                                                      \
    } while (0)

#define ASSERT_NEAR(a, b, eps, msg)                                            \
    do {                                                                       \
        double _d = (double)(a) - (double)(b);                                 \
        if (_d < -(eps) || _d > (eps)) {                                       \
            printf("    expected ~%f, got %f\n", (double)(b), (double)(a));    \
            FAIL(msg);                                                         \
        }                                                                      \
    } while (0)

/* =========================================================================
 * JVS wire-format helpers
 * ========================================================================= */

#define SYNC_BYTE   ((unsigned char)0xE0)
#define ESCAPE_BYTE ((unsigned char)0xD0)

/**
 * Write one byte to buf[] at *idx with JVS escaping applied.
 * Escaped bytes (SYNC and ESCAPE) are expanded to a two-byte sequence.
 * Accumulates the byte's value into *checksum.
 */
static void jvs_wire_put(unsigned char *buf, int *idx, unsigned char *checksum,
                          unsigned char byte)
{
    *checksum = (unsigned char)((*checksum + byte) & 0xFF);
    if (byte == SYNC_BYTE || byte == ESCAPE_BYTE) {
        buf[(*idx)++] = ESCAPE_BYTE;
        buf[(*idx)++] = (unsigned char)(byte - 1);
    } else {
        buf[(*idx)++] = byte;
    }
}

/**
 * Build a raw JVS wire packet into buf[].
 * Returns the number of bytes written.
 *
 * Wire format:  SYNC | dest | length | data... | checksum
 * where length = data_len + 1  (counts the checksum byte itself)
 * All bytes are escaped: if a byte equals SYNC or ESCAPE it is replaced
 * by ESCAPE followed by (byte - 1).
 */
static int jvs_build_wire(unsigned char *buf, unsigned char dest,
                           const unsigned char *data, int data_len)
{
    int idx = 0;
    unsigned char checksum = 0;

    buf[idx++] = SYNC_BYTE;

    jvs_wire_put(buf, &idx, &checksum, dest);
    jvs_wire_put(buf, &idx, &checksum, (unsigned char)(data_len + 1));
    for (int i = 0; i < data_len; i++)
        jvs_wire_put(buf, &idx, &checksum, data[i]);

    /* Checksum itself is also escaped if needed */
    if (checksum == SYNC_BYTE || checksum == ESCAPE_BYTE) {
        buf[idx++] = ESCAPE_BYTE;
        buf[idx++] = (unsigned char)(checksum - 1);
    } else {
        buf[idx++] = checksum;
    }

    return idx;
}

/**
 * Decoded JVS response received from the device.
 */
typedef struct {
    unsigned char dest;
    unsigned char data[256];
    int  data_len;
    int  valid;   /* 1 = ok, -1 = checksum error, 0 = no/incomplete data */
} JVSResponse;

/**
 * Read one JVS wire packet from fd (with 1-second timeout) and decode it.
 */
static JVSResponse jvs_read_response(int fd)
{
    JVSResponse resp;
    memset(&resp, 0, sizeof(resp));

    fd_set fds;
    struct timeval tv = {1, 0};
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    if (select(fd + 1, &fds, NULL, NULL, &tv) < 1) {
        resp.valid = 0;
        return resp;
    }

    unsigned char raw[512];
    int n = (int)read(fd, raw, sizeof(raw));
    if (n <= 0) { resp.valid = 0; return resp; }

    /* Decode: find SYNC then parse dest / length / data / checksum */
    int i = 0;
    /* Skip to SYNC */
    while (i < n && raw[i] != SYNC_BYTE) i++;
    if (i >= n) { resp.valid = 0; return resp; }
    i++;  /* consume SYNC */

    int   escape    = 0;
    int   phase     = 0;
    unsigned char checksum  = 0;
    unsigned char wlen      = 0;
    int   data_idx  = 0;

    while (i < n) {
        unsigned char byte = raw[i++];

        if (!escape && byte == SYNC_BYTE)  { phase = 0; data_idx = 0; checksum = 0; continue; }
        if (!escape && byte == ESCAPE_BYTE){ escape = 1; continue; }
        if (escape) { byte++; escape = 0; }

        switch (phase) {
        case 0:
            resp.dest = byte;
            checksum = byte;
            phase++;
            break;
        case 1:
            wlen = byte;
            checksum = (unsigned char)((checksum + byte) & 0xFF);
            phase++;
            break;
        case 2:
            if (data_idx == wlen - 1) {
                resp.data_len = data_idx;
                resp.valid = (checksum == byte) ? 1 : -1;
                return resp;
            }
            resp.data[data_idx++] = byte;
            checksum = (unsigned char)((checksum + byte) & 0xFF);
            break;
        }
    }

    resp.valid = 0;
    return resp;
}

/**
 * Check whether the fd has any data available (non-blocking peek).
 * Returns 1 if data is ready, 0 if empty within 50 ms.
 */
static int fd_has_data(int fd)
{
    fd_set fds;
    struct timeval tv = {0, 50000};  /* 50 ms */
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    return select(fd + 1, &fds, NULL, NULL, &tv) > 0;
}

/**
 * Create a test JVSIO pre-configured for the namco-FCA1 capabilities.
 * Does NOT call initDevice() so no real hardware is touched.
 */
static JVSIO make_test_io(void)
{
    JVSIO io;
    memset(&io, 0, sizeof(io));
    io.deviceID  = -1;
    io.chainedIO = NULL;

    JVSCapabilities *c = &io.capabilities;
    strncpy(c->name, "namco ltd.;TEST;Ver1.00;JPN", sizeof(c->name) - 1);
    strncpy(c->displayName, "Test IO", sizeof(c->displayName) - 1);
    c->commandVersion   = 0x11;
    c->jvsVersion       = 0x20;
    c->commsVersion     = 0x10;
    c->players          = 2;
    c->switches         = 16;
    c->coins            = 2;
    c->analogueInChannels = 4;
    c->analogueInBits   = 10;
    c->rotaryChannels   = 2;
    c->gunChannels      = 2;
    c->gunXBits         = 12;
    c->gunYBits         = 12;
    c->generalPurposeInputs  = 8;
    c->generalPurposeOutputs = 6;
    c->rightAlignBits   = 0;

    initIO(&io);  /* sets analogueMax, gunXMax, gunYMax; zeros state */
    initJVS(&io); /* sets analogueRestBits, gunXRestBits, gunYRestBits */
    return io;
}

/**
 * Open a socketpair and set serialIO to the device side.
 * Returns the "arcade" fd (sv[1]). Caller must close both ends when done.
 */
static int open_test_socket(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        return -1;
    }
    serialIO = sv[0];  /* device side */
    return sv[1];      /* arcade side  */
}

/* =========================================================================
 * ──────────────────────────── IO STATE TESTS ──────────────────────────────
 * ========================================================================= */

static void test_initIO_zeros_state(void)
{
    TEST_BEGIN(test_initIO_zeros_state);

    JVSIO io;
    memset(&io, 0xFF, sizeof(io));  /* poison */
    io.capabilities.players           = 2;
    io.capabilities.analogueInChannels= 4;
    io.capabilities.analogueInBits    = 10;
    io.capabilities.rotaryChannels    = 2;
    io.capabilities.coins             = 2;
    io.capabilities.gunChannels       = 2;
    io.capabilities.gunXBits          = 12;
    io.capabilities.gunYBits          = 12;
    io.capabilities.rightAlignBits    = 0;

    int r = initIO(&io);
    ASSERT(r == 1, "initIO should return 1");
    ASSERT(io.state.inputSwitch[0]     == 0, "system switch should be 0");
    ASSERT(io.state.inputSwitch[1]     == 0, "player 1 switch should be 0");
    ASSERT(io.state.inputSwitch[2]     == 0, "player 2 switch should be 0");
    ASSERT(io.state.analogueChannel[0] == 0, "analogue ch 0 should be 0");
    ASSERT(io.state.coinCount[0]       == 0, "coin 0 should be 0");
    ASSERT(io.state.coinCount[1]       == 0, "coin 1 should be 0");
    ASSERT(io.analogueMax == 1023, "analogueMax for 10-bit");
    ASSERT(io.gunXMax     == 4095, "gunXMax for 12-bit");
    ASSERT(io.gunYMax     == 4095, "gunYMax for 12-bit");
    ASSERT(io.state.gunChannel[0] == 0, "gun channel 0 should be 0");
    ASSERT(io.state.gunChannel[1] == 0, "gun channel 1 should be 0");
    ASSERT(io.state.gunChannel[2] == 0, "gun channel 2 should be 0");
    ASSERT(io.state.gunChannel[3] == 0, "gun channel 3 should be 0");
    TEST_PASS();
}

static void test_setSwitch_system(void)
{
    TEST_BEGIN(test_setSwitch_system);
    JVSIO io = make_test_io();

    int r = setSwitch(&io, SYSTEM, BUTTON_TEST, 1);
    ASSERT(r == 1, "setSwitch should succeed");
    ASSERT(io.state.inputSwitch[0] & BUTTON_TEST, "BUTTON_TEST bit should be set");

    /* Pressing a second button accumulates */
    setSwitch(&io, SYSTEM, BUTTON_TILT_1, 1);
    ASSERT(io.state.inputSwitch[0] & BUTTON_TEST,  "BUTTON_TEST still set");
    ASSERT(io.state.inputSwitch[0] & BUTTON_TILT_1, "BUTTON_TILT_1 also set");

    /* Releasing one clears only that bit */
    setSwitch(&io, SYSTEM, BUTTON_TEST, 0);
    ASSERT(!(io.state.inputSwitch[0] & BUTTON_TEST),  "BUTTON_TEST cleared");
    ASSERT(io.state.inputSwitch[0] & BUTTON_TILT_1,   "BUTTON_TILT_1 still set");
    TEST_PASS();
}

static void test_setSwitch_player1(void)
{
    TEST_BEGIN(test_setSwitch_player1);
    JVSIO io = make_test_io();

    setSwitch(&io, PLAYER_1, BUTTON_START, 1);
    ASSERT(io.state.inputSwitch[1] & BUTTON_START, "P1 START set");

    setSwitch(&io, PLAYER_1, BUTTON_UP, 1);
    setSwitch(&io, PLAYER_1, BUTTON_DOWN, 1);
    ASSERT(io.state.inputSwitch[1] & BUTTON_UP,   "P1 UP set");
    ASSERT(io.state.inputSwitch[1] & BUTTON_DOWN, "P1 DOWN set");

    setSwitch(&io, PLAYER_1, BUTTON_UP, 0);
    ASSERT(!(io.state.inputSwitch[1] & BUTTON_UP), "P1 UP cleared");
    ASSERT(io.state.inputSwitch[1] & BUTTON_DOWN,  "P1 DOWN unchanged");
    TEST_PASS();
}

static void test_setSwitch_player2(void)
{
    TEST_BEGIN(test_setSwitch_player2);
    JVSIO io = make_test_io();

    setSwitch(&io, PLAYER_2, BUTTON_1, 1);
    ASSERT(!(io.state.inputSwitch[1] & BUTTON_1), "P1 state unaffected");
    ASSERT(io.state.inputSwitch[2]   & BUTTON_1,  "P2 BUTTON_1 set");
    TEST_PASS();
}

static void test_setSwitch_out_of_range_player(void)
{
    TEST_BEGIN(test_setSwitch_out_of_range_player);
    JVSIO io = make_test_io();  /* players = 2 */

    /* PLAYER_3 = 3 > 2 → should fail */
    int r = setSwitch(&io, PLAYER_3, BUTTON_1, 1);
    ASSERT(r == 0, "setSwitch for player > max should return 0");
    ASSERT(io.state.inputSwitch[3] == 0, "inputSwitch[3] should stay 0");
    TEST_PASS();
}

/*
 * setSwitch must reject a player index >= JVS_MAX_STATE_SIZE even when
 * capabilities.players is set to that same large value.  Without the
 * JVS_MAX_STATE_SIZE guard the write to inputSwitch[player] would be
 * out-of-bounds.
 */
static void test_setSwitch_oversized_player(void)
{
    TEST_BEGIN(test_setSwitch_oversized_player);

    JVSIO io;
    memset(&io, 0, sizeof(io));
    /* Set capabilities.players to JVS_MAX_STATE_SIZE so the first guard
     * (player > capabilities.players) would NOT catch the out-of-bounds
     * access without the second JVS_MAX_STATE_SIZE guard. */
    io.capabilities.players = JVS_MAX_STATE_SIZE;
    initIO(&io);

    int r = setSwitch(&io, (JVSPlayer)JVS_MAX_STATE_SIZE, BUTTON_1, 1);
    ASSERT_EQ_INT(r, 0, "setSwitch with player == JVS_MAX_STATE_SIZE must return 0");
    TEST_PASS();
}

static void test_setSwitch_all_buttons(void)
{
    TEST_BEGIN(test_setSwitch_all_buttons);
    JVSIO io = make_test_io();

    /* Set every player button for player 1 */
    setSwitch(&io, PLAYER_1, BUTTON_START,   1);
    setSwitch(&io, PLAYER_1, BUTTON_SERVICE, 1);
    setSwitch(&io, PLAYER_1, BUTTON_UP,      1);
    setSwitch(&io, PLAYER_1, BUTTON_DOWN,    1);
    setSwitch(&io, PLAYER_1, BUTTON_LEFT,    1);
    setSwitch(&io, PLAYER_1, BUTTON_RIGHT,   1);
    setSwitch(&io, PLAYER_1, BUTTON_1,       1);
    setSwitch(&io, PLAYER_1, BUTTON_2,       1);
    setSwitch(&io, PLAYER_1, BUTTON_3,       1);
    setSwitch(&io, PLAYER_1, BUTTON_4,       1);

    int sw = io.state.inputSwitch[1];
    ASSERT(sw & BUTTON_START,   "BUTTON_START");
    ASSERT(sw & BUTTON_SERVICE, "BUTTON_SERVICE");
    ASSERT(sw & BUTTON_UP,      "BUTTON_UP");
    ASSERT(sw & BUTTON_DOWN,    "BUTTON_DOWN");
    ASSERT(sw & BUTTON_LEFT,    "BUTTON_LEFT");
    ASSERT(sw & BUTTON_RIGHT,   "BUTTON_RIGHT");
    ASSERT(sw & BUTTON_1,       "BUTTON_1");
    ASSERT(sw & BUTTON_2,       "BUTTON_2");
    ASSERT(sw & BUTTON_3,       "BUTTON_3");
    ASSERT(sw & BUTTON_4,       "BUTTON_4");
    TEST_PASS();
}

static void test_incrementCoin_basic(void)
{
    TEST_BEGIN(test_incrementCoin_basic);
    JVSIO io = make_test_io();

    int r = incrementCoin(&io, PLAYER_1, 1);
    ASSERT(r == 1, "incrementCoin should return 1");
    ASSERT_EQ_INT(io.state.coinCount[0], 1, "coin count for P1");

    incrementCoin(&io, PLAYER_1, 4);
    ASSERT_EQ_INT(io.state.coinCount[0], 5, "coin count accumulated");

    r = incrementCoin(&io, PLAYER_2, 3);
    ASSERT(r == 1, "P2 coin increment");
    ASSERT_EQ_INT(io.state.coinCount[1], 3, "P2 coin count");
    ASSERT_EQ_INT(io.state.coinCount[0], 5, "P1 coin count unchanged");
    TEST_PASS();
}

static void test_incrementCoin_system_rejected(void)
{
    TEST_BEGIN(test_incrementCoin_system_rejected);
    JVSIO io = make_test_io();

    int r = incrementCoin(&io, SYSTEM, 1);
    ASSERT_EQ_INT(r, 0, "SYSTEM player coin should be rejected");
    TEST_PASS();
}

static void test_incrementCoin_out_of_range(void)
{
    TEST_BEGIN(test_incrementCoin_out_of_range);
    JVSIO io = make_test_io();  /* coins = 2 */

    /* PLAYER_3 maps to coinCount[2] which is beyond coins=2 */
    int r = incrementCoin(&io, PLAYER_3, 1);
    ASSERT_EQ_INT(r, 0, "out-of-range coin slot rejected");
    TEST_PASS();
}

static void test_setAnalogue_full_scale(void)
{
    TEST_BEGIN(test_setAnalogue_full_scale);
    JVSIO io = make_test_io();  /* analogueInBits=10, analogueMax=1023 */

    int r = setAnalogue(&io, ANALOGUE_1, 1.0);
    ASSERT(r == 1, "setAnalogue should return 1");
    ASSERT_EQ_INT(io.state.analogueChannel[0], 1023, "full-scale analogue");

    setAnalogue(&io, ANALOGUE_1, 0.0);
    ASSERT_EQ_INT(io.state.analogueChannel[0], 0, "zero analogue");

    setAnalogue(&io, ANALOGUE_1, 0.5);
    ASSERT_EQ_INT(io.state.analogueChannel[0], 511, "mid-scale analogue");
    TEST_PASS();
}

static void test_setAnalogue_out_of_range_channel(void)
{
    TEST_BEGIN(test_setAnalogue_out_of_range_channel);
    JVSIO io = make_test_io();  /* analogueInChannels=4 */

    int r = setAnalogue(&io, ANALOGUE_5 /* channel 4 */, 1.0);
    ASSERT_EQ_INT(r, 0, "channel 4 out of range (max index 3)");
    TEST_PASS();
}

static void test_setAnalogue_all_channels(void)
{
    TEST_BEGIN(test_setAnalogue_all_channels);
    JVSIO io = make_test_io();

    for (int ch = 0; ch < 4; ch++) {
        double v = (double)ch / 3.0;
        setAnalogue(&io, (JVSInput)ch, v);
    }
    ASSERT_EQ_INT(io.state.analogueChannel[0], 0,    "ch0");
    ASSERT_EQ_INT(io.state.analogueChannel[1], 341,  "ch1");
    ASSERT_EQ_INT(io.state.analogueChannel[2], 682,  "ch2");
    ASSERT_EQ_INT(io.state.analogueChannel[3], 1023, "ch3");
    TEST_PASS();
}

/*
 * setAnalogue must clamp values outside [0.0, 1.0] rather than writing a
 * negative channel value or one exceeding analogueMax.
 */
static void test_setAnalogue_value_clamping(void)
{
    TEST_BEGIN(test_setAnalogue_value_clamping);
    JVSIO io = make_test_io();  /* analogueInBits=10, analogueMax=1023 */

    /* Value above 1.0 clamps to 1.0 → stored as analogueMax */
    int r = setAnalogue(&io, ANALOGUE_1, 2.0);
    ASSERT(r == 1, "setAnalogue returns 1 for clamped value");
    ASSERT_EQ_INT(io.state.analogueChannel[0], 1023, "value > 1.0 clamped to analogueMax");

    /* Value below 0.0 clamps to 0.0 → stored as 0 */
    setAnalogue(&io, ANALOGUE_1, -0.5);
    ASSERT_EQ_INT(io.state.analogueChannel[0], 0, "value < 0.0 clamped to 0");

    TEST_PASS();
}

static void test_setGun_x_channel(void)
{
    TEST_BEGIN(test_setGun_x_channel);
    JVSIO io = make_test_io();  /* gunXBits=12, gunXMax=4095 */

    /* Channel 0 = X for gun 0 */
    int r = setGun(&io, 0, 1.0);
    ASSERT(r == 1, "setGun X should succeed");
    ASSERT_EQ_INT(io.state.gunChannel[0], 4095, "full-scale gun X");
    TEST_PASS();
}

static void test_setGun_y_channel(void)
{
    TEST_BEGIN(test_setGun_y_channel);
    JVSIO io = make_test_io();  /* gunYBits=12, gunYMax=4095 */

    /* Channel 1 = Y for gun 0: stored as value * gunYMax */
    setGun(&io, 1, 0.0);
    ASSERT_EQ_INT(io.state.gunChannel[1], 0, "Y=0.0 → stored as 0");

    setGun(&io, 1, 1.0);
    ASSERT_EQ_INT(io.state.gunChannel[1], 4095, "Y=1.0 → stored as 4095 (max)");
    TEST_PASS();
}

static void test_setGun_gun2(void)
{
    TEST_BEGIN(test_setGun_gun2);
    JVSIO io = make_test_io();  /* gunChannels=2 */

    /* Gun 2 uses channels 2 (X) and 3 (Y) */
    setGun(&io, 2, 0.5);
    ASSERT_EQ_INT(io.state.gunChannel[2], 2047, "gun2 X mid-scale");

    setGun(&io, 3, 0.5);
    ASSERT_EQ_INT(io.state.gunChannel[3], 2047, "gun2 Y mid-scale (1.0-0.5)*4095=2047");
    TEST_PASS();
}

static void test_setGun_out_of_range(void)
{
    TEST_BEGIN(test_setGun_out_of_range);
    JVSIO io = make_test_io();  /* gunChannels=2 → valid channels 0-3 */

    int r = setGun(&io, 4, 1.0);
    ASSERT_EQ_INT(r, 0, "channel 4 out of range");
    TEST_PASS();
}

/*
 * setGun must clamp values outside [0.0, 1.0] to the boundary rather than
 * producing out-of-range channel data.
 *   X channel (even): stored as value * gunXMax → >1.0 clamps to gunXMax,
 *                                                   <0.0 clamps to 0.
 *   Y channel (odd):  stored as value * gunYMax → >1.0 clamps to gunYMax,
 *                                                   <0.0 clamps to 0.
 */
static void test_setGun_value_clamping(void)
{
    TEST_BEGIN(test_setGun_value_clamping);
    JVSIO io = make_test_io();  /* gunXBits=12, gunYBits=12 → max=4095 */

    /* X: value > 1.0 clamps to 1.0 → stored as gunXMax */
    int r = setGun(&io, 0, 5.0);
    ASSERT(r == 1, "setGun returns 1 for clamped X");
    ASSERT_EQ_INT(io.state.gunChannel[0], 4095, "X value > 1.0 clamped to gunXMax");

    /* X: value < 0.0 clamps to 0.0 → stored as 0 */
    setGun(&io, 0, -1.0);
    ASSERT_EQ_INT(io.state.gunChannel[0], 0, "X value < 0.0 clamped to 0");

    /* Y: value > 1.0 clamps to 1.0 → stored as 1.0*gunYMax = 4095 */
    setGun(&io, 1, 5.0);
    ASSERT_EQ_INT(io.state.gunChannel[1], 4095, "Y value > 1.0 clamped to gunYMax");

    /* Y: value < 0.0 clamps to 0.0 → stored as 0.0*gunYMax = 0 */
    setGun(&io, 1, -1.0);
    ASSERT_EQ_INT(io.state.gunChannel[1], 0, "Y value < 0.0 clamped to 0");

    TEST_PASS();
}

static void test_setRotary_getRotary_roundtrip(void)
{
    TEST_BEGIN(test_setRotary_getRotary_roundtrip);
    JVSIO io = make_test_io();  /* rotaryChannels=2 */

    int r = setRotary(&io, ROTARY_1, 12345);
    ASSERT(r == 1, "setRotary should return 1");
    ASSERT_EQ_INT(getRotary(&io, ROTARY_1), 12345, "round-trip rotary value");

    setRotary(&io, ROTARY_2, -500);
    ASSERT_EQ_INT(getRotary(&io, ROTARY_2), -500, "negative rotary value");
    TEST_PASS();
}

static void test_setRotary_out_of_range(void)
{
    TEST_BEGIN(test_setRotary_out_of_range);
    JVSIO io = make_test_io();  /* rotaryChannels=2 */

    int r = setRotary(&io, ROTARY_3, 999);
    ASSERT_EQ_INT(r, 0, "channel 2 out of range");
    ASSERT_EQ_INT(getRotary(&io, ROTARY_3), 0, "getRotary out-of-range returns 0");
    TEST_PASS();
}

/* -- incrementRotary tests ------------------------------------------------- */

/* Basic accumulation: increment twice, values must sum */
static void test_incrementRotary_basic(void)
{
    TEST_BEGIN(test_incrementRotary_basic);
    JVSIO io = make_test_io();  /* rotaryChannels=2 */

    int r = incrementRotary(&io, ROTARY_1, 100);
    ASSERT(r == 1, "incrementRotary returns 1");
    ASSERT_EQ_INT(getRotary(&io, ROTARY_1), 100, "rotary after first increment");

    incrementRotary(&io, ROTARY_1, 50);
    ASSERT_EQ_INT(getRotary(&io, ROTARY_1), 150, "rotary after second increment");

    TEST_PASS();
}

/* Negative delta subtracts from the accumulated value */
static void test_incrementRotary_negative_delta(void)
{
    TEST_BEGIN(test_incrementRotary_negative_delta);
    JVSIO io = make_test_io();

    setRotary(&io, ROTARY_1, 500);
    incrementRotary(&io, ROTARY_1, -200);
    ASSERT_EQ_INT(getRotary(&io, ROTARY_1), 300, "rotary after negative delta");

    TEST_PASS();
}

/* Out-of-range channel (ROTARY_3=2, but rotaryChannels=2) must return 0 */
static void test_incrementRotary_out_of_range(void)
{
    TEST_BEGIN(test_incrementRotary_out_of_range);
    JVSIO io = make_test_io();  /* rotaryChannels=2 → valid: ROTARY_1, ROTARY_2 */

    int r = incrementRotary(&io, ROTARY_3, 10);
    ASSERT_EQ_INT(r, 0, "incrementRotary out-of-range returns 0");
    /* Value must remain 0 (untouched) */
    ASSERT_EQ_INT(getRotary(&io, ROTARY_3), 0, "out-of-range channel value unchanged");

    TEST_PASS();
}

/* Negative channel index (cast from -1) must be rejected */
static void test_incrementRotary_negative_channel(void)
{
    TEST_BEGIN(test_incrementRotary_negative_channel);
    JVSIO io = make_test_io();

    int r = incrementRotary(&io, (JVSInput)-1, 50);
    ASSERT_EQ_INT(r, 0, "incrementRotary with channel -1 must return 0");

    TEST_PASS();
}

static void test_jvsInputFromString_known(void)
{
    TEST_BEGIN(test_jvsInputFromString_known);

    ASSERT_EQ_INT(jvsInputFromString("BUTTON_TEST"),    BUTTON_TEST,    "BUTTON_TEST");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_TILT_1"),  BUTTON_TILT_1,  "BUTTON_TILT_1");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_START"),   BUTTON_START,   "BUTTON_START");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_SERVICE"), BUTTON_SERVICE, "BUTTON_SERVICE");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_UP"),      BUTTON_UP,      "BUTTON_UP");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_DOWN"),    BUTTON_DOWN,    "BUTTON_DOWN");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_LEFT"),    BUTTON_LEFT,    "BUTTON_LEFT");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_RIGHT"),   BUTTON_RIGHT,   "BUTTON_RIGHT");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_1"),       BUTTON_1,       "BUTTON_1");
    ASSERT_EQ_INT(jvsInputFromString("BUTTON_10"),      BUTTON_10,      "BUTTON_10");
    ASSERT_EQ_INT(jvsInputFromString("ANALOGUE_1"),     ANALOGUE_1,     "ANALOGUE_1");
    ASSERT_EQ_INT(jvsInputFromString("ANALOGUE_10"),    ANALOGUE_10,    "ANALOGUE_10");
    ASSERT_EQ_INT(jvsInputFromString("ROTARY_1"),       ROTARY_1,       "ROTARY_1");
    ASSERT_EQ_INT(jvsInputFromString("COIN"),           COIN,           "COIN");
    TEST_PASS();
}

static void test_jvsInputFromString_unknown(void)
{
    TEST_BEGIN(test_jvsInputFromString_unknown);

    JVSInput r = jvsInputFromString("BUTTON_DOES_NOT_EXIST");
    ASSERT((int)r == -1, "unknown input should return -1");
    TEST_PASS();
}

/* ── New tests for PR bug-fixes ──────────────────────────────────────────── */

/*
 * setSwitch must reject a negative switchNumber.
 * jvsInputFromString("BAD_NAME") returns (JVSInput)-1; before the fix that
 * value was used directly in a bitwise OR, setting ALL bits of inputSwitch
 * and making every button appear simultaneously pressed on the JVS bus.
 */
static void test_setSwitch_invalid_switch_number(void)
{
    TEST_BEGIN(test_setSwitch_invalid_switch_number);
    JVSIO io = make_test_io();

    /* Ensure the state starts clean */
    ASSERT_EQ_INT(io.state.inputSwitch[1], 0, "P1 switch state starts at 0");

    /* Pass the -1 sentinel returned by jvsInputFromString on lookup failure */
    int r = setSwitch(&io, PLAYER_1, (JVSInput)-1, 1);
    ASSERT_EQ_INT(r, 0, "setSwitch with switchNumber -1 must return 0");

    /* The switch state must not be corrupted (must still be 0, not 0xFFFF) */
    ASSERT_EQ_INT(io.state.inputSwitch[1], 0,
                  "switch state must not be corrupted by invalid switchNumber");

    /* Also verify the release path doesn't clear everything */
    setSwitch(&io, PLAYER_1, BUTTON_START, 1);
    setSwitch(&io, PLAYER_1, (JVSInput)-1, 0);
    ASSERT(io.state.inputSwitch[1] & BUTTON_START,
           "valid BUTTON_START bit must survive invalid-switch release");

    TEST_PASS();
}

/*
 * Calling initIO() twice on the same JVSIO must not produce undefined behaviour.
 * The first call initialises the mutex; the second call must destroy then
 * re-initialise it safely, confirmed by the mutexInitialized guard introduced
 * to prevent pthread_mutex_destroy on a garbage-initialised struct.
 */
static void test_initIO_reinit_mutex_safety(void)
{
    TEST_BEGIN(test_initIO_reinit_mutex_safety);

    JVSIO io;
    memset(&io, 0, sizeof(io));
    io.capabilities.players            = 2;
    io.capabilities.analogueInChannels = 2;
    io.capabilities.analogueInBits     = 10;
    io.capabilities.coins              = 2;
    io.capabilities.rotaryChannels     = 0;
    io.capabilities.gunChannels        = 0;

    int r1 = initIO(&io);
    ASSERT_EQ_INT(r1, 1, "first initIO returns 1");
    ASSERT_EQ_INT(io.mutexInitialized, 1, "mutexInitialized set after first init");

    /* Set some state, then re-init; state must be zeroed again */
    io.state.inputSwitch[1] = 0xFFFF;
    int r2 = initIO(&io);
    ASSERT_EQ_INT(r2, 1, "second initIO returns 1");
    ASSERT_EQ_INT(io.state.inputSwitch[1], 0, "state zeroed by second initIO");

    /* The mutex must still be usable after re-init */
    int r3 = setSwitch(&io, PLAYER_1, BUTTON_START, 1);
    ASSERT_EQ_INT(r3, 1, "setSwitch works after re-init");

    TEST_PASS();
}

/*
 * setSwitch must reject a negative player index.
 * jvsPlayerFromString("INVALID") returns (JVSPlayer)-1, which before the fix
 * would pass the "player > capabilities.players" check and underflow the array.
 */
static void test_setSwitch_negative_player(void)
{
    TEST_BEGIN(test_setSwitch_negative_player);
    JVSIO io = make_test_io();

    /* Cast -1 explicitly to JVSPlayer to simulate what jvsPlayerFromString
     * returns on a lookup failure. */
    int r = setSwitch(&io, (JVSPlayer)-1, BUTTON_1, 1);
    ASSERT_EQ_INT(r, 0, "setSwitch with player -1 must return 0");
    TEST_PASS();
}

/*
 * setAnalogue must reject a negative channel index.
 */
static void test_setAnalogue_negative_channel(void)
{
    TEST_BEGIN(test_setAnalogue_negative_channel);
    JVSIO io = make_test_io();

    int r = setAnalogue(&io, (JVSInput)-1, 1.0);
    ASSERT_EQ_INT(r, 0, "setAnalogue with channel -1 must return 0");
    TEST_PASS();
}

/*
 * setGun must reject a negative channel index.
 */
static void test_setGun_negative_channel(void)
{
    TEST_BEGIN(test_setGun_negative_channel);
    JVSIO io = make_test_io();

    int r = setGun(&io, (JVSInput)-1, 1.0);
    ASSERT_EQ_INT(r, 0, "setGun with channel -1 must return 0");
    TEST_PASS();
}

/*
 * setRotary / getRotary must reject a negative channel index.
 */
static void test_setRotary_negative_channel(void)
{
    TEST_BEGIN(test_setRotary_negative_channel);
    JVSIO io = make_test_io();

    int r = setRotary(&io, (JVSInput)-1, 999);
    ASSERT_EQ_INT(r, 0, "setRotary with channel -1 must return 0");
    ASSERT_EQ_INT(getRotary(&io, (JVSInput)-1), 0, "getRotary with channel -1 must return 0");
    TEST_PASS();
}

/*
 * incrementCoin must cap the coin count at 16383 (13-bit JVS wire max).
 */
static void test_incrementCoin_cap_at_16383(void)
{
    TEST_BEGIN(test_incrementCoin_cap_at_16383);
    JVSIO io = make_test_io();

    /* Increment well past the 16383 cap */
    incrementCoin(&io, PLAYER_1, 16000);
    ASSERT_EQ_INT(io.state.coinCount[0], 16000, "normal accumulation before cap");
    incrementCoin(&io, PLAYER_1, 16000);
    ASSERT_EQ_INT(io.state.coinCount[0], 16383, "coin count capped at 16383");

    /* A single large increment also caps correctly */
    io.state.coinCount[1] = 0;
    incrementCoin(&io, PLAYER_2, 99999);
    ASSERT_EQ_INT(io.state.coinCount[1], 16383, "large single increment capped at 16383");
    TEST_PASS();
}

static void test_jvsPlayerFromString_known(void)
{
    TEST_BEGIN(test_jvsPlayerFromString_known);

    ASSERT_EQ_INT(jvsPlayerFromString("SYSTEM"),   SYSTEM,   "SYSTEM");
    ASSERT_EQ_INT(jvsPlayerFromString("PLAYER_1"), PLAYER_1, "PLAYER_1");
    ASSERT_EQ_INT(jvsPlayerFromString("PLAYER_2"), PLAYER_2, "PLAYER_2");
    ASSERT_EQ_INT(jvsPlayerFromString("PLAYER_3"), PLAYER_3, "PLAYER_3");
    ASSERT_EQ_INT(jvsPlayerFromString("PLAYER_4"), PLAYER_4, "PLAYER_4");
    TEST_PASS();
}

static void test_jvsPlayerFromString_unknown(void)
{
    TEST_BEGIN(test_jvsPlayerFromString_unknown);

    JVSPlayer r = jvsPlayerFromString("PLAYER_99");
    ASSERT((int)r == -1, "unknown player should return -1");
    TEST_PASS();
}

/* =========================================================================
 * ─────────────────────────── CONFIG PARSING TESTS ─────────────────────────
 * ========================================================================= */

static void test_getDefaultConfig(void)
{
    TEST_BEGIN(test_getDefaultConfig);

    JVSConfig cfg;
    memset(&cfg, 0xFF, sizeof(cfg));
    JVSConfigStatus s = getDefaultConfig(&cfg);
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "getDefaultConfig returns SUCCESS");
    ASSERT_EQ_INT(cfg.senseLineType,            DEFAULT_SENSE_LINE_TYPE, "senseLineType");
    ASSERT_EQ_INT(cfg.senseLinePin,             DEFAULT_SENSE_LINE_PIN,  "senseLinePin");
    ASSERT_EQ_INT(cfg.debugLevel,               DEFAULT_DEBUG_LEVEL,     "debugLevel");
    ASSERT_EQ_INT(cfg.autoControllerDetection,  DEFAULT_AUTO_CONTROLLER_DETECTION, "autoController");
    ASSERT(strcmp(cfg.defaultGamePath, DEFAULT_GAME)    == 0, "defaultGamePath");
    ASSERT(strcmp(cfg.devicePath,      DEFAULT_DEVICE_PATH) == 0, "devicePath");
    ASSERT(strcmp(cfg.capabilitiesPath, DEFAULT_IO)     == 0, "capabilitiesPath");
    ASSERT(cfg.secondCapabilitiesPath[0] == 0x00, "secondCapabilitiesPath empty");
    ASSERT_NEAR(cfg.analogDeadzonePlayer1, DEFAULT_ANALOG_DEADZONE, 0.001, "deadzone P1");
    ASSERT_NEAR(cfg.analogDeadzonePlayer2, DEFAULT_ANALOG_DEADZONE, 0.001, "deadzone P2");
    ASSERT_NEAR(cfg.wiiIRScale, DEFAULT_WII_IR_SCALE, 0.001, "wiiIRScale");
    TEST_PASS();
}

static void test_parseConfig_valid_file(void)
{
    TEST_BEGIN(test_parseConfig_valid_file);

    const char *path = "/tmp/mjtest_config.conf";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "create temp config file");
    fprintf(f,
        "# comment\n"
        "\n"
        "SENSE_LINE_TYPE 0\n"
        "SENSE_LINE_PIN 13\n"
        "DEFAULT_GAME sfiii\n"
        "EMULATE namco-jyu\n"
        "DEVICE_PATH /dev/ttyUSB1\n"
        "DEBUG_MODE 1\n"
        "AUTO_CONTROLLER_DETECTION 0\n"
        "ANALOG_DEADZONE_PLAYER_1 0.1\n"
        "ANALOG_DEADZONE_PLAYER_2 0.3\n"
        "WII_IR_SCALE 1.5\n");
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    JVSConfigStatus s = parseConfig((char *)path, &cfg);
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "parseConfig SUCCESS");
    ASSERT_EQ_INT(cfg.senseLineType, 0,   "senseLineType");
    ASSERT_EQ_INT(cfg.senseLinePin,  13,  "senseLinePin");
    ASSERT(strcmp(cfg.defaultGamePath,   "sfiii")        == 0, "defaultGamePath");
    ASSERT(strcmp(cfg.capabilitiesPath,  "namco-jyu")    == 0, "capabilitiesPath");
    ASSERT(strcmp(cfg.devicePath,        "/dev/ttyUSB1") == 0, "devicePath");
    ASSERT_EQ_INT(cfg.debugLevel,              1, "debugLevel");
    ASSERT_EQ_INT(cfg.autoControllerDetection, 0, "autoControllerDetection");
    ASSERT_NEAR(cfg.analogDeadzonePlayer1, 0.1, 0.001, "deadzone P1");
    ASSERT_NEAR(cfg.analogDeadzonePlayer2, 0.3, 0.001, "deadzone P2");
    ASSERT_NEAR(cfg.wiiIRScale, 1.5, 0.001, "wiiIRScale");
    unlink(path);
    TEST_PASS();
}

static void test_parseConfig_file_not_found(void)
{
    TEST_BEGIN(test_parseConfig_file_not_found);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    JVSConfigStatus s = parseConfig("/tmp/does_not_exist_xyzzy.conf", &cfg);
    ASSERT(s == JVS_CONFIG_STATUS_FILE_NOT_FOUND, "non-existent file returns FILE_NOT_FOUND");
    TEST_PASS();
}

/*
 * EMULATE_SECOND must store the second-IO capability profile name so that
 * the daemon can load a second emulated IO board alongside the primary one.
 */
static void test_parseConfig_emulate_second(void)
{
    TEST_BEGIN(test_parseConfig_emulate_second);

    const char *path = "/tmp/mjtest_emul2.conf";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "create temp config file");
    fprintf(f, "EMULATE_SECOND namco-FCA1\n");
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    JVSConfigStatus s = parseConfig((char *)path, &cfg);
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "parseConfig SUCCESS");
    ASSERT(strcmp(cfg.secondCapabilitiesPath, "namco-FCA1") == 0,
           "secondCapabilitiesPath set correctly");

    unlink(path);
    TEST_PASS();
}

/*
 * An invalid (non-numeric) value for an integer key must not change the
 * existing field – the parser should keep the default/previous value.
 */
static void test_parseConfig_invalid_int_fallback(void)
{
    TEST_BEGIN(test_parseConfig_invalid_int_fallback);

    const char *path = "/tmp/mjtest_invalid_int.conf";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "create temp config file");
    fprintf(f, "DEBUG_MODE notanumber\n");
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    int default_level = cfg.debugLevel;
    parseConfig((char *)path, &cfg);
    /* The invalid token must not corrupt the field */
    ASSERT_EQ_INT(cfg.debugLevel, default_level,
                  "invalid integer token keeps the fallback/default value");

    unlink(path);
    TEST_PASS();
}

static void test_parseConfig_comments_and_blanks(void)
{
    TEST_BEGIN(test_parseConfig_comments_and_blanks);

    const char *path = "/tmp/mjtest_comments.conf";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "create temp file");
    /* Only comments and blanks – nothing should change from defaults */
    fprintf(f, "# full comment\n\n# another\n  \n\r\n");
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    parseConfig((char *)path, &cfg);
    ASSERT(strcmp(cfg.defaultGamePath, DEFAULT_GAME) == 0, "defaultGamePath unchanged");
    ASSERT_EQ_INT(cfg.debugLevel, DEFAULT_DEBUG_LEVEL, "debugLevel unchanged");
    unlink(path);
    TEST_PASS();
}

static void test_parseConfig_deadzone_clamping(void)
{
    TEST_BEGIN(test_parseConfig_deadzone_clamping);

    const char *path = "/tmp/mjtest_deadzone.conf";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "create temp file");
    /* Values beyond limits should be clamped */
    fprintf(f,
        "ANALOG_DEADZONE_PLAYER_1 0.99\n"  /* > 0.5 → clamp to 0.49 */
        "ANALOG_DEADZONE_PLAYER_2 -0.1\n"  /* < 0   → clamp to 0.0  */
        "ANALOG_DEADZONE_PLAYER_3 0.5\n"   /* == 0.5 → clamp to 0.49 */
        "ANALOG_DEADZONE_PLAYER_4 0.2\n"); /* within range, unchanged */
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    parseConfig((char *)path, &cfg);
    ASSERT(cfg.analogDeadzonePlayer1 < MAX_ANALOG_DEADZONE, "P1 deadzone clamped <0.5");
    ASSERT_NEAR(cfg.analogDeadzonePlayer2, 0.0, 0.001, "P2 deadzone clamped to 0");
    ASSERT(cfg.analogDeadzonePlayer3 < MAX_ANALOG_DEADZONE, "P3 deadzone clamped <0.5");
    ASSERT_NEAR(cfg.analogDeadzonePlayer4, 0.2, 0.001, "P4 deadzone unchanged");
    unlink(path);
    TEST_PASS();
}

static void test_parseConfig_wii_ir_scale_clamping(void)
{
    TEST_BEGIN(test_parseConfig_wii_ir_scale_clamping);

    const char *path = "/tmp/mjtest_wiiscale.conf";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "create temp file");
    fprintf(f, "WII_IR_SCALE 99.0\n");  /* > MAX_WII_IR_SCALE → clamp to 5.0 */
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    parseConfig((char *)path, &cfg);
    ASSERT_NEAR(cfg.wiiIRScale, MAX_WII_IR_SCALE, 0.001, "WII_IR_SCALE clamped to max");
    unlink(path);

    /* Below minimum */
    f = fopen(path, "w");
    fprintf(f, "WII_IR_SCALE 0.0\n");  /* < MIN_WII_IR_SCALE → clamp to 0.1 */
    fclose(f);
    getDefaultConfig(&cfg);
    parseConfig((char *)path, &cfg);
    ASSERT_NEAR(cfg.wiiIRScale, MIN_WII_IR_SCALE, 0.001, "WII_IR_SCALE clamped to min");
    unlink(path);
    TEST_PASS();
}

static void test_parseConfig_include(void)
{
    TEST_BEGIN(test_parseConfig_include);

    const char *base = "/tmp/mjtest_base.conf";
    const char *incl = "/tmp/mjtest_incl.conf";

    FILE *f = fopen(incl, "w");
    ASSERT(f != NULL, "create include file");
    fprintf(f, "DEBUG_MODE 2\n");
    fclose(f);

    f = fopen(base, "w");
    ASSERT(f != NULL, "create base file");
    fprintf(f, "INCLUDE %s\nDEVICE_PATH /dev/test\n", incl);
    fclose(f);

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    parseConfig((char *)base, &cfg);
    ASSERT_EQ_INT(cfg.debugLevel, 2, "debugLevel from included file");
    ASSERT(strcmp(cfg.devicePath, "/dev/test") == 0, "devicePath from base");
    unlink(base);
    unlink(incl);
    TEST_PASS();
}

static void test_parseIO_namco_FCA1(void)
{
    TEST_BEGIN(test_parseIO_namco_FCA1);

    JVSCapabilities caps;
    memset(&caps, 0, sizeof(caps));
    JVSConfigStatus s = parseIO("namco-FCA1", &caps);
    if (s == JVS_CONFIG_STATUS_FILE_NOT_FOUND)
    {
        printf("    SKIP: /etc/modernjvs/ios/namco-FCA1 not installed\n");
        TEST_PASS();
        return;
    }
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "parseIO namco-FCA1 SUCCESS");
    ASSERT(strlen(caps.name) > 0,         "name not empty");
    ASSERT(strlen(caps.displayName) > 0,  "displayName not empty");
    ASSERT_EQ_INT(caps.players, 1, "players");
    ASSERT_EQ_INT(caps.switches, 16, "switches");
    ASSERT_EQ_INT(caps.coins, 2, "coins");
    ASSERT(caps.analogueInChannels > 0, "analogue channels > 0");
    ASSERT(caps.rotaryChannels > 0,     "rotary channels > 0");
    TEST_PASS();
}

static void test_parseIO_file_not_found(void)
{
    TEST_BEGIN(test_parseIO_file_not_found);

    JVSCapabilities caps;
    memset(&caps, 0, sizeof(caps));
    JVSConfigStatus s = parseIO("no-such-io-board-xyzzy", &caps);
    ASSERT(s == JVS_CONFIG_STATUS_FILE_NOT_FOUND, "missing IO file → FILE_NOT_FOUND");
    TEST_PASS();
}

static void test_parseIO_capcom_naomi(void)
{
    TEST_BEGIN(test_parseIO_capcom_naomi);

    JVSCapabilities caps;
    memset(&caps, 0, sizeof(caps));
    JVSConfigStatus s = parseIO("capcom-naomi", &caps);
    if (s == JVS_CONFIG_STATUS_FILE_NOT_FOUND)
    {
        printf("    SKIP: /etc/modernjvs/ios/capcom-naomi not installed\n");
        TEST_PASS();
        return;
    }
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "parseIO capcom-naomi SUCCESS");
    ASSERT(caps.players >= 2, "naomi has >= 2 players");
    TEST_PASS();
}

/* =========================================================================
 * ─────────────────────────── DEBUG LEVEL TESTS ────────────────────────────
 * ========================================================================= */

static void test_debug_getLevel(void)
{
    TEST_BEGIN(test_debug_getLevel);

    initDebug(0);
    ASSERT_EQ_INT(getDebugLevel(), 0, "level 0");
    initDebug(2);
    ASSERT_EQ_INT(getDebugLevel(), 2, "level 2");
    initDebug(0);
    TEST_PASS();
}

static void test_debug_level_filtering(void)
{
    TEST_BEGIN(test_debug_level_filtering);
    /* Redirect stdout to /dev/null temporarily so debug() doesn't pollute output */
    int saved_stdout = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    ASSERT(devnull != -1, "open /dev/null");
    dup2(devnull, STDOUT_FILENO);

    initDebug(1);
    /* These calls must not crash regardless of level */
    debug(0, "level 0 message\n");
    debug(1, "level 1 message\n");
    debug(2, "level 2 message (suppressed)\n");
    ASSERT_EQ_INT(getDebugLevel(), 1, "debug level still 1");

    /* Restore stdout */
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    close(devnull);
    initDebug(0);
    TEST_PASS();
}

/* =========================================================================
 * ─────────────────────── JVS PACKET FRAMING TESTS ─────────────────────────
 * (uses a pipe: test writes wire bytes → readPacket() reads them)
 * ========================================================================= */

/*
 * A packet whose length byte is 0x00 is always malformed (the length field
 * counts the following bytes including the checksum, so the minimum valid
 * value is 1).  readPacket() must return JVS_STATUS_ERROR_CHECKSUM immediately
 * rather than accepting the malformed frame.
 */
static void test_readPacket_zero_length(void)
{
    TEST_BEGIN(test_readPacket_zero_length);

    /* Raw wire bytes: SYNC(E0) + dest(01) + length(00) + garbage(01) */
    unsigned char stream[] = {0xE0, 0x01, 0x00, 0x01};
    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[0];
    write(fds[1], stream, sizeof(stream));

    JVSPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_ERROR, "zero-length packet → ERROR (framing error, not checksum error)");

    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

/*
 * resetPacketParser() must discard any partial receive state accumulated by a
 * preceding incomplete/timed-out readPacket() call so that the next
 * well-formed packet decodes cleanly.
 *
 * Sequence:
 *   1. Feed a partial packet (SYNC + dest + length=5 + 2 data bytes) then
 *      close the write end → EOF causes readPacket() to time-out with the
 *      parser in phase 2.
 *   2. Call resetPacketParser() to wipe the stale state.
 *   3. Open a fresh pipe, write a complete valid packet.
 *   4. readPacket() must succeed and decode the correct content.
 */
static void test_resetPacketParser_clears_stale_state(void)
{
    TEST_BEGIN(test_resetPacketParser_clears_stale_state);

    /* Step 1: partial packet – SYNC + dest=0x01 + length=5 (claims 4 data bytes,
     * but we only provide 2) before EOF. */
    int fds1[2];
    ASSERT(pipe(fds1) == 0, "pipe 1");
    serialIO = fds1[0];
    unsigned char partial[] = {0xE0, 0x01, 0x05, 0xAA, 0xBB};
    write(fds1[1], partial, sizeof(partial));
    close(fds1[1]);  /* EOF on write end → readBytes returns -1 */

    JVSPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    JVSStatus s1 = readPacket(&pkt);
    ASSERT(s1 == JVS_STATUS_ERROR_TIMEOUT, "incomplete packet → timeout");
    close(fds1[0]);

    /* Step 2: reset the parser – must clear rxPhase / rxDataIndex / etc. */
    resetPacketParser();

    /* Step 3: fresh pipe with a complete, valid packet (CMD_REQUEST_ID) */
    unsigned char data[] = {0x10};
    unsigned char wire[32];
    int wlen = jvs_build_wire(wire, 0x01, data, 1);
    int fds2[2];
    ASSERT(pipe(fds2) == 0, "pipe 2");
    serialIO = fds2[0];
    write(fds2[1], wire, wlen);

    memset(&pkt, 0, sizeof(pkt));
    JVSStatus s2 = readPacket(&pkt);
    ASSERT(s2 == JVS_STATUS_SUCCESS, "valid packet after resetPacketParser → SUCCESS");
    ASSERT_EQ_INT(pkt.destination, 0x01, "destination correct");
    ASSERT_EQ_INT(pkt.data[0], 0x10, "data byte correct (CMD_REQUEST_ID)");

    close(fds2[0]);
    close(fds2[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_readPacket_valid(void)
{
    TEST_BEGIN(test_readPacket_valid);

    /* Packet: dest=0x01, data=[CMD_ASSIGN_ADDR=0xF1, 0x01], length=3
     * checksum = (0x01 + 0x03 + 0xF1 + 0x01) & 0xFF = 0xF6 */
    unsigned char data[] = {0xF1, 0x01};
    unsigned char wire[32];
    int wlen = jvs_build_wire(wire, 0x01, data, 2);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe created");
    serialIO = fds[0];

    write(fds[1], wire, wlen);

    JVSPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "readPacket SUCCESS");
    ASSERT_EQ_INT(pkt.destination, 0x01, "destination");
    /* pkt.length = wire_length byte = data_len + 1 = 3 */
    ASSERT_EQ_INT(pkt.length, 3, "pkt.length");
    ASSERT_EQ_INT(pkt.data[0], 0xF1, "data[0] = CMD_ASSIGN_ADDR");
    ASSERT_EQ_INT(pkt.data[1], 0x01, "data[1] = address");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_readPacket_checksum_error(void)
{
    TEST_BEGIN(test_readPacket_checksum_error);

    unsigned char data[] = {0xF1, 0x01};
    unsigned char wire[32];
    int wlen = jvs_build_wire(wire, 0x01, data, 2);

    /* Corrupt the checksum (last byte) */
    wire[wlen - 1] ^= 0xFF;

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe created");
    serialIO = fds[0];
    write(fds[1], wire, wlen);

    JVSPacket pkt;
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_ERROR_CHECKSUM, "bad checksum → ERROR_CHECKSUM");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_readPacket_escape_bytes(void)
{
    TEST_BEGIN(test_readPacket_escape_bytes);

    /* Data byte 0xE0 (SYNC) must be escaped on the wire → 0xD0 0xDF */
    unsigned char data[] = {0xE0, 0x42};  /* contains a raw SYNC value */
    unsigned char wire[32];
    int wlen = jvs_build_wire(wire, 0xFF, data, 2);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[0];
    write(fds[1], wire, wlen);

    JVSPacket pkt;
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "readPacket with escaped 0xE0 SUCCESS");
    ASSERT_EQ_INT(pkt.data[0], 0xE0, "0xE0 correctly unescaped");
    ASSERT_EQ_INT(pkt.data[1], 0x42, "0x42 unchanged");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_readPacket_escape_escape_byte(void)
{
    TEST_BEGIN(test_readPacket_escape_escape_byte);

    /* Data byte 0xD0 (ESCAPE) must also be escaped → 0xD0 0xCF */
    unsigned char data[] = {0xD0};
    unsigned char wire[32];
    int wlen = jvs_build_wire(wire, 0xFF, data, 1);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[0];
    write(fds[1], wire, wlen);

    JVSPacket pkt;
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "readPacket with escaped 0xD0 SUCCESS");
    ASSERT_EQ_INT(pkt.data[0], 0xD0, "0xD0 correctly unescaped");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_readPacket_sync_resets_parser(void)
{
    TEST_BEGIN(test_readPacket_sync_resets_parser);

    /* Send garbage bytes followed by a valid packet – parser should re-sync */
    unsigned char data[] = {0x10};          /* CMD_REQUEST_ID */
    unsigned char wire[32];
    int wlen = jvs_build_wire(wire, 0x01, data, 1);

    unsigned char stream[64];
    int slen = 0;
    /* Garbage: a partial packet with wrong content */
    stream[slen++] = 0xE0;  /* SYNC */
    stream[slen++] = 0xAB;  /* spurious destination */
    stream[slen++] = 0x05;  /* length */
    /* Valid packet follows */
    memcpy(stream + slen, wire, wlen);
    slen += wlen;

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[0];
    write(fds[1], stream, slen);

    JVSPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    JVSStatus s = readPacket(&pkt);
    /* The second SYNC inside 'wire' resets the parser (including checksum)
     * so the good packet must decode with SUCCESS. */
    ASSERT(s == JVS_STATUS_SUCCESS, "parser recovers after spurious SYNC");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

/*
 * Verify that the checksum accumulator is correctly zeroed when a SYNC byte
 * is seen mid-stream, so a valid packet that follows a partial one decodes
 * with the right checksum.
 *
 * Stream layout (all wire-escaped):
 *   [partial bad packet: SYNC dest=0x02 len=0x05 data=0xAA]
 *   [valid full packet:  SYNC dest=0x01 len=0x02 data=0x10 checksum]
 *
 * Before the fix the checksum was never reset; the partial packet's bytes
 * would pollute the accumulator, causing the second packet to fail with
 * JVS_STATUS_ERROR_CHECKSUM.
 */
static void test_readPacket_checksum_reset_on_sync(void)
{
    TEST_BEGIN(test_readPacket_checksum_reset_on_sync);

    /* Build a valid packet: dest=0x01, data=[0x10] */
    unsigned char valid_data[] = {0x10};
    unsigned char valid_wire[32];
    int valid_len = jvs_build_wire(valid_wire, 0x01, valid_data, 1);

    unsigned char stream[128];
    int slen = 0;

    /* Partial bad packet: SYNC + dest + length (no data, no complete packet) */
    stream[slen++] = 0xE0;  /* SYNC */
    stream[slen++] = 0x02;  /* dest */
    stream[slen++] = 0x05;  /* length (claims 4 data bytes – won't arrive) */
    stream[slen++] = 0xAA;  /* one data byte – leaves stream incomplete */

    /* Immediately follow with the well-formed packet */
    ASSERT(slen + valid_len <= (int)sizeof(stream), "stream buffer sufficient");
    memcpy(stream + slen, valid_wire, valid_len);
    slen += valid_len;

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[0];
    write(fds[1], stream, slen);

    JVSPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS,
           "valid packet after partial one must succeed (checksum reset on SYNC)");
    ASSERT_EQ_INT(pkt.destination, 0x01, "correct destination decoded");
    ASSERT_EQ_INT(pkt.data[0], 0x10, "correct command byte decoded");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_readPacket_timeout(void)
{
    TEST_BEGIN(test_readPacket_timeout);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[0];
    /* Don't write anything – readPacket must time out */
    JVSPacket pkt;
    JVSStatus s = readPacket(&pkt);
    ASSERT(s == JVS_STATUS_ERROR_TIMEOUT, "empty pipe → timeout");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_writePacket_basic(void)
{
    TEST_BEGIN(test_writePacket_basic);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[1];  /* write side */

    JVSPacket pkt;
    pkt.destination = 0x00;  /* BUS_MASTER */
    pkt.length      = 2;
    pkt.data[0]     = 0x01;  /* STATUS_SUCCESS */
    pkt.data[1]     = 0x01;  /* REPORT_SUCCESS */

    JVSStatus s = writePacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "writePacket SUCCESS");
    ASSERT_EQ_INT(pkt.length, 2, "packet length not modified after writePacket");

    /* Read and decode the raw bytes from the pipe */
    unsigned char buf[64];
    int n = (int)read(fds[0], buf, sizeof(buf));
    ASSERT(n >= 6, "at least 6 bytes written");
    ASSERT_EQ_INT(buf[0], 0xE0, "SYNC byte");
    ASSERT_EQ_INT(buf[1], 0x00, "destination = BUS_MASTER");
    ASSERT_EQ_INT(buf[2], 0x03, "wire length = 3");
    ASSERT_EQ_INT(buf[3], 0x01, "STATUS_SUCCESS");
    ASSERT_EQ_INT(buf[4], 0x01, "REPORT_SUCCESS");
    /* Checksum = (0x00 + 0x03 + 0x01 + 0x01) & 0xFF = 0x05 */
    ASSERT_EQ_INT(buf[5], 0x05, "checksum");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_writePacket_length_not_modified(void)
{
    TEST_BEGIN(test_writePacket_length_not_modified);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[1];

    JVSPacket pkt;
    pkt.destination = 0x00;
    pkt.length      = 3;
    pkt.data[0]     = 0x01;
    pkt.data[1]     = 0x01;
    pkt.data[2]     = 0x42;

    unsigned char saved = pkt.length;
    writePacket(&pkt);
    ASSERT_EQ_INT(pkt.length, saved, "writePacket must not permanently modify packet->length");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_writePacket_below_min_length(void)
{
    TEST_BEGIN(test_writePacket_below_min_length);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[1];

    JVSPacket pkt;
    pkt.destination = 0x00;
    pkt.length      = 0;  /* truly empty → must not write */
    pkt.data[0]     = 0x01;

    JVSStatus s = writePacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "returns SUCCESS even with empty packet");

    /* No bytes should have been written */
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    unsigned char buf[64];
    int n = (int)read(fds[0], buf, sizeof(buf));
    ASSERT(n <= 0, "no bytes written for empty packet");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

static void test_writePacket_escape_in_data(void)
{
    TEST_BEGIN(test_writePacket_escape_in_data);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[1];

    JVSPacket pkt;
    pkt.destination = 0x00;
    pkt.length      = 3;
    pkt.data[0]     = 0x01;  /* STATUS_SUCCESS */
    pkt.data[1]     = 0xE0;  /* SYNC – must be escaped */
    pkt.data[2]     = 0x01;

    writePacket(&pkt);

    unsigned char buf[64];
    int n = (int)read(fds[0], buf, sizeof(buf));
    ASSERT(n >= 7, "extra escape byte expands packet");

    /* Find and verify the escaped 0xE0 sequence */
    int found = 0;
    for (int i = 1; i < n - 1; i++) {
        if (buf[i] == 0xD0 && buf[i + 1] == 0xDF) { found = 1; break; }
    }
    ASSERT(found, "0xE0 in data escaped as 0xD0 0xDF");
    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

/*
 * writePacket must return JVS_STATUS_ERROR and not produce any wire output
 * when packet->length == JVS_MAX_PACKET_SIZE (255).  Adding 1 for the JVS
 * wire-format checksum would overflow the 1-byte length field (256 truncates
 * to 0), sending an unparseable packet to the arcade machine.
 */
static void test_writePacket_max_length_guard(void)
{
    TEST_BEGIN(test_writePacket_max_length_guard);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[1];

    JVSPacket pkt;
    pkt.destination = BUS_MASTER;
    pkt.length      = JVS_MAX_PACKET_SIZE;  /* 255 — wireLength would wrap to 0 */
    memset(pkt.data, 0x01, sizeof(pkt.data));

    JVSStatus s = writePacket(&pkt);
    ASSERT(s == JVS_STATUS_ERROR, "writePacket with length==MAX must return ERROR");
    ASSERT_EQ_INT(pkt.length, JVS_MAX_PACKET_SIZE, "packet->length must not be modified");

    /* No bytes should have been written to the wire */
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    unsigned char buf[64];
    int n = (int)read(fds[0], buf, sizeof(buf));
    ASSERT(n <= 0, "no bytes written when length overflow guard fires");

    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

/** Send a JVS command packet from the arcade side and call processPacket(). */
static JVSStatus run_processPacket(JVSIO *io, int arcade_fd,
                                   unsigned char dest,
                                   const unsigned char *cmd_data, int cmd_len)
{
    unsigned char wire[512];
    int wlen = jvs_build_wire(wire, dest, cmd_data, cmd_len);
    write(arcade_fd, wire, wlen);
    return processPacket(io);
}

static void test_processPacket_cmd_reset(void)
{
    TEST_BEGIN(test_processPacket_cmd_reset);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;  /* pre-assigned */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* CMD_RESET (broadcast) – device ID must be cleared, no response */
    unsigned char cmd[] = {CMD_RESET, CMD_RESET_ARG};
    JVSStatus s = run_processPacket(&io, afd, BROADCAST, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_RESET returns SUCCESS");
    ASSERT_EQ_INT(io.deviceID, -1, "deviceID reset to -1");

    /* No response should be written (CMD_RESET is broadcast-only per JVS spec) */
    ASSERT(!fd_has_data(afd), "CMD_RESET produces no response");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_assign_addr(void)
{
    TEST_BEGIN(test_processPacket_cmd_assign_addr);

    JVSIO io = make_test_io();
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_ASSIGN_ADDR, 0x01};
    JVSStatus s = run_processPacket(&io, afd, BROADCAST, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_ASSIGN_ADDR returns SUCCESS");
    ASSERT_EQ_INT(io.deviceID, 0x01, "deviceID assigned");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response checksum ok");
    ASSERT_EQ_INT(r.dest, BUS_MASTER, "response to bus master");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * When every IO in the chain already has an address assigned and the arcade
 * board re-sends CMD_ASSIGN_ADDR (e.g. without an intervening CMD_RESET),
 * the emulator must acknowledge with REPORT_SUCCESS but must NOT overwrite the
 * existing address.
 */
static void test_processPacket_cmd_assign_addr_all_assigned(void)
{
    TEST_BEGIN(test_processPacket_cmd_assign_addr_all_assigned);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;  /* already assigned */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Try to assign a different address to an already-assigned single-device chain */
    unsigned char cmd[] = {CMD_ASSIGN_ADDR, 0x02};
    JVSStatus s = run_processPacket(&io, afd, BROADCAST, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_ASSIGN_ADDR still returns SUCCESS");

    /* Existing address must not be overwritten */
    ASSERT_EQ_INT(io.deviceID, 0x01, "deviceID unchanged after re-assign attempt");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_request_id(void)
{
    TEST_BEGIN(test_processPacket_cmd_request_id);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_REQUEST_ID};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 1);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_REQUEST_ID returns SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS, "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* Name starts at data[2] */
    ASSERT(r.data_len > 2, "response includes name bytes");
    ASSERT(strcmp((char *)&r.data[2], io.capabilities.name) == 0, "name matches");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_command_version(void)
{
    TEST_BEGIN(test_processPacket_cmd_command_version);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_COMMAND_VERSION};
    run_processPacket(&io, afd, 0x01, cmd, 1);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");
    ASSERT_EQ_INT(r.data[2], io.capabilities.commandVersion, "commandVersion");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_jvs_version(void)
{
    TEST_BEGIN(test_processPacket_cmd_jvs_version);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_JVS_VERSION};
    run_processPacket(&io, afd, 0x01, cmd, 1);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[2], io.capabilities.jvsVersion, "jvsVersion");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_comms_version(void)
{
    TEST_BEGIN(test_processPacket_cmd_comms_version);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_COMMS_VERSION};
    run_processPacket(&io, afd, 0x01, cmd, 1);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[2], io.capabilities.commsVersion, "commsVersion");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_capabilities(void)
{
    TEST_BEGIN(test_processPacket_cmd_capabilities);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_CAPABILITIES};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 1);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_CAPABILITIES SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS, "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* CAP_PLAYERS should be present (0x01) */
    ASSERT(r.data_len > 4, "capabilities data present");
    ASSERT_EQ_INT(r.data[2], CAP_PLAYERS, "first capability = CAP_PLAYERS");
    ASSERT_EQ_INT(r.data[3], io.capabilities.players, "player count");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_switches_zero(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_switches_zero);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    /* All switches zero (default from initIO) */
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Request 2 players, 16 switches each */
    unsigned char cmd[] = {CMD_READ_SWITCHES, 0x02, 0x10};
    run_processPacket(&io, afd, 0x01, cmd, 3);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS, "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    ASSERT_EQ_INT(r.data[2], 0x00, "system switch byte = 0");
    ASSERT_EQ_INT(r.data[3], 0x00, "P1 high byte = 0");
    ASSERT_EQ_INT(r.data[4], 0x00, "P1 low byte = 0");
    ASSERT_EQ_INT(r.data[5], 0x00, "P2 high byte = 0");
    ASSERT_EQ_INT(r.data[6], 0x00, "P2 low byte = 0");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_switches_pressed(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_switches_pressed);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    setSwitch(&io, SYSTEM,   BUTTON_TEST,  1);
    setSwitch(&io, PLAYER_1, BUTTON_START, 1);
    setSwitch(&io, PLAYER_1, BUTTON_1,     1);

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_SWITCHES, 0x02, 0x10};
    run_processPacket(&io, afd, 0x01, cmd, 3);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");

    /* System byte: BUTTON_TEST is bit 7 → 0x80 */
    ASSERT(r.data[2] & 0x80, "BUTTON_TEST in system byte");
    /* Player 1 high byte: BUTTON_START is bit 7 of the 16-bit word → high byte bit 7 */
    ASSERT(r.data[3] & (BUTTON_START >> 8), "BUTTON_START in P1 high byte");
    /* BUTTON_1 is bit 9 of the 16-bit word → high byte bit 1 */
    ASSERT(r.data[3] & (BUTTON_1 >> 8), "BUTTON_1 in P1 high byte");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_coins(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_coins);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    incrementCoin(&io, PLAYER_1, 5);
    incrementCoin(&io, PLAYER_2, 3);

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_COINS, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS, "STATUS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT");
    /* Slot 1: 0x00 0x05 */
    ASSERT_EQ_INT(r.data[2], 0x00, "slot1 high");
    ASSERT_EQ_INT(r.data[3], 0x05, "slot1 low");
    /* Slot 2: 0x00 0x03 */
    ASSERT_EQ_INT(r.data[4], 0x00, "slot2 high");
    ASSERT_EQ_INT(r.data[5], 0x03, "slot2 low");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_analogs(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_analogs);

    JVSIO io = make_test_io();  /* analogueInBits=10, analogueRestBits=6 */
    io.deviceID = 0x01;
    setAnalogue(&io, ANALOGUE_1, 1.0);  /* analogueChannel[0] = 1023 */
    setAnalogue(&io, ANALOGUE_2, 0.0);  /* analogueChannel[1] = 0    */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_ANALOGS, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    /* analogData = 1023 << 6 = 65472 = 0xFFC0 */
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT");
    ASSERT_EQ_INT(r.data[2], 0xFF, "ch0 high byte");
    ASSERT_EQ_INT(r.data[3], 0xC0, "ch0 low byte");
    ASSERT_EQ_INT(r.data[4], 0x00, "ch1 high byte");
    ASSERT_EQ_INT(r.data[5], 0x00, "ch1 low byte");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_rotary(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_rotary);

    JVSIO io = make_test_io();  /* rotaryChannels=2 */
    io.deviceID = 0x01;
    setRotary(&io, ROTARY_1, 0x1234);
    setRotary(&io, ROTARY_2, 0x00AB);

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_ROTARY, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT");
    ASSERT_EQ_INT(r.data[2], 0x12, "rotary1 high");
    ASSERT_EQ_INT(r.data[3], 0x34, "rotary1 low");
    ASSERT_EQ_INT(r.data[4], 0x00, "rotary2 high");
    ASSERT_EQ_INT(r.data[5], 0xAB, "rotary2 low");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_lightgun(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_lightgun);

    JVSIO io = make_test_io();  /* gunChannels=2, gunXBits=12, gunYBits=12 */
    io.deviceID = 0x01;
    /* Gun 1: X=full (4095), Y=0 (stored: (1.0-0.0)*4095=4095) */
    setGun(&io, 0, 1.0);  /* X → gunChannel[0] = 4095 */
    setGun(&io, 1, 0.0);  /* Y → gunChannel[1] = (1-0)*4095 = 4095 */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_LIGHTGUN, 0x01};  /* 1 gun */
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT");
    /* gunRestBits=4 for 12-bit: xData = 4095 << 4 = 65520 = 0xFFF0 */
    ASSERT_EQ_INT(r.data[2], 0xFF, "gun X high");
    ASSERT_EQ_INT(r.data[3], 0xF0, "gun X low");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_gpi(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_gpi);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_GPI, 0x02};  /* 2 bytes of GPI */
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT");
    ASSERT_EQ_INT(r.data[2], 0x00, "GPI byte 0 = 0");
    ASSERT_EQ_INT(r.data[3], 0x00, "GPI byte 1 = 0");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_decrease_coins(void)
{
    TEST_BEGIN(test_processPacket_cmd_decrease_coins);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    io.state.coinCount[0] = 10;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Decrease slot 1 by 3: [CMD_DECREASE_COINS, slot=0x01, high=0x00, low=0x03] */
    unsigned char cmd[] = {CMD_DECREASE_COINS, 0x01, 0x00, 0x03};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 4);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_DECREASE_COINS SUCCESS");
    ASSERT_EQ_INT(io.state.coinCount[0], 7, "coinCount decreased by 3");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_write_coins(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_coins);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    io.state.coinCount[1] = 0;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Increment slot 2 by 7: [CMD_WRITE_COINS, slot=0x02, high=0x00, low=0x07] */
    unsigned char cmd[] = {CMD_WRITE_COINS, 0x02, 0x00, 0x07};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 4);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_COINS SUCCESS");
    ASSERT_EQ_INT(io.state.coinCount[1], 7, "slot 2 coin count = 7");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_write_gpo(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_gpo);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Write 1 GPO byte of value 0xAA */
    unsigned char cmd[] = {CMD_WRITE_GPO, 0x01, 0xAA};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 3);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_GPO SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_write_gpo_byte(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_gpo_byte);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Write byte index 0, value 0x55 */
    unsigned char cmd[] = {CMD_WRITE_GPO_BYTE, 0x00, 0x55};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 3);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_GPO_BYTE SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_convey_id(void)
{
    TEST_BEGIN(test_processPacket_cmd_convey_id);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* CONVEY_ID with string "SEGA" + null */
    unsigned char cmd[] = {CMD_CONVEY_ID, 'S', 'E', 'G', 'A', '\0'};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 6);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_CONVEY_ID SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_remaining_payout(void)
{
    TEST_BEGIN(test_processPacket_cmd_remaining_payout);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_REMAINING_PAYOUT, 0x01};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_set_payout(void)
{
    TEST_BEGIN(test_processPacket_cmd_set_payout);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_SET_PAYOUT, 0x01, 0x00, 0x00};
    run_processPacket(&io, afd, 0x01, cmd, 4);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_not_for_us(void)
{
    TEST_BEGIN(test_processPacket_not_for_us);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Packet addressed to 0x02 – our deviceID is 0x01 */
    unsigned char cmd[] = {CMD_REQUEST_ID};
    JVSStatus s = run_processPacket(&io, afd, 0x02, cmd, 1);
    ASSERT(s == JVS_STATUS_NOT_FOR_US, "non-matching address → NOT_FOR_US");
    ASSERT(!fd_has_data(afd), "no response when not for us");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_broadcast_after_assign(void)
{
    TEST_BEGIN(test_processPacket_broadcast_after_assign);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* CMD_RESET via broadcast – should still be handled */
    unsigned char cmd[] = {CMD_RESET, CMD_RESET_ARG};
    JVSStatus s = run_processPacket(&io, afd, BROADCAST, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "BROADCAST accepted even after address assignment");
    ASSERT_EQ_INT(io.deviceID, -1, "deviceID reset");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_retransmit(void)
{
    TEST_BEGIN(test_processPacket_retransmit);

    JVSIO io = make_test_io();
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Step 1: Send CMD_ASSIGN_ADDR (broadcast); response = STATUS + REPORT */
    unsigned char cmd_assign[] = {CMD_ASSIGN_ADDR, 0x01};
    run_processPacket(&io, afd, BROADCAST, cmd_assign, 2);

    /* Read and discard the assign response */
    JVSResponse r1 = jvs_read_response(afd);
    ASSERT(r1.valid == 1, "first response valid");
    int first_data_len = r1.data_len;

    /* Step 2: Send CMD_RETRANSMIT; device must re-send the SAME packet */
    unsigned char cmd_retx[] = {CMD_RETRANSMIT};
    run_processPacket(&io, afd, 0x01, cmd_retx, 1);

    JVSResponse r2 = jvs_read_response(afd);
    ASSERT(r2.valid == 1, "retransmit response valid checksum");
    ASSERT_EQ_INT(r2.data_len, first_data_len, "retransmit length matches original");
    ASSERT(memcmp(r1.data, r2.data, (size_t)first_data_len) == 0, "retransmit data matches");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_multi_command(void)
{
    TEST_BEGIN(test_processPacket_multi_command);

    /* Pack CMD_COMMAND_VERSION + CMD_JVS_VERSION into one JVS packet */
    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_COMMAND_VERSION, CMD_JVS_VERSION};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "multi-command SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS, "STATUS_SUCCESS");
    /* First command result: REPORT + version byte */
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "first REPORT");
    ASSERT_EQ_INT(r.data[2], io.capabilities.commandVersion, "commandVersion");
    /* Second command result: REPORT + version byte */
    ASSERT_EQ_INT(r.data[3], REPORT_SUCCESS, "second REPORT");
    ASSERT_EQ_INT(r.data[4], io.capabilities.jvsVersion, "jvsVersion");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_chained_address_assign(void)
{
    TEST_BEGIN(test_processPacket_chained_address_assign);

    /* Two chained IO boards: first assigns 0x01, second assigns 0x02 */
    JVSIO io2;
    memset(&io2, 0, sizeof(io2));
    io2.deviceID  = -1;
    io2.chainedIO = NULL;
    strncpy(io2.capabilities.name, "test-second", sizeof(io2.capabilities.name) - 1);
    initIO(&io2);

    JVSIO io1 = make_test_io();
    io1.chainedIO = &io2;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Assign address 0x01 to first unassigned (io1) */
    unsigned char cmd1[] = {CMD_ASSIGN_ADDR, 0x01};
    run_processPacket(&io1, afd, BROADCAST, cmd1, 2);
    jvs_read_response(afd);  /* consume response */

    ASSERT_EQ_INT(io1.deviceID, 0x01, "io1 assigned 0x01");
    ASSERT_EQ_INT(io2.deviceID, -1,   "io2 not yet assigned");

    /* Assign address 0x02 to next unassigned (io2) */
    unsigned char cmd2[] = {CMD_ASSIGN_ADDR, 0x02};
    run_processPacket(&io1, afd, BROADCAST, cmd2, 2);
    jvs_read_response(afd);  /* consume response */

    ASSERT_EQ_INT(io1.deviceID, 0x01, "io1 still 0x01");
    ASSERT_EQ_INT(io2.deviceID, 0x02, "io2 assigned 0x02");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_connection_timeout(void)
{
    TEST_BEGIN(test_processPacket_connection_timeout);

    /* Verify that JVS_STATUS_ERROR_TIMEOUT is returned when no data arrives */
    JVSIO io = make_test_io();
    io.deviceID = 0x01;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Write nothing – processPacket should time out */
    JVSStatus s = processPacket(&io);
    ASSERT(s == JVS_STATUS_ERROR_TIMEOUT, "empty socket → TIMEOUT");

    close(sv[0]); close(sv[1]); serialIO = -1;
    (void)afd;
    TEST_PASS();
}

static void test_processPacket_namco_specific(void)
{
    TEST_BEGIN(test_processPacket_namco_specific);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Namco sub-command 0x01: returns 8 bytes of 0xFF */
    unsigned char cmd[] = {CMD_NAMCO_SPECIFIC, 0x01};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_NAMCO_SPECIFIC 0x01 SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    for (int i = 2; i < 10; i++)
        ASSERT_EQ_INT(r.data[i], 0xFF, "Namco response byte = 0xFF");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_namco_specific_program_date(void)
{
    TEST_BEGIN(test_processPacket_namco_specific_program_date);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Namco sub-command 0x02: program date */
    unsigned char cmd[] = {CMD_NAMCO_SPECIFIC, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* First two bytes of extId: 0x19 0x97 */
    ASSERT_EQ_INT(r.data[2], 0x19, "extId byte 0 = 0x19");
    ASSERT_EQ_INT(r.data[3], 0x97, "extId byte 1 = 0x97");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * Namco sub-command 0x03: DIP switch status.
 * Must return REPORT_SUCCESS followed by exactly one byte of 0xFF.
 */
static void test_processPacket_namco_specific_dip_switch(void)
{
    TEST_BEGIN(test_processPacket_namco_specific_dip_switch);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_NAMCO_SPECIFIC, 0x03};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_NAMCO_SPECIFIC 0x03 SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response checksum valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");
    ASSERT_EQ_INT(r.data[2], 0xFF, "DIP byte = 0xFF");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * Namco sub-command 0x04: unknown status bytes.
 * Must return REPORT_SUCCESS followed by two bytes of 0xFF.
 */
static void test_processPacket_namco_specific_04(void)
{
    TEST_BEGIN(test_processPacket_namco_specific_04);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_NAMCO_SPECIFIC, 0x04};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_NAMCO_SPECIFIC 0x04 SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response checksum valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");
    ASSERT_EQ_INT(r.data[2], 0xFF, "first byte = 0xFF");
    ASSERT_EQ_INT(r.data[3], 0xFF, "second byte = 0xFF");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * Unsupported command: an unrecognised command byte must cause the response
 * STATUS byte to be STATUS_UNSUPPORTED (0x02) and stop further processing.
 */
static void test_processPacket_unsupported_command(void)
{
    TEST_BEGIN(test_processPacket_unsupported_command);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* 0xAA is not a defined JVS command */
    unsigned char cmd[] = {0xAA};
    run_processPacket(&io, afd, 0x01, cmd, 1);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_UNSUPPORTED, "STATUS_UNSUPPORTED");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_REMAINING_PAYOUT with 2 slots: response must contain REPORT_SUCCESS
 * followed by exactly 2 zero-bytes per requested slot (4 bytes total for 2 slots).
 */
static void test_processPacket_cmd_remaining_payout_two_slots(void)
{
    TEST_BEGIN(test_processPacket_cmd_remaining_payout_two_slots);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_REMAINING_PAYOUT, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");
    /* 2 slots × 2 bytes each = 4 data bytes, all zero */
    ASSERT_EQ_INT(r.data[2], 0x00, "slot1 high = 0");
    ASSERT_EQ_INT(r.data[3], 0x00, "slot1 low = 0");
    ASSERT_EQ_INT(r.data[4], 0x00, "slot2 high = 0");
    ASSERT_EQ_INT(r.data[5], 0x00, "slot2 low = 0");
    /* Total response data length: STATUS(1) + REPORT(1) + 2*2 = 6 */
    ASSERT_EQ_INT(r.data_len, 6, "data_len = 6");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * INCLUDE depth limit: a chain of 12 files each including the next should not
 * crash or recurse infinitely.  After MAX_INCLUDE_DEPTH (10) levels the
 * remaining files are silently skipped.  The settings set in the first 10
 * files must be applied; the setting in file 11 must NOT be applied.
 */
static void test_parseConfig_include_depth_limit(void)
{
    TEST_BEGIN(test_parseConfig_include_depth_limit);

#define CHAIN_LEN 12
    char paths[CHAIN_LEN][64];
    for (int i = 0; i < CHAIN_LEN; i++)
        snprintf(paths[i], sizeof(paths[i]), "/tmp/mjtest_chain_%02d.conf", i);

    /* Write from the deepest file upward so each includes the next */
    for (int i = CHAIN_LEN - 1; i >= 0; i--)
    {
        FILE *f = fopen(paths[i], "w");
        ASSERT(f != NULL, "create chain file");
        if (i < CHAIN_LEN - 1)
            fprintf(f, "INCLUDE %s\n", paths[i + 1]);
        /* Every file sets DEBUG_MODE to its depth index, except file 11
         * which uses a sentinel value (999) that must NOT appear in cfg
         * because it lives beyond MAX_INCLUDE_DEPTH=10. */
        int val = (i == CHAIN_LEN - 1) ? 999 : i;
        fprintf(f, "DEBUG_MODE %d\n", val);
        fclose(f);
    }

    JVSConfig cfg;
    getDefaultConfig(&cfg);
    /* Must not crash or hang */
    parseConfig(paths[0], &cfg);

    /* File 0 sets DEBUG_MODE 0, file 1 sets 1, … file 10 (depth 10 = limit)
     * would be skipped.  The last successfully applied value comes from file 9
     * (depth 9 < MAX_INCLUDE_DEPTH=10), which sets DEBUG_MODE 9.
     * File 0's own "DEBUG_MODE 0" line runs AFTER the INCLUDE returns, so the
     * final value is 0 (file 0 wins because it appears after the INCLUDE). */
    ASSERT_EQ_INT(cfg.debugLevel, 0, "depth-limited INCLUDE chain completes without crash");
    /* Verify the sentinel value from file 11 was NOT applied */
    ASSERT(cfg.debugLevel != 999, "file beyond depth limit must not be applied");

    for (int i = 0; i < CHAIN_LEN; i++)
        unlink(paths[i]);
#undef CHAIN_LEN
    TEST_PASS();
}

/*
 * writePacket must correctly emit all data bytes for a large (but non-trivial)
 * packet.  This exercises the int wireLength fix that prevents an unsigned-char
 * overflow when packet->length == 255 (which the old code incremented directly,
 * wrapping to 0 and causing the wire-format loop to emit only 1 byte).
 *
 * With length = 10 the wire frame must be:
 *   SYNC(1) + dest(1) + wire_len(1) + 9 data bytes(9) + checksum(1) = 13 bytes
 * and packet->length must equal 10 after the call (unchanged by callee).
 */
static void test_writePacket_large_length_no_wrap(void)
{
    TEST_BEGIN(test_writePacket_large_length_no_wrap);

    int fds[2];
    ASSERT(pipe(fds) == 0, "pipe");
    serialIO = fds[1];

    JVSPacket pkt;
    pkt.destination = BUS_MASTER;
    pkt.length      = 10;
    /* 9 identifiable data bytes (length - 1, since length counts checksum too) */
    for (int i = 0; i < 9; i++)
        pkt.data[i] = (unsigned char)(0x10 + i);

    unsigned char saved_length = pkt.length;
    JVSStatus s = writePacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "writePacket SUCCESS");
    ASSERT_EQ_INT(pkt.length, (int)saved_length, "packet->length not modified after writePacket");

    unsigned char buf[128];
    int n = (int)read(fds[0], buf, sizeof(buf));
    /* Minimum: SYNC(1) + dest(1) + wire_len_field(1) + 9 data bytes + checksum(1) = 13.
     * More if any byte is 0xE0 or 0xD0 and needs escaping. */
    ASSERT(n >= 13, "correct minimum number of bytes written");
    ASSERT_EQ_INT(buf[0], 0xE0, "SYNC byte");
    ASSERT_EQ_INT(buf[1], BUS_MASTER, "destination byte");
    /* Wire length field = saved_length + 1 = 11 */
    ASSERT_EQ_INT(buf[2], (int)(saved_length + 1), "wire length field = packet->length + 1");

    close(fds[0]);
    close(fds[1]);
    serialIO = -1;
    TEST_PASS();
}

/*
 * INCLUDE in a device mapping file must *merge* the included mappings into the
 * current set rather than replacing them.  A mapping declared before the INCLUDE
 * line must survive alongside the mappings brought in by the include.
 *
 * The bug (now fixed): parseInputMappingInternal used memcpy to replace the
 * entire InputMappings struct with the included file's contents, silently
 * discarding any mappings already parsed in the outer file.
 *
 * Test layout:
 *   mjtest-incl-base-dev:    BTN_EAST  → CONTROLLER_BUTTON_B
 *   mjtest-incl-overlay-dev: BTN_SOUTH → CONTROLLER_BUTTON_A
 *                            INCLUDE mjtest-incl-base-dev
 *
 * Expected: mappings.length >= 2, both BUTTON_A and BUTTON_B present.
 */
static void test_parseInputMapping_include_merges(void)
{
    TEST_BEGIN(test_parseInputMapping_include_merges);

    /* Create the directory hierarchy required by parseInputMapping */
    if (mkdir("/etc/modernjvs", 0755) == -1 && errno != EEXIST)
    {
        printf("    SKIP: cannot create /etc/modernjvs (%s)\n", strerror(errno));
        TEST_PASS();
        return;
    }
    if (mkdir("/etc/modernjvs/devices", 0755) == -1 && errno != EEXIST)
    {
        printf("    SKIP: cannot create /etc/modernjvs/devices (%s)\n", strerror(errno));
        TEST_PASS();
        return;
    }

    const char *base_path    = "/etc/modernjvs/devices/mjtest-incl-base-dev";
    const char *overlay_path = "/etc/modernjvs/devices/mjtest-incl-overlay-dev";

    FILE *f = fopen(base_path, "w");
    ASSERT(f != NULL, "create base device file");
    fprintf(f, "BTN_EAST CONTROLLER_BUTTON_B\n");
    fclose(f);

    f = fopen(overlay_path, "w");
    ASSERT(f != NULL, "create overlay device file");
    /* CONTROLLER_BUTTON_A mapping comes BEFORE the INCLUDE – this is the
     * case that the old memcpy-replace code silently dropped. */
    fprintf(f, "BTN_SOUTH CONTROLLER_BUTTON_A\nINCLUDE mjtest-incl-base-dev\n");
    fclose(f);

    InputMappings mappings;
    memset(&mappings, 0, sizeof(mappings));
    JVSConfigStatus s = parseInputMapping("mjtest-incl-overlay-dev", &mappings);
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "parseInputMapping SUCCESS");

    /* Both the pre-INCLUDE mapping (BUTTON_A) and the included mapping
     * (BUTTON_B) must be present after the merge. */
    ASSERT(mappings.length >= 2, "both mappings present after INCLUDE merge");

    int found_a = 0, found_b = 0;
    for (int i = 0; i < mappings.length; i++)
    {
        if (mappings.mappings[i].input == CONTROLLER_BUTTON_A) found_a = 1;
        if (mappings.mappings[i].input == CONTROLLER_BUTTON_B) found_b = 1;
    }
    ASSERT(found_a, "CONTROLLER_BUTTON_A (before INCLUDE) preserved by merge");
    ASSERT(found_b, "CONTROLLER_BUTTON_B (from INCLUDE) present after merge");

    unlink(base_path);
    unlink(overlay_path);
    TEST_PASS();
}

/*
 * INCLUDE in a game output-mapping file must *merge* the included mappings into
 * the current set rather than replacing them.
 *
 * The same memcpy-replace bug existed in parseOutputMappingInternal.
 *
 * Test layout:
 *   mjtest-incl-base-game:    CONTROLLER_BUTTON_B CONTROLLER_1 BUTTON_2 PLAYER_1
 *   mjtest-incl-overlay-game: CONTROLLER_BUTTON_A CONTROLLER_1 BUTTON_1 PLAYER_1
 *                             INCLUDE mjtest-incl-base-game
 *
 * Expected: mappings.length >= 2, both BUTTON_A and BUTTON_B present.
 */
static void test_parseOutputMapping_include_merges(void)
{
    TEST_BEGIN(test_parseOutputMapping_include_merges);

    if (mkdir("/etc/modernjvs", 0755) == -1 && errno != EEXIST)
    {
        printf("    SKIP: cannot create /etc/modernjvs (%s)\n", strerror(errno));
        TEST_PASS();
        return;
    }
    if (mkdir("/etc/modernjvs/games", 0755) == -1 && errno != EEXIST)
    {
        printf("    SKIP: cannot create /etc/modernjvs/games (%s)\n", strerror(errno));
        TEST_PASS();
        return;
    }

    const char *base_path    = "/etc/modernjvs/games/mjtest-incl-base-game";
    const char *overlay_path = "/etc/modernjvs/games/mjtest-incl-overlay-game";

    FILE *f = fopen(base_path, "w");
    ASSERT(f != NULL, "create base game file");
    fprintf(f, "CONTROLLER_BUTTON_B CONTROLLER_1 BUTTON_2 PLAYER_1\n");
    fclose(f);

    f = fopen(overlay_path, "w");
    ASSERT(f != NULL, "create overlay game file");
    /* CONTROLLER_BUTTON_A mapping comes BEFORE the INCLUDE. */
    fprintf(f, "CONTROLLER_BUTTON_A CONTROLLER_1 BUTTON_1 PLAYER_1\nINCLUDE mjtest-incl-base-game\n");
    fclose(f);

    OutputMappings mappings;
    memset(&mappings, 0, sizeof(mappings));
    char configPath[MAX_PATH_LENGTH]       = "";
    char secondConfigPath[MAX_PATH_LENGTH] = "";
    JVSConfigStatus s = parseOutputMapping("mjtest-incl-overlay-game", &mappings,
                                           configPath, secondConfigPath);
    ASSERT(s == JVS_CONFIG_STATUS_SUCCESS, "parseOutputMapping SUCCESS");

    ASSERT(mappings.length >= 2, "both mappings present after INCLUDE merge");

    int found_a = 0, found_b = 0;
    for (int i = 0; i < mappings.length; i++)
    {
        if (mappings.mappings[i].input == CONTROLLER_BUTTON_A) found_a = 1;
        if (mappings.mappings[i].input == CONTROLLER_BUTTON_B) found_b = 1;
    }
    ASSERT(found_a, "CONTROLLER_BUTTON_A (before INCLUDE) preserved by merge");
    ASSERT(found_b, "CONTROLLER_BUTTON_B (from INCLUDE) present after merge");

    unlink(base_path);
    unlink(overlay_path);
    TEST_PASS();
}

/**
 * Verify that initIO() clamps loop bounds when capabilities are larger than
 * JVS_MAX_STATE_SIZE.  The fix prevents out-of-bounds writes to the state
 * arrays when an IO config file specifies an unusually large capability count.
 */
static void test_initIO_oversized_capabilities(void)
{
    TEST_BEGIN(test_initIO_oversized_capabilities);

    JVSIO io;
    memset(&io, 0xFF, sizeof(io));  /* poison all bytes */

    /* Set capability counts well above JVS_MAX_STATE_SIZE (100) */
    io.capabilities.players            = 200;
    io.capabilities.analogueInChannels = 150;
    io.capabilities.analogueInBits     = 10;
    io.capabilities.rotaryChannels     = 120;
    io.capabilities.coins              = 110;
    io.capabilities.gunChannels        = 2;
    io.capabilities.gunXBits           = 12;
    io.capabilities.gunYBits           = 12;
    io.capabilities.rightAlignBits     = 0;
    io.chainedIO                       = NULL;

    /* Must not crash or corrupt memory */
    int r = initIO(&io);
    ASSERT(r == 1, "initIO with oversized capabilities returns 1");

    /* initIO should have zeroed at least the first entry in each array
     * (clamped to JVS_MAX_STATE_SIZE iterations) */
    ASSERT_EQ_INT(io.state.inputSwitch[0],     0, "system switch clamped to 0");
    ASSERT_EQ_INT(io.state.inputSwitch[1],     0, "player 1 switch clamped to 0");
    ASSERT_EQ_INT(io.state.analogueChannel[0], 0, "analogue[0] clamped to 0");
    ASSERT_EQ_INT(io.state.coinCount[0],       0, "coin[0] clamped to 0");
    ASSERT_EQ_INT(io.state.rotaryChannel[0],   0, "rotary[0] clamped to 0");
    ASSERT_EQ_INT(io.state.gunChannel[0],      0, "gunChannel[0] clamped to 0");
    ASSERT_EQ_INT(io.state.gunChannel[1],      0, "gunChannel[1] clamped to 0");

    /* analogueMax / gunXMax / gunYMax must still be computed correctly */
    ASSERT_EQ_INT(io.analogueMax, 1023, "analogueMax for 10-bit");
    ASSERT_EQ_INT(io.gunXMax,     4095, "gunXMax for 12-bit");
    ASSERT_EQ_INT(io.gunYMax,     4095, "gunYMax for 12-bit");

    TEST_PASS();
}

/**
 * initIO must set analogueMax to 0 when analogueInBits is 0 (invalid).
 * The intent is to prevent undefined-behaviour shifts and zero the channel output.
 */
static void test_initIO_zero_analogue_bits(void)
{
    TEST_BEGIN(test_initIO_zero_analogue_bits);

    JVSIO io;
    memset(&io, 0, sizeof(io));
    io.capabilities.analogueInChannels = 2;
    io.capabilities.analogueInBits     = 0;  /* invalid: guard should yield max=0 */

    int r = initIO(&io);
    ASSERT(r == 1, "initIO returns 1");
    ASSERT_EQ_INT(io.analogueMax, 0, "analogueMax = 0 for 0-bit analogue");

    TEST_PASS();
}

/**
 * initIO must set analogueMax to 0 when analogueInBits > 16 (shift would be UB).
 */
static void test_initIO_oversized_analogue_bits(void)
{
    TEST_BEGIN(test_initIO_oversized_analogue_bits);

    JVSIO io;
    memset(&io, 0, sizeof(io));
    io.capabilities.analogueInChannels = 2;
    io.capabilities.analogueInBits     = 17;  /* > 16: guard should yield max=0 */

    int r = initIO(&io);
    ASSERT(r == 1, "initIO returns 1");
    ASSERT_EQ_INT(io.analogueMax, 0, "analogueMax = 0 for 17-bit analogue");

    TEST_PASS();
}

/**
 * When rightAlignBits == 1, initJVS must leave analogueRestBits /
 * gunXRestBits / gunYRestBits at zero rather than computing (16 - bits).
 * This allows IO board files that want right-aligned (raw) output to opt
 * out of the automatic left-shift.
 */
static void test_initJVS_right_align_bits(void)
{
    TEST_BEGIN(test_initJVS_right_align_bits);

    JVSIO io;
    memset(&io, 0, sizeof(io));
    io.capabilities.analogueInBits = 10;
    io.capabilities.gunXBits       = 12;
    io.capabilities.gunYBits       = 12;
    io.capabilities.rightAlignBits = 1;  /* skip rest-bit computation */
    io.chainedIO = NULL;
    initIO(&io);
    initJVS(&io);  /* must NOT overwrite the zero rest bits */

    ASSERT_EQ_INT(io.analogueRestBits, 0, "rightAlignBits=1: analogueRestBits stays 0");
    ASSERT_EQ_INT(io.gunXRestBits,     0, "rightAlignBits=1: gunXRestBits stays 0");
    ASSERT_EQ_INT(io.gunYRestBits,     0, "rightAlignBits=1: gunYRestBits stays 0");

    TEST_PASS();
}

/**
 * initJVS must propagate the correct analogueRestBits / gunXRestBits /
 * gunYRestBits to every IO in the chain, not only the primary IO.
 *
 * This is the bug-fix regression test for the chained-IO restBits omission
 * where the second IO kept 0 restBits regardless of its bit-depth.
 */
static void test_initJVS_chained_io_rest_bits(void)
{
    TEST_BEGIN(test_initJVS_chained_io_rest_bits);

    JVSIO io1, io2;
    memset(&io1, 0, sizeof(io1));
    memset(&io2, 0, sizeof(io2));

    /* io1: 10-bit analogue, 12-bit gun */
    io1.capabilities.analogueInBits = 10;
    io1.capabilities.gunXBits       = 12;
    io1.capabilities.gunYBits       = 12;
    io1.capabilities.rightAlignBits = 0;

    /* io2: 12-bit analogue, 10-bit gun — different depths to detect mix-ups */
    io2.capabilities.analogueInBits = 12;
    io2.capabilities.gunXBits       = 10;
    io2.capabilities.gunYBits       = 10;
    io2.capabilities.rightAlignBits = 0;
    io2.chainedIO = NULL;

    io1.chainedIO = &io2;

    initIO(&io1);
    initIO(&io2);
    initJVS(&io1);  /* must walk the chain and set restBits on io2 too */

    ASSERT_EQ_INT(io1.analogueRestBits, 6,  "io1: 16-10 = 6");
    ASSERT_EQ_INT(io1.gunXRestBits,     4,  "io1: 16-12 = 4");
    ASSERT_EQ_INT(io1.gunYRestBits,     4,  "io1: 16-12 = 4");

    ASSERT_EQ_INT(io2.analogueRestBits, 4,  "io2: 16-12 = 4");
    ASSERT_EQ_INT(io2.gunXRestBits,     6,  "io2: 16-10 = 6");
    ASSERT_EQ_INT(io2.gunYRestBits,     6,  "io2: 16-10 = 6");

    TEST_PASS();
}

/**
 * Verify that CMD_RESET resets all IOs in a chained setup.
 *
 * This exercises the bug-fix that iterates the full chain and clears every
 * deviceID, not just the primary IO.  It also confirms that the connection-
 * tracking state (lastPacketTime / connectionLostLogged) is wiped by CMD_RESET
 * so that subsequent address assignment starts with a clean slate.
 */
static void test_processPacket_cmd_reset_chained_io(void)
{
    TEST_BEGIN(test_processPacket_cmd_reset_chained_io);

    JVSIO io1 = make_test_io();
    JVSIO io2 = make_test_io();
    io1.chainedIO = &io2;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Assign both devices an address first */
    unsigned char assign1[] = {CMD_ASSIGN_ADDR, 0x01};
    run_processPacket(&io1, afd, BROADCAST, assign1, 2);
    /* drain the response */
    jvs_read_response(afd);

    unsigned char assign2[] = {CMD_ASSIGN_ADDR, 0x02};
    run_processPacket(&io1, afd, BROADCAST, assign2, 2);
    jvs_read_response(afd);

    ASSERT_EQ_INT(io1.deviceID, 0x01, "io1 assigned 0x01 before reset");
    ASSERT_EQ_INT(io2.deviceID, 0x02, "io2 assigned 0x02 before reset");

    /* CMD_RESET (broadcast) must clear BOTH devices in the chain */
    unsigned char cmd_reset[] = {CMD_RESET, CMD_RESET_ARG};
    JVSStatus s = run_processPacket(&io1, afd, BROADCAST, cmd_reset, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_RESET returns SUCCESS");

    ASSERT_EQ_INT(io1.deviceID, -1, "io1.deviceID cleared after reset");
    ASSERT_EQ_INT(io2.deviceID, -1, "io2.deviceID cleared after reset");

    /* No response should be emitted for CMD_RESET */
    ASSERT(!fd_has_data(afd), "CMD_RESET produces no response");

    /* Verify we can re-assign addresses after a reset (confirms the
     * connection-tracking state was properly wiped) */
    run_processPacket(&io1, afd, BROADCAST, assign1, 2);
    jvs_read_response(afd);
    run_processPacket(&io1, afd, BROADCAST, assign2, 2);
    jvs_read_response(afd);

    ASSERT_EQ_INT(io1.deviceID, 0x01, "io1 re-assigned after reset");
    ASSERT_EQ_INT(io2.deviceID, 0x02, "io2 re-assigned after reset");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/* =========================================================================
 * ──────────────────── ADDITIONAL COMMAND TESTS ───────────────────────────
 * ========================================================================= */

static void test_processPacket_cmd_set_comms_mode(void)
{
    TEST_BEGIN(test_processPacket_cmd_set_comms_mode);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Set comms mode 0x01; per JVS spec CMD_SET_COMMS_MODE is broadcast-only
     * and requires no response — the emulator returns immediately without
     * calling writePacket. */
    unsigned char cmd[] = {CMD_SET_COMMS_MODE, 0x01};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_SET_COMMS_MODE SUCCESS");
    ASSERT(!fd_has_data(afd), "CMD_SET_COMMS_MODE produces no response");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_SET_COMMS_MODE appearing after another command in a batch must NOT
 * silently discard the REPORT bytes already assembled for the prior command.
 * Before the fix the handler did an unconditional `return`, dropping any
 * partially-built response.
 *
 * Batch: CMD_COMMAND_VERSION | CMD_SET_COMMS_MODE 0x01
 * Expected response: STATUS_SUCCESS + REPORT_SUCCESS + commandVersion byte
 *   (the SET_COMMS_MODE does not add a REPORT byte but the version reply
 *    must be present in the wire output).
 */
static void test_processPacket_cmd_set_comms_mode_batch_preserves_prior(void)
{
    TEST_BEGIN(test_processPacket_cmd_set_comms_mode_batch_preserves_prior);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Build a two-command batch: CMD_COMMAND_VERSION (no args) followed by
     * CMD_SET_COMMS_MODE 0x01. */
    unsigned char cmd[] = {CMD_COMMAND_VERSION, CMD_SET_COMMS_MODE, 0x01};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 3);
    ASSERT(s == JVS_STATUS_SUCCESS, "batch with CMD_SET_COMMS_MODE SUCCESS");

    /* The response for CMD_COMMAND_VERSION must be present; without the fix
     * the SET_COMMS_MODE early-return would have dropped it entirely. */
    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response checksum valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS, "STATUS_SUCCESS present");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS for CMD_COMMAND_VERSION");
    ASSERT_EQ_INT(r.data[2], io.capabilities.commandVersion,
                  "commandVersion byte preserved in response");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_read_keypad(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_keypad);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* CMD_READ_KEYPAD takes no argument and always returns 0x00 */
    unsigned char cmd[] = {CMD_READ_KEYPAD};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 1);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_READ_KEYPAD SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");
    ASSERT_EQ_INT(r.data[2], 0x00, "keypad byte = 0x00");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_write_gpo_bit(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_gpo_bit);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Write GPO bit: byte_index=0, bit_value=1 */
    unsigned char cmd[] = {CMD_WRITE_GPO_BIT, 0x00, 0x01};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 3);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_GPO_BIT SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_write_analog(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_analog);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Write 2 analogue output channels; size = 2 + 2*2 = 6 bytes */
    unsigned char cmd[] = {CMD_WRITE_ANALOG, 0x02, 0x00, 0x80, 0x00, 0x80};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 6);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_ANALOG SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_write_display(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_display);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* 1-column × 1-row display: cmd(1)+cols(1)+rows(1)+encoding(1)+data(1) = 5 bytes */
    unsigned char cmd[] = {CMD_WRITE_DISPLAY, 0x01, 0x01, 0x00, 'A'};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 5);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_DISPLAY SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

static void test_processPacket_cmd_subtract_payout(void)
{
    TEST_BEGIN(test_processPacket_cmd_subtract_payout);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Subtract payout: slot=1, amount high=0x00 low=0x05 */
    unsigned char cmd[] = {CMD_SUBTRACT_PAYOUT, 0x01, 0x00, 0x05};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 4);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_SUBTRACT_PAYOUT SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * End-to-end path for the PR #177 fix (allow 16-bit analogue/gun channels).
 * Verifies that CMD_READ_ANALOGS produces the correct wire bytes when
 * analogueInBits == 16 (analogueRestBits == 0, no left-shift applied).
 *
 * With channel set to 1.0:
 *   analogueMax = (1<<16)-1 = 65535
 *   analogueData = 65535 << 0 = 65535 = 0xFFFF → high=0xFF, low=0xFF
 */
static void test_processPacket_cmd_read_analogs_16bit(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_analogs_16bit);

    JVSIO io;
    memset(&io, 0, sizeof(io));
    io.deviceID  = 0x01;
    io.chainedIO = NULL;

    io.capabilities.players            = 2;
    io.capabilities.analogueInChannels = 2;
    io.capabilities.analogueInBits     = 16;
    io.capabilities.coins              = 2;
    io.capabilities.rightAlignBits     = 0;

    initIO(&io);   /* analogueMax = 65535 */
    initJVS(&io);  /* analogueRestBits = 16-16 = 0 */

    ASSERT_EQ_INT(io.analogueMax, 65535, "analogueMax for 16-bit");

    setAnalogue(&io, ANALOGUE_1, 1.0);  /* channel[0] = 65535 */
    setAnalogue(&io, ANALOGUE_2, 0.0);  /* channel[1] = 0     */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_ANALOGS, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* ch0: 65535 << 0 = 65535 = 0xFFFF */
    ASSERT_EQ_INT(r.data[2], 0xFF, "ch0 high byte = 0xFF");
    ASSERT_EQ_INT(r.data[3], 0xFF, "ch0 low byte = 0xFF");
    /* ch1: 0 */
    ASSERT_EQ_INT(r.data[4], 0x00, "ch1 high byte = 0x00");
    ASSERT_EQ_INT(r.data[5], 0x00, "ch1 low byte = 0x00");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_READ_LIGHTGUN: verify the Y-channel value is correctly emitted.
 * The existing test only checked the X value; this test checks both X and Y.
 *
 * setGun(channel_odd, 0.5) stores (1.0-0.5)*gunYMax = 0.5*4095 = 2047.
 * yData = 2047 << 4 = 32752 = 0x7FF0.
 */
static void test_processPacket_cmd_read_lightgun_y_channel(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_lightgun_y_channel);

    JVSIO io = make_test_io();  /* gunXBits=12, gunYBits=12 → restBits=4 */
    io.deviceID = 0x01;
    setGun(&io, 0, 1.0);  /* X → gunChannel[0] = 4095 */
    setGun(&io, 1, 0.5);  /* Y → gunChannel[1] = (int)((1.0-0.5)*4095) = 2047 */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_LIGHTGUN, 0x01};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* X: 4095 << 4 = 65520 = 0xFFF0 */
    ASSERT_EQ_INT(r.data[2], 0xFF, "gun X high = 0xFF");
    ASSERT_EQ_INT(r.data[3], 0xF0, "gun X low = 0xF0");
    /* Y: 2047 << 4 = 32752 = 0x7FF0 */
    ASSERT_EQ_INT(r.data[4], 0x7F, "gun Y high = 0x7F");
    ASSERT_EQ_INT(r.data[5], 0xF0, "gun Y low = 0xF0");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_READ_LIGHTGUN with two guns: verify both guns' X/Y values are reported.
 * Gun 1 is at (0, 4095) (left/bottom), gun 2 is at (4095, 0) (right/top).
 *
 * setGun(even, value) → xMax * value.
 * setGun(odd,  value) → yMax * value.
 * setGun(0, 0.0) → channel[0] = 0.
 * setGun(1, 1.0) → channel[1] = 4095.
 * setGun(2, 1.0) → channel[2] = 4095.
 * setGun(3, 0.0) → channel[3] = 0.
 */
static void test_processPacket_cmd_read_lightgun_two_guns(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_lightgun_two_guns);

    JVSIO io = make_test_io();  /* gunChannels=2, 12-bit, restBits=4 */
    io.deviceID = 0x01;
    /* Gun 1: X=0, Y=4095 */
    setGun(&io, 0, 0.0);  /* channel[0] = 0    */
    setGun(&io, 1, 1.0);  /* channel[1] = 4095 */
    /* Gun 2: X=4095, Y=0 */
    setGun(&io, 2, 1.0);  /* channel[2] = 4095 */
    setGun(&io, 3, 0.0);  /* channel[3] = 0    */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    unsigned char cmd[] = {CMD_READ_LIGHTGUN, 0x02};
    run_processPacket(&io, afd, 0x01, cmd, 2);

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* Gun 1 X=0: 0<<4=0 */
    ASSERT_EQ_INT(r.data[2], 0x00, "gun1 X high = 0x00");
    ASSERT_EQ_INT(r.data[3], 0x00, "gun1 X low = 0x00");
    /* Gun 1 Y=4095: 4095<<4 = 65520 = 0xFFF0 */
    ASSERT_EQ_INT(r.data[4], 0xFF, "gun1 Y high = 0xFF");
    ASSERT_EQ_INT(r.data[5], 0xF0, "gun1 Y low = 0xF0");
    /* Gun 2 X=4095: 4095<<4 = 65520 = 0xFFF0 */
    ASSERT_EQ_INT(r.data[6], 0xFF, "gun2 X high = 0xFF");
    ASSERT_EQ_INT(r.data[7], 0xF0, "gun2 X low = 0xF0");
    /* Gun 2 Y=0: 0<<4=0 */
    ASSERT_EQ_INT(r.data[8], 0x00, "gun2 Y high = 0x00");
    ASSERT_EQ_INT(r.data[9], 0x00, "gun2 Y low = 0x00");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_DECREASE_COINS underflow protection: decreasing by more than the current
 * count must clamp the count to zero, not underflow to a negative value.
 */
static void test_processPacket_cmd_decrease_coins_underflow_clamp(void)
{
    TEST_BEGIN(test_processPacket_cmd_decrease_coins_underflow_clamp);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    io.state.coinCount[0] = 3;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Slot 1, decrement 10 (0x000A) — more than the current count of 3 */
    unsigned char cmd[] = {CMD_DECREASE_COINS, 0x01, 0x00, 0x0A};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 4);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_DECREASE_COINS SUCCESS");
    ASSERT_EQ_INT(io.state.coinCount[0], 0, "coin count clamped to 0, not negative");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_WRITE_COINS overflow protection: adding coins beyond 16383 must clamp
 * the count to 16383, not overflow.
 */
static void test_processPacket_cmd_write_coins_overflow_clamp(void)
{
    TEST_BEGIN(test_processPacket_cmd_write_coins_overflow_clamp);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    io.state.coinCount[0] = 16380;

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Slot 1, increment 100 (0x0064) — would overflow 16383 */
    unsigned char cmd[] = {CMD_WRITE_COINS, 0x01, 0x00, 0x64};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 4);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_WRITE_COINS SUCCESS");
    ASSERT_EQ_INT(io.state.coinCount[0], 16383, "coin count clamped at 16383");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_NAMCO_SPECIFIC sub-command 0x18 (Triforce ID check):
 * followed by 4 data bytes, must return REPORT_SUCCESS + 0xFF.
 */
static void test_processPacket_namco_specific_18(void)
{
    TEST_BEGIN(test_processPacket_namco_specific_18);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Sub-command 0x18 followed by 4 data bytes */
    unsigned char cmd[] = {CMD_NAMCO_SPECIFIC, 0x18, 0x01, 0x02, 0x03, 0x04};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 6);
    ASSERT(s == JVS_STATUS_SUCCESS, "CMD_NAMCO_SPECIFIC 0x18 SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_SUCCESS,  "STATUS_SUCCESS");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS,  "REPORT_SUCCESS");
    ASSERT_EQ_INT(r.data[2], 0xFF, "Namco 0x18 response byte = 0xFF");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * An unrecognised Namco sub-command (not 0x01..0x04 or 0x18) must cause the
 * response STATUS byte to be STATUS_UNSUPPORTED (0x02).  The handler rolls
 * back the preliminary REPORT_SUCCESS it emitted and returns STATUS_UNSUPPORTED
 * to signal to the master that the command is not implemented.
 */
static void test_processPacket_namco_specific_unknown(void)
{
    TEST_BEGIN(test_processPacket_namco_specific_unknown);

    JVSIO io = make_test_io();
    io.deviceID = 0x01;
    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Sub-command 0x99 is not implemented */
    unsigned char cmd[] = {CMD_NAMCO_SPECIFIC, 0x99};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "unknown Namco sub-cmd still returns SUCCESS");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[0], STATUS_UNSUPPORTED, "STATUS_UNSUPPORTED");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/*
 * CMD_READ_LIGHTGUN requesting more guns than the IO board declares:
 * the extra (undeclared) gun slots must be reported as X=0, Y=0 rather than
 * emitting stale channel data or crashing.
 *
 * make_test_io() declares gunChannels=2.  Requesting 3 guns means gun 3
 * (index 2) is beyond the declaration and must produce 0x0000 / 0x0000.
 */
static void test_processPacket_cmd_read_lightgun_extra_guns_zero(void)
{
    TEST_BEGIN(test_processPacket_cmd_read_lightgun_extra_guns_zero);

    JVSIO io = make_test_io();  /* gunChannels=2, 12-bit, restBits=4 */
    io.deviceID = 0x01;
    /* Set known values for declared guns so the assertion is unambiguous */
    setGun(&io, 0, 1.0);  /* gun1 X = 4095 */
    setGun(&io, 1, 0.0);  /* gun1 Y = (1-0)*4095 = 4095 */
    setGun(&io, 2, 1.0);  /* gun2 X = 4095 */
    setGun(&io, 3, 0.0);  /* gun2 Y = 4095 */

    int sv[2];
    int afd = open_test_socket(sv);
    ASSERT(afd >= 0, "socketpair");

    /* Request 3 guns; only 2 are declared */
    unsigned char cmd[] = {CMD_READ_LIGHTGUN, 0x03};
    JVSStatus s = run_processPacket(&io, afd, 0x01, cmd, 2);
    ASSERT(s == JVS_STATUS_SUCCESS, "SUCCESS even when more guns requested than declared");

    JVSResponse r = jvs_read_response(afd);
    ASSERT(r.valid == 1, "response valid");
    ASSERT_EQ_INT(r.data[1], REPORT_SUCCESS, "REPORT_SUCCESS");
    /* Gun 3 (index 2, beyond declared): both X and Y must be zero.
     * Response byte layout:
     *   [0] = STATUS_SUCCESS
     *   [1] = REPORT_SUCCESS
     *   [2..5]  = gun1 X_hi, X_lo, Y_hi, Y_lo
     *   [6..9]  = gun2 X_hi, X_lo, Y_hi, Y_lo
     *   [10..13] = gun3 X_hi, X_lo, Y_hi, Y_lo  (undeclared, must be 0) */
    ASSERT_EQ_INT(r.data[10], 0x00, "gun3 X high = 0x00");
    ASSERT_EQ_INT(r.data[11], 0x00, "gun3 X low = 0x00");
    ASSERT_EQ_INT(r.data[12], 0x00, "gun3 Y high = 0x00");
    ASSERT_EQ_INT(r.data[13], 0x00, "gun3 Y low = 0x00");

    close(sv[0]); close(sv[1]); serialIO = -1;
    TEST_PASS();
}

/* =========================================================================
 * ───────────────────────────── MAIN RUNNER ────────────────────────────────
 * ========================================================================= */

typedef void (*TestFn)(void);

static const TestFn tests[] = {
    /* IO state */
    test_initIO_zeros_state,
    test_setSwitch_system,
    test_setSwitch_player1,
    test_setSwitch_player2,
    test_setSwitch_out_of_range_player,
    test_setSwitch_oversized_player,
    test_setSwitch_all_buttons,
    test_incrementCoin_basic,
    test_incrementCoin_system_rejected,
    test_incrementCoin_out_of_range,
    test_setAnalogue_full_scale,
    test_setAnalogue_out_of_range_channel,
    test_setAnalogue_all_channels,
    test_setAnalogue_value_clamping,
    test_setGun_x_channel,
    test_setGun_y_channel,
    test_setGun_gun2,
    test_setGun_out_of_range,
    test_setGun_value_clamping,
    test_setRotary_getRotary_roundtrip,
    test_setRotary_out_of_range,
    test_incrementRotary_basic,
    test_incrementRotary_negative_delta,
    test_incrementRotary_out_of_range,
    test_incrementRotary_negative_channel,
    test_jvsInputFromString_known,
    test_jvsInputFromString_unknown,
    test_jvsPlayerFromString_known,
    test_jvsPlayerFromString_unknown,
    /* New bounds-check tests (PR bug-fixes) */
    test_setSwitch_invalid_switch_number,
    test_setSwitch_negative_player,
    test_setAnalogue_negative_channel,
    test_setGun_negative_channel,
    test_setRotary_negative_channel,
    test_incrementCoin_cap_at_16383,
    /* initIO and initJVS capability / bit-depth tests */
    test_initIO_oversized_capabilities,
    test_initIO_zero_analogue_bits,
    test_initIO_oversized_analogue_bits,
    test_initIO_reinit_mutex_safety,
    test_initJVS_right_align_bits,
    test_initJVS_chained_io_rest_bits,
    /* Config parsing */
    test_getDefaultConfig,
    test_parseConfig_valid_file,
    test_parseConfig_file_not_found,
    test_parseConfig_emulate_second,
    test_parseConfig_invalid_int_fallback,
    test_parseConfig_comments_and_blanks,
    test_parseConfig_deadzone_clamping,
    test_parseConfig_wii_ir_scale_clamping,
    test_parseConfig_include,
    test_parseConfig_include_depth_limit,
    test_parseInputMapping_include_merges,
    test_parseOutputMapping_include_merges,
    test_parseIO_namco_FCA1,
    test_parseIO_file_not_found,
    test_parseIO_capcom_naomi,
    /* Debug */
    test_debug_getLevel,
    test_debug_level_filtering,
    /* JVS packet framing */
    test_readPacket_zero_length,
    test_resetPacketParser_clears_stale_state,
    test_readPacket_valid,
    test_readPacket_checksum_error,
    test_readPacket_escape_bytes,
    test_readPacket_escape_escape_byte,
    test_readPacket_sync_resets_parser,
    test_readPacket_checksum_reset_on_sync,
    test_readPacket_timeout,
    test_writePacket_basic,
    test_writePacket_length_not_modified,
    test_writePacket_below_min_length,
    test_writePacket_escape_in_data,
    test_writePacket_large_length_no_wrap,
    test_writePacket_max_length_guard,
    /* processPacket integration */
    test_processPacket_cmd_reset,
    test_processPacket_cmd_reset_chained_io,
    test_processPacket_cmd_assign_addr,
    test_processPacket_cmd_assign_addr_all_assigned,
    test_processPacket_cmd_request_id,
    test_processPacket_cmd_command_version,
    test_processPacket_cmd_jvs_version,
    test_processPacket_cmd_comms_version,
    test_processPacket_cmd_capabilities,
    test_processPacket_cmd_read_switches_zero,
    test_processPacket_cmd_read_switches_pressed,
    test_processPacket_cmd_read_coins,
    test_processPacket_cmd_read_analogs,
    test_processPacket_cmd_read_rotary,
    test_processPacket_cmd_read_lightgun,
    test_processPacket_cmd_read_gpi,
    test_processPacket_cmd_decrease_coins,
    test_processPacket_cmd_write_coins,
    test_processPacket_cmd_write_gpo,
    test_processPacket_cmd_write_gpo_byte,
    test_processPacket_cmd_convey_id,
    test_processPacket_cmd_remaining_payout,
    test_processPacket_cmd_set_payout,
    test_processPacket_not_for_us,
    test_processPacket_broadcast_after_assign,
    test_processPacket_retransmit,
    test_processPacket_multi_command,
    test_processPacket_chained_address_assign,
    test_processPacket_connection_timeout,
    test_processPacket_namco_specific,
    test_processPacket_namco_specific_program_date,
    test_processPacket_namco_specific_dip_switch,
    test_processPacket_namco_specific_04,
    test_processPacket_unsupported_command,
    test_processPacket_cmd_remaining_payout_two_slots,
    /* Additional command coverage */
    test_processPacket_cmd_set_comms_mode,
    test_processPacket_cmd_set_comms_mode_batch_preserves_prior,
    test_processPacket_cmd_read_keypad,
    test_processPacket_cmd_write_gpo_bit,
    test_processPacket_cmd_write_analog,
    test_processPacket_cmd_write_display,
    test_processPacket_cmd_subtract_payout,
    test_processPacket_cmd_read_analogs_16bit,
    test_processPacket_cmd_read_lightgun_y_channel,
    test_processPacket_cmd_read_lightgun_two_guns,
    test_processPacket_cmd_read_lightgun_extra_guns_zero,
    test_processPacket_cmd_decrease_coins_underflow_clamp,
    test_processPacket_cmd_write_coins_overflow_clamp,
    test_processPacket_namco_specific_18,
    test_processPacket_namco_specific_unknown,
};

int main(void)
{
    printf("\n========================================\n");
    printf("  ModernJVS Test Suite\n");
    printf("========================================\n\n");

    /* Suppress debug output during tests */
    initDebug(0);

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
        tests[i]();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf("  (%d FAILED)", g_tests_failed);
    printf("\n========================================\n\n");

    return (g_tests_failed == 0) ? 0 : 1;
}
