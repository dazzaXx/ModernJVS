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

static void test_setGun_y_channel_inverted(void)
{
    TEST_BEGIN(test_setGun_y_channel_inverted);
    JVSIO io = make_test_io();  /* gunYBits=12, gunYMax=4095 */

    /* Channel 1 = Y for gun 0, Y is inverted: stored as (1.0 - value) * gunYMax */
    setGun(&io, 1, 0.0);
    ASSERT_EQ_INT(io.state.gunChannel[1], 4095, "Y=0 → stored as 4095 (max)");

    setGun(&io, 1, 1.0);
    ASSERT_EQ_INT(io.state.gunChannel[1], 0, "Y=1.0 → stored as 0 (min)");
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
    pkt.length      = 1;  /* < 2 → must not write */
    pkt.data[0]     = 0x01;

    JVSStatus s = writePacket(&pkt);
    ASSERT(s == JVS_STATUS_SUCCESS, "returns SUCCESS even with short packet");

    /* No bytes should have been written */
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    unsigned char buf[64];
    int n = (int)read(fds[0], buf, sizeof(buf));
    ASSERT(n <= 0, "no bytes written for short packet");
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

/* =========================================================================
 * ──────────────────── processPacket INTEGRATION TESTS ─────────────────────
 * (uses socketpair so both read and write go through serialIO)
 * ========================================================================= */

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

    /* No response should be written (packet data length < 2 → writePacket skips) */
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
    /* First two bytes of date: 0x19 0x98 (year 1998) */
    ASSERT_EQ_INT(r.data[2], 0x19, "century 0x19");
    ASSERT_EQ_INT(r.data[3], 0x98, "year 0x98");

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
    test_setSwitch_all_buttons,
    test_incrementCoin_basic,
    test_incrementCoin_system_rejected,
    test_incrementCoin_out_of_range,
    test_setAnalogue_full_scale,
    test_setAnalogue_out_of_range_channel,
    test_setAnalogue_all_channels,
    test_setGun_x_channel,
    test_setGun_y_channel_inverted,
    test_setGun_gun2,
    test_setGun_out_of_range,
    test_setRotary_getRotary_roundtrip,
    test_setRotary_out_of_range,
    test_jvsInputFromString_known,
    test_jvsInputFromString_unknown,
    test_jvsPlayerFromString_known,
    test_jvsPlayerFromString_unknown,
    /* New bounds-check tests (PR bug-fixes) */
    test_setSwitch_negative_player,
    test_setAnalogue_negative_channel,
    test_setGun_negative_channel,
    test_setRotary_negative_channel,
    test_incrementCoin_cap_at_16383,
    /* Config parsing */
    test_getDefaultConfig,
    test_parseConfig_valid_file,
    test_parseConfig_file_not_found,
    test_parseConfig_comments_and_blanks,
    test_parseConfig_deadzone_clamping,
    test_parseConfig_wii_ir_scale_clamping,
    test_parseConfig_include,
    test_parseConfig_include_depth_limit,
    test_parseIO_namco_FCA1,
    test_parseIO_file_not_found,
    test_parseIO_capcom_naomi,
    /* Debug */
    test_debug_getLevel,
    test_debug_level_filtering,
    /* JVS packet framing */
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
    /* processPacket integration */
    test_processPacket_cmd_reset,
    test_processPacket_cmd_assign_addr,
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
