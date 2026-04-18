#include <string.h>
#include <math.h>

#include "jvs/io.h"
#include "console/debug.h"

int initIO(JVSIO *io)
{
	/* Clamp loop bounds to the state array size to prevent out-of-bounds writes
	 * if an IO config file specifies capability counts larger than JVS_MAX_STATE_SIZE. */
	int maxPlayers  = io->capabilities.players + 1;
	if (maxPlayers  > JVS_MAX_STATE_SIZE) maxPlayers  = JVS_MAX_STATE_SIZE;
	int maxAnalogue = io->capabilities.analogueInChannels;
	if (maxAnalogue > JVS_MAX_STATE_SIZE) maxAnalogue = JVS_MAX_STATE_SIZE;
	int maxRotary   = io->capabilities.rotaryChannels;
	if (maxRotary   > JVS_MAX_STATE_SIZE) maxRotary   = JVS_MAX_STATE_SIZE;
	int maxCoins    = io->capabilities.coins;
	if (maxCoins    > JVS_MAX_STATE_SIZE) maxCoins    = JVS_MAX_STATE_SIZE;

	for (int player = 0; player < maxPlayers; player++)
		io->state.inputSwitch[player] = 0;

	for (int analogueChannels = 0; analogueChannels < maxAnalogue; analogueChannels++)
		io->state.analogueChannel[analogueChannels] = 0;

	for (int rotaryChannels = 0; rotaryChannels < maxRotary; rotaryChannels++)
		io->state.rotaryChannel[rotaryChannels] = 0;

	for (int player = 0; player < maxCoins; player++)
		io->state.coinCount[player] = 0;

	int maxGun = io->capabilities.gunChannels * 2;
	if (maxGun > JVS_MAX_STATE_SIZE) maxGun = JVS_MAX_STATE_SIZE;
	for (int gunChannels = 0; gunChannels < maxGun; gunChannels++)
		io->state.gunChannel[gunChannels] = 0;

	/* Compute the maximum representable value for each channel type.
	 * Use integer bit-shifts instead of pow() to keep this as pure integer
	 * arithmetic.  Guard against bits == 0 (would produce max == 0, silently
	 * zeroing all channel output) and bits > 16 (shift would be > 16, which
	 * is undefined behaviour on C99).  16 is the maximum supported by the JVS
	 * wire format and is valid on the Raspberry Pi where int is 32-bit. */
	io->analogueMax = (io->capabilities.analogueInBits > 0 && io->capabilities.analogueInBits <= 16)
	                  ? (1 << io->capabilities.analogueInBits) - 1 : 0;
	io->gunXMax     = (io->capabilities.gunXBits > 0 && io->capabilities.gunXBits <= 16)
	                  ? (1 << io->capabilities.gunXBits) - 1 : 0;
	io->gunYMax     = (io->capabilities.gunYBits > 0 && io->capabilities.gunYBits <= 16)
	                  ? (1 << io->capabilities.gunYBits) - 1 : 0;

	if (io->capabilities.analogueInChannels > 0 && io->analogueMax == 0)
		debug(0, "Warning: analogueInBits is 0 or >16 — analogue output will be zeroed\n");
	if (io->capabilities.gunChannels > 0 && (io->gunXMax == 0 || io->gunYMax == 0))
		debug(0, "Warning: gunXBits/gunYBits is 0 or >16 — lightgun output will be zeroed\n");

	pthread_mutex_init(&io->state_mutex, NULL);

	return 1;
}

int setSwitch(JVSIO *io, JVSPlayer player, JVSInput switchNumber, int value)
{
	if ((int)player < 0 || player > io->capabilities.players ||
	    (int)player >= JVS_MAX_STATE_SIZE)
	{
		debug(0, "Error: That player %d does not exist.\n", player);
		return 0;
	}

	if (value)
	{
		pthread_mutex_lock(&io->state_mutex);
		io->state.inputSwitch[player] |= switchNumber;
		pthread_mutex_unlock(&io->state_mutex);
	}
	else
	{
		pthread_mutex_lock(&io->state_mutex);
		io->state.inputSwitch[player] &= ~switchNumber;
		pthread_mutex_unlock(&io->state_mutex);
	}

	return 1;
}

int incrementCoin(JVSIO *io, JVSPlayer player, int amount)
{
	if ((int)player <= 0)
		return 0;

	/* coins is an unsigned char (max 255) but coinCount[] is only
	 * JVS_MAX_STATE_SIZE elements wide — guard both limits. */
	if (player - 1 >= io->capabilities.coins ||
	    (int)(player - 1) >= JVS_MAX_STATE_SIZE)
		return 0;

	pthread_mutex_lock(&io->state_mutex);
	io->state.coinCount[player - 1] += amount;
	/* Cap at 16383 (max representable by the 13-bit JVS wire format) */
	if (io->state.coinCount[player - 1] > 16383)
		io->state.coinCount[player - 1] = 16383;
	pthread_mutex_unlock(&io->state_mutex);
	return 1;
}

int setAnalogue(JVSIO *io, JVSInput channel, double value)
{
	/* analogueInChannels is an unsigned char (max 255) but analogueChannel[]
	 * is only JVS_MAX_STATE_SIZE elements wide — guard both limits. */
	if ((int)channel < 0 || channel >= io->capabilities.analogueInChannels ||
	    (int)channel >= JVS_MAX_STATE_SIZE)
		return 0;
	pthread_mutex_lock(&io->state_mutex);
	io->state.analogueChannel[channel] = (int)((double)value * (double)io->analogueMax);
	pthread_mutex_unlock(&io->state_mutex);
	return 1;
}

int setGun(JVSIO *io, JVSInput channel, double value)
{
	/* Bounds check: channel must be non-negative, within the declared gun
	 * channel range, and within the fixed-size state array.  gunChannels is
	 * an unsigned char (max 255) so gunChannels * 2 can reach 510, but
	 * gunChannel[] is only JVS_MAX_STATE_SIZE elements wide. */
	if ((int)channel < 0 || channel >= io->capabilities.gunChannels * 2 ||
	    (int)channel >= JVS_MAX_STATE_SIZE)
		return 0;

	if (channel % 2 == 0)
	{
		pthread_mutex_lock(&io->state_mutex);
		io->state.gunChannel[channel] = (int)((double)value * (double)io->gunXMax);
		pthread_mutex_unlock(&io->state_mutex);
	}
	else
	{
		pthread_mutex_lock(&io->state_mutex);
		io->state.gunChannel[channel] = (int)((double)((double)1.0 - value) * (double)io->gunYMax);
		pthread_mutex_unlock(&io->state_mutex);
	}
	return 1;
}

int setRotary(JVSIO *io, JVSInput channel, int value)
{
	/* rotaryChannels is an unsigned char (max 255) but rotaryChannel[]
	 * is only JVS_MAX_STATE_SIZE elements wide — guard both limits. */
	if ((int)channel < 0 || channel >= io->capabilities.rotaryChannels ||
	    (int)channel >= JVS_MAX_STATE_SIZE)
		return 0;

	pthread_mutex_lock(&io->state_mutex);
	io->state.rotaryChannel[channel] = value;
	pthread_mutex_unlock(&io->state_mutex);
	return 1;
}

int getRotary(JVSIO *io, JVSInput channel)
{
	if ((int)channel < 0 || channel >= io->capabilities.rotaryChannels ||
	    (int)channel >= JVS_MAX_STATE_SIZE)
		return 0;

	pthread_mutex_lock(&io->state_mutex);
	int rotaryValue = io->state.rotaryChannel[channel];
	pthread_mutex_unlock(&io->state_mutex);
	return rotaryValue;
}

/**
 * Atomically increment (or decrement) a rotary channel by delta.
 *
 * Performs the read-modify-write under the state mutex so that concurrent
 * EV_REL events from multiple controller threads for the same channel are
 * never lost.
 *
 * @param io      The JVSIO to modify.
 * @param channel The rotary channel index.
 * @param delta   Amount to add (negative values subtract).
 * @returns 1 on success, 0 if the channel index is out of range.
 */
int incrementRotary(JVSIO *io, JVSInput channel, int delta)
{
	if ((int)channel < 0 || channel >= io->capabilities.rotaryChannels ||
	    (int)channel >= JVS_MAX_STATE_SIZE)
		return 0;

	pthread_mutex_lock(&io->state_mutex);
	io->state.rotaryChannel[channel] += delta;
	pthread_mutex_unlock(&io->state_mutex);
	return 1;
}

JVSInput jvsInputFromString(char *jvsInputString)
{
	for (long unsigned int i = 0; i < sizeof(jvsInputConversion) / sizeof(jvsInputConversion[0]); i++)
	{
		if (strcmp(jvsInputConversion[i].string, jvsInputString) == 0)
			return jvsInputConversion[i].input;
	}
	debug(0, "Error: Could not find the JVS INPUT string specified for %s\n", jvsInputString);
	return -1;
}

JVSPlayer jvsPlayerFromString(char *jvsPlayerString)
{
	for (long unsigned int i = 0; i < sizeof(jvsPlayerConversion) / sizeof(jvsPlayerConversion[0]); i++)
	{
		if (strcmp(jvsPlayerConversion[i].string, jvsPlayerString) == 0)
			return jvsPlayerConversion[i].player;
	}
	debug(0, "Error: Could not find the JVS PLAYER string specified for %s\n", jvsPlayerString);
	return -1;
}
