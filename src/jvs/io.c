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

	io->analogueMax = pow(2, io->capabilities.analogueInBits) - 1;
	io->gunXMax = pow(2, io->capabilities.gunXBits) - 1;
	io->gunYMax = pow(2, io->capabilities.gunYBits) - 1;

	return 1;
}

int setSwitch(JVSIO *io, JVSPlayer player, JVSInput switchNumber, int value)
{
	if ((int)player < 0 || player > io->capabilities.players)
	{
		debug(0, "Error: That player %d does not exist.\n", player);
		return 0;
	}

	if (value)
	{
		io->state.inputSwitch[player] |= switchNumber;
	}
	else
	{
		io->state.inputSwitch[player] &= ~switchNumber;
	}

	return 1;
}

int incrementCoin(JVSIO *io, JVSPlayer player, int amount)
{
	if ((int)player <= 0)
		return 0;

	// Bounds check to prevent array overflow
	if (player - 1 >= io->capabilities.coins)
		return 0;

	io->state.coinCount[player - 1] += amount;
	/* Cap at 16383 (max representable by the 13-bit JVS wire format) */
	if (io->state.coinCount[player - 1] > 16383)
		io->state.coinCount[player - 1] = 16383;
	return 1;
}

int setAnalogue(JVSIO *io, JVSInput channel, double value)
{
	if ((int)channel < 0 || channel >= io->capabilities.analogueInChannels)
		return 0;
	io->state.analogueChannel[channel] = (int)((double)value * (double)io->analogueMax);
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
		io->state.gunChannel[channel] = (int)((double)value * (double)io->gunXMax);
	}
	else
	{
		io->state.gunChannel[channel] = (int)((double)((double)1.0 - value) * (double)io->gunYMax);
	}
	return 1;
}

int setRotary(JVSIO *io, JVSInput channel, int value)
{
	if ((int)channel < 0 || channel >= io->capabilities.rotaryChannels)
		return 0;

	io->state.rotaryChannel[channel] = value;
	return 1;
}

int getRotary(JVSIO *io, JVSInput channel)
{
	if ((int)channel < 0 || channel >= io->capabilities.rotaryChannels)
		return 0;

	return io->state.rotaryChannel[channel];
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
