#include "jvs/jvs.h"
#include "hardware/device.h"
#include "console/debug.h"

#include <time.h>

/* Packet structures for the current incoming command and the outgoing response */
JVSPacket inputPacket, outputPacket;

/* The in and out buffer used to read and write to and from */
/* outputBuffer must accommodate worst-case escaping: SYNC (1) + destination (up to 2)
 * + length (up to 2) + all data bytes (each up to 2 after escaping) + checksum (up to 2).
 * Worst case: 1 + 2 + 2 + 2*JVS_MAX_PACKET_SIZE + 2 = 2*JVS_MAX_PACKET_SIZE + 7 bytes.
 * Sized to 2*JVS_MAX_PACKET_SIZE + 8 to include one byte of headroom. */
unsigned char outputBuffer[JVS_MAX_PACKET_SIZE * 2 + 8], inputBuffer[JVS_MAX_PACKET_SIZE];

/* Packet counter for debugging */
static unsigned long packetCounter = 0;

/* --------------------------------------------------------------------------
 * Persistent packet-parser state
 *
 * These variables survive across readPacket() calls so that a mid-packet
 * read() timeout (JVS_STATUS_ERROR_TIMEOUT) does not discard bytes that
 * were already consumed from the kernel serial FIFO.  Without this, a
 * partial packet arriving in two bursts separated by more than the 200 ms
 * select() timeout would cause the second burst to be parsed from phase 0,
 * producing spurious checksum errors and forcing an extra round-trip retry.
 *
 * resetPacketParser() must be called whenever the receive stream is
 * deliberately discarded (e.g. after flushDevice()) to ensure stale bytes
 * in inputBuffer are not treated as the beginning of a new packet.
 * --------------------------------------------------------------------------*/
static int           rxBytesAvailable = 0;
static int           rxPhase          = 0;
static int           rxDataIndex      = 0;
static int           rxEscape         = 0;
static unsigned char rxChecksum       = 0x00;

/**
 * Reset the JVS packet-parser state
 *
 * Discards any partial packet currently being assembled and clears the
 * receive buffer.  Call this after flushing the serial receive buffer
 * (flushDevice) so that stale bytes in inputBuffer are not treated as
 * the start of the next packet.
 */
void resetPacketParser(void)
{
	rxBytesAvailable = 0;
	rxPhase          = 0;
	rxDataIndex      = 0;
	rxEscape         = 0;
	rxChecksum       = 0x00;
}

/* Connection inactivity timeout tracking */
#define JVS_CONNECTION_TIMEOUT_SECONDS 5
static time_t lastPacketTime = 0;
static int connectionLostLogged = 0;

/* Helper macro: verify there are at least (n) bytes of free space in the
 * given packet buffer before writing.  Returns JVS_STATUS_ERROR if not.
 * The packet pointer is passed explicitly to make the dependency clear. */
#define CHECK_OUTPUT_SPACE(pkt, n) \
	do { \
		if ((pkt)->length + (n) > JVS_MAX_PACKET_SIZE) { \
			debug(0, "Error: Output packet buffer full, dropping response byte(s)\n"); \
			return JVS_STATUS_ERROR; \
		} \
	} while (0)

/**
 * Get the name of a JVS command
 *
 * Returns a human-readable string for a given JVS command byte.
 *
 * @param cmd The command byte
 * @returns A string containing the command name
 */
static const char *getCommandName(unsigned char cmd)
{
	switch (cmd)
	{
	case CMD_RESET: return "RESET";
	case CMD_ASSIGN_ADDR: return "ASSIGN_ADDR";
	case CMD_SET_COMMS_MODE: return "SET_COMMS_MODE";
	case CMD_REQUEST_ID: return "REQUEST_ID";
	case CMD_COMMAND_VERSION: return "COMMAND_VERSION";
	case CMD_JVS_VERSION: return "JVS_VERSION";
	case CMD_COMMS_VERSION: return "COMMS_VERSION";
	case CMD_CAPABILITIES: return "CAPABILITIES";
	case CMD_CONVEY_ID: return "CONVEY_ID";
	case CMD_READ_SWITCHES: return "READ_SWITCHES";
	case CMD_READ_COINS: return "READ_COINS";
	case CMD_READ_ANALOGS: return "READ_ANALOGS";
	case CMD_READ_ROTARY: return "READ_ROTARY";
	case CMD_READ_KEYPAD: return "READ_KEYPAD";
	case CMD_READ_LIGHTGUN: return "READ_LIGHTGUN";
	case CMD_READ_GPI: return "READ_GPI";
	case CMD_RETRANSMIT: return "RETRANSMIT";
	case CMD_DECREASE_COINS: return "DECREASE_COINS";
	case CMD_WRITE_GPO: return "WRITE_GPO";
	case CMD_WRITE_ANALOG: return "WRITE_ANALOG";
	case CMD_WRITE_DISPLAY: return "WRITE_DISPLAY";
	case CMD_WRITE_COINS: return "WRITE_COINS";
	case CMD_REMAINING_PAYOUT: return "REMAINING_PAYOUT";
	case CMD_SET_PAYOUT: return "SET_PAYOUT";
	case CMD_SUBTRACT_PAYOUT: return "SUBTRACT_PAYOUT";
	case CMD_WRITE_GPO_BYTE: return "WRITE_GPO_BYTE";
	case CMD_WRITE_GPO_BIT: return "WRITE_GPO_BIT";
	case CMD_NAMCO_SPECIFIC: return "NAMCO_SPECIFIC";
	default:
		if (cmd >= CMD_MANUFACTURER_START && cmd <= CMD_MANUFACTURER_END)
			return "MANUFACTURER_SPECIFIC";
		return "UNKNOWN";
	}
}

/**
 * Initialise the JVS emulation
 *
 * Setup the JVS emulation on a specific device path with an
 * IO mapping provided.
 *
 * @param devicePath The linux filepath for the RS485 adapter
 * @param capabilitiesSetup The representation of the IO to emulate
 * @returns 1 if the device was initialised successfully, 0 otherwise.
 */
int initJVS(JVSIO *jvsIO)
{
	/* Calculate the alignments for analogue and gun channels for every IO in
	 * the chain.  Previously only the primary IO was initialised here, leaving
	 * the chained IO with analogueRestBits/gunXRestBits/gunYRestBits == 0 (from
	 * zero-initialisation in main), which caused analogue and lightgun data to
	 * be sent un-shifted (effectively right-aligned) for the second device
	 * instead of the correct left-aligned format. */
	JVSIO *io = jvsIO;
	while (io != NULL)
	{
		if (!io->capabilities.rightAlignBits)
		{
			io->analogueRestBits = 16 - io->capabilities.analogueInBits;
			io->gunXRestBits = 16 - io->capabilities.gunXBits;
			io->gunYRestBits = 16 - io->capabilities.gunYBits;
		}
		/* Clamp rest-bit counts to the valid shift range [0, 15].
		 * analogueInBits/gunXBits/gunYBits are parsed from IO definition files;
		 * a value of 0 would produce a shift of 16 (undefined behaviour on all
		 * platforms where int is 32 bits, and actual UB where int is 16 bits).
		 * A value > 16 would produce a negative shift, also UB. */
		if (io->analogueRestBits < 0) io->analogueRestBits = 0;
		if (io->analogueRestBits > 15) io->analogueRestBits = 15;
		if (io->gunXRestBits < 0) io->gunXRestBits = 0;
		if (io->gunXRestBits > 15) io->gunXRestBits = 15;
		if (io->gunYRestBits < 0) io->gunYRestBits = 0;
		if (io->gunYRestBits > 15) io->gunYRestBits = 15;
		io = io->chainedIO;
	}

	/* Float the sense line ready for connection */
	setSenseLine(0);

	return 1;
}

/**
 * Disconnect from the JVS device
 *
 * Disconnects from the device communicating with the
 * arcade machine so JVS can be shutdown safely.
 *
 * @returns 1 if the device disconnected successfully, 0 otherwise.
 */
int disconnectJVS(void)
{
	return closeDevice();
}

/**
 * Writes a single feature to an output packet
 *
 * Writes a single JVS feature, which are specified
 * in the JVS spec, to the output packet.
 *
 * @param outputPacket The packet to write to.
 * @param capability The specific capability to write
 * @param arg0 The first argument of the capability
 * @param arg1 The second argument of the capability
 * @param arg2 The final argument of the capability
 * @returns 1 on success, 0 if buffer would overflow
 */
static int writeFeature(JVSPacket *packet, char capability, char arg0, char arg1, char arg2)
{
	/* Check if there's enough space in the packet buffer */
	if (packet->length + 4 > JVS_MAX_PACKET_SIZE)
	{
		debug(0, "Error: Packet buffer overflow prevented in writeFeature\n");
		return 0;
	}
	
	packet->data[packet->length] = capability;
	packet->data[packet->length + 1] = arg0;
	packet->data[packet->length + 2] = arg1;
	packet->data[packet->length + 3] = arg2;
	packet->length += 4;
	return 1;
}

/**
 * Write the entire set of features to an output packet
 *
 * Writes the set of features specified in the JVSCapabilities
 * struct to the specified output packet.
 *
 * @param outputPacket The packet to write to.
 * @param capabilities The capabilities object to read from
 */
static void writeFeatures(JVSPacket *packet, JVSCapabilities *capabilities)
{
	if (packet->length + 1 > JVS_MAX_PACKET_SIZE)
	{
		debug(0, "Error: Packet buffer overflow in writeFeatures (REPORT_SUCCESS)\n");
		return;
	}
	packet->data[packet->length] = REPORT_SUCCESS;
	packet->length += 1;

	/* Input Functions */

	if (capabilities->players)
		writeFeature(packet, CAP_PLAYERS, capabilities->players, capabilities->switches, 0x00);

	if (capabilities->coins)
		writeFeature(packet, CAP_COINS, capabilities->coins, 0x00, 0x00);

	if (capabilities->analogueInChannels)
		writeFeature(packet, CAP_ANALOG_IN, capabilities->analogueInChannels, capabilities->analogueInBits, 0x00);

	if (capabilities->rotaryChannels)
		writeFeature(packet, CAP_ROTARY, capabilities->rotaryChannels, 0x00, 0x00);

	if (capabilities->keypad)
		writeFeature(packet, CAP_KEYPAD, 0x00, 0x00, 0x00);

	if (capabilities->gunChannels)
		writeFeature(packet, CAP_LIGHTGUN, capabilities->gunXBits, capabilities->gunYBits, capabilities->gunChannels);

	if (capabilities->generalPurposeInputs)
		writeFeature(packet, CAP_GPI, 0x00, capabilities->generalPurposeInputs, 0x00);

	/* Output Functions */

	if (capabilities->card)
		writeFeature(packet, CAP_CARD, capabilities->card, 0x00, 0x00);

	if (capabilities->hopper)
		writeFeature(packet, CAP_HOPPER, capabilities->hopper, 0x00, 0x00);

	if (capabilities->generalPurposeOutputs)
		writeFeature(packet, CAP_GPO, capabilities->generalPurposeOutputs, 0x00, 0x00);

	if (capabilities->analogueOutChannels)
		writeFeature(packet, CAP_ANALOG_OUT, capabilities->analogueOutChannels, 0x00, 0x00);

	if (capabilities->displayOutColumns)
		writeFeature(packet, CAP_DISPLAY, capabilities->displayOutColumns, capabilities->displayOutRows, capabilities->displayOutEncodings);

	/* Other */

	if (capabilities->backup)
		writeFeature(packet, CAP_BACKUP, 0x00, 0x00, 0x00);

	if (packet->length + 1 > JVS_MAX_PACKET_SIZE)
	{
		debug(0, "Error: Packet buffer overflow in writeFeatures (CAP_END)\n");
		return;
	}
	packet->data[packet->length] = CAP_END;
	packet->length += 1;
}

/**
 * Processes and responds to an entire JVS packet
 *
 * Follows the JVS spec and proceses and responds
 * to a single entire JVS packet.
 *
 * @returns The status of the entire operation
 */
JVSStatus processPacket(JVSIO *jvsIO)
{
	/* Initially read in a packet */
	JVSStatus readPacketStatus = readPacket(&inputPacket);
	if (readPacketStatus != JVS_STATUS_SUCCESS)
	{
		/* Detect connection loss when the arcade machine powers off without sending CMD_RESET.
		 * After JVS_CONNECTION_TIMEOUT_SECONDS of inactivity on an established connection,
		 * log a "Connection lost" event once so the WebUI can reflect the disconnected state.
		 * lastPacketTime != 0 ensures we only fire after at least one packet has been received
		 * (deviceID is only set after CMD_ASSIGN_ADDR which counts as a received packet, so
		 * the two guards together prevent any false trigger before a connection is made). */
		if (readPacketStatus == JVS_STATUS_ERROR_TIMEOUT &&
		    jvsIO->deviceID != -1 &&
		    lastPacketTime != 0 &&
		    !connectionLostLogged &&
		    difftime(time(NULL), lastPacketTime) > JVS_CONNECTION_TIMEOUT_SECONDS)
		{
			debug(0, "JVS: Connection lost\n");
			connectionLostLogged = 1;
		}
		return readPacketStatus;
	}

	/* A packet was received — reset inactivity tracking */
	lastPacketTime = time(NULL);
	connectionLostLogged = 0;

	/* Check if the packet is for us and loop through connected boards */
	if (inputPacket.destination != BROADCAST)
	{
		while (inputPacket.destination != jvsIO->deviceID && jvsIO->chainedIO != NULL)
		{
			jvsIO = jvsIO->chainedIO;
		}

		if (inputPacket.destination != jvsIO->deviceID)
		{
			return JVS_STATUS_NOT_FOR_US;
		}
	}

	/* Handle re-transmission requests */
	/* CMD_RETRANSMIT: only valid if at least one data byte is present */
	if (inputPacket.length >= 2 && inputPacket.data[0] == CMD_RETRANSMIT)
		return writePacket(&outputPacket);

	/* Setup the output packet */
	outputPacket.length = 0;
	outputPacket.destination = BUS_MASTER;

	int index = 0;

	/* Write the STATUS_SUCCESS byte required at the start of every JVS response;
	 * individual per-command results follow as REPORT_SUCCESS bytes below */
	outputPacket.data[outputPacket.length++] = STATUS_SUCCESS;

	while (index < inputPacket.length - 1)
	{
		int size = 1;
		switch (inputPacket.data[index])
		{

		/* The arcade hardware sends a reset command and we clear our memory */
		case CMD_RESET:
		{
			debug(1, "CMD_RESET - Resetting all devices\n");
			size = 2;
			JVSIO *tmpIO = jvsIO;
			__atomic_store_n(&tmpIO->deviceID, -1, __ATOMIC_RELEASE);
			while (tmpIO->chainedIO != NULL)
			{
				tmpIO = tmpIO->chainedIO;
				__atomic_store_n(&tmpIO->deviceID, -1, __ATOMIC_RELEASE);
			}
			setSenseLine(0);
			/* Clear connection-tracking so the timeout/lost logic starts
			 * fresh after the reset rather than firing immediately on the
			 * next inactivity window. */
			lastPacketTime = 0;
			connectionLostLogged = 0;
			debug(0, "JVS: Connection reset\n");
			/* CMD_RESET is a broadcast command: the JVS spec requires no response. */
			return JVS_STATUS_SUCCESS;
		}
		break;

		/* The arcade hardware assigns an address to our IO */
		case CMD_ASSIGN_ADDR:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_ASSIGN_ADDR - packet too short\n");
				break;
			}

			/* Find the first device in the chain that has not yet been assigned an address */
			JVSIO *ioToAssign = jvsIO;
			while (ioToAssign->deviceID != -1 && ioToAssign->chainedIO != NULL)
			{
				ioToAssign = ioToAssign->chainedIO;
			}

			/* Guard: only assign if this IO is still unaddressed.  If every IO
			 * in the chain already has an address (e.g. the arcade re-sends
			 * CMD_ASSIGN_ADDR without a preceding CMD_RESET) we acknowledge
			 * the command but do not overwrite any existing address. */
			if (ioToAssign->deviceID == -1)
			{
				int newID = inputPacket.data[index + 1];
				__atomic_store_n(&ioToAssign->deviceID, newID, __ATOMIC_RELEASE);
				debug(1, "CMD_ASSIGN_ADDR - Assigning address 0x%02X\n", newID);
			}
			else
			{
				debug(0, "Warning: CMD_ASSIGN_ADDR received but all IOs already have addresses assigned\n");
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			/* Raise the sense line only after all devices in the chain have been assigned */
			int allAssigned = 1;
			JVSIO *checkIO = jvsIO;
			while (checkIO != NULL)
			{
				if (checkIO->deviceID == -1)
				{
					allAssigned = 0;
					break;
				}
				checkIO = checkIO->chainedIO;
			}
			if (allAssigned)
			{
				setSenseLine(1);
				debug(0, "JVS: Connection established\n");
			}
		}
		break;

		/* Sent by some boards to switch the comms mode (e.g. baud rate or
		 * RS232 vs RS485).  We always acknowledge with REPORT_SUCCESS without
		 * actually changing anything — the board will simply continue in its
		 * current mode, which is the correct behaviour for an emulator.
		 * size=2 because the command byte is followed by one mode argument. */
		case CMD_SET_COMMS_MODE:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_SET_COMMS_MODE - packet too short\n");
				break;
			}
			debug(1, "CMD_SET_COMMS_MODE - Mode 0x%02X (acknowledged)\n", inputPacket.data[index + 1]);
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		/* Ask for the name of the IO board */
		case CMD_REQUEST_ID:
		{
			debug(1, "CMD_REQUEST_ID - Returning ID: %s\n", jvsIO->capabilities.name);
			size_t nameLen = strlen(jvsIO->capabilities.name);
			/* Calculate available space: total buffer - current position - REPORT_SUCCESS byte - null terminator byte */
			size_t availableSpace = JVS_MAX_PACKET_SIZE - outputPacket.length - 2;
			
			/* Check if the name fits in the packet buffer */
			if (nameLen > availableSpace)
			{
				debug(0, "Warning: Name too long for packet buffer, truncating from %zu to %zu bytes\n", nameLen, availableSpace);
				nameLen = availableSpace;
			}
			
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			memcpy(&outputPacket.data[outputPacket.length + 1], jvsIO->capabilities.name, nameLen);
			/* Always add null terminator within bounds */
			outputPacket.data[outputPacket.length + 1 + nameLen] = '\0';
			outputPacket.length += nameLen + 2;  // +1 for REPORT_SUCCESS, +1 for null terminator
		}
		break;

		/* Asks for version information */
		case CMD_COMMAND_VERSION:
		{
			debug(1, "CMD_COMMAND_VERSION - Returning version 0x%02X\n", jvsIO->capabilities.commandVersion);
			CHECK_OUTPUT_SPACE(&outputPacket, 2);
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = jvsIO->capabilities.commandVersion;
			outputPacket.length += 2;
		}
		break;

		/* Asks for version information */
		case CMD_JVS_VERSION:
		{
			debug(1, "CMD_JVS_VERSION - Returning version 0x%02X\n", jvsIO->capabilities.jvsVersion);
			CHECK_OUTPUT_SPACE(&outputPacket, 2);
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = jvsIO->capabilities.jvsVersion;
			outputPacket.length += 2;
		}
		break;

		/* Asks for version information */
		case CMD_COMMS_VERSION:
		{
			debug(1, "CMD_COMMS_VERSION - Returning version 0x%02X\n", jvsIO->capabilities.commsVersion);
			CHECK_OUTPUT_SPACE(&outputPacket, 2);
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = jvsIO->capabilities.commsVersion;
			outputPacket.length += 2;
		}
		break;

		/* Asks what our IO board supports */
		case CMD_CAPABILITIES:
		{
			debug(1, "CMD_CAPABILITIES - Returning capabilities\n");
			writeFeatures(&outputPacket, &jvsIO->capabilities);
		}
		break;

		/* Asks for the status of our IO boards switches */
		case CMD_READ_SWITCHES:
		{
			size = 3;
			if (index + 2 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_READ_SWITCHES - packet too short\n");
				break;
			}
			debug(1, "CMD_READ_SWITCHES - Players: %d, Switches: %d\n", 
				inputPacket.data[index + 1], inputPacket.data[index + 2]);
			// Bounds check before writing the 2-byte header (REPORT_SUCCESS + system switch byte)
			if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
			{
				debug(0, "Error: Output packet size exceeded in CMD_READ_SWITCHES\n");
				return JVS_STATUS_ERROR;
			}

			/* Snapshot the switch state to avoid holding the mutex over the output loop
			 * (which contains early-return error paths). */
			int switchSnapshot[JVS_MAX_STATE_SIZE];
			pthread_mutex_lock(&jvsIO->state_mutex);
			memcpy(switchSnapshot, jvsIO->state.inputSwitch, sizeof(switchSnapshot));
			pthread_mutex_unlock(&jvsIO->state_mutex);

			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = switchSnapshot[0];
			outputPacket.length += 2;
			/* Clamp switch-byte count to 2: our inputSwitch register is 16 bits wide.
			 * More than 2 bytes would require a right-shift of (8 - j*8) with j>=2,
			 * i.e. a negative shift amount, which is undefined behaviour in C99. */
			int playerSwitchBytes = inputPacket.data[index + 2];
			if (playerSwitchBytes > 2)
				playerSwitchBytes = 2;
			for (int i = 0; i < inputPacket.data[index + 1]; i++)
			{
				// Bounds check to prevent inputSwitch array overflow
				if (i + 1 >= JVS_MAX_STATE_SIZE)
				{
					debug(0, "Error: Player index out of bounds in CMD_READ_SWITCHES\n");
					return JVS_STATUS_ERROR;
				}
				for (int j = 0; j < playerSwitchBytes; j++)
				{
					// Bounds check to prevent buffer overflow
					// Check before writing to ensure we have space for the next byte
					if (outputPacket.length + 1 > JVS_MAX_PACKET_SIZE)
					{
						debug(0, "Error: Output packet size exceeded in CMD_READ_SWITCHES\n");
						return JVS_STATUS_ERROR;
					}
					outputPacket.data[outputPacket.length++] = switchSnapshot[i + 1] >> (8 - (j * 8));
				}
			}
		}
		break;

		case CMD_READ_COINS:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_READ_COINS - packet too short\n");
				break;
			}
			int numberCoinSlots = inputPacket.data[index + 1];
			debug(1, "CMD_READ_COINS - Reading %d coin slot(s)\n", numberCoinSlots);
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			if (numberCoinSlots > JVS_MAX_STATE_SIZE)
			{
				debug(0, "Error: Coin slot count %d exceeds maximum %d in CMD_READ_COINS\n", numberCoinSlots, JVS_MAX_STATE_SIZE);
				return JVS_STATUS_ERROR;
			}

			/* Snapshot the coin state to avoid holding the mutex over the output loop. */
			int coinSnapshot[JVS_MAX_STATE_SIZE];
			pthread_mutex_lock(&jvsIO->state_mutex);
			memcpy(coinSnapshot, jvsIO->state.coinCount, sizeof(coinSnapshot));
			pthread_mutex_unlock(&jvsIO->state_mutex);

			for (int i = 0; i < numberCoinSlots; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_COINS\n");
					return JVS_STATUS_ERROR;
				}
				// Send coin count as 2 bytes (high byte with 5-bit limit, then low byte)
				outputPacket.data[outputPacket.length] = (coinSnapshot[i] >> 8) & 0x1F;
				outputPacket.data[outputPacket.length + 1] = coinSnapshot[i] & 0xFF;
				outputPacket.length += 2;
			}
		}
		break;

		case CMD_READ_ANALOGS:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_READ_ANALOGS - packet too short\n");
				break;
			}
			int numberChannels = inputPacket.data[index + 1];
			debug(1, "CMD_READ_ANALOGS - Reading %d analog channel(s)\n", numberChannels);

			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			if (numberChannels > JVS_MAX_STATE_SIZE)
			{
				debug(0, "Error: Analogue channel count %d exceeds maximum %d in CMD_READ_ANALOGS\n", numberChannels, JVS_MAX_STATE_SIZE);
				return JVS_STATUS_ERROR;
			}

			/* Snapshot the analogue state to avoid holding the mutex over the output loop. */
			int analogueSnapshot[JVS_MAX_STATE_SIZE];
			pthread_mutex_lock(&jvsIO->state_mutex);
			memcpy(analogueSnapshot, jvsIO->state.analogueChannel, sizeof(analogueSnapshot));
			pthread_mutex_unlock(&jvsIO->state_mutex);

			for (int i = 0; i < numberChannels; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_ANALOGS\n");
					return JVS_STATUS_ERROR;
				}
				/* By default left align the data */
				int analogueData = analogueSnapshot[i] << jvsIO->analogueRestBits;
				outputPacket.data[outputPacket.length] = analogueData >> 8;
				outputPacket.data[outputPacket.length + 1] = analogueData;
				outputPacket.length += 2;
			}
		}
		break;

		case CMD_READ_ROTARY:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_READ_ROTARY - packet too short\n");
				break;
			}
			int numberChannels = inputPacket.data[index + 1];
			debug(1, "CMD_READ_ROTARY - Reading %d rotary channel(s)\n", numberChannels);

			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			if (numberChannels > JVS_MAX_STATE_SIZE)
			{
				debug(0, "Error: Rotary channel count %d exceeds maximum %d in CMD_READ_ROTARY\n", numberChannels, JVS_MAX_STATE_SIZE);
				return JVS_STATUS_ERROR;
			}

			/* Snapshot the rotary state to avoid holding the mutex over the output loop. */
			int rotarySnapshot[JVS_MAX_STATE_SIZE];
			pthread_mutex_lock(&jvsIO->state_mutex);
			memcpy(rotarySnapshot, jvsIO->state.rotaryChannel, sizeof(rotarySnapshot));
			pthread_mutex_unlock(&jvsIO->state_mutex);

			for (int i = 0; i < numberChannels; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_ROTARY\n");
					return JVS_STATUS_ERROR;
				}
				outputPacket.data[outputPacket.length] = rotarySnapshot[i] >> 8;
				outputPacket.data[outputPacket.length + 1] = rotarySnapshot[i] & 0xFF;
				outputPacket.length += 2;
			}
		}
		break;

		case CMD_READ_KEYPAD:
		{
			debug(1, "CMD_READ_KEYPAD - Reading keypad state\n");
			// Bounds check to prevent buffer overflow
			if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
			{
				debug(0, "Error: Output packet size exceeded in CMD_READ_KEYPAD\n");
				return JVS_STATUS_ERROR;
			}
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = 0x00;
			outputPacket.length += 2;
		}
		break;

		case CMD_READ_GPI:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_READ_GPI - packet too short\n");
				break;
			}
			int numberBytes = inputPacket.data[index + 1];
			debug(1, "CMD_READ_GPI - Reading %d byte(s) of GPI data\n", numberBytes);
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
			for (int i = 0; i < numberBytes; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 1 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_GPI\n");
					return JVS_STATUS_ERROR;
				}
				outputPacket.data[outputPacket.length++] = 0x00;
			}
		}
		break;

		case CMD_REMAINING_PAYOUT:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_REMAINING_PAYOUT - packet too short\n");
				break;
			}
			int numberSlots = inputPacket.data[index + 1];
			debug(1, "CMD_REMAINING_PAYOUT - Reading %d slot(s)\n", numberSlots);
			if (numberSlots > JVS_MAX_STATE_SIZE)
			{
				debug(0, "Error: Slot count %d exceeds maximum %d in CMD_REMAINING_PAYOUT\n", numberSlots, JVS_MAX_STATE_SIZE);
				return JVS_STATUS_ERROR;
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
			for (int i = 0; i < numberSlots; i++)
			{
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_REMAINING_PAYOUT\n");
					return JVS_STATUS_ERROR;
				}
				outputPacket.data[outputPacket.length] = 0;
				outputPacket.data[outputPacket.length + 1] = 0;
				outputPacket.length += 2;
			}
		}
		break;

		case CMD_SET_PAYOUT:
		{
			debug(1, "CMD_SET_PAYOUT - Setting payout value\n");
			size = 4;
			if (index + 3 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_SET_PAYOUT - packet too short\n");
				break;
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_GPO:
		{
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_WRITE_GPO - packet too short\n");
				break;
			}
			int numBytes = inputPacket.data[index + 1];
			debug(1, "CMD_WRITE_GPO - Writing %d byte(s) to GPO\n", numBytes);
			size = 2 + numBytes;
			/* Warn when the computed size would skip past the end of the packet, which
			 * would cause all remaining commands in this packet to be silently dropped. */
			if (index + size > (int)inputPacket.length - 1)
			{
				debug(0, "Warning: CMD_WRITE_GPO - %d GPO byte(s) (%d total) exceeds remaining packet length; remaining commands in this packet will be skipped\n",
				      numBytes, size);
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.length += 1;
		}
		break;

		case CMD_WRITE_GPO_BYTE:
		{
			size = 3;
			if (index + 2 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_WRITE_GPO_BYTE - packet too short\n");
				break;
			}
			debug(1, "CMD_WRITE_GPO_BYTE - Byte %d = 0x%02X\n", 
				inputPacket.data[index + 1], inputPacket.data[index + 2]);
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_GPO_BIT:
		{
			size = 3;
			if (index + 2 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_WRITE_GPO_BIT - packet too short\n");
				break;
			}
			debug(1, "CMD_WRITE_GPO_BIT - Byte %d, Bit %d\n", 
				inputPacket.data[index + 1], inputPacket.data[index + 2]);
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_ANALOG:
		{
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_WRITE_ANALOG - packet too short\n");
				break;
			}
			int numChannels = inputPacket.data[index + 1];
			debug(1, "CMD_WRITE_ANALOG - Writing %d analog channel(s)\n", numChannels);
			size = numChannels * 2 + 2;
			/* Warn when the computed size would skip past the end of the packet, which
			 * would cause all remaining commands in this packet to be silently dropped. */
			if (index + size > (int)inputPacket.length - 1)
			{
				debug(0, "Warning: CMD_WRITE_ANALOG - %d channel(s) (%d total bytes) exceeds remaining packet length; remaining commands in this packet will be skipped\n",
				      numChannels, size);
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_SUBTRACT_PAYOUT:
		{
			debug(1, "CMD_SUBTRACT_PAYOUT - Subtracting payout\n");
			size = 3;
			if (index + 2 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_SUBTRACT_PAYOUT - packet too short\n");
				break;
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_COINS:
		{
			size = 4;
			if (index + 3 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_WRITE_COINS - packet too short\n");
				break;
			}
			// - 1 because JVS is 1-indexed, but our array is 0-indexed
			int slot_index = inputPacket.data[index + 1] - 1;
			int coin_increment = ((int)(inputPacket.data[index + 3]) | ((int)(inputPacket.data[index + 2]) << 8));
			debug(1, "CMD_WRITE_COINS - Slot %d, incrementing by %d\n", slot_index + 1, coin_increment);

			/* Validate slot index to prevent out-of-bounds array access */
			if (slot_index < 0 || slot_index >= JVS_MAX_STATE_SIZE)
			{
				debug(0, "Error: Slot index out of bounds in CMD_WRITE_COINS\n");
				return JVS_STATUS_ERROR;
			}

			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			/* Prevent overflow of coins */
			pthread_mutex_lock(&jvsIO->state_mutex);
			if (coin_increment + jvsIO->state.coinCount[slot_index] > 16383)
				coin_increment = 16383 - jvsIO->state.coinCount[slot_index];
			jvsIO->state.coinCount[slot_index] += coin_increment;
			pthread_mutex_unlock(&jvsIO->state_mutex);
		}
		break;

		case CMD_WRITE_DISPLAY:
		{
			if (index + 2 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_WRITE_DISPLAY - packet too short\n");
				break;
			}
			int cols = inputPacket.data[index + 1];
			int rows = inputPacket.data[index + 2];
			debug(1, "CMD_WRITE_DISPLAY - Writing %d×%d display data\n", cols, rows);
			/* JVS spec: cmd(1) + cols(1) + rows(1) + encoding(1) + data(cols×rows) */
			size = 4 + cols * rows;
			/* Warn when the computed size would skip past the end of the packet, which
			 * would cause all remaining commands in this packet to be silently dropped. */
			if (index + size > (int)inputPacket.length - 1)
			{
				debug(0, "Warning: CMD_WRITE_DISPLAY - %d×%d data (%d bytes) exceeds remaining packet length; remaining commands in this packet will be skipped\n",
				      cols, rows, size);
			}
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_DECREASE_COINS:
		{
			size = 4;
			if (index + 3 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_DECREASE_COINS - packet too short\n");
				break;
			}
			// - 1 because JVS is 1-indexed, but our array is 0-indexed
			int slot_index = inputPacket.data[index + 1] - 1;
			int coin_decrement = ((int)(inputPacket.data[index + 3]) | ((int)(inputPacket.data[index + 2]) << 8));
			debug(1, "CMD_DECREASE_COINS - Slot %d, decrementing by %d\n", slot_index + 1, coin_decrement);

			/* Validate slot index to prevent out-of-bounds array access */
			if (slot_index < 0 || slot_index >= JVS_MAX_STATE_SIZE)
			{
				debug(0, "Error: Slot index out of bounds in CMD_DECREASE_COINS\n");
				return JVS_STATUS_ERROR;
			}

			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			/* Prevent underflow of coins */
			pthread_mutex_lock(&jvsIO->state_mutex);
			if (coin_decrement > jvsIO->state.coinCount[slot_index])
				coin_decrement = jvsIO->state.coinCount[slot_index];
			jvsIO->state.coinCount[slot_index] -= coin_decrement;
			pthread_mutex_unlock(&jvsIO->state_mutex);
		}
		break;

		case CMD_CONVEY_ID:
		{
			debug(1, "CMD_CONVEY_ID - Receiving main board ID\n");
			size = 1;
			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
			char idData[100];
			int i;
			for (i = 0; i < 99; i++)
			{
				/* Prevent reading past end of the received packet data */
				if (index + 1 + i >= (int)inputPacket.length - 1)
					break;
				idData[i] = (char)inputPacket.data[index + 1 + i];
				size++;
				if (!inputPacket.data[index + 1 + i])
					break;
			}
			// Ensure null termination. When the loop breaks on the null byte,
			// idData[i] was just copied as '\0'. When the loop runs to i == 99
			// without finding a null (malformed packet), we terminate at [99].
			idData[i] = '\0';
			debug(0, "CMD_CONVEY_ID - Main board ID: %s\n", idData);
		}
		break;

		/* The touch screen and light gun input, returns X/Y for each requested gun */
		case CMD_READ_LIGHTGUN:
		{
			size = 2;
			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_READ_LIGHTGUN - packet too short\n");
				break;
			}
			/* inputPacket.data is unsigned char so numberGuns is always 0-255 */
			int numberGuns = inputPacket.data[index + 1];
			debug(1, "CMD_READ_LIGHTGUN - Reading %d gun(s)\n", numberGuns);

			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			/* Each gun occupies two consecutive state slots (X then Y), so the
			 * maximum safe gun count is half the state array size. */
			if (numberGuns > JVS_MAX_STATE_SIZE / 2)
			{
				debug(0, "Error: Gun count %d exceeds maximum %d in CMD_READ_LIGHTGUN\n", numberGuns, JVS_MAX_STATE_SIZE / 2);
				return JVS_STATUS_ERROR;
			}

			/* Snapshot the gun channel state to avoid holding the mutex over the output loop. */
			int gunSnapshot[JVS_MAX_STATE_SIZE];
			pthread_mutex_lock(&jvsIO->state_mutex);
			memcpy(gunSnapshot, jvsIO->state.gunChannel, sizeof(gunSnapshot));
			pthread_mutex_unlock(&jvsIO->state_mutex);

			for (int i = 0; i < numberGuns; i++)
			{
				if (outputPacket.length + 4 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_LIGHTGUN\n");
					return JVS_STATUS_ERROR;
				}
				/* Guard against a request for more guns than this IO board declares.
				 * Channels beyond the configured count are reported as zero. */
				int xData = 0, yData = 0;
				if (i < jvsIO->capabilities.gunChannels)
				{
					xData = gunSnapshot[i * 2] << jvsIO->gunXRestBits;
					yData = gunSnapshot[i * 2 + 1] << jvsIO->gunYRestBits;
				}
				outputPacket.data[outputPacket.length] = xData >> 8;
				outputPacket.data[outputPacket.length + 1] = xData;
				outputPacket.data[outputPacket.length + 2] = yData >> 8;
				outputPacket.data[outputPacket.length + 3] = yData;
				outputPacket.length += 4;
			}
		}
		break;

		/* Namco Specific */
		case CMD_NAMCO_SPECIFIC:
		{
			debug(1, "CMD_NAMCO_SPECIFIC - Processing Namco command\n");

			if (index + 1 >= (int)inputPacket.length - 1)
			{
				debug(0, "Error: CMD_NAMCO_SPECIFIC - packet too short\n");
				break;
			}

			CHECK_OUTPUT_SPACE(&outputPacket, 1);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			size = 2;

			switch (inputPacket.data[index + 1])
			{

			// Read 8 bytes of memory
			case 0x01:
			{
				if (outputPacket.length + 8 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_NAMCO_SPECIFIC 0x01\n");
					return JVS_STATUS_ERROR;
				}
				for (int i = 0; i < 8; i++)
					outputPacket.data[outputPacket.length++] = 0xFF;
			}
			break;

			// Read the program date
			case 0x02:
			{
				if (outputPacket.length + 8 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_NAMCO_SPECIFIC 0x02\n");
					return JVS_STATUS_ERROR;
				}
				// 1998 October 26th at 12:00:00 (Unsure what last 00 is)
				unsigned char programDate[] = {0x19, 0x98, 0x10, 0x26, 0x12, 0x00, 0x00, 0x00};
				memcpy(&outputPacket.data[outputPacket.length], programDate, 8);
				outputPacket.length += 8;
			}
			break;

			// Dip switch status
			case 0x03:
			{
				if (outputPacket.length + 1 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_NAMCO_SPECIFIC 0x03\n");
					return JVS_STATUS_ERROR;
				}
				unsigned char dips = 0xFF;
				outputPacket.data[outputPacket.length++] = dips;
			}
			break;

			// Purpose of sub-command 0x04 is undocumented; returns 0xFF, 0xFF as a safe default
			case 0x04:
			{
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_NAMCO_SPECIFIC 0x04\n");
					return JVS_STATUS_ERROR;
				}
				outputPacket.data[outputPacket.length++] = 0xFF;
				outputPacket.data[outputPacket.length++] = 0xFF;
			}
			break;

			// ID Check (0xFF is what Triforce branch sends)
			case 0x18:
			{
				/* This sub-command is followed by 4 bytes of data.  Only
				 * advance the parser past them if the packet is actually
				 * large enough to contain them, so that a short/malformed
				 * packet does not cause subsequent command bytes to be
				 * skipped. */
				if (index + 5 < (int)inputPacket.length - 1)
					size += 4;
				CHECK_OUTPUT_SPACE(&outputPacket, 1);
				outputPacket.data[outputPacket.length++] = 0xFF;
			}
			break;

			default:
			{
				debug(0, "CMD_NAMCO_UNSUPPORTED - Unsupported Namco command: 0x%02hhX\n", inputPacket.data[index + 1]);
			}
			}
		}
		break;

		default:
		{
			debug(0, "CMD_UNSUPPORTED - Unsupported command: 0x%02hhX\n", inputPacket.data[index]);
			/* Per JVS spec: reply with STATUS_UNSUPPORTED and stop processing further commands */
			outputPacket.data[0] = STATUS_UNSUPPORTED;
			outputPacket.length = 1;
			return writePacket(&outputPacket);
		}
		}
		index += size;
	}

	return writePacket(&outputPacket);
}

/**
 * Read a JVS Packet
 *
 * A single JVS packet is read into the packet pointer
 * after it has been received, unescaped and checked
 * for any checksum errors.
 *
 * @param packet The packet to read into
 */
JVSStatus readPacket(JVSPacket *packet)
{
	/* index is intentionally local: it always starts at 0 because inputBuffer
	 * is compacted (via memmove) before every return so that unprocessed bytes
	 * are always at the front.  The persistent parse state lives in the static
	 * rx* variables declared above. */
	int index = 0, finished = 0;

	while (!finished)
	{
		int bytesRead = readBytes(inputBuffer + rxBytesAvailable, JVS_MAX_PACKET_SIZE - rxBytesAvailable);

		if (bytesRead < 0)
		{
			/* Preserve unprocessed bytes and current parse state for the
			 * next call.  The inner loop always drains every available byte
			 * (index == rxBytesAvailable when we reach here), but we compact
			 * defensively in case a future refactor changes that invariant. */
			int remaining = rxBytesAvailable - index;
			if (remaining > 0 && index > 0)
				memmove(inputBuffer, inputBuffer + index, remaining);
			rxBytesAvailable = remaining > 0 ? remaining : 0;
			return JVS_STATUS_ERROR_TIMEOUT;
		}

		rxBytesAvailable += bytesRead;

		while ((index < rxBytesAvailable) && !finished)
		{
			/* If we encounter a SYNC start again */
			if (!rxEscape && (inputBuffer[index] == SYNC))
			{
				rxPhase     = 0;
				rxDataIndex = 0;
				rxChecksum  = 0x00;
				rxEscape    = 0;
				/* Compact: discard everything up to and including this SYNC byte so
				 * that framing noise cannot exhaust the 255-byte inputBuffer.  Any
				 * bytes already read after the SYNC are shifted to the front so they
				 * are not lost. */
				int remaining = rxBytesAvailable - index - 1;
				if (remaining > 0)
					memmove(inputBuffer, inputBuffer + index + 1, remaining);
				/* `remaining` is always >= 0 here (loop invariant: index < rxBytesAvailable),
				 * but clamp defensively to prevent any future refactor from setting a
				 * negative rxBytesAvailable and passing a bogus offset to readBytes. */
				rxBytesAvailable = remaining > 0 ? remaining : 0;
				index = 0;
				continue;
			}

			/* If we encounter an ESCAPE byte escape the next byte */
			if (!rxEscape && inputBuffer[index] == ESCAPE)
			{
				rxEscape = 1;
				index++;
				continue;
			}

			/* Escape next byte by adding 1 to it */
			if (rxEscape)
			{
				inputBuffer[index]++;
				rxEscape = 0;
			}

			/* Deal with the main bulk of the data */
			switch (rxPhase)
			{
			case 0: // If we have not yet got the address
				packet->destination = inputBuffer[index];
				rxChecksum = packet->destination & 0xFF;
				rxPhase++;
				break;
			case 1: // If we have not yet got the length
				packet->length = inputBuffer[index];
				rxChecksum = (rxChecksum + packet->length) & 0xFF;
				/* A JVS length of 0 is always malformed: the length field counts
				 * the bytes that follow it including the checksum itself, so the
				 * minimum valid value is 1.  If we accepted 0, the expression
				 * (packet->length - 1) below would wrap to -1 (int promotion of
				 * unsigned char 0 minus 1) and the checksum guard would never
				 * trigger, causing every subsequent byte to be written to
				 * packet->data[rxDataIndex++] without bound — a stack overflow. */
				if (packet->length == 0)
				{
					resetPacketParser();
					return JVS_STATUS_ERROR_CHECKSUM;
				}
				rxPhase++;
				break;
			case 2: // If there is still data to read
				if (rxDataIndex == (packet->length - 1))
				{
					if (rxChecksum != inputBuffer[index])
					{
						resetPacketParser();
						return JVS_STATUS_ERROR_CHECKSUM;
					}
					finished = 1;
					break;
				}
				/* Defensive bounds check: packet->data is JVS_MAX_PACKET_SIZE bytes.
				 * With valid length values (1..255) the maximum rxDataIndex at write
				 * time is length-2 <= 253, well within range.  This guard protects
				 * against any future refactoring that could relax the length==0
				 * check above. */
				if (rxDataIndex >= JVS_MAX_PACKET_SIZE)
				{
					resetPacketParser();
					return JVS_STATUS_ERROR;
				}
				packet->data[rxDataIndex++] = inputBuffer[index];
				rxChecksum = (rxChecksum + inputBuffer[index]) & 0xFF;
				break;
			default:
				resetPacketParser();
				return JVS_STATUS_ERROR;
			}
			index++;
		}
	}

	/* Only compute debug output if debug level is high enough.  Do this
	 * BEFORE compacting the buffer so that inputBuffer[0..index-1] still
	 * holds the raw bytes of the packet we just received. */
	if (getDebugLevel() >= 2)
	{
		debug(2, "\n=== INPUT PACKET #%lu ===\n", ++packetCounter);
		debug(2, "  Destination: 0x%02X  Length: %d bytes\n", packet->destination, packet->length);

		/* Show potential commands in packet data
		 * Note: Only the first byte is typically a command, subsequent bytes are usually
		 * parameters/arguments. This shows what each byte COULD mean if interpreted as
		 * a command, which helps identify actual command bytes vs arguments (UNKNOWN).
		 */
		if (packet->length > 1)
		{
			debug(2, "  Data bytes: ");
			for (int i = 0; i < packet->length - 1 && i < 10; i++)
			{
				unsigned char byte = packet->data[i];
				const char *cmdName = getCommandName(byte);
				debug(2, "%s(0x%02X) ", cmdName, byte);
			}
			if (packet->length - 1 > 10)
				debug(2, "...");
			debug(2, "\n");
		}

		debug(2, "  Raw data: ");
		debugBuffer(2, inputBuffer, index);
	}

	/* Compact any bytes belonging to the next packet to the front of
	 * inputBuffer so they are available on the next readPacket() call. */
	int remaining = rxBytesAvailable - index;
	if (remaining > 0 && index > 0)
		memmove(inputBuffer, inputBuffer + index, remaining);
	rxBytesAvailable = remaining > 0 ? remaining : 0;

	/* Reset parse state ready for the next packet */
	rxPhase     = 0;
	rxDataIndex = 0;
	rxEscape    = 0;
	rxChecksum  = 0x00;

	return JVS_STATUS_SUCCESS;
}

/**
 * Write a JVS Packet
 *
 * A single JVS Packet is written to the arcade
 * system after it has been escaped and had
 * a checksum calculated.
 *
 * @param packet The packet to send
 */
JVSStatus writePacket(JVSPacket *packet)
{
	/* Don't return anything if the packet has no data at all */
	if (packet->length < 1)
		return JVS_STATUS_SUCCESS;

	/* The JVS wire-format length field is a single byte whose value includes
	 * the checksum byte.  Adding 1 to packet->length must therefore remain ≤
	 * 255, i.e. packet->length ≤ 254.  If this invariant is violated the
	 * wire length byte would silently wrap to 0, producing a corrupt packet
	 * that the arcade machine cannot parse. */
	if (packet->length >= JVS_MAX_PACKET_SIZE)
	{
		debug(0, "Error: Output packet length %d exceeds wire format maximum, dropping\n", packet->length);
		return JVS_STATUS_ERROR;
	}

	/* Get pointer to raw data in packet */
	unsigned char *packetPointer = (unsigned char *)packet;

	/* Add SYNC and reset buffer */
	int checksum = 0;
	int outputIndex = 1;
	outputBuffer[0] = SYNC;

	/* Increment the length to include the checksum byte in the wire-format
	 * length field, then restore it afterwards so that the packet struct
	 * stays consistent (important for CMD_RETRANSMIT which re-calls this
	 * function with the same outputPacket without rebuilding it).
	 * packet->length < JVS_MAX_PACKET_SIZE (255) is guaranteed by the check
	 * above, so wireLength ≤ 255 and the cast to unsigned char is lossless. */
	unsigned char savedLength = packet->length;
	int wireLength = (int)packet->length + 1;
	packet->length = (unsigned char)wireLength;

	/* Write out entire packet */
	for (int i = 0; i < wireLength + 1; i++)
	{
		if (packetPointer[i] == SYNC || packetPointer[i] == ESCAPE)
		{
			outputBuffer[outputIndex++] = ESCAPE;
			outputBuffer[outputIndex++] = (packetPointer[i] - 1);
		}
		else
		{
			outputBuffer[outputIndex++] = (packetPointer[i]);
		}
		checksum = (checksum + packetPointer[i]) & 0xFF;
	}

	/* Write out escaped checksum */
	if (checksum == SYNC || checksum == ESCAPE)
	{
		outputBuffer[outputIndex++] = ESCAPE;
		outputBuffer[outputIndex++] = (checksum - 1);
	}
	else
	{
		outputBuffer[outputIndex++] = checksum;
	}

	/* Only compute debug output if debug level is high enough */
	if (getDebugLevel() >= 2)
	{
		debug(2, "\n=== OUTPUT PACKET #%lu ===\n", packetCounter);
		debug(2, "  Destination: 0x%02X  Length: %d bytes\n", packet->destination, packet->length);
		debug(2, "  Raw data: ");
		debugBuffer(2, outputBuffer, outputIndex);
	}

	int written = 0, timeout = 0;

	/* Restore the original data length before returning so that the packet
	 * struct is left in a consistent state (needed by CMD_RETRANSMIT). */
	packet->length = savedLength;

	while (written < outputIndex)
	{
		if (timeout > JVS_RETRY_COUNT)
			return JVS_STATUS_ERROR_WRITE_FAIL;

		int result = writeBytes(outputBuffer + written, outputIndex - written);
		if (result <= 0)
		{
			timeout++;
			continue;
		}
		written += result;
		timeout = 0;
	}

	return JVS_STATUS_SUCCESS;
}
