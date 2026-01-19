#include "jvs/jvs.h"
#include "hardware/device.h"
#include "console/debug.h"

#include <time.h>

/* The in and out packets used to read and write to and from*/
JVSPacket inputPacket, outputPacket;

/* The in and out buffer used to read and write to and from */
unsigned char outputBuffer[JVS_MAX_PACKET_SIZE], inputBuffer[JVS_MAX_PACKET_SIZE];

/* Packet counter for debugging */
static unsigned long packetCounter = 0;

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
	/* Calculate the alignments for analogue and gun channels, default is left */
	if (!jvsIO->capabilities.rightAlignBits)
	{
		jvsIO->analogueRestBits = 16 - jvsIO->capabilities.analogueInBits;
		jvsIO->gunXRestBits = 16 - jvsIO->capabilities.gunXBits;
		jvsIO->gunYRestBits = 16 - jvsIO->capabilities.gunYBits;
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
		return readPacketStatus;

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
	if (inputPacket.data[0] == CMD_RETRANSMIT)
		return writePacket(&outputPacket);

	/* Setup the output packet */
	outputPacket.length = 0;
	outputPacket.destination = BUS_MASTER;

	int index = 0;

	/* Set the entire packet success line */
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
			jvsIO->deviceID = -1;
			while (jvsIO->chainedIO != NULL)
			{
				jvsIO = jvsIO->chainedIO;
				jvsIO->deviceID = -1;
			}
			setSenseLine(0);
		}
		break;

		/* The arcade hardware assigns an address to our IO */
		case CMD_ASSIGN_ADDR:
		{
			size = 2;

			JVSIO *ioToAssign = jvsIO;
			while (ioToAssign->deviceID != -1 && ioToAssign->chainedIO != NULL)
			{
				ioToAssign = ioToAssign->chainedIO;
			}

			ioToAssign->deviceID = inputPacket.data[index + 1];
			debug(1, "CMD_ASSIGN_ADDR - Assigning address 0x%02X\n", ioToAssign->deviceID);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			// Check if there are any more unassigned boards in the chain
			int hasUnassignedBoards = 0;
			JVSIO *checkIO = jvsIO;
			while (checkIO != NULL)
			{
				if (checkIO->deviceID == -1)
				{
					hasUnassignedBoards = 1;
					break;
				}
				checkIO = checkIO->chainedIO;
			}

			// Set sense line based on whether there are unassigned boards
			setSenseLine(hasUnassignedBoards);
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
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = jvsIO->capabilities.commandVersion;
			outputPacket.length += 2;
		}
		break;

		/* Asks for version information */
		case CMD_JVS_VERSION:
		{
			debug(1, "CMD_JVS_VERSION - Returning version 0x%02X\n", jvsIO->capabilities.jvsVersion);
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = jvsIO->capabilities.jvsVersion;
			outputPacket.length += 2;
		}
		break;

		/* Asks for version information */
		case CMD_COMMS_VERSION:
		{
			debug(1, "CMD_COMMS_VERSION - Returning version 0x%02X\n", jvsIO->capabilities.commsVersion);
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
			debug(1, "CMD_READ_SWITCHES - Players: %d, Switches: %d\n", 
				inputPacket.data[index + 1], inputPacket.data[index + 2]);
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = jvsIO->state.inputSwitch[0];
			outputPacket.length += 2;
			for (int i = 0; i < inputPacket.data[index + 1]; i++)
			{
				for (int j = 0; j < inputPacket.data[index + 2]; j++)
				{
					// Bounds check to prevent buffer overflow
					// Check before writing to ensure we have space for the next byte
					if (outputPacket.length + 1 > JVS_MAX_PACKET_SIZE)
					{
						debug(0, "Error: Output packet size exceeded in CMD_READ_SWITCHES\n");
						return JVS_STATUS_ERROR;
					}
					outputPacket.data[outputPacket.length++] = jvsIO->state.inputSwitch[i + 1] >> (8 - (j * 8));
				}
			}
		}
		break;

		case CMD_READ_COINS:
		{
			size = 2;
			int numberCoinSlots = inputPacket.data[index + 1];
			debug(1, "CMD_READ_COINS - Reading %d coin slot(s)\n", numberCoinSlots);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			for (int i = 0; i < numberCoinSlots; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_COINS\n");
					return JVS_STATUS_ERROR;
				}
				// Send coin count as 2 bytes (high byte with 5-bit limit, then low byte)
				outputPacket.data[outputPacket.length] = (jvsIO->state.coinCount[i] >> 8) & 0x1F;
				outputPacket.data[outputPacket.length + 1] = jvsIO->state.coinCount[i] & 0xFF;
				outputPacket.length += 2;
			}
		}
		break;

		case CMD_READ_ANALOGS:
		{
			size = 2;
			int numberChannels = inputPacket.data[index + 1];
			debug(1, "CMD_READ_ANALOGS - Reading %d analog channel(s)\n", numberChannels);

			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			for (int i = 0; i < numberChannels; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_ANALOGS\n");
					return JVS_STATUS_ERROR;
				}
				/* By default left align the data */
				int analogueData = jvsIO->state.analogueChannel[i] << jvsIO->analogueRestBits;
				outputPacket.data[outputPacket.length] = analogueData >> 8;
				outputPacket.data[outputPacket.length + 1] = analogueData;
				outputPacket.length += 2;
			}
		}
		break;

		case CMD_READ_ROTARY:
		{
			size = 2;
			int numberChannels = inputPacket.data[index + 1];
			debug(1, "CMD_READ_ROTARY - Reading %d rotary channel(s)\n", numberChannels);

			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			for (int i = 0; i < numberChannels; i++)
			{
				// Bounds check to prevent buffer overflow
				if (outputPacket.length + 2 > JVS_MAX_PACKET_SIZE)
				{
					debug(0, "Error: Output packet size exceeded in CMD_READ_ROTARY\n");
					return JVS_STATUS_ERROR;
				}
				outputPacket.data[outputPacket.length] = jvsIO->state.rotaryChannel[i] >> 8;
				outputPacket.data[outputPacket.length + 1] = jvsIO->state.rotaryChannel[i] & 0xFF;
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
			int numberBytes = inputPacket.data[index + 1];
			debug(1, "CMD_READ_GPI - Reading %d byte(s) of GPI data\n", numberBytes);
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
			for (int i = 0; i < inputPacket.data[index + 1]; i++)
			{
				outputPacket.data[outputPacket.length++] = 0x00;
			}
		}
		break;

		case CMD_REMAINING_PAYOUT:
		{
			debug(1, "CMD_REMAINING_PAYOUT - Returning payout status\n");
			size = 2;
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = 0;
			outputPacket.data[outputPacket.length + 2] = 0;
			outputPacket.data[outputPacket.length + 3] = 0;
			outputPacket.data[outputPacket.length + 4] = 0;
			outputPacket.length += 5;
		}
		break;

		case CMD_SET_PAYOUT:
		{
			debug(1, "CMD_SET_PAYOUT - Setting payout value\n");
			size = 4;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_GPO:
		{
			int numBytes = inputPacket.data[index + 1];
			debug(1, "CMD_WRITE_GPO - Writing %d byte(s) to GPO\n", numBytes);
			size = 2 + numBytes;
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.length += 1;
		}
		break;

		case CMD_WRITE_GPO_BYTE:
		{
			debug(1, "CMD_WRITE_GPO_BYTE - Byte %d = 0x%02X\n", 
				inputPacket.data[index + 1], inputPacket.data[index + 2]);
			size = 3;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_GPO_BIT:
		{
			debug(1, "CMD_WRITE_GPO_BIT - Byte %d, Bit %d\n", 
				inputPacket.data[index + 1], inputPacket.data[index + 2]);
			size = 3;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_ANALOG:
		{
			int numChannels = inputPacket.data[index + 1];
			debug(1, "CMD_WRITE_ANALOG - Writing %d analog channel(s)\n", numChannels);
			size = numChannels * 2 + 2;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_SUBTRACT_PAYOUT:
		{
			debug(1, "CMD_SUBTRACT_PAYOUT - Subtracting payout\n");
			size = 3;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_WRITE_COINS:
		{
			size = 4;
			// - 1 because JVS is 1-indexed, but our array is 0-indexed
			int slot_index = inputPacket.data[index + 1] - 1;
			int coin_increment = ((int)(inputPacket.data[index + 3]) | ((int)(inputPacket.data[index + 2]) << 8));
			debug(1, "CMD_WRITE_COINS - Slot %d, incrementing by %d\n", slot_index + 1, coin_increment);

			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			/* Prevent overflow of coins */
			if (coin_increment + jvsIO->state.coinCount[slot_index] > 16383)
				coin_increment = 16383 - jvsIO->state.coinCount[slot_index];
			jvsIO->state.coinCount[slot_index] += coin_increment;
		}
		break;

		case CMD_WRITE_DISPLAY:
		{
			debug(1, "CMD_WRITE_DISPLAY - Writing display data\n");
			size = (inputPacket.data[index + 1] * 2) + 2;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
		}
		break;

		case CMD_DECREASE_COINS:
		{
			size = 4;
			// - 1 because JVS is 1-indexed, but our array is 0-indexed
			int slot_index = inputPacket.data[index + 1] - 1;
			int coin_decrement = ((int)(inputPacket.data[index + 3]) | ((int)(inputPacket.data[index + 2]) << 8));
			debug(1, "CMD_DECREASE_COINS - Slot %d, decrementing by %d\n", slot_index + 1, coin_decrement);

			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			/* Prevent underflow of coins */
			if (coin_decrement > jvsIO->state.coinCount[slot_index])
				coin_decrement = jvsIO->state.coinCount[slot_index];
			jvsIO->state.coinCount[slot_index] -= coin_decrement;
		}
		break;

		case CMD_CONVEY_ID:
		{
			debug(1, "CMD_CONVEY_ID - Receiving main board ID\n");
			size = 1;
			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;
			char idData[100];
			idData[0] = '\0'; // Initialize to empty string
			for (int i = 1; i < 100; i++)
			{
				idData[i] = (char)inputPacket.data[index + i];
				size++;
				if (!inputPacket.data[index + i])
					break;
			}
			debug(0, "CMD_CONVEY_ID - Main board ID: %s\n", idData);
		}
		break;

		/* The touch screen and light gun input, simply using analogue channels */
		case CMD_READ_LIGHTGUN:
		{
			debug(1, "CMD_READ_LIGHTGUN - Reading light gun position\n");
			size = 2;

			int analogueXData = jvsIO->state.gunChannel[0] << jvsIO->gunXRestBits;
			int analogueYData = jvsIO->state.gunChannel[1] << jvsIO->gunYRestBits;
			outputPacket.data[outputPacket.length] = REPORT_SUCCESS;
			outputPacket.data[outputPacket.length + 1] = analogueXData >> 8;
			outputPacket.data[outputPacket.length + 2] = analogueXData;
			outputPacket.data[outputPacket.length + 3] = analogueYData >> 8;
			outputPacket.data[outputPacket.length + 4] = analogueYData;
			outputPacket.length += 5;
		}
		break;

		/* Namco Specific */
		case CMD_NAMCO_SPECIFIC:
		{
			debug(1, "CMD_NAMCO_SPECIFIC - Processing Namco command\n");

			outputPacket.data[outputPacket.length++] = REPORT_SUCCESS;

			size = 2;

			switch (inputPacket.data[index + 1])
			{

			// Read 8 bytes of memory
			case 0x01:
			{
				for (int i = 0; i < 8; i++)
					outputPacket.data[outputPacket.length++] = 0xFF;
			}
			break;

			// Read the program date
			case 0x02:
			{
				// 1998 October 26th at 12:00:00 (Unsure what last 00 is)
				unsigned char programDate[] = {0x19, 0x98, 0x10, 0x26, 0x12, 0x00, 0x00, 0x00};
				memcpy(&outputPacket.data[outputPacket.length], programDate, 8);
				outputPacket.length += 8;
			}
			break;

			// Dip switch status
			case 0x03:
			{
				unsigned char dips = 0xFF;
				outputPacket.data[outputPacket.length++] = dips;
			}
			break;

			// Unsure
			case 0x04:
			{
				outputPacket.data[outputPacket.length++] = 0xFF;
				outputPacket.data[outputPacket.length++] = 0xFF;
			}
			break;

			// ID Check (0xFF is what Triforce branch sends)
			case 0x18:
			{
				size += 4;
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
	int bytesAvailable = 0, escape = 0, phase = 0, index = 0, dataIndex = 0, finished = 0;
	unsigned char checksum = 0x00;

	while (!finished)
	{
		int bytesRead = readBytes(inputBuffer + bytesAvailable, JVS_MAX_PACKET_SIZE - bytesAvailable);

		if (bytesRead < 0)
			return JVS_STATUS_ERROR_TIMEOUT;

		bytesAvailable += bytesRead;

		while ((index < bytesAvailable) && !finished)
		{
			/* If we encounter a SYNC start again */
			if (!escape && (inputBuffer[index] == SYNC))
			{
				phase = 0;
				dataIndex = 0;
				index++;
				continue;
			}

			/* If we encounter an ESCAPE byte escape the next byte */
			if (!escape && inputBuffer[index] == ESCAPE)
			{
				escape = 1;
				index++;
				continue;
			}

			/* Escape next byte by adding 1 to it */
			if (escape)
			{
				inputBuffer[index]++;
				escape = 0;
			}

			/* Deal with the main bulk of the data */
			switch (phase)
			{
			case 0: // If we have not yet got the address
				packet->destination = inputBuffer[index];
				checksum = packet->destination & 0xFF;
				phase++;
				break;
			case 1: // If we have not yet got the length
				packet->length = inputBuffer[index];
				checksum = (checksum + packet->length) & 0xFF;
				phase++;
				break;
			case 2: // If there is still data to read
				if (dataIndex == (packet->length - 1))
				{
					if (checksum != inputBuffer[index])
						return JVS_STATUS_ERROR_CHECKSUM;
					finished = 1;
					break;
				}
				packet->data[dataIndex++] = inputBuffer[index];
				checksum = (checksum + inputBuffer[index]) & 0xFF;
				break;
			default:
				return JVS_STATUS_ERROR;
			}
			index++;
		}
	}

	/* Only compute debug output if debug level is high enough */
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
	/* Don't return anything if there isn't anything to write! */
	if (packet->length < 2)
		return JVS_STATUS_SUCCESS;

	/* Get pointer to raw data in packet */
	unsigned char *packetPointer = (unsigned char *)packet;

	/* Add SYNC and reset buffer */
	int checksum = 0;
	int outputIndex = 1;
	outputBuffer[0] = SYNC;

	packet->length++;

	/* Write out entire packet */
	for (int i = 0; i < packet->length + 1; i++)
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
	while (written < outputIndex)
	{
		if (written != 0)
			timeout = 0;

		if (timeout > JVS_RETRY_COUNT)
			return JVS_STATUS_ERROR_WRITE_FAIL;

		written += writeBytes(outputBuffer + written, outputIndex - written);
		timeout++;
	}

	return JVS_STATUS_SUCCESS;
}
