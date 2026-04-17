#include "console/debug.h"

#include <stdarg.h>

int globalLevel = 0;

int initDebug(int level)
{
    globalLevel = level;
    if (globalLevel > 0)
    {
        debug(0, "\nWarning: ModernJVS is running in debug mode. This will slow down the overall emulation\n\n");
    }
    return 1;
}

void debug(int level, const char *format, ...)
{
    if (globalLevel < level)
        return;

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    /* Flush immediately for always-shown messages (level 0) to ensure they
     * appear before a potential crash.  Skip the syscall for debug-mode output
     * (level >= 1) — flushing on every packet would visibly slow emulation. */
    if (level == 0)
        fflush(stdout);
}

int getDebugLevel(void)
{
    return globalLevel;
}

void debugBuffer(int level, unsigned char *buffer, int length)
{
    if (globalLevel < level)
        return;

    for (int i = 0; i < length; i++)
        debug(level, "0x%02hhX ", buffer[i]);
    debug(level, "\n");
}

void debugPacket(int level, JVSPacket *packet)
{
    if (globalLevel < level)
        return;

    debug(level, "DESTINATION: %d\n", packet->destination);
    debug(level, "LENGTH: %d\n", packet->length);
    debug(level, "DATA: ");
    if (packet->length > 0)
    {
        for (int i = 0; i < packet->length - 1; i++)
            debug(level, "0x%02hhX ", packet->data[i]);
    }
    debug(level, "\n");
}
