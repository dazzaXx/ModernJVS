#include "ffb/ffb.h"
#include "console/debug.h"
#include "controller/threading.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/input.h>
#include <errno.h>

#define BITS_PER_LONG (sizeof(long) * 8)
#define NBITS(x) ((((x)-1) / BITS_PER_LONG) + 1)
#define OFF(x) ((x) % BITS_PER_LONG)
#define LONG(x) ((x) / BITS_PER_LONG)
#define test_bit(bit, array) ((array[LONG(bit)] >> OFF(bit)) & 1)

void *ffbThread(void *_args);
static int findEventDevice(int controllerFd, char *eventPath, size_t pathSize);
static int detectFFBCapabilities(FFBState *state);
static int uploadFFBEffect(FFBState *state, FFBCommand *command);
static int playEffect(int fd, int effectId);
static int stopEffect(int fd, int effectId);
static void stopAllEffects(FFBState *state);
static void cleanupEffects(FFBState *state);

FFBStatus initFFB(FFBState *state, FFBEmulationType type, char *serialPath)
{
    debug(0, "Init ffb %s\n", serialPath);
    state->type = type;
    state->serial = -1;
    state->controller = -1;
    state->eventFd = -1;
    state->hasFFB = 0;
    state->hasConstant = 0;
    state->hasSpring = 0;
    state->hasDamper = 0;
    state->hasRumble = 0;
    state->effectCount = 0;
    memset(state->effectIds, -1, sizeof(state->effectIds));
    memset(state->eventPath, 0, sizeof(state->eventPath));
    
    // Initialize command queue
    state->commandQueue.head = 0;
    state->commandQueue.tail = 0;
    state->commandQueue.count = 0;
    pthread_mutex_init(&state->commandQueue.mutex, NULL);

    if (createThread(ffbThread, state) != THREAD_STATUS_SUCCESS)
        return FFB_STATUS_ERROR;

    return FFB_STATUS_SUCCESS;
}

FFBStatus closeFFB(FFBState *state)
{
    if (state->eventFd >= 0)
    {
        stopAllEffects(state);
        cleanupEffects(state);
        close(state->eventFd);
        state->eventFd = -1;
    }
    
    pthread_mutex_destroy(&state->commandQueue.mutex);
    state->serial = -1;
    return FFB_STATUS_SUCCESS;
}

FFBStatus bindController(FFBState *state, int controller)
{
    if (state->controller > -1)
        return FFB_STATUS_ERROR_CONTROLLED_ALREADY_BOUND;

    state->controller = controller;
    
    // Try to find and open the event device for this controller
    if (findEventDevice(controller, state->eventPath, sizeof(state->eventPath)) == 0)
    {
        state->eventFd = open(state->eventPath, O_RDWR);
        if (state->eventFd < 0)
        {
            debug(1, "FFB: Could not open event device %s: %s\n", state->eventPath, strerror(errno));
            return FFB_STATUS_SUCCESS; // Not an error - controller just doesn't support FFB
        }
        
        debug(1, "FFB: Opened event device %s for controller %d\n", state->eventPath, controller);
        
        // Detect FFB capabilities
        if (detectFFBCapabilities(state) == 0)
        {
            debug(0, "FFB: Controller %d supports force feedback\n", controller);
            if (state->hasRumble)
                debug(1, "  - Rumble effects (gamepad/controller)\n");
            if (state->hasConstant)
                debug(1, "  - Constant force (steering wheel)\n");
            if (state->hasSpring)
                debug(1, "  - Spring effects (centering)\n");
            if (state->hasDamper)
                debug(1, "  - Damper effects (friction)\n");
        }
    }

    return FFB_STATUS_SUCCESS;
}

FFBStatus queueFFBCommand(FFBState *state, FFBCommand *command)
{
    if (!state || !command)
        return FFB_STATUS_ERROR;
    
    pthread_mutex_lock(&state->commandQueue.mutex);
    
    if (state->commandQueue.count >= FFB_COMMAND_QUEUE_SIZE)
    {
        // Queue is full, drop oldest command
        debug(2, "FFB: Command queue full, dropping oldest command\n");
        state->commandQueue.head = (state->commandQueue.head + 1) % FFB_COMMAND_QUEUE_SIZE;
        state->commandQueue.count--;
    }
    
    state->commandQueue.commands[state->commandQueue.tail] = *command;
    state->commandQueue.tail = (state->commandQueue.tail + 1) % FFB_COMMAND_QUEUE_SIZE;
    state->commandQueue.count++;
    
    pthread_mutex_unlock(&state->commandQueue.mutex);
    
    return FFB_STATUS_SUCCESS;
}

void *ffbThread(void *_args)
{
    FFBState *state = (FFBState *)_args;

    debug(1, "FFB: Thread started for serial %d\n", state->serial);

    // Wait for controller to be bound
    while (getThreadsRunning() && state->controller < 0)
    {
        usleep(100000); // 100ms
    }
    
    if (!getThreadsRunning())
    {
        debug(1, "FFB: Thread exiting (no controller bound)\n");
        return 0;
    }
    
    // Wait for event device to be opened
    while (getThreadsRunning() && state->eventFd < 0)
    {
        usleep(100000); // 100ms
    }
    
    if (!getThreadsRunning())
    {
        debug(1, "FFB: Thread exiting (no event device)\n");
        return 0;
    }
    
    if (!state->hasFFB)
    {
        debug(1, "FFB: Controller does not support force feedback, thread idle\n");
        while (getThreadsRunning())
        {
            usleep(500000); // 500ms
        }
        return 0;
    }
    
    debug(1, "FFB: Thread processing commands for controller %d\n", state->controller);

    // Main FFB processing loop
    while (getThreadsRunning())
    {
        FFBCommand command;
        int hasCommand = 0;
        
        // Check for pending commands
        pthread_mutex_lock(&state->commandQueue.mutex);
        if (state->commandQueue.count > 0)
        {
            command = state->commandQueue.commands[state->commandQueue.head];
            state->commandQueue.head = (state->commandQueue.head + 1) % FFB_COMMAND_QUEUE_SIZE;
            state->commandQueue.count--;
            hasCommand = 1;
        }
        pthread_mutex_unlock(&state->commandQueue.mutex);
        
        if (hasCommand)
        {
            debug(2, "FFB: Processing command type %d, strength %d, duration %d\n", 
                  command.type, command.strength, command.duration);
            
            if (command.type == FFB_COMMAND_TYPE_STOP_ALL)
            {
                stopAllEffects(state);
            }
            else
            {
                uploadFFBEffect(state, &command);
            }
        }
        
        // Sleep briefly to avoid busy-waiting
        usleep(10000); // 10ms
    }

    debug(1, "FFB: Thread shutting down\n");
    stopAllEffects(state);
    cleanupEffects(state);

    return 0;
}

static int findEventDevice(int controllerFd, char *eventPath, size_t pathSize)
{
    // Try to find the event device by checking /proc/self/fd/ symlinks
    // NOTE: This is a simplified approach for single-controller setups.
    // For multi-controller scenarios, proper device matching via sysfs
    // or udev would be needed to ensure FFB binds to the correct controller.
    
    char fdPath[256];
    char linkPath[256];
    ssize_t len;
    
    snprintf(fdPath, sizeof(fdPath), "/proc/self/fd/%d", controllerFd);
    len = readlink(fdPath, linkPath, sizeof(linkPath) - 1);
    
    if (len < 0)
    {
        debug(2, "FFB: Could not read link for fd %d\n", controllerFd);
        
        // Fallback: scan /dev/input/event* devices
        DIR *dir = opendir("/dev/input");
        if (!dir)
            return -1;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strncmp(entry->d_name, "event", 5) == 0)
            {
                snprintf(eventPath, pathSize, "/dev/input/%s", entry->d_name);
                
                // Try to open and check if it's a joystick/gamepad
                int testFd = open(eventPath, O_RDONLY);
                if (testFd >= 0)
                {
                    unsigned long evbit[NBITS(EV_MAX)];
                    if (ioctl(testFd, EVIOCGBIT(0, sizeof(evbit)), evbit) >= 0)
                    {
                        // Check if device has absolute axes (likely a joystick/gamepad)
                        if (test_bit(EV_ABS, evbit) && test_bit(EV_FF, evbit))
                        {
                            close(testFd);
                            closedir(dir);
                            debug(2, "FFB: Found event device %s with FFB support\n", eventPath);
                            return 0;
                        }
                    }
                    close(testFd);
                }
            }
        }
        closedir(dir);
        return -1;
    }
    
    linkPath[len] = '\0';
    
    // Extract the event number from the path
    // Typically paths look like /dev/input/event5 or /dev/input/js0
    char *eventNum = strstr(linkPath, "/event");
    if (eventNum)
    {
        snprintf(eventPath, pathSize, "/dev/input%s", eventNum);
        return 0;
    }
    
    // If it's a js device, try to find corresponding event device
    char *jsNum = strstr(linkPath, "/js");
    if (jsNum)
    {
        // Scan for event devices with FFB capability
        DIR *dir = opendir("/dev/input");
        if (!dir)
            return -1;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strncmp(entry->d_name, "event", 5) == 0)
            {
                snprintf(eventPath, pathSize, "/dev/input/%s", entry->d_name);
                closedir(dir);
                return 0;
            }
        }
        closedir(dir);
    }
    
    return -1;
}

static int detectFFBCapabilities(FFBState *state)
{
    if (state->eventFd < 0)
        return -1;
    
    unsigned long ffBits[NBITS(FF_MAX)];
    memset(ffBits, 0, sizeof(ffBits));
    
    if (ioctl(state->eventFd, EVIOCGBIT(EV_FF, sizeof(ffBits)), ffBits) < 0)
    {
        debug(2, "FFB: Device does not support force feedback\n");
        return -1;
    }
    
    state->hasFFB = 1;
    state->hasConstant = test_bit(FF_CONSTANT, ffBits);
    state->hasSpring = test_bit(FF_SPRING, ffBits);
    state->hasDamper = test_bit(FF_DAMPER, ffBits);
    state->hasRumble = test_bit(FF_RUMBLE, ffBits);
    
    // Get number of effects the device can store
    int numEffects = 0;
    if (ioctl(state->eventFd, EVIOCGEFFECTS, &numEffects) >= 0)
    {
        debug(2, "FFB: Device can store %d simultaneous effects\n", numEffects);
    }
    
    return 0;
}

static int uploadFFBEffect(FFBState *state, FFBCommand *command)
{
    if (state->eventFd < 0 || !state->hasFFB)
        return -1;
    
    struct ff_effect effect;
    memset(&effect, 0, sizeof(effect));
    effect.id = -1; // Let kernel assign ID
    
    // Set replay parameters
    effect.replay.length = command->duration > 0 ? command->duration : 1000; // Default 1 second
    effect.replay.delay = 0;
    
    switch (command->type)
    {
    case FFB_COMMAND_TYPE_CONSTANT:
        if (!state->hasConstant)
        {
            debug(2, "FFB: Device does not support constant force effects\n");
            return -1;
        }
        effect.type = FF_CONSTANT;
        effect.u.constant.level = (command->strength * 32767) / 255; // Scale to -32767 to 32767
        effect.direction = (command->direction * 0xFFFF) / 360; // Scale to 0x0000 to 0xFFFF
        effect.u.constant.envelope.attack_length = 0;
        effect.u.constant.envelope.attack_level = 0;
        effect.u.constant.envelope.fade_length = 0;
        effect.u.constant.envelope.fade_level = 0;
        break;
        
    case FFB_COMMAND_TYPE_SPRING:
        if (!state->hasSpring)
        {
            debug(2, "FFB: Device does not support spring effects\n");
            return -1;
        }
        effect.type = FF_SPRING;
        effect.u.condition[0].right_saturation = 0x7fff;
        effect.u.condition[0].left_saturation = 0x7fff;
        effect.u.condition[0].right_coeff = (command->strength * 0x7fff) / 255;
        effect.u.condition[0].left_coeff = (command->strength * 0x7fff) / 255;
        effect.u.condition[0].deadband = 0;
        effect.u.condition[0].center = 0;
        break;
        
    case FFB_COMMAND_TYPE_DAMPER:
        if (!state->hasDamper)
        {
            debug(2, "FFB: Device does not support damper effects\n");
            return -1;
        }
        effect.type = FF_DAMPER;
        effect.u.condition[0].right_saturation = 0x7fff;
        effect.u.condition[0].left_saturation = 0x7fff;
        effect.u.condition[0].right_coeff = (command->strength * 0x7fff) / 255;
        effect.u.condition[0].left_coeff = (command->strength * 0x7fff) / 255;
        effect.u.condition[0].deadband = 0;
        effect.u.condition[0].center = 0;
        break;
        
    case FFB_COMMAND_TYPE_RUMBLE:
        if (!state->hasRumble)
        {
            debug(2, "FFB: Device does not support rumble effects\n");
            return -1;
        }
        effect.type = FF_RUMBLE;
        effect.u.rumble.strong_magnitude = (command->leftMagnitude * 0xFFFF) / 255;
        effect.u.rumble.weak_magnitude = (command->rightMagnitude * 0xFFFF) / 255;
        break;
        
    default:
        debug(1, "FFB: Unknown effect type %d\n", command->type);
        return -1;
    }
    
    // Upload the effect
    if (ioctl(state->eventFd, EVIOCSFF, &effect) < 0)
    {
        debug(1, "FFB: Failed to upload effect: %s\n", strerror(errno));
        return -1;
    }
    
    // Store effect ID if there's room, otherwise replace oldest
    if (state->effectCount < FFB_MAX_EFFECTS)
    {
        state->effectIds[state->effectCount++] = effect.id;
    }
    else
    {
        // Cleanup oldest effect and replace it
        debug(2, "FFB: Effect limit reached, replacing oldest effect\n");
        ioctl(state->eventFd, EVIOCRMFF, state->effectIds[0]);
        
        // Shift all effects down and add new one at the end
        for (int i = 0; i < FFB_MAX_EFFECTS - 1; i++)
        {
            state->effectIds[i] = state->effectIds[i + 1];
        }
        state->effectIds[FFB_MAX_EFFECTS - 1] = effect.id;
    }
    
    // Play the effect
    playEffect(state->eventFd, effect.id);
    
    debug(2, "FFB: Effect uploaded and playing (ID: %d)\n", effect.id);
    
    return 0;
}

static int playEffect(int fd, int effectId)
{
    struct input_event play;
    memset(&play, 0, sizeof(play));
    play.type = EV_FF;
    play.code = effectId;
    play.value = 1; // Play once
    
    if (write(fd, &play, sizeof(play)) != sizeof(play))
    {
        debug(2, "FFB: Failed to play effect %d\n", effectId);
        return -1;
    }
    
    return 0;
}

static int stopEffect(int fd, int effectId)
{
    struct input_event stop;
    memset(&stop, 0, sizeof(stop));
    stop.type = EV_FF;
    stop.code = effectId;
    stop.value = 0; // Stop
    
    if (write(fd, &stop, sizeof(stop)) != sizeof(stop))
    {
        debug(2, "FFB: Failed to stop effect %d\n", effectId);
        return -1;
    }
    
    return 0;
}

static void stopAllEffects(FFBState *state)
{
    if (state->eventFd < 0)
        return;
    
    for (int i = 0; i < state->effectCount; i++)
    {
        if (state->effectIds[i] >= 0)
        {
            stopEffect(state->eventFd, state->effectIds[i]);
        }
    }
    
    debug(2, "FFB: Stopped all effects\n");
}

static void cleanupEffects(FFBState *state)
{
    if (state->eventFd < 0)
        return;
    
    for (int i = 0; i < state->effectCount; i++)
    {
        if (state->effectIds[i] >= 0)
        {
            ioctl(state->eventFd, EVIOCRMFF, state->effectIds[i]);
            state->effectIds[i] = -1;
        }
    }
    
    state->effectCount = 0;
    debug(2, "FFB: Cleaned up all effects\n");
}
