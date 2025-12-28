#include "hardware/device.h"
#include "console/debug.h"

#ifdef USE_LIBGPIOD
#include <gpiod.h>

#define GPIO_CHIP_NUMBER 0
#define GPIO_CONSUMER_NAME "openjvs"

#ifdef GPIOD_API_V2
// libgpiod v2 API - we need to keep track of line requests per pin
// Note: This implementation assumes single-threaded access to GPIO
static struct gpiod_line_request *line_request = NULL;
static int current_pin = -1;
static int current_direction = -1;

// Helper function to open GPIO chip
static struct gpiod_chip *open_gpio_chip(void)
{
  char chip_path[32];
  snprintf(chip_path, sizeof(chip_path), "/dev/gpiochip%d", GPIO_CHIP_NUMBER);
  return gpiod_chip_open(chip_path);
}
#endif

#endif

#define TIMEOUT_SELECT 200

int serialIO = -1;
int localSenseLinePin = 12;
int localSenseLineType = 0;

int setSerialAttributes(int fd, int myBaud);
int setupGPIO(int pin);
int setGPIODirection(int pin, int dir);
int writeGPIO(int pin, int value);

int initDevice(char *devicePath, int senseLineType, int senseLinePin)
{
  if ((serialIO = open(devicePath, O_RDWR | O_NOCTTY | O_SYNC | O_NDELAY)) < 0)
    return 0;

  /* Setup the serial connection */
  setSerialAttributes(serialIO, B115200);

  /* Copy variables over from config */
  localSenseLineType = senseLineType;
  localSenseLinePin = senseLinePin;

  /* Setup the GPIO pins */
  if (localSenseLineType && setupGPIO(localSenseLinePin) == -1)
    debug(0, "Sense line pin %d not available\n", senseLinePin);

  /* Setup the GPIO pins initial state */
  switch (senseLineType)
  {
  case 0:
    debug(1, "Debug: No sense line set\n");
    break;
  case 1:
    debug(1, "Debug: Float/Sync sense line set\n");
    setGPIODirection(senseLinePin, IN);
    break;
  case 2:
    debug(1, "Debug: Complex sense line set\n");
    setGPIODirection(senseLinePin, OUT);
    break;
  default:
    debug(0, "Debug: Invalid sense line type set\n");
    break;
  }

  /* Initially float the sense line */
  setSenseLine(0);

  return 1;
}

int closeDevice()
{
  tcflush(serialIO, TCIOFLUSH);
  
#ifdef USE_LIBGPIOD
#ifdef GPIOD_API_V2
  // Clean up libgpiod v2 resources
  if (line_request)
  {
    gpiod_line_request_release(line_request);
    line_request = NULL;
  }
  current_pin = -1;
  current_direction = -1;
#endif
#endif
  
  return close(serialIO) == 0;
}

int readBytes(unsigned char *buffer, int amount)
{
  fd_set fd_serial;
  struct timeval tv;

  FD_ZERO(&fd_serial);
  FD_SET(serialIO, &fd_serial);

  tv.tv_sec = 0;
  tv.tv_usec = TIMEOUT_SELECT * 1000;

  int filesReadyToRead = select(serialIO + 1, &fd_serial, NULL, NULL, &tv);

  if (filesReadyToRead < 1)
    return -1;

  if (!FD_ISSET(serialIO, &fd_serial))
    return -1;

  return read(serialIO, buffer, amount);
}

int writeBytes(unsigned char *buffer, int amount)
{
  return write(serialIO, buffer, amount);
}

/* Sets the configuration of the serial port */
int setSerialAttributes(int fd, int myBaud)
{
  struct termios options;
  int status;
  tcgetattr(fd, &options);

  cfmakeraw(&options);
  cfsetispeed(&options, myBaud);
  cfsetospeed(&options, myBaud);

  options.c_cflag |= (CLOCAL | CREAD);
  options.c_cflag &= ~PARENB;
  options.c_cflag &= ~CSTOPB;
  options.c_cflag &= ~CSIZE;
  options.c_cflag |= CS8;
  options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
  options.c_oflag &= ~OPOST;

  options.c_cc[VMIN] = 0;
  options.c_cc[VTIME] = 0; // One seconds (10 deciseconds)

  tcsetattr(fd, TCSANOW, &options);

  ioctl(fd, TIOCMGET, &status);

  status |= TIOCM_DTR;
  status |= TIOCM_RTS;

  ioctl(fd, TIOCMSET, &status);

  usleep(100 * 1000); // 10mS

  struct serial_struct serial_settings;

  ioctl(fd, TIOCGSERIAL, &serial_settings);

  serial_settings.flags |= ASYNC_LOW_LATENCY;
  ioctl(fd, TIOCSSERIAL, &serial_settings);

  tcflush(serialIO, TCIOFLUSH);
  usleep(100 * 1000); // Required to make flush work, for some reason

  return 0;
}

#ifdef USE_LIBGPIOD

#ifdef GPIOD_API_V2
// libgpiod v2 API implementation

int setupGPIO(int pin)
{
  struct gpiod_chip *chip = open_gpio_chip();
  if (!chip)
    return 0;
  
  // In v2, we verify the line exists by getting info
  struct gpiod_line_info *info = gpiod_chip_get_line_info(chip, pin);
  int result = (info != NULL);
  
  if (info)
    gpiod_line_info_free(info);
  
  gpiod_chip_close(chip);
  return result;
}

int setGPIODirection(int pin, int dir)
{
  struct gpiod_chip *chip = open_gpio_chip();
  if (!chip)
    return 0;
  
  // Release existing request only if we're changing pins or direction
  if (line_request && (current_pin != pin || current_direction != dir))
  {
    gpiod_line_request_release(line_request);
    line_request = NULL;
    current_pin = -1;
    current_direction = -1;
  }
  
  // If we already have a request for this pin and direction, reuse it
  if (line_request && current_pin == pin && current_direction == dir)
  {
    gpiod_chip_close(chip);
    return 1;
  }
  
  struct gpiod_line_settings *settings = gpiod_line_settings_new();
  if (!settings)
  {
    gpiod_chip_close(chip);
    return 0;
  }
  
  if (dir == IN)
  {
    gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
  }
  else
  {
    gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_OUTPUT);
    gpiod_line_settings_set_output_value(settings, GPIOD_LINE_VALUE_INACTIVE);
  }
  
  struct gpiod_line_config *config = gpiod_line_config_new();
  if (!config)
  {
    gpiod_line_settings_free(settings);
    gpiod_chip_close(chip);
    return 0;
  }
  
  int ret = gpiod_line_config_add_line_settings(config, &pin, 1, settings);
  if (ret)
  {
    gpiod_line_config_free(config);
    gpiod_line_settings_free(settings);
    gpiod_chip_close(chip);
    return 0;
  }
  
  struct gpiod_request_config *req_config = gpiod_request_config_new();
  if (!req_config)
  {
    gpiod_line_config_free(config);
    gpiod_line_settings_free(settings);
    gpiod_chip_close(chip);
    return 0;
  }
  
  gpiod_request_config_set_consumer(req_config, GPIO_CONSUMER_NAME);
  
  line_request = gpiod_chip_request_lines(chip, req_config, config);
  
  gpiod_request_config_free(req_config);
  gpiod_line_config_free(config);
  gpiod_line_settings_free(settings);
  gpiod_chip_close(chip);
  
  if (line_request)
  {
    current_pin = pin;
    current_direction = dir;
    return 1;
  }
  
  return 0;
}

int writeGPIO(int pin, int value)
{
  struct gpiod_chip *chip = open_gpio_chip();
  if (!chip)
    return 0;
  
  // Release existing request if we're changing pins
  if (line_request && current_pin != pin)
  {
    gpiod_line_request_release(line_request);
    line_request = NULL;
    current_pin = -1;
    current_direction = -1;
  }
  
  struct gpiod_line_settings *settings = gpiod_line_settings_new();
  if (!settings)
  {
    gpiod_chip_close(chip);
    return 0;
  }
  
  gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_OUTPUT);
  gpiod_line_settings_set_output_value(settings, 
    value == LOW ? GPIOD_LINE_VALUE_INACTIVE : GPIOD_LINE_VALUE_ACTIVE);
  
  struct gpiod_line_config *config = gpiod_line_config_new();
  if (!config)
  {
    gpiod_line_settings_free(settings);
    gpiod_chip_close(chip);
    return 0;
  }
  
  int ret = gpiod_line_config_add_line_settings(config, &pin, 1, settings);
  if (ret)
  {
    gpiod_line_config_free(config);
    gpiod_line_settings_free(settings);
    gpiod_chip_close(chip);
    return 0;
  }
  
  struct gpiod_request_config *req_config = gpiod_request_config_new();
  if (!req_config)
  {
    gpiod_line_config_free(config);
    gpiod_line_settings_free(settings);
    gpiod_chip_close(chip);
    return 0;
  }
  
  gpiod_request_config_set_consumer(req_config, GPIO_CONSUMER_NAME);
  
  line_request = gpiod_chip_request_lines(chip, req_config, config);
  
  gpiod_request_config_free(req_config);
  gpiod_line_config_free(config);
  gpiod_line_settings_free(settings);
  gpiod_chip_close(chip);
  
  if (line_request)
  {
    current_pin = pin;
    current_direction = OUT;
    return 1;
  }
  
  return 0;
}

int readGPIO(int pin)
{
  struct gpiod_chip *chip = open_gpio_chip();
  if (!chip)
    return -1;
  
  // Release existing request if we're changing pins
  if (line_request && current_pin != pin)
  {
    gpiod_line_request_release(line_request);
    line_request = NULL;
    current_pin = -1;
    current_direction = -1;
  }
  
  // If we don't have a request or it's not configured as input, create/recreate it
  if (!line_request || current_direction != IN)
  {
    if (line_request)
    {
      gpiod_line_request_release(line_request);
      line_request = NULL;
    }
    
    struct gpiod_line_settings *settings = gpiod_line_settings_new();
    if (!settings)
    {
      gpiod_chip_close(chip);
      return -1;
    }
    
    gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
    
    struct gpiod_line_config *config = gpiod_line_config_new();
    if (!config)
    {
      gpiod_line_settings_free(settings);
      gpiod_chip_close(chip);
      return -1;
    }
    
    int ret = gpiod_line_config_add_line_settings(config, &pin, 1, settings);
    if (ret)
    {
      gpiod_line_config_free(config);
      gpiod_line_settings_free(settings);
      gpiod_chip_close(chip);
      return -1;
    }
    
    struct gpiod_request_config *req_config = gpiod_request_config_new();
    if (!req_config)
    {
      gpiod_line_config_free(config);
      gpiod_line_settings_free(settings);
      gpiod_chip_close(chip);
      return -1;
    }
    
    gpiod_request_config_set_consumer(req_config, GPIO_CONSUMER_NAME);
    
    line_request = gpiod_chip_request_lines(chip, req_config, config);
    
    gpiod_request_config_free(req_config);
    gpiod_line_config_free(config);
    gpiod_line_settings_free(settings);
    
    if (!line_request)
    {
      gpiod_chip_close(chip);
      return -1;
    }
    
    current_pin = pin;
    current_direction = IN;
  }
  
  enum gpiod_line_value value = gpiod_line_request_get_value(line_request, pin);
  
  gpiod_chip_close(chip);
  
  return (value == GPIOD_LINE_VALUE_ACTIVE) ? 1 : 0;
}

#else
// libgpiod v1 API implementation

int setupGPIO(int pin)
{
  // With libgpiod, we don't need to export the GPIO pin
  // The character device interface handles this automatically
  // We just verify we can open the chip
  struct gpiod_chip *chip = gpiod_chip_open_by_number(GPIO_CHIP_NUMBER);
  if (!chip)
    return 0;
  
  // Verify the line exists
  struct gpiod_line *line = gpiod_chip_get_line(chip, pin);
  int result = (line != NULL) ? 1 : 0;
  
  gpiod_chip_close(chip);
  return result;
}

int setGPIODirection(int pin, int dir)
{
  struct gpiod_chip *chip = gpiod_chip_open_by_number(GPIO_CHIP_NUMBER);
  if (!chip)
    return 0;
  
  struct gpiod_line *line = gpiod_chip_get_line(chip, pin);
  if (!line)
  {
    gpiod_chip_close(chip);
    return 0;
  }
  
  int result;
  if (dir == IN)
  {
    result = gpiod_line_request_input(line, GPIO_CONSUMER_NAME);
  }
  else
  {
    result = gpiod_line_request_output(line, GPIO_CONSUMER_NAME, 0);
  }
  
  gpiod_chip_close(chip);
  return (result == 0) ? 1 : 0;
}

int writeGPIO(int pin, int value)
{
  struct gpiod_chip *chip = gpiod_chip_open_by_number(GPIO_CHIP_NUMBER);
  if (!chip)
    return 0;
  
  struct gpiod_line *line = gpiod_chip_get_line(chip, pin);
  if (!line)
  {
    gpiod_chip_close(chip);
    return 0;
  }
  
  // Request the line as output with the desired value
  int result = gpiod_line_request_output(line, GPIO_CONSUMER_NAME, value == LOW ? 0 : 1);
  
  gpiod_chip_close(chip);
  return (result == 0) ? 1 : 0;
}

int readGPIO(int pin)
{
  struct gpiod_chip *chip = gpiod_chip_open_by_number(GPIO_CHIP_NUMBER);
  if (!chip)
    return -1;
  
  struct gpiod_line *line = gpiod_chip_get_line(chip, pin);
  if (!line)
  {
    gpiod_chip_close(chip);
    return -1;
  }
  
  // Request the line as input
  if (gpiod_line_request_input(line, GPIO_CONSUMER_NAME) != 0)
  {
    gpiod_chip_close(chip);
    return -1;
  }
  
  int value = gpiod_line_get_value(line);
  gpiod_chip_close(chip);
  
  return value;
}

#endif  // GPIOD_API_V2

#else  // USE_LIBGPIOD

int setupGPIO(int pin)
{
  char buffer[3];
  ssize_t bytesWritten;
  int fd;

  if ((fd = open("/sys/class/gpio/export", O_WRONLY)) == -1)
    return 0;

  bytesWritten = snprintf(buffer, 3, "%d", pin);
  if (write(fd, buffer, bytesWritten) != bytesWritten)
    return 0;

  close(fd);
  return 1;
}

int setGPIODirection(int pin, int dir)
{
  static const char s_directions_str[] = "in\0out";

  char path[35];
  int fd;

  snprintf(path, 35, "/sys/class/gpio/gpio%d/direction", pin);
  if ((fd = open(path, O_WRONLY)) == -1)
    return 0;

  int length = IN == dir ? 2 : 3;
  if (write(fd, &s_directions_str[IN == dir ? 0 : 3], length) != length)
    return 0;

  close(fd);
  return 1;
}

int writeGPIO(int pin, int value)
{
  static const char stringValues[] = "01";

  char path[100];
  int fd;

  snprintf(path, 100, "/sys/class/gpio/gpio%d/value", pin);
  if ((fd = open(path, O_WRONLY)) == -1)
    return 0;

  if (write(fd, &stringValues[LOW == value ? 0 : 1], 1) != 1)
    return 0;

  close(fd);
  return 1;
}

int readGPIO(int pin)
{
  char path[100];
  char value_str[3];
  int fd;

  snprintf(path, 100, "/sys/class/gpio/gpio%d/value", pin);
  if ((fd = open(path, O_RDONLY)) == -1)
    return -1;

  if (read(fd, value_str, 3) == -1)
    return -1;

  close(fd);
  return (atoi(value_str));
}

#endif  // USE_LIBGPIOD

int setSenseLine(int state)
{
  if (localSenseLineType == 0)
    return 1;

  switch (localSenseLineType)
  {
  /* Normal Float Style */
  case 1:
  {
    if (!state)
    {
      if (!setGPIODirection(localSenseLinePin, IN))
      {
        debug(1, "Warning: Failed to float sense line %d\n", localSenseLinePin);
        return 0;
      }
    }
    else
    {
      if (!setGPIODirection(localSenseLinePin, OUT) || !writeGPIO(localSenseLinePin, 0))
      {
        debug(1, "Warning: Failed to sink sense line %d\n", localSenseLinePin);
        return 0;
      }
    }
  }
  break;

  /* Switch Style */
  case 2:
  {
    if (!state)
    {
      if (!writeGPIO(localSenseLinePin, 0))
      {
        printf("Warning: Failed to set sense line to 1 %d\n", localSenseLinePin);
        return 0;
      }
    }
    else
    {
      if (!writeGPIO(localSenseLinePin, 1))
      {
        printf("Warning: Failed to sink sense line %d\n", localSenseLinePin);
        return 0;
      }
    }
  }
  break;

  default:
    debug(0, "Invalid sense line type set\n");
    break;
  }

  return 1;
}
