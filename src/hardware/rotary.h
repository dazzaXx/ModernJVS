#ifndef ROTARY_H_
#define ROTARY_H_

typedef enum
{
    JVS_ROTARY_STATUS_UNUSED,
    JVS_ROTARY_STATUS_ERROR,
    JVS_ROTARY_STATUS_SUCCESS
} JVSRotaryStatus;

JVSRotaryStatus initRotary(void);
int getRotaryValue(void);

#endif // ROTARY_H_
