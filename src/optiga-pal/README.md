# Porting Guide

The implementation of Platform Abstraction Layer (PAL) needs to be updated in order to migrate to a new
target platform.

The PAL reference code for the XMC4800 IoT connectivity kit is provided as part of package which can be used.
The implementation can be found in “<INSTALLDIR>/pal/xmc4800” and the header files are available in
“<INSTALLDIR>/optiga/include” with the required APIs used by upper layers. The header files are platform
agnostic and would not require any changes. The low level drivers used by PAL for XMC4800 are configured and
generated using DAVE™.

## Communication with OPTIGA™ Trust M

The hardware/platform resource configuration with respect to I2C master and GPIOs (Vdd and Reset) are to be
updated in pal_ifx_i2c_config.c. These configurations are used by the IFX I2C implementation to communicate
with OPTIGA™ Trust M.

### Update I2C master platform specific context[e.g. (void)&i2c_master_0]

```c
/*
* \brief PAL I2C configuration for OPTIGA
*/
pal_i2c_t optiga_pal_i2c_context_0 =
{
    /// Pointer to I2C master platform specific context
    (void)&i2c_master_0,
    /// Slave address
    0x30,
    /// Upper layer context
    NULL,
    /// Callback event handler
    NULL
};
```

### Update platform specific context for GPIOs (Vdd and Reset) [e.g. (void)&pin_3_4]
```c
/*
* \brief Vdd pin configuration for OPTIGA
*/
pal_gpio_t optiga_vdd_0 =
{
    // Platform specific GPIO context for the pin used to toggle Vdd
    (void*)&vdd_pin
};

/**
* \brief Reset pin configuration for OPTIGA
*/
 pal_gpio_t optiga_reset_0 =
{
    // Platform specific GPIO context for the pin used to toggle Reset
    (void*)&reset_pin
};
```

### Update PAL I2C APIs [pal_i2c.c] to communicate with OPTIGA™ Trust M

The `pal_i2c` is expected to provide the APIs for I2C driver initialization, de-initialization, read, write and set
bitrate kind of operations

1. `pal_i2c_init`
2. `pal_i2c_deinit`
3. `pal_i2c_read`
4. `pal_i2c_write`
5. `pal_i2c_set_bitrate`

A few target platforms, the I2C master driver initialization (`pal_i2c_init`) is done during the platform start up. In
such an environment, there is no need to implement pal_i2c_init and `pal_i2c_deinit` functions. Otherwise,
these (`pal_i2c_init` & `pal_i2c_deinit`) functions must be implemented as per the upper layer expectations based
on the need. The details of these expectations are available in the [Host library API documentation (chm)](https://github.com/Infineon/optiga-trust-m/blob/master/documents/OPTIGA_Trust_M_V1_Host_Library_Documentation.chm).

The reference implementation of PAL I2C based on XMC4800 IoT connectivity kit does not need to have the
platform I2C driver initialization explicitly done as part of pal_i2c_init as it is taken care by the DAVE™ library
initialization. Hence pal_i2c_init & pal_i2c_deinit are not implemented.

In addition to the above specified APIs, the PAL I2C must handle the events from the low level I2C driver and
invoke the upper layer handlers registered with PAL I2C context for the respective transaction as shown in the
below example.

```c
//I2C driver callback function when the transmit is completed successfully
void i2c_master_end_of_transmit_callback(void)
{
    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, (uint8_t)PAL_I2C_EVENT_TX_SUCCESS);
}
```

In above example the I2C driver callback, when transmission is successful invokes the handler to inform the
result.

### Update PAL GPIO [pal_gpio.c] to power on and reset the OPTIGA™ Trust M

1. `pal_gpio_set_high`
2. `pal_gpio_set_low`

### Update PAL Timer [pal_os_timer.c] to enable timer

1. `pal_os_timer_get_time_in_milliseconds`
2. `pal_os_timer_delay_in_milliseconds`

### Update Event management for the asynchronous interactions for IFX I2C [pal_os_event.c]

1. `pal_os_event_register_callback_oneshot`
2. `pal_os_event_trigger_registered_callback`

The `pal_os_event_register_callback_oneshot` function is expected to register the handler and context
provided as part of input parameters and triggers the timer for the requested time. The `p_pal_os_event` is an
event instance created using `pal_os_event_create`.

```c
void pal_os_event_register_callback_oneshot(pal_os_event_t * p_pal_os_event,
                                            register_callback callback,
                                            void* callback_args,
                                            uint32_t time_us)
{
    p_pal_os_event->callback_registered = callback;
    p_pal_os_event->callback_ctx = callback_args;
    //lint --e{534} suppress "Return value is not required to be checked"
    TIMER_SetTimeInterval(&scheduler_timer, (time_us*100));
    TIMER_Start(&scheduler_timer);
}
```

The handler registered must be invoked once the timer has elapsed as shown in
`pal_os_event_trigger_registered_callback`. The `pal_os_event_trigger_registered_callback` is to be
registered with event timer interrupt to get trigerred when the timer expires. The `pal_os_event_0` is the
instance in the `pal_os_event` used store the registered callback and context.

```c
void pal_os_event_trigger_registered_callback(void)
{
    register_callback callback;

    TIMER_ClearEvent(&scheduler_timer);
    //lint --e{534} suppress "Return value is not required to be checked"
    TIMER_Stop(&scheduler_timer);
    TIMER_Clear(&scheduler_timer);

    if (pal_os_event_0.callback_registered)
    {
        Callback = pal_os_event_0.callback_registered;
        callback ((void*)callback_ctx);
    }
}
```

## Initalisation hints

This is a code sample demonstrating initialization routine for the security chip, as well as a hibernation example
```c
#include "optiga/optiga_util.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"
#include "optiga/pal/pal_os_timer.h"
/**
 * Callback when optiga_util_xxxx operation is completed asynchronously
 */
static volatile optiga_lib_status_t optiga_lib_status;
static void optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
    optiga_lib_status = return_status;
}

int32_t main(void)
{
    uint8_t return_value = 0;

    optiga_lib_status_t return_status;

    optiga_util_t * me_util;

    do
    {
        //Create an instance of optiga_util to open the application on OPTIGA.
        me_util = optiga_util_create(0, optiga_util_callback, NULL);

        /**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */        
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_open_application(me_util, 0);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_open_application is completed
        }
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util open application failed
            break;
        }
        /**
         * Hibernate the application on OPTIGA 
         * using optiga_util_close_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(me_util, 1);
        
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
        /**
         * Restore the application on OPTIGA
         * using optiga_util_open_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_open_application(me_util, 1);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }
        while (OPTIGA_LIB_BUSY == optiga_lib_status)
        {
            //Wait until the optiga_util_open_application is completed
        }
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util open application failed
            break;
        }

        /*
         Paste your code is here
        */

                /**
         * Close the application on OPTIGA after all the operations are executed
         * using optiga_util_close_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(me_util, 0);
        
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }

        // destroy util and crypt instances
        optiga_util_destroy(me_util);
    }while (FALSE);

    return return_value;
}
```
