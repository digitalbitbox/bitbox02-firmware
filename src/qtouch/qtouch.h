/*============================================================================
Filename : touch.h
Project : QTouch Modular Library
Purpose : configuation macros for touch library

This file is part of QTouch Modular Library Release 7.4.1 application.

Important Note: This file was created using the QTouch Configurator within
                Atmel Start and then patched.

Usage License: Refer license.h file for license information
Support: Visit http://www.microchip.com/support/hottopics.aspx
               to create MySupport case.

------------------------------------------------------------------------------
Copyright (c) 2020 Microchip. All rights reserved.
------------------------------------------------------------------------------
============================================================================*/

#ifndef TOUCH_H
#define TOUCH_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*----------------------------------------------------------------------------
 *     include files
 *----------------------------------------------------------------------------*/

#include "touch_api_ptc.h"
#include <platform_config.h>

#if PLATFORM_BITBOXBASE == 1
bool qtouch_get_button_state(size_t idx);
#endif

/**********************************************************/
/******************* Acquisition controls *****************/
/**********************************************************/
/* Defines the Measurement Time in milli seconds.
 * Range: 1 to 255.
 * Default value: 20.
 */
#define DEF_TOUCH_MEASUREMENT_PERIOD_MS 20

/* Defines the Type of sensor
 * Default value: NODE_MUTUAL.
 */
#define DEF_SENSOR_TYPE NODE_SELFCAP

/* Set sensor calibration mode for charge share delay ,Prescaler or series resistor.
 * Range: CAL_AUTO_TUNE_NONE / CAL_AUTO_TUNE_RSEL / CAL_AUTO_TUNE_PRSC / CAL_AUTO_TUNE_CSD
 * Default value: CAL_AUTO_TUNE_NONE.
 */
#define DEF_PTC_CAL_OPTION CAL_AUTO_TUNE_NONE

/* Defines the interrupt priority for the PTC. Set low priority to PTC interrupt for applications
 * having interrupt time constraints. Range: 0 to 2 Default: 2 (Lowest Priority)
 */
#define DEF_PTC_INTERRUPT_PRIORITY 2

/* Calibration option to ensure full charge transfer */
/* Bits 7:0 = XX | TT SELECT_TAU | X | CAL_OPTION */
#define DEF_PTC_TAU_TARGET CAL_CHRG_5TAU
#define DEF_PTC_CAL_AUTO_TUNE \
    (uint8_t)((DEF_PTC_TAU_TARGET << CAL_CHRG_TIME_POS) | DEF_PTC_CAL_OPTION)

/* Set default bootup acquisition frequency.
 * Range: FREQ_SEL_0 - FREQ_SEL_15 , FREQ_SEL_SPREAD
 * Default value: FREQ_SEL_0.
 */
#define DEF_SEL_FREQ_INIT FREQ_SEL_8

/*----------------------------------------------------------------------------
 *     defines
 *----------------------------------------------------------------------------*/

#if PLATFORM_BITBOX02 == 1
/**********************************************************/
/***************** Node Params   ******************/
/**********************************************************/
/* Acquisition Set 1 */
/* Defines the number of sensor nodes in the acquisition set
 * Range: 1 to 65535.
 * Default value: 1
 */
#define DEF_NUM_CHANNELS (8)

/* Defines node parameter setting
 * {X-line, Y-line, Charge Share Delay, NODE_RSEL_PRSC(series resistor, prescaler), NODE_G(Analog
 * Gain , Digital Gain), filter level}
 */
// Slider 1 buttons
#define NODE_0_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(26), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
#define NODE_1_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(27), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
#define NODE_2_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(28), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
#define NODE_3_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(29), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
// Slider 0 buttons
#define NODE_4_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(30), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
#define NODE_5_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(31), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
#define NODE_6_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(20), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }
#define NODE_7_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(21), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_1), \
            NODE_GAIN(GAIN_4, GAIN_4), FILTER_LEVEL_512                     \
    }

/**********************************************************/
/***************** Key Params   ******************/
/**********************************************************/
/* Defines the number of key sensors
 * Range: 1 to 65535.
 * Default value: 1
 */
#define DEF_NUM_SENSORS (DEF_NUM_CHANNELS)

/* Defines Key Sensor setting
 * {Sensor Threshold, Sensor Hysterisis, Sensor AKS}
 */
// 0..3 higher Slider left to right 4..7 lower Slider right to left
#define KEY_0_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_1_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_2_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_3_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_4_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_5_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_6_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_7_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }

#elif PLATFORM_BITBOXBASE == 1
/**********************************************************/
/***************** Node Params   ******************/
/**********************************************************/
/* Acquisition Set 1 */
/* Defines the number of sensor nodes in the acquisition set
 * Range: 1 to 65535.
 * Default value: 1
 */
#define DEF_NUM_CHANNELS (6)

/* Defines node parameter setting
 * {X-line, Y-line, Charge Share Delay, NODE_RSEL_PRSC(series resistor, prescaler), NODE_G(Analog
 * Gain , Digital Gain), filter level}
 */
// Slider buttons
#define NODE_0_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(23), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_2), \
            NODE_GAIN(GAIN_8, GAIN_1), FILTER_LEVEL_32                      \
    }
#define NODE_1_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(22), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_2), \
            NODE_GAIN(GAIN_8, GAIN_1), FILTER_LEVEL_32                      \
    }
#define NODE_2_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(21), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_2), \
            NODE_GAIN(GAIN_8, GAIN_1), FILTER_LEVEL_32                      \
    }
#define NODE_3_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(20), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_2), \
            NODE_GAIN(GAIN_8, GAIN_1), FILTER_LEVEL_32                      \
    }
// Top buttons
#define NODE_4_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(30), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_4), \
            NODE_GAIN(GAIN_16, GAIN_2), FILTER_LEVEL_256                    \
    }
#define NODE_5_PARAMS                                                       \
    {                                                                       \
        X_NONE, Y_LINE(31), 0, NODE_RSEL_PRSC(RSEL_VAL_20, PRSC_DIV_SEL_4), \
            NODE_GAIN(GAIN_16, GAIN_2), FILTER_LEVEL_256                    \
    }

/**********************************************************/
/***************** Key Params   ******************/
/**********************************************************/
/* Defines the number of key sensors
 * Range: 1 to 65535.
 * Default value: 1
 */
#define DEF_NUM_SENSORS (DEF_NUM_CHANNELS)

/* Defines Key Sensor setting
 * {Sensor Threshold, Sensor Hysterisis, Sensor AKS}
 */
// 0..3 higher Slider left to right 4..7 lower Slider right to left
#define KEY_0_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_1_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_2_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_3_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_4_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }
#define KEY_5_PARAMS              \
    {                             \
        16, HYST_50, NO_AKS_GROUP \
    }

/*
 * Defines number of buttson
 */
#define DEF_NUM_BUTTONS 2
/*
 * Defines the offset to the first button in the node list
 */
#define DEF_BUTTON_OFFSET 4
#endif

/* De-bounce counter for additional measurements to confirm touch detection
 * Range: 0 to 255.
 * Default value: 4.
 */
#define DEF_TOUCH_DET_INT 0

/* De-bounce counter for additional measurements to confirm away from touch signal
 * to initiate Away from touch re-calibration.
 * Range: 0 to 255.
 * Default value: 5.
 */
#define DEF_ANTI_TCH_DET_INT 0

/* Threshold beyond with automatic sensor recalibration is initiated.
 * Range: RECAL_100/ RECAL_50 / RECAL_25 / RECAL_12_5 / RECAL_6_25 / MAX_RECAL
 * Default value: RECAL_100.
 */
#define DEF_ANTI_TCH_RECAL_THRSHLD RECAL_50

/* Rate at which sensor reference value is adjusted towards sensor signal value
 * when signal value is greater than reference.
 * Units: 200ms
 * Range: 0-255
 * Default value: 20u = 4 seconds.
 */
#define DEF_TCH_DRIFT_RATE 20

/* Rate at which sensor reference value is adjusted towards sensor signal value
 * when signal value is less than reference.
 * Units: 200ms
 * Range: 0-255
 * Default value: 5u = 1 second.
 */
#define DEF_ANTI_TCH_DRIFT_RATE 5

/* Time to restrict drift on all sensor when one or more sensors are activated.
 * Units: 200ms
 * Range: 0-255
 * Default value: 20u = 4 seconds.
 */
#define DEF_DRIFT_HOLD_TIME 20

/* Set mode for additional sensor measurements based on touch activity.
 * Range: REBURST_NONE / REBURST_UNRESOLVED / REBURST_ALL
 * Default value: REBURST_UNRESOLVED
 */
#define DEF_REBURST_MODE REBURST_ALL

/* Sensor maximum ON duration upon touch.
 * Range: 0-255
 * Default value: 0
 */
#define DEF_MAX_ON_DURATION 0

/*
 * The count that the reference value must be above the measured value to
 * allow the force calibrate procedure to overwrite the reference to the
 * current measured value.
 */
#define KEY_FORCE_CALIBRATE_THRESHOLD 10

/**********************************************************/
/***************** Slider/Wheel Parameters ****************/
/**********************************************************/
/*
 * Do not use qtouch scroller module. The button readings need
 * a custom post-filter to reduce noise. The output of the custom
 * filter is then fed into a custom scroller implementation.
 * This allows low noise button readings while keeping
 * fast responsiveness.
 */
#if PLATFORM_BITBOX02 == 1
#define DEF_NUM_SCROLLERS 2 // Number of scrollers (sliders or wheels)
#define DEF_SCROLLER_NUM_CHANNELS 4 // Number of channels per scroller
#define DEF_SCROLLER_OFFSET_0 4 // Index of first button in scroller
#define DEF_SCROLLER_OFFSET_1 0 // Index of first button in scroller
#elif PLATFORM_BITBOXBASE == 1
#define DEF_NUM_SCROLLERS 1 // Number of scrollers (sliders or wheels)
#define DEF_SCROLLER_NUM_CHANNELS 4 // Number of channels per scroller
#define DEF_SCROLLER_OFFSET_0 0 // Index of first button in scroller
#define DEF_SCROLLER_OFFSET_1 0 // Index of first button in scroller
#endif
#define DEF_SCROLLER_RESOLUTION 256 // Scroller resolution in bits
#define DEF_SCROLLER_DET_THRESHOLD 25 // Scroller detect threshold
#define DEF_SCROLLER_TOUCH_THRESHOLD 25 // Scroller active threshold
#define DEF_SCROLLER_UNTOUCH_THRESHOLD 20 // Scroller active threshold
#define DEF_SCROLLER_DEADBAND 13 // 13 bits = 5% of 256-bit range
#define DEF_SCROLLER_NUM_PREV_POS \
    4 // Number of previous scroller positions to remember; used in a simple filter
#define DEF_SCROLLER_OFF \
    0xFFFF // Marker for indicating scroller reading does not exceed detection threshold
#define DEF_SENSOR_EDGE_WEIGHT \
    0.15 // Percent added weight to edge sensors, which are physically smaller
#define DEF_SENSOR_NUM_PREV_POS \
    4 // Number of previous sensor positions to remember; used in a simple filter

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // TOUCH_C
