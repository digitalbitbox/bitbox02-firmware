/*============================================================================
Filename : touch.h
Project : QTouch Modular Library
Purpose : configuation macros for touch library

This file is part of QTouch Modular Library Release 5.1 example application.

Important Note: This file was created using the QTouch Configurator within
                Atmel Start and then patched.

Usage License: Refer license.h file for license information
Support: Visit http://www.microchip.com/support/hottopics.aspx
               to create MySupport case.

------------------------------------------------------------------------------
Copyright (c) 2017 Microchip. All rights reserved.
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
