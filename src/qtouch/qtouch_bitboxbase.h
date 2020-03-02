// Copyright 2019 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __QTOUCH_BITBOXBASE_H
#define __QTOUCH_BITBOXBASE_H

/** QTouch parameters for the BitBoxBase HSM platform. */

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
 * Defines number of buttons
 */
#define DEF_NUM_BUTTONS 2

/*
 * Defines the offset to the first button in the node list
 */
#define DEF_BUTTON_OFFSET 4

#define DEF_NUM_SCROLLERS 1 // Number of scrollers (sliders or wheels)
#define DEF_SCROLLER_NUM_CHANNELS 4 // Number of channels per scroller
#define DEF_SCROLLER_OFFSET_0 0 // Index of first button in scroller
#define DEF_SCROLLER_OFFSET_1 0 // Index of first button in scroller

bool qtouch_get_button_state(size_t idx);

#endif // __QTOUCH_BITBOXBASE_H
