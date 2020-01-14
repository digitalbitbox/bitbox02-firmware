
/*============================================================================
Filename : touch.c
Project : QTouch Modular Library
Purpose : Provides Initialization, Processing and ISR handler of touch library,
          Simple API functions to get/set the key touch parameters from/to the
          touch library data structures

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

#ifndef TOUCH_C
#define TOUCH_C
/*----------------------------------------------------------------------------
 *     include files
 *----------------------------------------------------------------------------*/

#include "qtouch.h"
#include "license.h"
#include "touch_api_ptc.h"
#include "util.h"
#include <driver_init.h>
#include <platform_config.h>

#if PLATFORM_BITBOXBASE == 1
#include "qtouch_bitboxbase.h"
#else
#include "qtouch_bitbox02.h"
#endif

/*----------------------------------------------------------------------------
 *   prototypes
 *----------------------------------------------------------------------------*/

/*! \brief configure binding layer config parameter
 */
static void build_qtm_config(qtm_control_t* qtm);

/*! \brief configure keys, wheels and sliders.
 */
static touch_ret_t touch_sensors_config(void);

/*! \brief Init complete callback function prototype.
 */
static void init_complete_callback(void);

/*! \brief Touch measure complete callback function example prototype.
 */
static void qtm_measure_complete_callback(void);

/*! \brief Touch post process complete callback function prototype.
 */
static void qtm_post_process_complete(void);

/*! \brief Touch Error callback function prototype.
 */
static void qtm_error_callback(uint8_t err);

/*! \brief Calculate scroller positions based on custom filter.
 */
static void qtouch_process_scroller_positions(void);

#if PLATFORM_BITBOXBASE == 1
/* Calculate whether buttons have been pressed
 */
static void qtouch_process_buttons(void);
#endif

/*----------------------------------------------------------------------------
 *     Global Variables
 *----------------------------------------------------------------------------*/

/* Binding layer control */
qtm_control_t qtm_control;
qtm_control_t* p_qtm_control;
qtm_state_t qstate;

/* Measurement Done Touch Flag  */
volatile uint8_t measurement_done_touch = 0;

/* Error Handling */
uint8_t module_error_code = 0;

/* Acquisition module internal data - Size to largest acquisition set */
uint16_t touch_acq_signals_raw[DEF_NUM_CHANNELS];

/* Acquisition set 1 - General settings */
qtm_acq_node_group_config_t ptc_qtlib_acq_gen1 = {DEF_NUM_CHANNELS,
                                                  DEF_SENSOR_TYPE,
                                                  DEF_PTC_CAL_AUTO_TUNE,
                                                  DEF_SEL_FREQ_INIT,
                                                  DEF_PTC_INTERRUPT_PRIORITY};

/* Node status, signal, calibration values */
qtm_acq_node_data_t ptc_qtlib_node_stat1[DEF_NUM_CHANNELS];

#if PLATFORM_BITBOX02 == 1
/* Node configurations */
qtm_acq_samd51_node_config_t ptc_seq_node_cfg1[DEF_NUM_CHANNELS] = {NODE_0_PARAMS,
                                                                    NODE_1_PARAMS,
                                                                    NODE_2_PARAMS,
                                                                    NODE_3_PARAMS,
                                                                    NODE_4_PARAMS,
                                                                    NODE_5_PARAMS,
                                                                    NODE_6_PARAMS,
                                                                    NODE_7_PARAMS};
#elif PLATFORM_BITBOXBASE == 1
/* Node configurations */
qtm_acq_samd51_node_config_t ptc_seq_node_cfg1[DEF_NUM_CHANNELS] =
    {NODE_0_PARAMS, NODE_1_PARAMS, NODE_2_PARAMS, NODE_3_PARAMS, NODE_4_PARAMS, NODE_5_PARAMS};
#endif

/* Container */
qtm_acquisition_control_t qtlib_acq_set1 = {&ptc_qtlib_acq_gen1,
                                            &ptc_seq_node_cfg1[0],
                                            &ptc_qtlib_node_stat1[0]};

/* Stores recent unfiltered scroller positions for custom filter */
__extension__ static uint16_t scroller_previous_position[][DEF_SCROLLER_NUM_PREV_POS] = {
    [0 ...(DEF_NUM_SCROLLERS - 1)][0 ...(DEF_SCROLLER_NUM_PREV_POS - 1)] = 0};

/* Current scroller position consisting of a moving-average of preceding positions for custom filter
 */
__extension__ static uint16_t scroller_position[] = {[0 ...(DEF_NUM_SCROLLERS - 1)] = 0};

/* Whether or not scroller reading exceeds threshold for custom filter */
__extension__ static bool scroller_active[DEF_NUM_SCROLLERS] = {[0 ...(DEF_NUM_SCROLLERS - 1)] = 0};

#if PLATFORM_BITBOXBASE == 1
__extension__ static bool button_active[DEF_NUM_BUTTONS] = {[0 ...(DEF_NUM_BUTTONS - 1)] = false};
#endif

/**********************************************************/
/*********************** Keys Module **********************/
/**********************************************************/

/* Keys set 1 - General settings */
qtm_touch_key_group_config_t qtlib_key_grp_config_set1 = {DEF_NUM_SENSORS,
                                                          DEF_TOUCH_DET_INT,
                                                          DEF_MAX_ON_DURATION,
                                                          DEF_ANTI_TCH_DET_INT,
                                                          DEF_ANTI_TCH_RECAL_THRSHLD,
                                                          DEF_TCH_DRIFT_RATE,
                                                          DEF_ANTI_TCH_DRIFT_RATE,
                                                          DEF_DRIFT_HOLD_TIME,
                                                          DEF_REBURST_MODE};

qtm_touch_key_group_data_t qtlib_key_grp_data_set1;

/* Key data */
qtm_touch_key_data_t qtlib_key_data_set1[DEF_NUM_SENSORS];

#if PLATFORM_BITBOX02 == 1
/* Key Configurations */
qtm_touch_key_config_t qtlib_key_configs_set1[DEF_NUM_SENSORS] = {KEY_0_PARAMS,
                                                                  KEY_1_PARAMS,
                                                                  KEY_2_PARAMS,
                                                                  KEY_3_PARAMS,
                                                                  KEY_4_PARAMS,
                                                                  KEY_5_PARAMS,
                                                                  KEY_6_PARAMS,
                                                                  KEY_7_PARAMS};
#elif PLATFORM_BITBOXBASE == 1
/* Key Configurations */
qtm_touch_key_config_t qtlib_key_configs_set1[DEF_NUM_SENSORS] =
    {KEY_0_PARAMS, KEY_1_PARAMS, KEY_2_PARAMS, KEY_3_PARAMS, KEY_4_PARAMS, KEY_5_PARAMS};
#endif

/* Container */
qtm_touch_key_control_t qtlib_key_set1 = {&qtlib_key_grp_data_set1,
                                          &qtlib_key_grp_config_set1,
                                          &qtlib_key_data_set1[0],
                                          &qtlib_key_configs_set1[0]};

/**********************************************************/
/***************** Scroller Module ********************/
/**********************************************************/

/*
 * Do not use qtouch scroller module. The button readings need
 * a custom post-filter to reduce noise. The output of the custom
 * filter is then fed into a custom scroller implementation.
 * This allows low noise button readings while keeping
 * fast responsiveness.
 */

/**********************************************************/
/****************  Binding Layer Module  ******************/
/**********************************************************/
#define LIB_MODULES_INIT_LIST                                   \
    {                                                           \
        (module_init_t) & qtm_ptc_init_acquisition_module, null \
    }

#define LIB_MODULES_PROC_LIST                           \
    {                                                   \
        (module_proc_t) & qtm_key_sensors_process, null \
    }

#define LIB_INIT_DATA_MODELS_LIST    \
    {                                \
        (void*)&qtlib_acq_set1, null \
    }

#define LIB_DATA_MODELS_PROC_LIST    \
    {                                \
        (void*)&qtlib_key_set1, null \
    }

#define LIB_MODULES_ACQ_ENGINES_LIST                         \
    {                                                        \
        (module_acq_t) & qtm_ptc_start_measurement_seq, null \
    }

#define LIB_MODULES_ACQ_ENGINES_LIST_DM \
    {                                   \
        (void*)&qtlib_acq_set1, null    \
    }

/* QTM run time options */
module_init_t library_modules_init[] = LIB_MODULES_INIT_LIST;
module_proc_t library_modules_proc[] = LIB_MODULES_PROC_LIST;
module_arg_t library_module_init_data_models[] = LIB_INIT_DATA_MODELS_LIST;
module_acq_t library_modules_acq_engines[] = LIB_MODULES_ACQ_ENGINES_LIST;

module_arg_t library_module_acq_engine_data_model[] = LIB_MODULES_ACQ_ENGINES_LIST_DM;
module_arg_t library_module_proc_data_model[] = LIB_DATA_MODELS_PROC_LIST;

/*----------------------------------------------------------------------------
 *   function definitions
 *----------------------------------------------------------------------------*/

/*============================================================================
static void build_qtm_config(qtm_control_t *qtm)
------------------------------------------------------------------------------
Purpose: Initialization of binding layer module
Input  : Pointer of binding layer container data structure
Output : none
Notes  :
============================================================================*/
static void build_qtm_config(qtm_control_t* qtm)
{
    /* Initialise the Flags by clearing them */
    qtm->binding_layer_flags = 0x00U;

    /*!< List of function pointers to acquisition sets */
    qtm->library_modules_init = library_modules_init;

    /*!< List of function pointers to post processing modules  */
    qtm->library_modules_proc = library_modules_proc;

    /*!< List of Acquisition Engines (Acq Modules one per AcqSet */
    qtm->library_modules_acq = library_modules_acq_engines;

    /*!< Data Model for Acquisition modules  */
    qtm->library_module_init_data_model = library_module_init_data_models;

    /*!< Data Model for post processing modules  */
    qtm->library_module_proc_data_model = library_module_proc_data_model;

    /*!< Data model for inline module processes  */
    qtm->library_modules_acq_dm = library_module_acq_engine_data_model;

    /*!< Post porcessing pointer */
    qtm->qtm_acq_pp = qtm_acquisition_process;

    /* Register Binding layer callbacks */
    qtm->qtm_init_complete_callback = init_complete_callback;
    qtm->qtm_error_callback = qtm_error_callback;
    qtm->qtm_measure_complete_callback = qtm_measure_complete_callback;
    qtm->qtm_pre_process_callback = null;
    qtm->qtm_post_process_callback = qtm_post_process_complete;
}

/*============================================================================
static touch_ret_t touch_sensors_config(void)
------------------------------------------------------------------------------
Purpose: Initialization of touch key sensors
Input  : none
Output : none
Notes  :
============================================================================*/
/* Touch sensors config - assign nodes to buttons / wheels / sliders / surfaces / water level / etc
 */
static touch_ret_t touch_sensors_config(void)
{
    uint16_t sensor_nodes;
    touch_ret_t touch_ret = TOUCH_SUCCESS;

    /* Init pointers to DMA sequence memory */
    qtm_ptc_qtlib_assign_signal_memory(&touch_acq_signals_raw[0]);

    /* Initialize sensor nodes */
    for (sensor_nodes = 0U; sensor_nodes < DEF_NUM_CHANNELS; sensor_nodes++) {
        /* Enable each node for measurement and mark for calibration */
        qtm_enable_sensor_node(&qtlib_acq_set1, sensor_nodes);
        qtm_calibrate_sensor_node(&qtlib_acq_set1, sensor_nodes);
    }

    /* Enable sensor keys and assign nodes */
    for (sensor_nodes = 0U; sensor_nodes < DEF_NUM_CHANNELS; sensor_nodes++) {
        qtm_init_sensor_key(&qtlib_key_set1, sensor_nodes, &ptc_qtlib_node_stat1[sensor_nodes]);
    }
    return (touch_ret);
}

/*
 * Force calibrate
 *
 * Call this function when the user "probably" isn't touching the device to reset all the
 * calibration values. It will only reset inputs that are not considered to be in "touched" states
 */
void qtouch_force_calibrate(void)
{
    qtm_touch_key_data_t* key;
    for (uint16_t i = 0U; i < DEF_NUM_CHANNELS; i++) {
        key = &qtlib_key_data_set1[i];
        uint16_t value = key->node_data_struct_ptr->node_acq_signals;
        uint16_t reference = key->channel_reference;
        int32_t diff = (int32_t)reference - (int32_t)value;
        if (!(key->sensor_state & KEY_TOUCHED_MASK) && diff > KEY_FORCE_CALIBRATE_THRESHOLD) {
            key->channel_reference = key->node_data_struct_ptr->node_acq_signals;
        }
    }
}

/*============================================================================
static void init_complete_callback(void)
------------------------------------------------------------------------------
Purpose: Callback function from binding layer called after the completion of
         acquisition module initialization.
Input  : none
Output : none
Notes  :
============================================================================*/
static void init_complete_callback(void)
{
    /* Configure touch sensors with Application specific settings */
    touch_sensors_config();
}

/*============================================================================
static void qtm_measure_complete_callback( void )
------------------------------------------------------------------------------
Purpose: Callback function from binding layer called after the completion of
         measurement cycle. This function sets the post processing request
         flag to trigger the post processing.
Input  : none
Output : none
Notes  :
============================================================================*/
static void qtm_measure_complete_callback(void)
{
    qtm_control.binding_layer_flags |= (1 << node_pp_request);
}

/*============================================================================
static void qtm_post_process_complete(void)
------------------------------------------------------------------------------
Purpose: Callback function from binding layer called after the completion of
         post processing. This function sets the reburst flag based on the
         key sensor group status, calls the datastreamer output function to
         display the module data.
Input  : none
Output : none
Notes  :
============================================================================*/
static void qtm_post_process_complete(void)
{
    if ((0U != (qtlib_key_set1.qtm_touch_key_group_data->qtm_keys_status & 0x80U))) {
        p_qtm_control->binding_layer_flags |= (1U << reburst_request);
    } else {
        measurement_done_touch = 1;
        qtouch_process_scroller_positions(); // Run the custom filter
#if PLATFORM_BITBOXBASE == 1
        qtouch_process_buttons();
#endif
    }
}

/*============================================================================
static void qtm_error_callback(uint8_t error)
------------------------------------------------------------------------------
Purpose: Callback function from binding layer called after the completion of
                 post processing. This function is called only when there is error.
Input  : error code
Output : decoded module error code
Notes  :
Error Handling supported by Binding layer module:
        Acquisition Module Error codes: 0x8<error code>
        0x81 - Qtm init
        0x82 - start acq
        0x83 - cal sensors
        0x84 - cal hardware

        Post processing Modules error codes: 0x4<process_id>
        0x40, 0x41, 0x42, ...
        process_id is the sequence of process IDs listed in #define LIB_MODULES_PROC_LIST macro.
        Process IDs start from zero and maximum is 15

        Examples:
        0x40 -> error in post processing module 1
        0x42 -> error in post processing module 3

Derived Module_error_codes:
        Acquisition module error =1
        post processing module1 error = 2
        post processing module2 error = 3
        ... and so on

============================================================================*/
static void qtm_error_callback(uint8_t err)
{
    module_error_code = 0;
    if (err & 0x80) {
        module_error_code = 1;
    } else if (err & 0x40) {
        module_error_code = (err & 0x0F) + 2;
    }
}

/*============================================================================
void qtouch_init(void)
------------------------------------------------------------------------------
Purpose: Initialization of touch library. PTC, timer, binding layer and
         datastreamer modules are initialized in this function.
Input  : none
Output : none
Notes  :
============================================================================*/
void qtouch_init(void)
{
    qtouch_timer_config();

    build_qtm_config(&qtm_control);

    qtm_binding_layer_init(&qtm_control);

    /* get a pointer to the binding layer control */
    p_qtm_control = qmt_get_binding_layer_ptr();
}

/*============================================================================
void qtouch_process(void)
------------------------------------------------------------------------------
Purpose: Main processing function of touch library. This function initiates the
         acquisition, calls post processing after the acquistion complete and
         sets the flag for next measurement based on the sensor status.
Input  : none
Output : none
Notes  :
============================================================================*/
void qtouch_process(void)
{
    touch_ret_t touch_ret;

    /* check the time_to_measure_touch flag for Touch Acquisition */
    if (p_qtm_control->binding_layer_flags & (1U << time_to_measure_touch)) {
        /* Do the acquisition */
        touch_ret = qtm_lib_start_acquisition(0);

        /* if the Acquistion request was successful then clear the request flag */
        if (TOUCH_SUCCESS == touch_ret) {
            /* Clear the Measure request flag */
            p_qtm_control->binding_layer_flags &= (uint8_t) ~(1U << time_to_measure_touch);
        }
    }

    /* check the flag for node level post processing */
    if (p_qtm_control->binding_layer_flags & (1U << node_pp_request)) {
        /* Run Acquisition moudle level post pocessing*/
        touch_ret = qtm_lib_acq_process();

        /* Check the return value */
        if (TOUCH_SUCCESS == touch_ret) {
            /* Returned with success: Start module level post processing */
            qtm_lib_post_process();
        } else {
            /* Acq module Eror Detected: Issue an Acq module common error code 0x80 */
            qtm_error_callback(0x80);
        }

        /* Reset the flags for node_level_post_processing */
        p_qtm_control->binding_layer_flags &= (uint8_t) ~(1U << node_pp_request);

        if (p_qtm_control->binding_layer_flags & (1U << reburst_request)) {
            p_qtm_control->binding_layer_flags |= (1U << time_to_measure_touch);
            p_qtm_control->binding_layer_flags &= ~(1U << reburst_request);
        }
    }
}

/*============================================================================
void qtouch_timer_handler(void)
------------------------------------------------------------------------------
Purpose: This function updates the time elapsed to the touch key module to
         synchronize the internal time counts used by the module.
Input  : none
Output : none
Notes  :
============================================================================*/
void qtouch_timer_handler(void)
{
    /* Count complete - Measure touch sensors */
    qtm_control.binding_layer_flags |= (1U << time_to_measure_touch);
    qtm_update_qtlib_timer(DEF_TOUCH_MEASUREMENT_PERIOD_MS);
}

static void qtouch_timer_task_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    qtouch_timer_handler();
}

void qtouch_timer_config(void)
{
    static struct timer_task Timer_task;
    Timer_task.interval = DEF_TOUCH_MEASUREMENT_PERIOD_MS;
    Timer_task.cb = qtouch_timer_task_cb;
    Timer_task.mode = TIMER_TASK_REPEAT;

    timer_add_task(&TIMER_0, &Timer_task);
    timer_start(&TIMER_0);
}

uint16_t qtouch_get_sensor_node_signal(uint16_t sensor_node)
{
    return (ptc_qtlib_node_stat1[sensor_node].node_acq_signals);
}

uint16_t qtouch_get_sensor_node_reference(uint16_t sensor_node)
{
    return (qtlib_key_data_set1[sensor_node].channel_reference);
}

uint16_t qtouch_get_sensor_cc_val(uint16_t sensor_node)
{
    return (ptc_qtlib_node_stat1[sensor_node].node_comp_caps);
}

uint8_t qtouch_get_sensor_state(uint16_t sensor_node)
{
    return (qtlib_key_set1.qtm_touch_key_data[sensor_node].sensor_state);
}

/* Holds preceding unfiltered scroller positions */
static uint16_t sensor_previous_filtered_reading[DEF_NUM_SENSORS][DEF_SENSOR_NUM_PREV_POS] = {0};

/* Custom sensor signal filter. */
uint16_t qtouch_get_sensor_node_signal_filtered(uint16_t sensor_node)
{
    // Filter the sensor signal.
    //
    // Smooth it out and saturate it so that values never go beyond 50.
    // This helps to mitigate 'jumpy' channels that exist at higher sensor readings when
    // in noisy environments.
    //
    uint16_t X;
    uint16_t sensor_raw = qtouch_get_sensor_node_signal(sensor_node);
    uint16_t sensor_reference = qtouch_get_sensor_node_reference(sensor_node);
    X = sensor_raw < sensor_reference ? 0 : sensor_raw - sensor_reference;
    // Add more weight to edge buttons because they are physically smaller (smaller readings).
    if ((sensor_node == DEF_SCROLLER_OFFSET_0) || (sensor_node == DEF_SCROLLER_OFFSET_1) ||
        (sensor_node == DEF_SCROLLER_OFFSET_0 + DEF_SCROLLER_NUM_CHANNELS - 1) ||
        (sensor_node == DEF_SCROLLER_OFFSET_1 + DEF_SCROLLER_NUM_CHANNELS - 1)) {
        X = X * (1 + DEF_SENSOR_EDGE_WEIGHT);
    }
    // Saturate out-of-range readings.
    X = (X > 50) ? 50 : X;

    // Calculate sensor readout using a moving average
    // The moving average wieghts previous N readings twice current reading
    uint16_t moving_average_cummulative_weight = 1; // Add one for current reading calculated above
    uint16_t X_ave = X;
    for (size_t j = 0; j < DEF_SENSOR_NUM_PREV_POS; j++) {
        moving_average_cummulative_weight += 2;
        X_ave += sensor_previous_filtered_reading[sensor_node][j] * 2;
    }
    X_ave = X_ave / moving_average_cummulative_weight;

    // Update recorded previous positions
    for (size_t j = 0; j < DEF_SENSOR_NUM_PREV_POS - 1; j++) {
        sensor_previous_filtered_reading[sensor_node][j] =
            sensor_previous_filtered_reading[sensor_node][j + 1];
    }
    sensor_previous_filtered_reading[sensor_node][DEF_SENSOR_NUM_PREV_POS - 1] = X;

    return X_ave;
}

bool qtouch_is_scroller_active(uint16_t scroller)
{
    return scroller_active[scroller];
}

uint16_t qtouch_get_scroller_position(uint16_t sensor_node)
{
    return scroller_position[sensor_node];
}

void qtouch_process_scroller_positions(void)
{
    for (uint8_t scroller = 0; scroller < DEF_NUM_SCROLLERS; scroller++) {
        uint8_t i, j;
        uint16_t sum = 0;
        uint16_t max_sensor_reading = 0;
        uint16_t weighted_sum = 0;
        uint16_t sensor_location[DEF_SCROLLER_NUM_CHANNELS] = {
            1, // Offset by `1` because a `0` location cannot be weight-averaged
            DEF_SCROLLER_RESOLUTION / 3,
            DEF_SCROLLER_RESOLUTION / 3 * 2,
            DEF_SCROLLER_RESOLUTION};

        // Read filterd data and weight by sensor physical location
        for (i = 0; i < DEF_SCROLLER_NUM_CHANNELS; i++) {
            uint16_t value;
            value = qtouch_get_sensor_node_signal_filtered(
                i + (scroller ? DEF_SCROLLER_OFFSET_1 : DEF_SCROLLER_OFFSET_0));
            sum += value;
            weighted_sum += value * sensor_location[i];
            max_sensor_reading = (value > max_sensor_reading) ? value : max_sensor_reading;
        }

        // Compensate for deadband (i.e. when only a single edge button gives a reading and
        // neighbors do not)
        uint16_t scaled_value = weighted_sum / sum;
        scaled_value =
            (scaled_value < DEF_SCROLLER_DEADBAND) ? DEF_SCROLLER_DEADBAND : (weighted_sum / sum);
        scaled_value = (scaled_value > (DEF_SCROLLER_RESOLUTION - DEF_SCROLLER_DEADBAND))
                           ? (DEF_SCROLLER_RESOLUTION - DEF_SCROLLER_DEADBAND)
                           : scaled_value;
        scaled_value = ((scaled_value - DEF_SCROLLER_DEADBAND) * (DEF_SCROLLER_RESOLUTION - 1)) /
                       (DEF_SCROLLER_RESOLUTION - 2 * DEF_SCROLLER_DEADBAND);

        // Calculate scroller position using a moving average
        // The moving average wieghts previous N readings twice current reading
        if (sum >= DEF_SCROLLER_DET_THRESHOLD) {
            uint16_t moving_average_cummulative_weight = 0;
            scroller_position[scroller] = 0;
            for (j = 0; j < DEF_SCROLLER_NUM_PREV_POS; j++) {
                if (scroller_previous_position[scroller][j] != DEF_SCROLLER_OFF) {
                    moving_average_cummulative_weight += 2;
                    scroller_position[scroller] += scroller_previous_position[scroller][j] * 2;
                }
            }
            scroller_position[scroller] +=
                scaled_value; // Most recent signal is half weight of others to help avoid bounce
                              // when finger is released
            scroller_position[scroller] =
                scroller_position[scroller] / (moving_average_cummulative_weight + 1);
        }

        // Update recorded previous positions and scroller active state
        for (j = 0; j < DEF_SCROLLER_NUM_PREV_POS - 1; j++) {
            scroller_previous_position[scroller][j] = scroller_previous_position[scroller][j + 1];
        }
        if (sum >= DEF_SCROLLER_DET_THRESHOLD) {
            scroller_previous_position[scroller][DEF_SCROLLER_NUM_PREV_POS - 1] = scaled_value;
        } else {
            scroller_previous_position[scroller][DEF_SCROLLER_NUM_PREV_POS - 1] = DEF_SCROLLER_OFF;
        }
        // Use the maximum value of all sensor readings as an estimate of pressure.
        // Put a threshold on this to detect whether we're touching or not.
        if (max_sensor_reading >= DEF_SCROLLER_TOUCH_THRESHOLD) {
            scroller_active[scroller] = true;
        } else if (max_sensor_reading <= DEF_SCROLLER_UNTOUCH_THRESHOLD) {
            scroller_active[scroller] = false;
        }
    }
}

#if PLATFORM_BITBOXBASE == 1
bool qtouch_get_button_state(size_t idx)
{
    return button_active[idx];
}

void qtouch_process_buttons(void)
{
    for (size_t idx = 0; idx < DEF_NUM_BUTTONS; idx++) {
        uint16_t value = qtouch_get_sensor_node_signal_filtered(DEF_BUTTON_OFFSET + idx);
        if (value > DEF_SCROLLER_TOUCH_THRESHOLD) {
            button_active[idx] = true;
        } else {
            button_active[idx] = false;
        }
    }
}
#endif

/*============================================================================
ISR(ADC0_RESRDY_vect)
------------------------------------------------------------------------------
Purpose:  ADC EOC Interrupt - Call PTC handler or application
Input    :  none
Output  :  none
Notes    :  none
============================================================================*/
void ADC0_1_Handler(void)
{
    ADC0->INTFLAG.reg |= 1U;
    qtm_samd51_ptc_handler();
}

#endif /* TOUCH_C */
