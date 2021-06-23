/*============================================================================
Filename : qtm_touch_key_api.h
Project : QTouch Modular Library
Purpose : Structs and definitions for use within modules
------------------------------------------------------------------------------
Copyright (c) 2019 Microchip. All rights reserved.
------------------------------------------------------------------------------
============================================================================*/

#ifndef TOUCH_API_KEYS_H
#define TOUCH_API_KEYS_H

/* Include files */
#include <stdint.h>
#include "qtm_common_components_api.h"

/* Keys status dlags */
#define QTM_KEY_REBURST 0x80u
#define QTM_KEY_DETECT 0x01u

/* QTLib Timebase */
#define QTLIB_TIMEBASE 200u

/*----------------------------------------------------------------------------
 *     type definitions
 *----------------------------------------------------------------------------*/

/* ! An unsigned 8-bit number setting a sensor detection threshold. */
typedef uint8_t threshold_t;

/* ! Sensor number type. */
typedef uint16_t sensor_id_t;

/* ! Current time type. */
typedef uint16_t touch_current_time_t;

/* ! Touch sensor delta value type. */
typedef int16_t touch_delta_t;

/* ! Status of Touch measurement. */
typedef uint16_t touch_acq_status_t;

typedef enum tag_hysteresis_t { HYST_50, HYST_25, HYST_12_5, HYST_6_25, MAX_HYST } QTM_hysteresis_t;

typedef enum tag_aks_group_t {
	NO_AKS_GROUP,
	AKS_GROUP_1,
	AKS_GROUP_2,
	AKS_GROUP_3,
	AKS_GROUP_4,
	AKS_GROUP_5,
	AKS_GROUP_6,
	AKS_GROUP_7,
	MAX_AKS_GROUP
} QTM_aks_group_t;

typedef enum tag_recal_threshold_t {
	RECAL_100,
	RECAL_50,
	RECAL_25,
	RECAL_12_5,
	RECAL_6_25,
	MAX_RECAL
} recal_threshold_t;

/* Reburst mode:
0 = none (application calls only)
1 = Unresolved - i.e. sensors in process of calibration / filter in / filter out and AKS groups
2 = All keys
*/
typedef enum { REBURST_NONE, REBURST_UNRESOLVED, REBURST_ALL } reburst_mode_t;
/*----------------------------------------------------------------------------
 *     Structure Declarations
 *----------------------------------------------------------------------------*/

/* Key process module */
/* Sensor group config */
typedef struct {
	uint16_t num_key_sensors;              /* Number of sensors */
	uint8_t  sensor_touch_di;              /* Count in to Detect */
	uint8_t  sensor_max_on_time;           /* Max on duration x 200ms */
	uint8_t  sensor_anti_touch_di;         /* Count in to Anti-touch recal */
	uint8_t  sensor_anti_touch_recal_thr;  /* Anti-touch recal threshold % */
	uint8_t  sensor_touch_drift_rate;      /* One count per <200> ms */
	uint8_t  sensor_anti_touch_drift_rate; /* One count per <200> ms */
	uint8_t  sensor_drift_hold_time;       /* Drift hold time */
	uint8_t  sensor_reburst_mode;          /* None / Unresolved / All */
} qtm_touch_key_group_config_t;

/* Sensor group data */
typedef struct {
	uint8_t  qtm_keys_status;     /* Status byte - bitfield: Bit 7 = REBURST_REQ, Bits 6:1 = Reserved, Bit 0 = Detect */
	uint16_t acq_group_timestamp; /* For tracking this group drift etc */
	uint8_t  dht_count_in;        /* Count of drift hold time */
	uint8_t  tch_drift_count_in;  /* Count of towards touch drift */
	uint8_t  antitch_drift_count_in; /* Count of away from touch drift */
} qtm_touch_key_group_data_t;

/* Sensor keys config */
typedef struct {
	uint8_t channel_threshold;  /* Touch detection threshold */
	uint8_t channel_hysteresis; /* Percentage of threshold reduction to exit detect state */
	uint8_t channel_aks_group;  /* 0 = None, 1-255 = group number */
} qtm_touch_key_config_t;

/* ---------------------------------------------------------------------------------------- */
/* Key sensor run-time data - api common */
/* ---------------------------------------------------------------------------------------- */

/* Container */
typedef struct {
	qtm_touch_key_group_data_t(*qtm_touch_key_group_data);
	qtm_touch_key_group_config_t(*qtm_touch_key_group_config);
	qtm_touch_key_data_t(*qtm_touch_key_data);
	qtm_touch_key_config_t(*qtm_touch_key_config);
} qtm_touch_key_control_t;

/*----------------------------------------------------------------------------
 *   prototypes
 *----------------------------------------------------------------------------*/

/* Key Process Library Prototypes */

/*============================================================================
touch_ret_t qtm_init_sensor_key(qtm_touch_key_control_t* qtm_lib_key_group_ptr, uint8_t which_sensor_key,
qtm_acq_node_data_t* acq_lib_node_ptr)
------------------------------------------------------------------------------
Purpose: Initialize a touch key sensor
Input  : Pointer to key group control data, key number, pointers to sensor node status and signal
Output : TOUCH_SUCCESS
Notes  : none
============================================================================*/
touch_ret_t qtm_init_sensor_key(qtm_touch_key_control_t *qtm_lib_key_group_ptr, uint8_t which_sensor_key,
                                qtm_acq_node_data_t *acq_lib_node_ptr);

/*============================================================================
touch_ret_t qtm_key_sensors_process(qtm_touch_key_control_t* qtm_lib_key_group_ptr)
------------------------------------------------------------------------------
Purpose: Sensor key post-processing (touch detect state machine)
Input  : Pointer to key group control data
Output : TOUCH_SUCCESS
Notes  : none
============================================================================*/
touch_ret_t qtm_key_sensors_process(qtm_touch_key_control_t *qtm_lib_key_group_ptr);

/*============================================================================
touch_ret_t qtm_key_suspend(uint16_t which_sensor_key, qtm_touch_key_control_t* qtm_lib_key_group_ptr)
------------------------------------------------------------------------------
Purpose: Suspends acquisition measurements for the key
Input  : Key number, Pointer to key group control data
Output : TOUCH_SUCCESS
Notes  : none
============================================================================*/
touch_ret_t qtm_key_suspend(uint16_t which_sensor_key, qtm_touch_key_control_t *qtm_lib_key_group_ptr);

/*============================================================================
touch_ret_t qtm_key_resume(uint16_t which_sensor_key, qtm_touch_key_control_t* qtm_lib_key_group_ptr)
------------------------------------------------------------------------------
Purpose: Resumes acquisition measurements for the key
Input  : Key number, Pointer to key group control data
Output : TOUCH_SUCCESS
Notes  : none
============================================================================*/
touch_ret_t qtm_key_resume(uint16_t which_sensor_key, qtm_touch_key_control_t *qtm_lib_key_group_ptr);

/*============================================================================
void update_qtlib_timer(uint16_t time_elapsed_since_update)
------------------------------------------------------------------------------
Purpose: Updates local variable with time period
Input  : Number of ms since last update
Output : none
Notes  : none
============================================================================*/
void qtm_update_qtlib_timer(uint16_t time_elapsed_since_update);

/*============================================================================
uint16_t qtm_get_touch_keys_module_id(void)
------------------------------------------------------------------------------
Purpose: Returns the module ID
Input  : none
Output : Module ID
Notes  : none
============================================================================*/
uint16_t qtm_get_touch_keys_module_id(void);

/*============================================================================
uint8_t qtm_get_touch_keys_module_ver(void)
------------------------------------------------------------------------------
Purpose: Returns the module Firmware version
Input  : none
Output : Module ID - Upper nibble major / Lower nibble minor
Notes  : none
============================================================================*/
uint8_t qtm_get_touch_keys_module_ver(void);

#endif /* TOUCH_API_PTC_H */
