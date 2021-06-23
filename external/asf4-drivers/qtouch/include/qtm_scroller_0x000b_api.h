/*============================================================================
Filename : qtm_scroller_api.h
Project : QTouch Modular Library
Purpose : Structs and definitions for use within modules
------------------------------------------------------------------------------
Copyright (C) 2020 Microchip. All rights reserved.
------------------------------------------------------------------------------
============================================================================*/

#ifndef TOUCH_API_SCROLLER_H
#define TOUCH_API_SCROLLER_H

/* Include files */
#include <stdint.h>
#include "qtm_common_components_api.h"

/* Scroller status bits */
#define SCROLLER_TOUCH_ACTIVE (uint8_t)((uint8_t)1 << 0u)    /* Bit 0 */
#define SCROLLER_POSITION_CHANGE (uint8_t)((uint8_t)1 << 1u) /* Bit 1 */
#define SCROLLER_REBURST (uint8_t)((uint8_t)1 << 7u)         /* Bit 7 */

/* Extract Resolution / Deadband */
#define SCROLLER_RESOLUTION(m) (uint8_t)(((m)&0xF0u) >> 4u)
#define SCROLLER_DEADBAND(m) (uint8_t)((m)&0x0Fu)

/* Combine Resolution / Deadband */
#define SCROLLER_RESOL_DEADBAND(r, p) (uint8_t)(((r) << 4u) | (p))

/* scroller resolution setting */
typedef enum tag_scroller_resolution_t {
	SCR_RESOL_2_BIT = 2,
	SCR_RESOL_3_BIT,
	SCR_RESOL_4_BIT,
	SCR_RESOL_5_BIT,
	SCR_RESOL_6_BIT,
	SCR_RESOL_7_BIT,
	SCR_RESOL_8_BIT,
	SCR_RESOL_9_BIT,
	SCR_RESOL_10_BIT,
	SCR_RESOL_11_BIT,
	SCR_RESOL_12_BIT
} scroller_resolution_t;

/* scroller deadband percentage setting */
typedef enum tag_scroller_deadband_t {
	SCR_DB_NONE,
	SCR_DB_1_PERCENT,
	SCR_DB_2_PERCENT,
	SCR_DB_3_PERCENT,
	SCR_DB_4_PERCENT,
	SCR_DB_5_PERCENT,
	SCR_DB_6_PERCENT,
	SCR_DB_7_PERCENT,
	SCR_DB_8_PERCENT,
	SCR_DB_9_PERCENT,
	SCR_DB_10_PERCENT,
	SCR_DB_11_PERCENT,
	SCR_DB_12_PERCENT,
	SCR_DB_13_PERCENT,
	SCR_DB_14_PERCENT,
	SCR_DB_15_PERCENT
} scroller_deadband_t;

/*----------------------------------------------------------------------------
 *     Structure Declarations
 *----------------------------------------------------------------------------*/

/* Configuration - Group of scrollers */
typedef struct {
	qtm_touch_key_data_t *qtm_touch_key_data;
	uint8_t               num_scrollers;
} qtm_scroller_group_config_t;

/* Data - Group of scrollers */
typedef struct {
	uint8_t scroller_group_status;
} qtm_scroller_group_data_t;

/* Configuration - Each slider / wheel */
typedef struct {
	uint8_t  type;
	uint16_t start_key;
	uint8_t  number_of_keys;
	uint8_t  resol_deadband;
	uint8_t  position_hysteresis;
	uint16_t contact_min_threshold;
} qtm_scroller_config_t;

/* Data Each - slider / wheel */
typedef struct {
	uint8_t  scroller_status;
	uint8_t  right_hyst;
	uint8_t  left_hyst;
	uint16_t raw_position;
	uint16_t position;
	uint16_t contact_size;
} qtm_scroller_data_t;

/* Container */
typedef struct {
	qtm_scroller_group_data_t *  qtm_scroller_group_data;
	qtm_scroller_group_config_t *qtm_scroller_group_config;
	qtm_scroller_data_t *        qtm_scroller_data;
	qtm_scroller_config_t *      qtm_scroller_config;
} qtm_scroller_control_t;

/*----------------------------------------------------------------------------
 *   prototypes
 *----------------------------------------------------------------------------*/

/*============================================================================
touch_ret_t qtm_init_scroller_module(qtm_scroller_control_t *qtm_scroller_control)
------------------------------------------------------------------------------
Purpose: Initialize a scroller
Input  : Pointer to scroller group control data
Output : TOUCH_SUCCESS
Notes  : none
============================================================================*/
touch_ret_t qtm_init_scroller_module(qtm_scroller_control_t *qtm_scroller_control);

/*============================================================================
touch_ret_t qtm_scroller_process(qtm_scroller_control_t *qtm_scroller_control)
------------------------------------------------------------------------------
Purpose: Scroller position calculation and filtering
Input  : Pointer to scroller group control data
Output : TOUCH_SUCCESS
Notes  : none
============================================================================*/
touch_ret_t qtm_scroller_process(qtm_scroller_control_t *qtm_scroller_control);

/*============================================================================
uint16_t qtm_get_scroller_module_id(void)
------------------------------------------------------------------------------
Purpose: Returns the module ID
Input  : none
Output : Module ID
Notes  : none
============================================================================*/
uint16_t qtm_get_scroller_module_id(void);

/*============================================================================
uint8_t qtm_get_scroller_module_ver(void)
------------------------------------------------------------------------------
Purpose: Returns the module Firmware version
Input  : none
Output : Module ID - Upper nibble major / Lower nibble minor
Notes  : none
============================================================================*/
uint8_t qtm_get_scroller_module_ver(void);

#endif /* TOUCH_API_SCROLLER_H */
