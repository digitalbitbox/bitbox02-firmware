/*============================================================================
Filename : qtm_binding_layer_api.h
Project : QTouch Modular Library
Purpose : Binds the acquisition and post processing modules and provides callback
------------------------------------------------------------------------------
Copyright (C) 2019 Microchip. All rights reserved.
------------------------------------------------------------------------------
============================================================================*/

/** @file */

/** \defgroup Misra Misra Compliance report  */

/**
 * \addtogroup Misra
 * <B>Complaiance:</B><BR>
 * the module code is compiled using IARs Embedded workbench for AVR<BR>
 * MISRA 2004 compliance is selected with all required options selected<BR>
 * any rule which has been violated will be documented and the rule switched off<BR>
 * <BR>
 * <HR>
 */

#ifndef TOUCH_API_BINDING_LAYER_H
#define TOUCH_API_BINDING_LAYER_H

/* Include files */
#include <stdint.h>
#include "qtm_common_components_api.h"

/*----------------------------------------------------------------------------
manifest constants
----------------------------------------------------------------------------*/
#define null '\0'

/*----------------------------------------------------------------------------
 *     type definitions
 *----------------------------------------------------------------------------*/

/*  Modular Library state   */
typedef enum QT_Modular_lib_state_tag { uninitialised, config_initialised, ready, busy, processing, error } qtm_state_t;

typedef enum QT_ModLib_Status_flags {
	time_to_measure_touch,
	node_pp_request,
	reburst_request,
	reserved_flag_pos_3,

	reserved_flag_pos_4,
	reserved_flag_pos_5,
	reserved_flag_pos_6,
	reserved_flag_pos_7,
} qtm_flags;

typedef void (*qtm_measure_complete_t)(void);
typedef void (*qtm_library_init_complete_t)(void);
typedef void (*qtm_pre_process_callback_t)(uint8_t *callback);
typedef void (*qtm_error_callback_t)(uint8_t error_code);
typedef void (*qtm_post_process_callback_t)(void);

typedef void *(*module_init_t)(void *data_model);
typedef void *(*module_proc_t)(void *data_model);
typedef void *(*module_init_inline_t)(void *data_model);
typedef void *(*module_inline_t)(void *data_model);
typedef void *(*module_conf_t)(void *data_model);
typedef void *(*module_acq_t)(void *data_model, void (*callback)(void));

/* this should take an arqument */
typedef touch_ret_t(qtm_acq_pp_t)(void);

typedef void *module_arg_t;

/*----------------------------------------------------------------------------
 *     Structure Declarations
 *----------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------------------- */
/* Key sensor run-time data - api common */
/* ---------------------------------------------------------------------------------------- */

/* Container */
/**
 * @brief a collection of controls for the binding layer
 */
typedef struct qtm_control_tag /*!< Control structure for the bonsding layer */
{
	uint8_t binding_layer_flags; /*!< Some Flags   */

	module_init_t *library_modules_init; /*!< List of function pointers to acquisition sets */
	module_proc_t *library_modules_proc; /*!< List of function pointers to post processing modules  */
	module_acq_t * library_modules_acq;

	module_arg_t *library_module_init_data_model; /*!< Data Model for Acquisition modules  */
	module_arg_t *library_module_proc_data_model; /*!< Data Model for post processing modules  */
	module_arg_t *library_modules_acq_dm;         /*!< Data model for inline module processes  */

	qtm_acq_pp_t *qtm_acq_pp; /*!< Post porcessing pointer */

	/*******************************/
	/* Callbacks for Binding layer */
	/*******************************/
	qtm_library_init_complete_t qtm_init_complete_callback;
	qtm_error_callback_t        qtm_error_callback;
	qtm_measure_complete_t      qtm_measure_complete_callback;
	qtm_pre_process_callback_t  qtm_pre_process_callback;
	qtm_post_process_callback_t qtm_post_process_callback;

} qtm_control_t;

/*----------------------------------------------------------------------------
 *   prototypes
 *----------------------------------------------------------------------------*/

/**
 *	@brief Returns a pointer to the binding layer control structure
 *
 *	This function is never used in the example code, but it is included here
 *	in case the user would like to get a (qtm_control_t)
 *
 *	This function accepts no inputs
 *
 * @return &qtm_control, this is a pointer to the binding layer control structure
 */
qtm_control_t *qmt_get_binding_layer_ptr(void);

/**
 * Initialises the binding layer, there are two possible outcomes
 *
 *
 * 1). There were no errors
 * \msc
 * a [label="User Application"],b [label="Modular Library"];
 * a=>>b [label="qtm_lib_init(&qtm_control);"];
 * b=>b;
 * a<<=b [label="qtm_init_complete_callback();"];
 * \endmsc
 *
 * 2). There were errors detected
 * \msc
 * a [label="User Application"],b [label="Modular Library"];
 * a=>>b [label="qtm_lib_init(&qtm_control);"];
 * b=>b;
 * a<<=b [label="qtm_error_callback(error_code);"];
 * \endmsc
 */

/**
 * @see qtm_state_t for a state diagram
 * @param qtm_control This is the control structure to the binding layer
 */

/**
 * Typical Application flow.
 *
 * @msc
 * a [label="User Application"],b [label="Modular Library"];
 * a=>>b [label="qtm_lib_init(&qtm_control);"];
 * b=>b;
 * a<<=b [label="qtm_init_complete_callback();"];
 * a=>>b [label="qtm_calibrate_hardware();"];
 *   ---  [ label = "library setup, Start normal acquisition" ];
 * a=>>b [label="qtm_lib_start_acquisition();"];
 * b=>b;
 * a<<=b [label="qtm_measure_complete_callback();"];
 *  ...;
 * a=>>b [label="qtm_lib_start_acquisition();"];
 * b=>b;
 * a<<=b [label="qtm_measure_complete_callback();"];
 *  ...;
 * a=>>b [label="qtm_lib_start_acquisition();"];
 * b=>b;
 * a<<=b [label="qtm_measure_complete_callback();"];
 *  ...;
 * a=>>b [label="qtm_lib_start_acquisition();"];
 * b=>b;
 * a<<=b [label="qtm_measure_complete_callback();"];
 *  ...;
 * @endmsc
 */

void qtm_binding_layer_init(qtm_control_t *qtm_control);

/**
 * @brief Starts the Modular library on the first acquisition set
 *
 * An Acquisition set is defined in the Acquisition Module documentation, but
 * essentially an acquisition set is a group of node with a common property,
 * the common property can be, Acquisition Type: Self or Mutual, or proximity or
 * spatial displacement to or from another.
 *
 * @return the library state, @see qtm_state_t
 */
touch_ret_t qtm_lib_start_acquisition(uint8_t set_id);

/*qtm_state_t qtm_post_process(void);*/
touch_ret_t qtm_lib_post_process(void);

/**
 * @brief Gets the library state
 *
 *        some tasks cannot happen if the library is not in the correct state
 *        if the library is requesting a start acquisition when there is an
 *        ongoing acquisition then the binding layer will move to the error
 *        state,  checking the library state before acquisition will prevent
 *        errors like this.
 *
 * @return the library state,
 * @see qtm_state_t
 */
qtm_state_t qtm_lib_get_state(void);

touch_ret_t qtm_lib_acq_process(void);

uint16_t qtm_get_binding_layer_module_id(void);

/*============================================================================
uint8_t get_qtm_m328pb_acq_module_version(void)
------------------------------------------------------------------------------
Purpose: Returns the module Firmware version
Input  : none
Output : Module ID - Upper nibble major / Lower nibble minor
Notes  : none
============================================================================*/
uint8_t qtm_get_binding_layer_module_version(void);

#endif /* TOUCH_API_BINDING_LAYER_H */
