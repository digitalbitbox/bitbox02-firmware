
/*============================================================================
Filename : touch_api_ptc.h
Project : QTouch Modular Library
Purpose : Includes the Module API header files based on the configured modules,
          prototypes for touch.c file and Application helper API functions

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

#ifndef TOUCH_API_PTC_H
#define TOUCH_API_PTC_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*----------------------------------------------------------------------------
 *     include files
 *----------------------------------------------------------------------------*/

#include "hal_timer.h"

#include "qtm_common_components_api.h"
#include "qtm_binding_layer_0x0005_api.h"
#include "qtm_acq_samd51_0x000f_api.h"
#include "qtm_touch_key_0x0002_api.h"
#include "qtm_scroller_0x000b_api.h"

/*----------------------------------------------------------------------------
 *   prototypes
 *----------------------------------------------------------------------------*/
/* Application Helper API's */
uint16_t qtouch_get_sensor_node_signal(uint16_t sensor_node);
uint16_t qtouch_get_sensor_node_reference(uint16_t sensor_node);
uint16_t qtouch_get_sensor_node_signal_filtered(uint16_t sensor_node);
uint16_t qtouch_get_sensor_cc_val(uint16_t sensor_node);
uint8_t qtouch_get_sensor_state(uint16_t sensor_node);
void qtouch_update_sensor_node_signal(uint16_t sensor_node, uint16_t new_signal);
void qtouch_update_sensor_node_reference(uint16_t sensor_node, uint16_t new_reference);
void qtouch_update_sensor_cc_val(uint16_t sensor_node, uint16_t new_cc_value);
void qtouch_update_sensor_state(uint16_t sensor_node, uint8_t new_state);
void qtouch_calibrate_node(uint16_t sensor_node);
bool qtouch_is_scroller_active(uint16_t sensor_node);
uint16_t qtouch_get_scroller_position(uint16_t sensor_node);

void qtouch_timer_handler(void);
void qtouch_init(void);
void qtouch_process(void);
void qtouch_force_calibrate(void);

void qtimer_task_cb(const struct timer_task *const timer_task);
void qtouch_timer_config(void);

#ifdef __cplusplus
}
#endif

#endif /* TOUCH_API_PTC_H */
