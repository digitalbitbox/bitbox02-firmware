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

#include "confirm.h"

#include "blocking.h"
#include "hardfault.h"

#include <hardfault.h>
#include <ui/components/confirm.h>
#include <ui/screen_stack.h>
#include <ui/workflow_stack.h>
#include <util.h>

#include <stddef.h>
#include <stdlib.h>

typedef struct {
    bool result;
    bool done;
    confirm_params_t params;
    void (*callback)(bool, void*);
    void* callback_param;
    char* title;
    char* body;
} data_t;

static void _confirm(void* param)
{
    workflow_t* self = (workflow_t*)param;
    data_t* data = (data_t*)self->data;
    data->result = true;
    data->done = true;
}

static void _reject(void* param)
{
    workflow_t* self = (workflow_t*)param;
    data_t* data = (data_t*)self->data;
    data->result = false;
    data->done = true;
}

/**
 * Checks if the user has confirmed the choice.
 */
static void _workflow_confirm_spin(workflow_t* self)
{
    data_t* data = (data_t*)self->data;
    if (data->done) {
        /* Publish our result. */
        if (data->callback) {
            data->callback(data->result, data->callback_param);
        }
        /* Time to go, goodbye. */
        workflow_stack_stop_workflow();
    }
}

/**
 * Starts this workflow.
 */
static void _workflow_confirm_init(workflow_t* self)
{
    data_t* data = (data_t*)self->data;
    component_t* comp;
    comp = confirm_create(
        &data->params, _confirm, self, data->params.accept_only ? NULL : _reject, self);
    ui_screen_stack_push(comp);
}

/**
 * Destroys this workflow.
 */
static void _workflow_confirm_cleanup(workflow_t* self)
{
    ui_screen_stack_pop();
    ui_screen_stack_cleanup();
    data_t* data = (data_t*)self->data;
    if (data->body) {
        util_zero(data->body, strlen(data->body));
    }
    if (data->title) {
        util_zero(data->title, strlen(data->title));
    }
    free(data->title);
    free(data->body);
}

workflow_t* workflow_confirm(
    const confirm_params_t* params,
    void (*callback)(bool, void*),
    void* callback_param)
{
    workflow_t* result = workflow_allocate(
        _workflow_confirm_init, _workflow_confirm_cleanup, _workflow_confirm_spin, sizeof(data_t));
    data_t* data = (data_t*)result->data;
    data->done = false;
    data->params = *params;
    /* Make a copy of the parameter strings. */
    if (data->params.title) {
        data->title = strdup(data->params.title);
        data->params.title = data->title;
    } else {
        data->title = NULL;
    }
    if (data->params.body) {
        data->body = strdup(data->params.body);
        data->params.body = data->body;
    } else {
        data->body = NULL;
    }
    if (!data->params.title || !data->params.body) {
        Abort("workflow_confirm\ntitle malloc");
    }

    data->callback = callback;
    data->callback_param = callback_param;
    result->data = data;
    return result;
}

static void _confirm_blocking_cb(bool status, void* param)
{
    bool* result = param;
    *result = status;
    workflow_blocking_unblock();
}

bool workflow_confirm_blocking(const confirm_params_t* params)
{
    bool _result;
    workflow_t* confirm_wf = workflow_confirm(params, _confirm_blocking_cb, &_result);
    workflow_stack_start_workflow(confirm_wf);
    workflow_blocking_block();
    return _result;
}
