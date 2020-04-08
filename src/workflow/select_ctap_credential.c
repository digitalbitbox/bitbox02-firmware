#include "select_ctap_credential.h"

#include <ui/components/scroll_through_all_variants.h>
#include <ui/screen_stack.h>
#include <ui/workflow_stack.h>
#include <util.h>
#include <workflow/workflow.h>

typedef struct {
    char* words[CTAP_CREDENTIAL_LIST_MAX_SIZE];
    size_t n_words;
    void (*callback)(int, void*);
    void *callback_param;
    bool done;
    int selected;
} data_t;

/**
 * Checks if the user has selected one of the credentials.
 */
static void _workflow_select_ctap_credential_spin(workflow_t* self)
{
    data_t* data = (data_t*)self->data;
    if (data->done) {
        /* Publish our result. */
        data->callback(data->selected, data->callback_param);
        /* Time to go, goodbye. */
        workflow_stack_stop_workflow();
    }
}

static void _credential_selected(uint8_t selected, void *param) {
    data_t* data = (data_t*)param;
    data->done = true;
    data->selected = selected;
}

static void _cancel_cb(void *param) {
    data_t* data = (data_t*)param;
    data->done = true;
    data->selected = -1;
}


/**
 * Starts this workflow.
 */
static void _workflow_select_ctap_credential_init(workflow_t* self)
{
    data_t* data = (data_t*)self->data;
    component_t* comp;
    comp = scroll_through_all_variants_create(
        (const char * const*)data->words,
        _credential_selected,
        data,
        data->n_words,
        "Select user",
        NULL,
        _cancel_cb,
        data,
        NULL);
    ui_screen_stack_push(comp);
}

/**
 * Destroys this workflow.
 */
static void _workflow_select_ctap_credential_cleanup(workflow_t* self)
{
    ui_screen_stack_pop();
    ui_screen_stack_cleanup();
    data_t* data = self->data;
    for (size_t i = 0; i < data->n_words; ++i) {
        util_zero(data->words[i], strlen(data->words[i]));
        free(data->words[i]);
    }
    util_zero(data, sizeof(*data));
    free(data);
    util_zero(self, sizeof(*self));
    free(self);
}

static char* _credential_to_string(ctap_credential_display_t* cred)
{
    if (strlen(cred->display_name) > 0) {
        return util_asprintf("%s\n(%s)", cred->display_name, cred->username);
    }
    return util_asprintf("%s", cred->username);
}

workflow_t* workflow_select_ctap_credential(ctap_credential_display_list_t* credentials, void (*callback)(int, void *), void *cb_param)
{
    workflow_t* result = workflow_allocate(
        _workflow_select_ctap_credential_init,
        _workflow_select_ctap_credential_cleanup,
        _workflow_select_ctap_credential_spin,
        sizeof(data_t)
        );
    data_t* data = (data_t*)result->data;
    data->callback = callback;
    data->callback_param = cb_param;
    /* Create the text representation of each credential. */
    for (size_t i = 0; i < credentials->n_elems; ++i) {
        data->words[i] = _credential_to_string(&credentials->creds[i]);
    }
    data->n_words = credentials->n_elems;
    return result;
}
