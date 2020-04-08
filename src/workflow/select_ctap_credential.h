#ifndef _WORKFLOW_SELECT_CTAP_CREDENTIAL_H
#define _WORKFLOW_SELECT_CTAP_CREDENTIAL_H

#include <fido2/ctap.h>
#include <workflow/workflow.h>

typedef struct {
    /* ID of the key in the RK storage table. */
    int mem_id;
    /* U2F counter at the time this credential was created. */
    uint32_t creation_time;
    char username[CTAP_STORAGE_USER_NAME_LIMIT];
    char display_name[CTAP_STORAGE_DISPLAY_NAME_LIMIT];
} ctap_credential_display_t;

typedef struct {
    size_t n_elems;
    ctap_credential_display_t creds[CTAP_CREDENTIAL_LIST_MAX_SIZE];
} ctap_credential_display_list_t;

/**
 * Starts the select credential workflow.
 * @param[in] credentials List of credentials to display.
 * @param[in] callback Callback that will be invoked before the workflow terminates.
 *                     It will be called with the index of the selected credential
 *                     (or -1 if the operation was cancelled), and the user-defined parameter.
 * @param[in] cb_param User-defined parameter to be passed to callback.
 * @return Workflow object.
 */
workflow_t* workflow_select_ctap_credential(ctap_credential_display_list_t* credentials, void (*callback)(int, void *), void *cb_param);

#endif // _WORKFLOW_SELECT_CTAP_CREDENTIAL_H
