// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>

#include "azure_c_shared_utility/platform.h"

#include "provisioning_service_client.h"
#include "provisioning_sc_enrollment_private.h"

int main()
{
    int result = 0;

    if (platform_init() != 0)
    {
        (void)printf("platform_init failed\r\n");
        result = __FAILURE__;
    }

    const char* connectionString = "[Connection String]";
    const char* registrationId = "[Registration Id]";
    const char* endorsementKey = "[Endorsement Key]";
    const char* deviceId = "[Device Id]";

    PROVISIONING_SERVICE_CLIENT_HANDLE prov_sc;
    ATTESTATION_MECHANISM_HANDLE am_handle;
    INDIVIDUAL_ENROLLMENT_HANDLE ie_handle;

    printf("Starting Individual Enrollment sample...\n");

    /* Create a Provisioning Service Client Handle */
    if ((prov_sc = prov_sc_create_from_connection_string(connectionString)) == NULL)
    {
        printf("Failed calling prov_sc_create_from_connection_string");
        result = __FAILURE__;
    }

    /* Optionally set connection options */
    prov_sc_set_trace(prov_sc, TRACING_STATUS_ON);

    /* Create an Individual Enrollment structure */
    printf("Creating an Individual Enrollment structure...\n");

    if ((am_handle = attestationMechanism_createWithTpm(endorsementKey)) == NULL)
    {
        printf("Failed calling attestationMechanism_createWithTpm\n");
        result = __FAILURE__;
    }
    else if ((ie_handle = individualEnrollment_create(registrationId, am_handle)) == NULL)
    {
        printf("Failed calling individualEnrollment_create\n");
        result = __FAILURE__;
    }
    else if (individualEnrollment_setDeviceId(ie_handle, deviceId) != 0) //optional - don't call if you don't need it
    {
       printf("Failed calling individualEnrollment_setDeviceId\n");
       result = __FAILURE__;
    }

    /* Create the Individual Enrollment on the Provisioning Service */
    printf("Creating an Individual Enrollment on the Provisioning Service...\n");

    if (prov_sc_create_or_update_individual_enrollment(prov_sc, &ie_handle) != 0) //ie_handle is updated with info from the Provisioning Service (as if a get was performed)
    {
        printf("Failed calling prov_sc_create_or_update_individual_enrollment\n");
        result = __FAILURE__;
    }
    else
    {
        printf("Successfully created Individual Enrollment on the Provisioning Service\n");
    }

    /* Retrieve an Individual Enrollment on the Provisioning Service */
    printf("Retrieving an Individual Enrollment from the Provisioning Service...\n");

    if (prov_sc_get_individual_enrollment(prov_sc, registrationId, &ie_handle) != 0) //note that in this context, this is a useless call since create or update already updated ie_handle
    {
        printf("Failed calling prov_sc_get_individual_enrollment\n");
        result = __FAILURE__;
    }
    else
    {
        printf("Successfully retrieved Individual Enrollment from the Provisioning Service\n");
    }

    /* Delete an Individual Enrollment on the Provisioning Service */
    printf("Deleting an Individual Enrollment on the Provisioning Service...\n");

    if (prov_sc_delete_individual_enrollment(prov_sc, ie_handle) != 0)
    {
        printf("Failed calling prov_sc_delete_individual_enrollment\n");
        result = __FAILURE__;
    }
    else
    {
        printf("Successfully deleted Individual Enrollment from the Provisioning Service\n");
    }

    /* Clean up handles */
    individualEnrollment_destroy(ie_handle);
    prov_sc_destroy(prov_sc);



    return result;
}
