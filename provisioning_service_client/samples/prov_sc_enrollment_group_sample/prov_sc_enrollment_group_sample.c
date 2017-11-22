// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>

#include "azure_c_shared_utility/platform.h"

#include "provisioning_service_client.h"

int main()
{
    int result = 0;

    if (platform_init() != 0)
    {
        (void)printf("platform_init failed\r\n");
        result = __FAILURE__;
    }

    const char* connectionString = "[Connection String]";
    const char* groupId = "[Group Id]";
    const char* signingCertificate = "[Signing Certificate]";

    PROVISIONING_SERVICE_CLIENT_HANDLE prov_sc;
    ATTESTATION_MECHANISM_HANDLE am_handle;
    ENROLLMENT_GROUP_HANDLE eg_handle;

    printf("Starting Enrollment Group sample...\n");

    /* Create a Provisioning Service Client Handle */
    if ((prov_sc = prov_sc_create_from_connection_string(connectionString)) == NULL)
    {
        printf("Failed calling prov_sc_create_from_connection_string");
        result = __FAILURE__;
    }

    /* Optionally set connection options */
    prov_sc_set_trace(prov_sc, TRACING_STATUS_ON);

    /* Create an Enrollment Group structure */
    printf("Creating an Enrollment Group structure...\n");

    if ((am_handle = attestationMechanism_createWithX509SigningCert(signingCertificate, NULL)) == NULL)
    {
        printf("Failed calling attestationMechanism_createX509SigningCert\n");
        result = __FAILURE__;
    }
    else if ((eg_handle = enrollmentGroup_create(groupId, am_handle)) == NULL)
    {
        printf("Failed calling enrollmentGroup_create\n");
        result = __FAILURE__;
    }

    /* Create the Enrollment Group on the Provisioning Service */
    printf("Creating an Enrollment Group on the Provisioning Service...\n");

    if (prov_sc_create_or_update_enrollment_group(prov_sc, &eg_handle) != 0) //eg_handle is updated with info from the Provisioning Service (as if a get was performed)
    {
        printf("Failed calling prov_sc_create_or_update_enrollment_group\n");
        result = __FAILURE__;
    }
    else
    {
        printf("Successfully created Enrollment Group on the Provisioning Service\n");
    }

    /* Retrieve an Enrollment Group on the Provisioning Service */
    printf("Retrieving an Enrollment Group from the Provisioning Service...\n");

    if (prov_sc_get_enrollment_group(prov_sc, groupId, &eg_handle) != 0) //note that in this context, this is a useless call since create or update already updated eg_handle
    {
        printf("Failed calling prov_sc_get_enrollment_group\n");
        result = __FAILURE__;
    }
    else
    {
        printf("Successfully retrieved Enrollment Group from the Provisioning Service\n");
    }

    /* Delete an Enrollment Group on the Provisioning Service */
    printf("Deleting an Enrollment Group on the Provisioning Service...\n");

    if (prov_sc_delete_enrollment_group(prov_sc, eg_handle) != 0)
    {
        printf("Failed calling prov_sc_delete_enrollment_group\n");
        result = __FAILURE__;
    }
    else
    {
        printf("Successfully deleted Enrollment Group from the Provisioning Service\n");
    }

    /* Clean up handles */
    enrollmentGroup_destroy(eg_handle);
    prov_sc_destroy(prov_sc);

    return result;
}
