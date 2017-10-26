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
        result = __LINE__;
    }

    const char* connectionString = "[Connection String]";
    const char* registrationId = "[Registration Id]";
    const char* deviceId = "[Device Id]";
    const char* endorsementKey = "[Endorsement Key]";

    INDIVIDUAL_ENROLLMENT_HANDLE ie_handle;
    INDIVIDUAL_ENROLLMENT_HANDLE ie_handle2;

    ie_handle = individualEnrollment_create_tpm(registrationId, endorsementKey);
    individualEnrollment_setDeviceId(ie_handle, deviceId);

    PROVISIONING_SERVICE_CLIENT_HANDLE prov_sc = prov_sc_create_from_connection_string(connectionString);
    
    prov_sc_create_or_update_individual_enrollment(prov_sc, &ie_handle);

    prov_sc_get_individual_enrollment(prov_sc, registrationId, &ie_handle2);

    prov_sc_delete_individual_enrollment(prov_sc, ie_handle2);

    individualEnrollment_destroy(ie_handle);
    individualEnrollment_destroy(ie_handle2);
    prov_sc_destroy(prov_sc);

    return result;
}
