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

    //const char* connectionString = "[DPS? Connection String]";
    //const char* deviceId = "[Device Id]";
    //const char* registrationId = "[Registration Id]";
    //const char* endorsementKey = "[Endorsement Key]";

    const char* connectionString = "HostName=carter-dps.azure-devices-provisioning.net;SharedAccessKeyName=provisioningserviceowner;SharedAccessKey=Ig2GIrPBSlly3v/C4X+M6OHh2zUIt7zPf92j/zIGetM=";
    //const char* deviceId = "sample-device-1";
    //const char* registrationId = "registration-catinney";
    //const char* endorsementKey = "test-ek";

    //INDIVIDUAL_ENROLLMENT* enrollment;
    //INDIVIDUAL_ENROLLMENT* enrollment2;
    //enrollment = individualEnrollment_create_tpm(registrationId, endorsementKey);
    //individualEnrollment_setDeviceId(enrollment, deviceId);

    //PROVISIONING_SERVICE_CLIENT_HANDLE prov_sc = prov_sc_create_from_connection_string(connectionString);
    //prov_sc_create_or_update_individual_enrollment(prov_sc, &enrollment);

    //prov_sc_delete_individual_enrollment(prov_sc, enrollment);

    //prov_sc_create_or_update_individual_enrollment(prov_sc, &enrollment);
    //prov_sc_get_individual_enrollment(prov_sc, enrollment->registration_id, &enrollment2);
    //prov_sc_delete_individual_enrollment_by_param(prov_sc, enrollment->registration_id, "*");

    //individualEnrollment_free(enrollment);
    //prov_sc_destroy(prov_sc);

    ENROLLMENT_GROUP* eg;
    PROVISIONING_SERVICE_CLIENT_HANDLE prov_sc = prov_sc_create_from_connection_string(connectionString);

    result = prov_sc_get_enrollment_group(prov_sc, "created-in-ui", &eg);

    return result;
}
