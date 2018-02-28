// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>

#include "azure_c_shared_utility/platform.h"

#include "provisioning_service_client.h"

int main()
{
    int result = 0;

    const char* connectionString = "HostName=carter-dps-2.azure-devices-provisioning.net;SharedAccessKeyName=provisioningserviceowner;SharedAccessKey=uNqKlY3IR6fB+p78K9mck9PrDsF2uLYpt0r91Hq2gh0=";
    const char* endorsementKey = "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAEMAEAgAAAAAAAEAxsj2gUScTk1UjuioeTlfGYZrrimExB+bScH75adUMRIi2UOMxG1kw4y+9RW/IVoMl4e620VxZad0ARX2gUqVjYO7KPVt3dyKhZS3dkcvfBisBhP1XH9B33VqHG9SHnbnQXdBUaCgKAfxome8UmBKfe+naTsE5fkvjb/do3/dD6l4sGBwFCnKRdln4XpM03zLpoHFao8zOwt8l/uP3qUIxmCYv9A7m69Ms+5/pCkTu/rK4mRDsfhZ0QLfbzVI6zQFOKF/rwsfBtFeWlWtcuJMKlXdD8TXWElTzgh7JS4qhFzreL0c1mI0GCj+Aws0usZh7dLIVPnlgZcBhgy1SSDQMQ==";

    const char* registrationId1 = "id1";
    const char* registrationId2 = "id2";

    PROVISIONING_SERVICE_CLIENT_HANDLE prov_sc;

    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(endorsementKey, NULL);
    INDIVIDUAL_ENROLLMENT_HANDLE ie1 = individualEnrollment_create(registrationId1, am);
    INDIVIDUAL_ENROLLMENT_HANDLE ie2 = individualEnrollment_create(registrationId2, am);
    
    INDIVIDUAL_ENROLLMENT_HANDLE ie_list[2];
    ie_list[0] = ie1;
    ie_list[1] = ie2;

    prov_sc = prov_sc_create_from_connection_string(connectionString);
    prov_sc_set_trace(prov_sc, TRACING_STATUS_ON);

    PROVISIONING_BULK_OPERATION bulkop = { 0 };
    bulkop.mode = BULK_OP_CREATE;
    bulkop.enrollments = ie_list;
    bulkop.enrollments_num = 2;

    prov_sc_run_individual_enrollment_bulk_operation(prov_sc, &bulkop);

    return result;
}
