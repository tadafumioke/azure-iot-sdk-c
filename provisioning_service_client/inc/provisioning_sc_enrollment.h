// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_ENROLLMENT_H
#define PROVISIONING_SC_ENROLLMENT_H

#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/macro_utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    typedef struct INDIVIDUAL_ENROLLMENT* INDIVIDUAL_ENROLLMENT_HANDLE;
    typedef struct ENROLLMENT_GROUP* ENROLLMENT_GROUP_HANDLE;
    typedef struct DEVICE_REGISTRATION_STATUS* DEVICE_REGISTRATION_STATUS_HANDLE;

    #define REGISTRATION_STATUS_VALUES \
            REGISTRATION_STATUS_NONE, \
            REGISTRATION_STATUS_UNASSIGNED, \
            REGISTRATION_STATUS_ASSIGNING, \
            REGISTRATION_STATUS_ASSIGNED, \
            REGISTRATION_STATUS_FAILED, \
            REGISTRATION_STATUS_DISABLED \

    //Note: REGISTRATION_STATUS_NONE is invalid, indicating error
    DEFINE_ENUM(REGISTRATION_STATUS, REGISTRATION_STATUS_VALUES);

    #define ATTESTATION_TYPE_VALUES \
            ATTESTATION_TYPE_NONE, \
            ATTESTATION_TYPE_TPM, \
            ATTESTATION_TYPE_X509 \

    //Note: ATTESTATION_TYPE_NONE is invalid, indicating error
    DEFINE_ENUM(ATTESTATION_TYPE, ATTESTATION_TYPE_VALUES);

    #define PROVISIONING_STATUS_VALUES \
            PROVISIONING_STATUS_NONE, \
            PROVISIONING_STATUS_ENABLED, \
            PROVISIONING_STATUS_DISABLED \

    //Note: PROVISIONING_STATUS_NONE is invalid, indicating error
    DEFINE_ENUM(PROVISIONING_STATUS, PROVISIONING_STATUS_VALUES);

    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_create_tpm, const char*, reg_id, const char*, endorsement_key);

    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_create_x509, const char*, reg_id, const char*, primary_cert, const char*, secondary_cert);

    MOCKABLE_FUNCTION(, void, individualEnrollment_destroy, INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    MOCKABLE_FUNCTION(, const char*, individualEnrollment_serialize, const INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_deserialize, const char*, json_string);

    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP_HANDLE, enrollmentGroup_create_x509, const char*, group_name, const char*, primary_cert, const char*, secondary_cert);

    MOCKABLE_FUNCTION(, void, enrollmentGroup_destroy, ENROLLMENT_GROUP_HANDLE, handle);

    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_serialize, const ENROLLMENT_GROUP_HANDLE, handle);

    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP_HANDLE, enrollmentGroup_deserialize, const char*, json_string);

    //accessors
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getRegistrationId, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setDeviceId, INDIVIDUAL_ENROLLMENT_HANDLE, handle, const char*, device_id);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getEtag, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setEtag, INDIVIDUAL_ENROLLMENT_HANDLE, handle, const char*, etag);

    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getGroupName, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getEtag, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, enrollmentGroup_setEtag, ENROLLMENT_GROUP_HANDLE, handle, const char*, etag);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_ENROLLMENT_H */
