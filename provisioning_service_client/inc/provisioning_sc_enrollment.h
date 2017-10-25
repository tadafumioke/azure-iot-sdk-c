// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_ENROLLMENT_H
#define PROVISIONING_SC_ENROLLMENT_H

#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/macro_utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

    #define CERTIFICATE_TYPE_VALUES \
    CERTIFICATE_TYPE_NONE, \
    CERTIFICATE_TYPE_CLIENT, \
    CERTIFICATE_TYPE_SIGNING \

    //Note: CERTIFICATE_TYPE_NONE is invalid, indicating error
    DEFINE_ENUM(CERTIFICATE_TYPE, CERTIFICATE_TYPE_VALUES);

    #define PROVISIONING_STATUS_VALUES \
    PROVISIONING_STATUS_NONE, \
    PROVISIONING_STATUS_ENABLED, \
    PROVISIONING_STATUS_DISABLED \

    //Note: PROVISIONING_STATUS_NONE is invalid, indicating error
    DEFINE_ENUM(PROVISIONING_STATUS, PROVISIONING_STATUS_VALUES);

    typedef struct TPM_ATTESTATION_TAG
    {
        char* endorsement_key;
        //const char* storage_root_key;
    } TPM_ATTESTATION;

    typedef struct X509_CERTIFICATE_INFO_TAG
    {
        char* subject_name;
        char* sha1_thumbprint;
        char* sha256_thumbprint;
        char* issuer_name;
        char* not_before_utc;
        char* not_after_utc;
        char* serial_number;
        int version;
    } X509_CERTIFICATE_INFO;

    typedef struct X509_CERTIFICATE_WITH_INFO_TAG
    {
        char* certificate;
        X509_CERTIFICATE_INFO* info;
    } X509_CERTIFICATE_WITH_INFO;

    typedef struct X509_CERTIFICATES_TAG
    {
        X509_CERTIFICATE_WITH_INFO* primary;
        X509_CERTIFICATE_WITH_INFO* secondary;
    } X509_CERTIFICATES;

    typedef struct X509_ATTESTATION_TAG
    {
        CERTIFICATE_TYPE type;
        union {
            X509_CERTIFICATES* client_certificates;
            X509_CERTIFICATES* signing_certificates;
        } certificates;
    } X509_ATTESTATION;

    typedef struct ATTESTATION_MECHANISM_TAG
    {
        ATTESTATION_TYPE type;
        union {
            TPM_ATTESTATION* tpm;
            X509_ATTESTATION* x509;
        } attestation;
    } ATTESTATION_MECHANISM;

    typedef struct METADATA_TAG
    {
        char* last_updated;
        int last_updated_version;
    } METADATA;

    typedef struct TWIN_COLLECTION_TAG
    {
        int version;
        int count;
        METADATA* metadata;
    } TWIN_COLLECTION;

    typedef struct TWIN_STATE_TAG{
        TWIN_COLLECTION* tags;
        TWIN_COLLECTION* desired_properties;
    } TWIN_STATE;

    typedef struct DEVICE_REGISTRATION_STATUS_TAG
    {
        char* registration_id;
        char* created_date_time_utc;
        char* device_id;
        REGISTRATION_STATUS status;
        char* updated_date_time_utc;
        int error_code;
        char* error_message;
        char* etag;
    } DEVICE_REGISTRATION_STATUS;

    typedef struct INDIVIDUAL_ENROLLMENT_TAG
    {
        char* registration_id; //read only
        char* device_id;
        DEVICE_REGISTRATION_STATUS* registration_status;
        ATTESTATION_MECHANISM* attestation_mechanism;
        //TWIN_STATE* initial_twin_state;
        char* etag;
        PROVISIONING_STATUS provisioning_status;
        char* created_date_time_utc; //read only
        char* updated_date_time_utc; //read only
    } INDIVIDUAL_ENROLLMENT;

    typedef struct ENROLLMENT_GROUP_TAG
    {
        char* group_name;
        ATTESTATION_MECHANISM* attestation_mechanism;
        //TWIN_STATE* initial_twin_state;
        char* etag;
        PROVISIONING_STATUS provisioning_status;
        char* created_date_time_utc;
        char* updated_date_time_utc;
    } ENROLLMENT_GROUP;


    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT*, individualEnrollment_create, const char*, reg_id);

    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT*, individualEnrollment_create_tpm, const char*, reg_id, const char*, endorsement_key);

    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT*, individualEnrollment_create_x509, const char*, reg_id, const char*, primary_cert, const char*, secondary_cert);

    MOCKABLE_FUNCTION(, void, individualEnrollment_free, INDIVIDUAL_ENROLLMENT*, enrollment);

    MOCKABLE_FUNCTION(, int, individualEnrollment_setDeviceId, INDIVIDUAL_ENROLLMENT*, enrollment, const char*, device_id);

    MOCKABLE_FUNCTION(, int, individualEnrollment_setEtag, INDIVIDUAL_ENROLLMENT*, enrollment, const char*, etag);

    MOCKABLE_FUNCTION(, const char*, individualEnrollment_serialize, const INDIVIDUAL_ENROLLMENT*, enrollment);

    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT*, individualEnrollment_deserialize, const char*, json_string);

    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP*, enrollmentGroup_create, const char*, group_name);

    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP*, enrollmentGroup_create_x509, const char*, group_name, const char*, primary_cert, const char*, secondary_cert);

    MOCKABLE_FUNCTION(, void, enrollmentGroup_free, ENROLLMENT_GROUP*, enrollment);

    MOCKABLE_FUNCTION(, int, enrollmentGroup_setEtag, ENROLLMENT_GROUP*, enrollment, const char*, etag);

    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_serialize, const ENROLLMENT_GROUP*, enrollment);

    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP*, enrollmentGroup_deserialize, const char*, json_string);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_ENROLLMENT_H */
