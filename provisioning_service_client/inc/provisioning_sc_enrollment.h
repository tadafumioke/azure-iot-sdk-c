// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_ENROLLMENT_H
#define PROVISIONING_SC_ENROLLMENT_H

#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/macro_utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    /** @brief  Handles to hide structs and use them in consequent APIs
    */
    typedef struct INDIVIDUAL_ENROLLMENT* INDIVIDUAL_ENROLLMENT_HANDLE;
    typedef struct ENROLLMENT_GROUP* ENROLLMENT_GROUP_HANDLE;
    typedef struct TPM_ATTESTATION* TPM_ATTESTATION_HANDLE;
    typedef struct X509_ATTESTATION* X509_ATTESTATION_HANDLE;
    typedef struct DEVICE_REGISTRATION_STATUS* DEVICE_REGISTRATION_STATUS_HANDLE;

    /** @brief  Enums representing types and states for values within handles
    */
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

    /* Enrollment Operation Functions */

    /** @brief  Creates an Individual Enrollment handle with a TPM Attestation for use in consequent APIs.
    *
    * @param    reg_id              A registration id for the Individual Enrollment.
    * @param    endorsement_key     An endorsement key for the TPM.
    *
    * @return   A non-NULL handle representing an Individual Enrollment for use with the Provisioning Service, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_create_tpm, const char*, reg_id, const char*, endorsement_key);

    /** @brief  Creates an Individual Enrollment handle with an X509 Attestation for use in consequent APIs.
    *
    * @param    reg_id              A registration id for the Individual Enrollment.
    * @param    primary_cert        An X509 certificate.
    * @param    secondary_cert      An optional secondary X509 certificate (pass NULL if not using).
    *
    * @return   A non-NULL handle representing an Individual Enrollment for use with Provisioning Service, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_create_x509, const char*, reg_id, const char*, primary_cert, const char*, secondary_cert);

    /** @brief  Destroys an Individual Enrollment handle, freeing all associated memory.
    *
    * @param    handle      A handle for the Individual Enrollment to be destroyed.
    */
    MOCKABLE_FUNCTION(, void, individualEnrollment_destroy, INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    /** @brief  Serializes an Individual Enrollment into a JSON String.
    *
    * @param    handle      A handle for the Individual Enrollment to be serialized.
    *
    * @return   A non-NULL string containing the serialized JSON String, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_serialize, const INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    /** @brief  Deserializes a JSON String representation of an Individual Enrollment.
    *
    * @param    json_string     A JSON String representing an Individual Enrollment.
    *
    * @return   A non-NULL handle representing an Individual Enrollment, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_deserialize, const char*, json_string);

    /** @brief  Creates an Enrollment Group handle with an X509 Attestation for use in consequent APIs.
    *
    * @param    group_name          A group name for the Enrollment Group.
    * @param    primary_cert        An X509 certificate.
    * @param    secondary_cert      An optional secondary X509 certificate (pass NULL if not using).
    *
    * @return   A non-NULL handle representing an Enrollment Group for use with the Provisioning Service, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP_HANDLE, enrollmentGroup_create_x509, const char*, group_name, const char*, primary_cert, const char*, secondary_cert);

    /** @brief  Destorys an Enrollment Group handle, freeing all associated memory.
    *
    * @param    handle      A handle for the Enrollment Group to be destroyed.
    */
    MOCKABLE_FUNCTION(, void, enrollmentGroup_destroy, ENROLLMENT_GROUP_HANDLE, handle);

    /** @brief  Serializes an Enrollment Group into a JSON String.
    *
    * @param    handle      A handle for the Enrollment Group to be serialized.
    *
    * @return   A non-NULL string containing the serialized JSON String, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_serialize, const ENROLLMENT_GROUP_HANDLE, handle);

    /** @brief  Deserializes a JSON String representation of an Enrollment Group.
    *
    * @param    json_string     A JSON String representing an Enrollment Group.
    *
    * @return   A non-NULL handle representing an Enrollment Group, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP_HANDLE, enrollmentGroup_deserialize, const char*, json_string);

    /* Individual Enrollment Accessor Functions */
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getRegistrationId, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getDeviceId, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setDeviceId, INDIVIDUAL_ENROLLMENT_HANDLE, handle, const char*, device_id);
    MOCKABLE_FUNCTION(, DEVICE_REGISTRATION_STATUS_HANDLE, individualEnrollment_getDeviceRegistrationStatus, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, ATTESTATION_TYPE, individualEnrollment_getAttestationType, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setAttestationType, INDIVIDUAL_ENROLLMENT_HANDLE, handle, ATTESTATION_TYPE, type);
    MOCKABLE_FUNCTION(, TPM_ATTESTATION_HANDLE, individualEnrollment_getTpmAttestation, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setTpmAttestation, INDIVIDUAL_ENROLLMENT_HANDLE, handle, TPM_ATTESTATION_HANDLE, attestation);
    MOCKABLE_FUNCTION(, X509_ATTESTATION_HANDLE, individualEnrollment_getX509Attestation, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setX509Attestation, INDIVIDUAL_ENROLLMENT_HANDLE, handle, X509_ATTESTATION_HANDLE, attestation);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getEtag, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setEtag, INDIVIDUAL_ENROLLMENT_HANDLE, handle, const char*, etag);
    MOCKABLE_FUNCTION(, PROVISIONING_STATUS, individualEnrollment_getProvisioningStatus, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setProvisioningStatus, INDIVIDUAL_ENROLLMENT_HANDLE, handle, PROVISIONING_STATUS, prov_status);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getCreatedDateTime, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getUpdatedDateTime, INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    /* Enrollment Group Accessor Functions */
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getGroupName, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, X509_ATTESTATION_HANDLE, enrollmentGroup_getX509Attestation, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, enrollmentGroup_setX509Attestation, ENROLLMENT_GROUP_HANDLE, handle, X509_ATTESTATION_HANDLE, attestation);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getEtag, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, enrollmentGroup_setEtag, ENROLLMENT_GROUP_HANDLE, handle, const char*, etag);
    MOCKABLE_FUNCTION(, PROVISIONING_STATUS, enrollmentGroup_getProvisioningStatus, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, enrollmentGroup_setProvisioningStatus, ENROLLMENT_GROUP_HANDLE, handle, PROVISIONING_STATUS, prov_status);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getCreatedDateTime, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getUpdatedDateTime, ENROLLMENT_GROUP_HANDLE, handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_ENROLLMENT_H */
