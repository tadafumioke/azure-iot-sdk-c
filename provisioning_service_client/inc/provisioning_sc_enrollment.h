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
    typedef struct ATTESTATION_MECHANISM* ATTESTATION_MECHANISM_HANDLE;
    typedef struct TPM_ATTESTATION* TPM_ATTESTATION_HANDLE;
    typedef struct X509_ATTESTATION* X509_ATTESTATION_HANDLE;
    typedef struct X509_CERTIFICATE_WITH_INFO* X509_CERTIFICATE_HANDLE;
    typedef struct DEVICE_REGISTRATION_STATE* DEVICE_REGISTRATION_STATE_HANDLE;

    /** @brief  Enums representing types and states for values within handles
    */
    #define REGISTRATION_STATUS_VALUES \
            REGISTRATION_STATUS_ERROR, \
            REGISTRATION_STATUS_UNASSIGNED, \
            REGISTRATION_STATUS_ASSIGNING, \
            REGISTRATION_STATUS_ASSIGNED, \
            REGISTRATION_STATUS_FAILED, \
            REGISTRATION_STATUS_DISABLED \

    //Note: REGISTRATION_STATUS_ERROR is invalid, indicating error
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


    /* OPERATION FUNCTIONS
    *
    * Use these functions to create and destroy handles
    *
    * PLEASE NOTE: Attempting to free any of the returned handles manually will result in unexpected behaviour and memory leakage.
    * Please ONLY use given "destroy" functions to free handles when you are done with them.
    */

    /* Attestation Mechanism Operation Functions */

    /** @brief  Creates an Attestation Mechanism handle that uses a TPM Attestation for use in consequent APIs.
    *
    * @param    endorsement_key     An endorsement key to use with the TPM.
    *
    * @return   A non NULL handle representing an Attestation Mechanism using a TPM Attestation, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, ATTESTATION_MECHANISM_HANDLE, attestationMechanism_createWithTpm, const char*, endorsement_key);

    /** @brief  Creates an Attestation Mechanism handle that uses an x509 Attestation for use in consequent APIs.
    *
    * @param    primary_cert        A primary certificate for use with the x509.
    * @param    secondary_cert      A secondary certificate for use with the x509 (optional - if not using two certs, pass NULL).
    *
    * @return   A non NULL handle representing an Attestation Mechanism using an X509 Attestation, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, ATTESTATION_MECHANISM_HANDLE, attestationMechanism_createWithX509, const char*, primary_cert, const char*, secondary_cert);

    /** @brief  Destroys an Attestation Mechanism handle, freeing all allocated memory. Please note that this also includes any memory
    *           in more specific handles generated from the handle (e.g. TPM_ATTESTATION_HANDLE). Please note further that this will also
    *           cause any Enrollment that the Attestation Mechanism has been attached to to have unexpected behvaiours. Do not use this function
    *           unless the attestation mechanism is unattached.
    *
    * @param    att_handle          The handle of the Attestation Mechanism
    */
    MOCKABLE_FUNCTION(, void, attestationMechanism_destroy, ATTESTATION_MECHANISM_HANDLE, att_handle);

    /** @brief Gives a TPM Attestation handle for accessing TPM Attestation values.
    *
    * @param    att_handle      The Attestation Mechanism handle to retrieve the TPM Attestation from.
    *
    * @return   A non-NULL handle representing a TPM Attestation, and NULL on failure - including if the Attestation Mechanism does not have a TPM Attestation.
    */
    MOCKABLE_FUNCTION(, TPM_ATTESTATION_HANDLE, attestationMechanism_getTpmAttestation, ATTESTATION_MECHANISM_HANDLE, att_handle);

    /** @brief Gives an x509 Attestation handle for accessing X509 Attestation values.
    *
    * @param    att_handle      The Attestation Mechanism to retrieve the x509 Attestation from.
    *
    * @return   A non-NULL handle representing an x509 Attestation, and NULL on failure - including if the Attestation Mechanism does not have an x509 Attestation.
    */
    MOCKABLE_FUNCTION(, X509_ATTESTATION_HANDLE, attestationMechanism_getX509Attestation, ATTESTATION_MECHANISM_HANDLE, att_handle);


    /* Enrollment Operation Functions */

    /** @brief  Creates an Individual Enrollment handle with a TPM Attestation for use in consequent APIs.
    *
    * @param    reg_id              A registration id for the Individual Enrollment.
    * @param    att_handle          The handle for the Attestation Mechanism to be used by the Individual Enrollment
    *
    * @return   A non-NULL handle representing an Individual Enrollment for use with the Provisioning Service, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, INDIVIDUAL_ENROLLMENT_HANDLE, individualEnrollment_create, const char*, reg_id, ATTESTATION_MECHANISM_HANDLE, att_handle);

    /** @brief  Destroys an Individual Enrollment handle, freeing all associated memory. Please note that this also includes the attestation mechanism
    *           that was given in the constructor.
    *
    * @param    handle      A handle for the Individual Enrollment to be destroyed.
    */
    MOCKABLE_FUNCTION(, void, individualEnrollment_destroy, INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    /** @brief  Creates an Enrollment Group handle with an X509 Attestation for use in consequent APIs.
    *
    * @param    group_id        A group name for the Enrollment Group.
    * @param    att_handle      The handle for the Attestation Mechanism to be used by the Enrollment Group. Note: only valid with type: X509
    *
    * @return   A non-NULL handle representing an Enrollment Group for use with the Provisioning Service, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, ENROLLMENT_GROUP_HANDLE, enrollmentGroup_create, const char*, group_id, ATTESTATION_MECHANISM_HANDLE, att_handle);

    /** @brief  Destorys an Enrollment Group handle, freeing all associated memory. Please note that this also includes the attestation mechanism
    *           that was given in the constructor.
    *
    * @param    handle      A handle for the Enrollment Group to be destroyed.
    */
    MOCKABLE_FUNCTION(, void, enrollmentGroup_destroy, ENROLLMENT_GROUP_HANDLE, handle);


    /* ACCESSOR FUNCTIONS
    *
    * Use these to retrieve and access properties of handles.
    *
    * PLEASE NOTE WELL: If given an invalid handle, "get" functions will return a default value (NULL, 0, etc.).
    * However, these values are not indicative of error - a handle may have a valid property with a value of NULL, 0, etc.
    * Please ensure that you only pass valid handles to "get" accessor functions to avoid unexpected behaviour.
    *
    * The "set" accessor functions on the other hand, will return a non-zero integer in the event of failure.
    */

    /* Attestation Mechanism Accessor Functions */
    MOCKABLE_FUNCTION(, ATTESTATION_TYPE, attestationMechanism_getType, ATTESTATION_MECHANISM_HANDLE, att_handle);

    /* Individual Enrollment Accessor Functions */
    MOCKABLE_FUNCTION(, ATTESTATION_MECHANISM_HANDLE, individualEnrollment_getAttestationMechanism, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setAttestationMechanism, INDIVIDUAL_ENROLLMENT_HANDLE, ie_handle, ATTESTATION_MECHANISM_HANDLE, am_handle);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getRegistrationId, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getDeviceId, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setDeviceId, INDIVIDUAL_ENROLLMENT_HANDLE, handle, const char*, device_id);
    MOCKABLE_FUNCTION(, DEVICE_REGISTRATION_STATE_HANDLE, individualEnrollment_getDeviceRegistrationState, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getEtag, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setEtag, INDIVIDUAL_ENROLLMENT_HANDLE, handle, const char*, etag);
    MOCKABLE_FUNCTION(, PROVISIONING_STATUS, individualEnrollment_getProvisioningStatus, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, individualEnrollment_setProvisioningStatus, INDIVIDUAL_ENROLLMENT_HANDLE, handle, PROVISIONING_STATUS, prov_status);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getCreatedDateTime, INDIVIDUAL_ENROLLMENT_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, individualEnrollment_getUpdatedDateTime, INDIVIDUAL_ENROLLMENT_HANDLE, handle);

    /* Enrollment Group Accessor Functions */
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getGroupId, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getEtag, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, enrollmentGroup_setEtag, ENROLLMENT_GROUP_HANDLE, handle, const char*, etag);
    MOCKABLE_FUNCTION(, PROVISIONING_STATUS, enrollmentGroup_getProvisioningStatus, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, enrollmentGroup_setProvisioningStatus, ENROLLMENT_GROUP_HANDLE, handle, PROVISIONING_STATUS, prov_status);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getCreatedDateTime, ENROLLMENT_GROUP_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, enrollmentGroup_getUpdatedDateTime, ENROLLMENT_GROUP_HANDLE, handle);

    /* Device Registration Status Accessor Functions */
    MOCKABLE_FUNCTION(, const char*, deviceRegistrationState_getRegistrationId, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, deviceRegistrationState_getCreatedDateTime, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, deviceRegistrationState_getDeviceId, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, REGISTRATION_STATUS, deviceRegistrationState_getRegistrationStatus, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, deviceRegistrationState_getUpdatedDateTime, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, deviceRegistrationState_getErrorCode, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, deviceRegistrationState_getErrorMessage, DEVICE_REGISTRATION_STATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, deviceRegistrationState_getEtag, DEVICE_REGISTRATION_STATE_HANDLE, handle);

    /* TPM Attestation Accessor Functions */
    MOCKABLE_FUNCTION(, const char*, tpmAttestation_getEndorsementKey, TPM_ATTESTATION_HANDLE, handle);

    /* X509 Attestation Accessor Functions */
    MOCKABLE_FUNCTION(, X509_CERTIFICATE_HANDLE, x509Attestation_getPrimaryCertificate, X509_ATTESTATION_HANDLE, handle);
    MOCKABLE_FUNCTION(, X509_CERTIFICATE_HANDLE, x509Attestation_getSecondaryCertificate, X509_ATTESTATION_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getSubjectName, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getSha1Thumbprint, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getSha256Thumbprint, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getIssuerName, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getNotBeforeUtc, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getNotAfterUtc, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, const char*, x509Certificate_getSerialNumber, X509_CERTIFICATE_HANDLE, handle);
    MOCKABLE_FUNCTION(, int, x509Certificate_getVersion, X509_CERTIFICATE_HANDLE, handle);
    


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_ENROLLMENT_H */
