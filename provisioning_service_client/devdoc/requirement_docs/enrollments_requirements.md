# Enrollment Requirements

## Overview

This module is used to manage data related to Provisioning Service enrollments

## Exposed API - Structures, Handles, Enums

```c
typedef struct INDIVIDUAL_ENROLLMENT* INDIVIDUAL_ENROLLMENT_HANDLE;
typedef struct ENROLLMENT_GROUP* ENROLLMENT_GROUP_HANDLE;
typedef struct ATTESTATION_MECHANISM* ATTESTATION_MECHANISM_HANDLE;
typedef struct TPM_ATTESTATION* TPM_ATTESTATION_HANDLE;
typedef struct X509_ATTESTATION* X509_ATTESTATION_HANDLE;
typedef struct X509_CERTIFICATE_WITH_INFO* X509_CERTIFICATE_HANDLE;
typedef struct DEVICE_REGISTRATION_STATE* DEVICE_REGISTRATION_STATE_HANDLE;

#define REGISTRATION_STATE_VALUES \
        REGISTRATION_STATE_ERROR, \
        REGISTRATION_STATE_UNASSIGNED, \
        REGISTRATION_STATE_ASSIGNING, \
        REGISTRATION_STATE_ASSIGNED, \
        REGISTRATION_STATE_FAILED, \
        REGISTRATION_STATE_DISABLED \

//Note: REGISTRATION_STATE_ERROR is invalid, indicating error
DEFINE_ENUM(REGISTRATION_STATE, REGISTRATION_STATE_VALUES);

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
```

## Exposed API - Operation Functions

```c
//Attestation Mechanism
ATTESTATION_MECHANISM_HANDLE attestationMechanism_createWithTpm(const char* endorsement_key);
ATTESTATION_MECHANISM_HANDLE attestationMechanism_createWithX509ClientCert(const char* primary_cert, const char* secondary_cert);
ATTESTATION_MECHANISM_HANDLE attestationMechanism_createWithX509SigningCert(const char* primary_cert, const char* secondary_cert);
void attestationMechanism_destroy(ATTESTATION_MECHANISM_HANDLE att_handle);
TPM_ATTESTATION_HANDLE attestationMechanism_getTpmAttestation(ATTESTATION_MECHANISM_HANDLE att_handle);
X509_ATTESTATION_HANDLE attestationMechanism_getX509Attestation(ATTESTATION_MECHANISM_HANDLE att_handle);

//Individual Enrollment
INDIVIDUAL_ENROLLMENT_HANDLE individualEnrollment_create(const char* reg_id, ATTESTATION_MECHANISM_HANDLE att_handle);
void individualEnrollment_destroy(INDIVIDUAL_ENROLLMENT_HANDLE handle);

//Enrollment Group
ENROLLMENT_GROUP_HANDLE enrollmentGroup_create(const char* group_id, ATTESTATION_MECHANISM_HANDLE att_handle);
void enrollmentGroup_destroy(ENROLLMENT_GROUP_HANDLE handle);
```

## Exposed API - Accessor Functions

```c
//Attestation Mechanism
ATTESTATION_TYPE attestationMechanism_getType(ATTESTATION_MECHANISM_HANDLE att_handle);

//Individual Enrollment
const char* individualEnrollment_getRegistrationId(INDIVIDUAL_ENROLLMENT_HANDLE handle);
const char* individualEnrollment_getDeviceId(INDIVIDUAL_ENROLLMENT_HANDLE handle);
int individualEnrollment_setDeviceId(INDIVIDUAL_ENROLLMENT_HANDLE handle, const char* device_id);
DEVICE_REGISTRATION_STATE_HANDLE individualEnrollment_getDeviceRegistrationState(INDIVIDUAL_ENROLLMENT_HANDLE handle);
const char* individualEnrollment_getEtag(INDIVIDUAL_ENROLLMENT_HANDLE handle);
int individualEnrollment_setEtag(INDIVIDUAL_ENROLLMENT_HANDLE handle, const char* etag);
PROVISIONING_STATUS individualEnrollment_getProvisioningStatus(INDIVIDUAL_ENROLLMENT_HANDLE handle);
int individualEnrollment_setProvisioningStatus(INDIVIDUAL_ENROLLMENT_HANDLE handle, PROVISIONING_STATUS prov_status);
PROVISIONING_STATUS individualEnrollment_getProvisioningStatus(INDIVIDUAL_ENROLLMENT_HANDLE handle);
const char* individualEnrollment_getCreatedDateTime(INDIVIDUAL_ENROLLMENT_HANDLE handle);
const char* individualEnrollment_getUpdatedDateTime(INDIVIDUAL_ENROLLMENT_HANDLE handle);

//Enrollment Group
const char* enrollmentGroup_getGroupId(ENROLLMENT_GROUP_HANDLE handle);
const char* enrollmentGroup_getEtag(ENROLLMENT_GROUP_HANDLE handle);
int enrollmentGroup_setEtag(ENROLLMENT_GROUP_HANDLE handle, const char* etag);
PROVISIONING_STATUS enrollmentGroup_getProvisioningStatus(ENROLLMENT_GROUP_HANDLE handle);
int enrollmentGroup_setProvisioningStatus(ENROLLMENT_GROUP_HANDLE handle, PROVISIONING_STATUS prov_status);

//Device Registration State
const char* deviceRegistrationState_getRegistrationId(DEVICE_REGISTRATION_STATE_HANDLE handle);
const char* deviceRegistrationState_getCreatedDateTime(DEVICE_REGISTRATION_STATE_HANDLE handle);
const char* deviceRegistrationState_getDeviceId(DEVICE_REGISTRATION_STATE_HANDLE handle);
const char* deviceRegistrationState_getUpdatedDateTime(DEVICE_REGISTRATION_STATE_HANDLE handle);
int deviceRegistrationState_getErrorCode(DEVICE_REGISTRATION_STATE_HANDLE handle);
const char* deviceRegistrationState_getErrorMessage(DEVICE_REGISTRATION_STATE_HANDLE handle);
const char* deviceRegistrationState_getEtag(DEVICE_REGISTRATION_STATE_HANDLE handle);

//TPM Attestation
const char* tpmAttestation_getEndorsementKey(TPM_ATTESTATION_HANDLE handle);

//X509 Attestation
X509_CERTIFICATE_HANDLE x509Attestation_getPrimaryCertificate(X509_ATTESTATION_HANDLE handle);
X509_CERTIFICATE_HANDLE x509Attestation_getSecondaryCertificate(X509_ATTESTATION_HANDLE handle);
const char* x509Certificate_getSubjectName(X509_CERTIFICATE_HANDLE handle);
const char* x509Certificate_getSha1Thumbprint(X509_CERTIFICATE_HANDLE handle);
const char* x509Certificate_getSha256Thumbprint(X509_CERTIFICATE_HANDLE handle);
const char* x509Certificate_getIssuerName(X509_CERTIFICATE_HANDLE handle);
const char* x509Certificate_getNotBeforeUtc(X509_CERTIFICATE_HANDLE handle);
const char* x509Certificate_getNotAfterUtc(X509_CERTIFICATE_HANDLE handle);
const char* x509Certificate_getSerialNumber(X509_CERTIFICATE_HANDLE handle);
int x509Certificate_getVersion(X509_CERTIFICATE_HANDLE handle);
```

## attestationMechansim_createWithTpm

```c
ATTESTATION_MECHANISM_HANDLE attestationMechanism_createWithTpm(const char* endorsement_key);
```

**SRS_ENROLLMENTS_22_001: [** If `endorsement_key` is NULL, `attestationMechanism_createWithTpm` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_002: [** If allocating memory for the new attestation mechanism fails, `attestationMechanism_createWithTpm` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_003: [** If setting initial values within the new attestation mechanism fails, `attestationMechanism_createWithTpm` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_004: [** Upon successful creation of the new `ATTESTATION_MECHANISM_HANDLE`, `attestationMechanism_createWithTpm` shall return it **]**


## attestationMechanism_createWithX509ClientCert

```c
ATTESTATION_MECHANISM_HANDLE attestationMechanism_createWithX509ClientCert(const char* primary_cert, const char* secondary_cert);
```

**SRS_ENROLLMENTS_22_005: [** If `primary_cert` is NULL, `attestationMechanism_createWithX509ClientCert` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_006: [** If allocating memory for the new attestation mechanism fails, `attestationMechanism_createWithX509ClientCert` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_007: [** If setting initial values within the new attestation mechanism fails, `attestationMechanism_createWithX509ClientCert` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_008: [** Upon successful creation of the new `ATTESTATION_MECHANISM_HANDLE`, `attestationMechanism_createWithX509ClientCert` shall return it **]**

**SRS_ENROLLMENTS_22_040: [** The new `ATTESTATION_MECHANISM_HANDLE` will have one certificate if it was only given `primary_cert` and two certificates if it was also given `secondary_cert`**]**


## attestationMechanism_createWithX509SigningCert

```c
ATTESTATION_MECHANISM_HANDLE attestationMechanism_createWithX509SigningCert(const char* primary_cert, const char* secondary_cert);
```

**SRS_ENROLLMENTS_22_043: [** If `primary_cert` is NULL, `attestationMechanism_createWithX509SigningCert` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_044: [** If allocating memory for the new attestation mechanism fails, `attestationMechanism_createWithX509SigningCert` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_045: [** If setting initial values within the new attestation mechanism fails, `attestationMechanism_createWithX509SigningCert` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_046: [** Upon successful creation of the new `ATTESTATION_MECHANISM_HANDLE`, `attestationMechanism_createWithX509SigningCert` shall return it **]**

**SRS_ENROLLMENTS_22_047: [** The new `ATTESTATION_MECHANISM_HANDLE` will have one certificate if it was only given `primary_cert` and two certificates if it was also given `secondary_cert`**]**


## attestationMechanism_destroy

```c
void attestationMechanism_destroy(ATTESTATION_MECHANISM_HANDLE att_handle);
```

**SRS_ENROLLMENTS_22_009: [** `attestationMechanism_destroy` shall free all memory contained within `att_handle` **]**


## attestationMechanism_getTpmAttestation

```c
TPM_ATTESTATION_HANDLE attestationMechanism_getTpmAttestation(ATTESTATION_MECHANISM_HANDLE att_handle);
```

**SRS_ENROLLMENTS_22_010: [** If `att_handle` is NULL, `attestationMechanism_getTpmAttestation` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_011: [** If the attestation type of `att_handle` is not TPM, `attestationMechanism_getTpmAttestation` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_012: [** Upon success, `attestationMechanism_getTpmAttestation` shall return a handle for the TPM Attestation contained in `att_handle` **]**


## attestationMechanism_getX509Attestation

```c
X509_ATTESTATION_HANDLE attestationMechanism_getX509Attestation(ATTESTATION_MECHANISM_HANDLE att_handle);
```

**SRS_ENROLLMENTS_22_013: [** If `att_handle` is NULL, `attestationMechanism_getX509Attestation` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_014: [** If the attestation type of `att_handle` is not X509, `attestationMechanism_getX509Attestation` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_015: [** Upon success `attestationMechanism_getTpmAttestation` shall return a handle for the X509 Attestation contained in `att_handle` **]**


## individualEnrollment_create

```c
INDIVIDUAL_ENROLLMENT_HANDLE individualEnrollment_create(const char* reg_id, ATTESTATION_MECHANISM_HANDLE att_handle);
```

**SRS_ENROLLMENTS_22_016: [** If `reg_id` is NULL, `individualEnrollment_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_017: [** If `att_handle` is NULL, `individualEnrollment_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_018: [** If allocating memory for the new individual enrollment fails, `individualEnrollment_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_019: [** If setting initial values within the new individual enrollment fails, `individualEnrollment_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_020: [** Upon success, `individualEnrollment_create` shall return a handle for the new individual enrollment **]**


## individualEnrollment_destroy

```c
void individualEnrollment_destroy(INDIVIDUAL_ENROLLMENT_HANDLE handle);
```

**SRS_ENROLLMENTS_22_021: [** `individualEnrollment_destroy` shall free all memory contained within `handle` **]**


## enrollmentGroup_create

```c
ENROLLMENT_GROUP_HANDLE enrollmentGroup_create(const char* group_id, ATTESTATION_MECHANISM_HANDLE att_handle);
```

**SRS_ENROLLMENTS_22_022: [** If `group_id` is NULL, `enrollmentGroup_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_023: [** If `att_handle` is NULL, `enrollmentGroup_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_041: [** If `att_handle` has an invalid Attestation Type (e.g. TPM), `enrollmentGroup_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_024: [** If allocating memory for the new enrollment group fails, `enrollmentGroup_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_025: [** If setting initial values within the new enrollment group fails, `enrollmentGroup_create` shall fail and return NULL **]**

**SRS_ENROLLMENTS_22_026: [** Upon success, `enrollmentGroup_create` shall return a handle for the new enrollment group **]**


## enrollmentGroup_destroy

```c
void enrollmentGroup_destroy(ENROLLMENT_GROUP_HANDLE handle);
```

**SRS_ENROLLMENTS_22_027: [** `enrollmentGroup_destroy` shall free all memory contained within `handle` **]**


## Generic "Get" Function

```c
<RETURN_TYPE> <STRUCTURE_TYPE>_get<PROPERTY>(<HANDLE_TYPE> handle);
```

**SRS_ENROLLMENTS_22_029: [** When <RETURN_TYPE> is `const char*`, the default return value is NULL **]**

**SRS_ENROLLMENTS_22_030: [** When <RETURN_TYPE> is `int`, the default return value is 0 **]**

**SRS_ENROLLMENTS_22_031: [** When <RETURN_TYPE> is some <HANDLE_TYPE>, the default return value is NULL **]**

**SRS_ENROLLMENTS_22_032: [** When <RETURN_TYPE> is `PROVISIONING_STATUS`, the default return value is `PROVISIONING_STATUS_NONE` **]**

**SRS_ENROLLMENTS_22_033: [** When <RETURN_TYPE> is `REGISTRATION_STATUS`, the default return value is `REGISTRATION_STATUS_ERROR` **]**

**SRS_ENROLLMENTS_22_042: [** When <RETURN_TYPE> is `ATTESTATION_TYPE`, the default return value is `ATTESTATION_TYPE_NONE` **]**

**SRS_ENROLLMENTS_22_028: [** If `handle` is NULL, the function shall return the default return value of <RETURN_TYPE> **]**

**SRS_ENROLLMENTS_22_034: [** Otherwise the function shall return the specified property, which may or may not be the same as the default value **]**


## Generic "Set" Function

```c
int <STRUCTURE_TYPE>_set<PROPERTY>(<HANDLE_TYPE> handle, <PROPERTY_TYPE> <PROPERTY_VALUE>)
```

**SRS_ENROLLMENTS_22_035: [** If `handle` is NULL, the function shall fail and return a non-zero value **]**

**SRS_ENROLLMENTS_22_036: [** If `<PROPERTY_VALUE>` is NULL, the function shall fail and return a non-zero value **]**

**SRS_ENROLLMENTS_22_037: [** The `<PROPERTY>` of `handle` shall be set to the value of `<PROPERTY_VALUE>` **]**

**SRS_ENROLLMENTS_22_038: [** If setting the value of `<PROPERTY>` fails, the function shall fail and return a non-zero value **]**

**SRS_ENROLLMENTS_22_039: [** On success, the function shall return 0 **]**

