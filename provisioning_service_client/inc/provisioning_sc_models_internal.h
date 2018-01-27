// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_MODEL_INTERNAL_H
#define PROVISIONING_SC_MODEL_INTERNAL_H

#include "azure_c_shared_utility/macro_utils.h"
#include "provisioning_sc_models.h"
#include "parson.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Internal serializers/deserializers */
MOCKABLE_FUNCTION(, ATTESTATION_MECHANISM_HANDLE, attestationMechanism_fromJson, JSON_Object*, root_object);
MOCKABLE_FUNCTION(, JSON_Value*, attestationMechanism_toJson, const ATTESTATION_MECHANISM_HANDLE, att_mech);
MOCKABLE_FUNCTION(, X509_ATTESTATION_HANDLE, x509Attestation_fromJson, JSON_Object*, root_object);
MOCKABLE_FUNCTION(, JSON_Value*, x509Attestation_toJson, const X509_ATTESTATION_HANDLE, x509_att);
MOCKABLE_FUNCTION(, TPM_ATTESTATION_HANDLE, tpmAttestation_fromJson, JSON_Object*, root_object);
MOCKABLE_FUNCTION(, JSON_Value*, tpmAttestation_toJson, const TPM_ATTESTATION_HANDLE, tpm_att);
MOCKABLE_FUNCTION(, DEVICE_REGISTRATION_STATE_HANDLE, deviceRegistrationState_fromJson, JSON_Object*, root_object);
MOCKABLE_FUNCTION(, INITIAL_TWIN_HANDLE, initialTwin_fromJson, JSON_Object*, root_object);
MOCKABLE_FUNCTION(, JSON_Value*, initialTwin_toJson, const INITIAL_TWIN_HANDLE, twin_state);

/* Memory allocation/deallocation */
MOCKABLE_FUNCTION(, TPM_ATTESTATION_HANDLE, tpmAttestation_create, const char*, endorsement_key, const char*, storage_root_key)
MOCKABLE_FUNCTION(, void, tpmAttestation_free, TPM_ATTESTATION_HANDLE, tpm_att);
MOCKABLE_FUNCTION(, X509_ATTESTATION_HANDLE, x509Attestation_create, X509_CERTIFICATE_TYPE, cert_type, const char*, primary_cert, const char*, secondary_cert)
MOCKABLE_FUNCTION(, void, x509Attestation_free, X509_ATTESTATION_HANDLE, x509_att);
MOCKABLE_FUNCTION(, void, deviceRegistrationState_free, DEVICE_REGISTRATION_STATE_HANDLE, device_reg_state);

/* Utility */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_MODEL_INTERNAL_H */