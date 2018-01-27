// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_TPM_ATTESTATION_H
#define PROVISIONING_SC_TPM_ATTESTATION_H

#include "azure_c_shared_utility/macro_utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct TPM_ATTESTATION_TAG* TPM_ATTESTATION_HANDLE;

/* TPM Attestation Accessor Functions */
MOCKABLE_FUNCTION(, const char*, tpmAttestation_getEndorsementKey, TPM_ATTESTATION_HANDLE, handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_TPM_ATTESTATION_H */