// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_X509_ATTESTATION_H
#define PROVISIONING_SC_X509_ATTESTATION_H

#include "azure_c_shared_utility/macro_utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define X509_CERTIFICATE_TYPE_VALUES \
            X509_CERTIFICATE_TYPE_NONE, \
            X509_CERTIFICATE_TYPE_CLIENT, \
            X509_CERTIFICATE_TYPE_SIGNING, \
            X509_CERTIFICATE_TYPE_CA_REFERENCES \
//Note: X509_CERTIFICATE_TYPE_NONE is invalid, indicating error
DEFINE_ENUM(X509_CERTIFICATE_TYPE, X509_CERTIFICATE_TYPE_VALUES);

typedef struct X509_ATTESTATION_TAG* X509_ATTESTATION_HANDLE;
typedef struct X509_CERTIFICATE_WITH_INFO_TAG* X509_CERTIFICATE_HANDLE;

/* X509 Attestation Accessor Functions */
MOCKABLE_FUNCTION(, X509_CERTIFICATE_TYPE, x509Attestation_getCertificateType, X509_ATTESTATION_HANDLE, handle);
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

#endif /* PROVISIONING_SC_X509_ATTESTATION_H */