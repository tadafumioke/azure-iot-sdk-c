// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>  

#include "azure_c_shared_utility/xlogging.h"

#include "provisioning_sc_enrollment.h"
#include "parson.h"

#define UNREFERENCED_PARAMETER(x) x

DEFINE_ENUM_STRINGS(ATTESTATION_TYPE, ATTESTATION_TYPE_VALUES)
DEFINE_ENUM_STRINGS(PROVISIONING_STATUS, PROVISIONING_STATUS_VALUES)

static void* ENROLLMENT_JSON_DEFUALT_VALUE_NULL = NULL;

static const char* ATTESTATION_TYPE_JSON_VALUE_TPM = "tpm";
static const char* ATTESTATION_TYPE_JSON_VALUE_X509 = "x509";

static const char* PROVISIONING_STATUS_JSON_VALUE_ENABLED = "enabled";
static const char* PROVISIONING_STATUS_JSON_VALUE_DISABLED = "disabled";

static const char* REGISTRATION_STATUS_JSON_VALUE_UNASSIGNED = "unassigned";
static const char* REGISTRATION_STATUS_JSON_VALUE_ASSIGNING = "assigning";
static const char* REGISTRATION_STATUS_JSON_VALUE_ASSIGNED = "assigned";
static const char* REGISTRATION_STATUS_JSON_VALUE_FAILED = "failed";
static const char* REGISTRATION_STATUS_JSON_VALUE_DISABLED = "disabled";

static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_ID = "registrationId";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_DEVICE_ID = "deviceId";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_STATUS = "registrationStatus";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_ATTESTATION = "attestation";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_ETAG = "etag";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_PROV_STATUS = "provisioningStatus";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_CREATED_TIME = "createdDateTimeUtc";
static const char* INDIVIDUAL_ENROLLMENT_JSON_KEY_UPDATED_TIME = "lastUpdatedDateTimeUtc";

static const char* ENROLLMENT_GROUP_JSON_KEY_GROUP_NAME = "enrollmentGroupId"; //this should be changing soon
static const char* ENROLLMENT_GROUP_JSON_KEY_ATTESTATION = "attestation";
static const char* ENROLLMENT_GROUP_JSON_KEY_ETAG = "etag";
static const char* ENROLLMENT_GROUP_JSON_KEY_PROV_STATUS = "provisioningStatus";
static const char* ENROLLMENT_GROUP_JSON_KEY_CREATED_TIME = "createdDateTimeUtc";
static const char* ENROLLMENT_GROUP_JSON_KEY_UPDATED_TIME = "lastUpdatedDateTimeUtc";

static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_REG_ID = "registrationId";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_CREATED_TIME = "createdDateTimeUtc";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_DEVICE_ID = "deviceId";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_REG_STATUS = "status";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_UPDATED_TIME = "lastUpdatedDateTimeUtc";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_ERROR_CODE = "errorCode";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_ERROR_MSG = "errorMessage";
static const char* DEVICE_REGISTRATION_STATUS_JSON_KEY_ETAG = "etag";

static const char* ATTESTATION_MECHANISM_JSON_KEY_TYPE = "type";
static const char* ATTESTATION_MECHANISM_JSON_KEY_TPM = "tpm";
static const char* ATTESTATION_MECHANISM_JSON_KEY_X509 = "x509";

static const char* TPM_ATTESTATION_JSON_KEY_EK = "endorsementKey";

static const char* X509_ATTESTATION_JSON_KEY_CLIENT_CERTS = "clientCertificates";
static const char* X509_ATTESTATION_JSON_KEY_SIGNING_CERTS = "signingCertificates";

static const char* X509_CERTIFICATES_JSON_KEY_PRIMARY = "primary";
static const char* X509_CERTIFICATES_JSON_KEY_SECONDARY = "secondary";

static const char* X509_CERTIFICATE_WITH_INFO_JSON_KEY_CERTIFICATE = "certificate";
static const char* X509_CERTIFICATE_WITH_INFO_JSON_KEY_INFO = "info";

static const char* X509_CERTIFICATE_INFO_JSON_KEY_SUBJECT_NAME = "subjectName";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_SHA1 = "sha1Thumbprint";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_SHA256 = "sha256Thumbprint";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_ISSUER = "issuerName";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_NOT_BEFORE = "notBeforeUtc";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_NOT_AFTER = "notAfterUtc";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_SERIAL_NO = "serialNumber";
static const char* X509_CERTIFICATE_INFO_JSON_KEY_VERSION = "version";


static int copy_string(char** dest, const char* string)
{
    int result = 0;
    char* new_copy = NULL;

    if (string != NULL)
    {
        size_t len = strlen(string);
        if ((new_copy = malloc(len + 1)) == NULL)
        {
            LogError("Allocating string for value '%s' failed");
            result = __LINE__;
        }
        else if ((strncpy(new_copy, string, len + 1)) == NULL)
        {
            LogError("Failed to copy value '%s'");
            free(new_copy);
            new_copy = NULL;
            result = __LINE__;
        }
    }

    *dest = new_copy;
    return result;
}

static int copy_json_string_field(char** dest, JSON_Object* root_object, const char* json_key)
{
    int result = 0;

    const char* string = json_object_get_string(root_object, json_key);
    if (string != NULL)
        if (copy_string(dest, string) != 0)
            result = __LINE__;

    return result;
}

static const REGISTRATION_STATUS registrationStatus_fromJson(const char* str_rep)
{
    REGISTRATION_STATUS new_status = REGISTRATION_STATUS_NONE;

    if (str_rep != NULL)
    {
        if (strcmp(str_rep, REGISTRATION_STATUS_JSON_VALUE_UNASSIGNED) == 0)
            new_status = REGISTRATION_STATUS_UNASSIGNED;
        else if (strcmp(str_rep, REGISTRATION_STATUS_JSON_VALUE_ASSIGNING) == 0)
            new_status = REGISTRATION_STATUS_ASSIGNING;
        else if (strcmp(str_rep, REGISTRATION_STATUS_JSON_VALUE_ASSIGNED) == 0)
            new_status = REGISTRATION_STATUS_ASSIGNED;
        else if (strcmp(str_rep, REGISTRATION_STATUS_JSON_VALUE_FAILED) == 0)
            new_status = REGISTRATION_STATUS_FAILED;
        else if (strcmp(str_rep, REGISTRATION_STATUS_JSON_VALUE_DISABLED) == 0)
            new_status = REGISTRATION_STATUS_DISABLED;
        else
            LogError("Could not convert '%s' from JSON", str_rep);
    }

    return new_status;
}

static const char* provisioningStatus_toJson(const PROVISIONING_STATUS status)
{
    const char* result = NULL;
    if (status == PROVISIONING_STATUS_ENABLED)
        result = PROVISIONING_STATUS_JSON_VALUE_ENABLED;
    else if (status == PROVISIONING_STATUS_DISABLED)
        result = PROVISIONING_STATUS_JSON_VALUE_DISABLED;
    else
        LogError("Could not convert '%s' to JSON", ENUM_TO_STRING(PROVISIONING_STATUS, status));

    return result;
}

static const PROVISIONING_STATUS provisioningStatus_fromJson(const char* str_rep)
{
    PROVISIONING_STATUS new_status = PROVISIONING_STATUS_NONE;

    if (str_rep != NULL)
    {
        if (strcmp(str_rep, PROVISIONING_STATUS_JSON_VALUE_ENABLED) == 0)
            new_status = PROVISIONING_STATUS_ENABLED;
        else if (strcmp(str_rep, PROVISIONING_STATUS_JSON_VALUE_DISABLED) == 0)
            new_status = PROVISIONING_STATUS_DISABLED;
        else
            LogError("Could not convert '%s' from JSON", str_rep);
    }

    return new_status;
}

static const char* attestationType_toJson(const ATTESTATION_TYPE type)
{
    const char* result = NULL;
    if (type == ATTESTATION_TYPE_TPM)
        result = ATTESTATION_TYPE_JSON_VALUE_TPM;
    else if (type == ATTESTATION_TYPE_X509)
        result = ATTESTATION_TYPE_JSON_VALUE_X509;
    else
        LogError("Could not convert '%s' to JSON", ENUM_TO_STRING(ATTESTATION_TYPE, type));

    return result;
}

static const ATTESTATION_TYPE attestationType_fromJson(const char* str_rep)
{
    ATTESTATION_TYPE new_type = ATTESTATION_TYPE_NONE;

    if (str_rep != NULL)
    {
        if (strcmp(str_rep, ATTESTATION_TYPE_JSON_VALUE_TPM) == 0)
            new_type = ATTESTATION_TYPE_TPM;
        else if (strcmp(str_rep, ATTESTATION_TYPE_JSON_VALUE_X509) == 0)
            new_type = ATTESTATION_TYPE_X509;
        else
            LogError("Could not convert '%s' from JSON", str_rep);
    }

    return new_type;
}

static void x509CertificateInfo_free(X509_CERTIFICATE_INFO* x509_info)
{
    free(x509_info->subject_name);
    free(x509_info->sha1_thumbprint);
    free(x509_info->sha256_thumbprint);
    free(x509_info->issuer_name);
    free(x509_info->not_before_utc);
    free(x509_info->not_after_utc);
    free(x509_info->serial_number);
    free(x509_info);
}

static JSON_Value* x509CertificateInfo_toJson(const X509_CERTIFICATE_INFO* x509_info)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_SUBJECT_NAME, x509_info->subject_name) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_SUBJECT_NAME);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_SHA1, x509_info->sha1_thumbprint) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_SHA1);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_SHA256, x509_info->sha256_thumbprint) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_SHA256);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_ISSUER, x509_info->issuer_name) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_ISSUER);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_NOT_BEFORE, x509_info->not_before_utc) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_NOT_BEFORE);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_NOT_AFTER, x509_info->not_after_utc) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_NOT_AFTER);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, X509_CERTIFICATE_INFO_JSON_KEY_SERIAL_NO, x509_info->serial_number) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_SERIAL_NO);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_number(root_object, X509_CERTIFICATE_INFO_JSON_KEY_VERSION, x509_info->version) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", X509_CERTIFICATE_INFO_JSON_KEY_VERSION);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static X509_CERTIFICATE_INFO* x509CertificateInfo_fromJson(JSON_Object* root_object)
{
    X509_CERTIFICATE_INFO* new_x509Info = NULL;

    if ((new_x509Info = malloc(sizeof(X509_CERTIFICATE_INFO))) == NULL)
    {
        LogError("Allocation of X509 Certificate Info failed");
    }
    else
    {
        memset(new_x509Info, 0, sizeof(*new_x509Info));

        if (copy_json_string_field(&(new_x509Info->subject_name), root_object, X509_CERTIFICATE_INFO_JSON_KEY_SUBJECT_NAME) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_SUBJECT_NAME);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else if (copy_json_string_field(&(new_x509Info->sha1_thumbprint), root_object, X509_CERTIFICATE_INFO_JSON_KEY_SHA1) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_SHA1);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else if (copy_json_string_field(&(new_x509Info->sha256_thumbprint), root_object, X509_CERTIFICATE_INFO_JSON_KEY_SHA256) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_SHA256);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else if (copy_json_string_field(&(new_x509Info->issuer_name), root_object, X509_CERTIFICATE_INFO_JSON_KEY_ISSUER) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_ISSUER);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else if (copy_json_string_field(&(new_x509Info->not_before_utc), root_object, X509_CERTIFICATE_INFO_JSON_KEY_NOT_BEFORE) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_NOT_BEFORE);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else if (copy_json_string_field(&(new_x509Info->not_after_utc), root_object, X509_CERTIFICATE_INFO_JSON_KEY_NOT_AFTER) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_NOT_AFTER);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else if (copy_json_string_field(&(new_x509Info->serial_number), root_object, X509_CERTIFICATE_INFO_JSON_KEY_SERIAL_NO) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate Info", X509_CERTIFICATE_INFO_JSON_KEY_SERIAL_NO);
            x509CertificateInfo_free(new_x509Info);
            new_x509Info = NULL;
        }
        else
            new_x509Info->version = (int)json_object_get_number(root_object, X509_CERTIFICATE_INFO_JSON_KEY_VERSION);
    }

    return new_x509Info;
}

static JSON_Value* x509CertificateWithInfo_toJson(const X509_CERTIFICATE_WITH_INFO* x509_certinfo)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if ((x509_certinfo->certificate != NULL) && (json_object_set_string(root_object, X509_CERTIFICATE_WITH_INFO_JSON_KEY_CERTIFICATE, x509_certinfo->certificate) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of X509 Certificate With Info", X509_CERTIFICATE_WITH_INFO_JSON_KEY_CERTIFICATE);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((x509_certinfo->info != NULL) && (json_object_set_value(root_object, X509_CERTIFICATE_WITH_INFO_JSON_KEY_INFO, x509CertificateInfo_toJson(x509_certinfo->info)) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of X509 Certificate With Info", X509_CERTIFICATE_WITH_INFO_JSON_KEY_INFO);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static void x509CertificateWithInfo_free(X509_CERTIFICATE_WITH_INFO* x509_certinfo)
{
    free(x509_certinfo->certificate);
    if (x509_certinfo->info != NULL)
        x509CertificateInfo_free(x509_certinfo->info);
    free(x509_certinfo);
}

static X509_CERTIFICATE_WITH_INFO* x509CertificateWithInfo_fromJson(JSON_Object* root_object)
{
    X509_CERTIFICATE_WITH_INFO* new_x509CertInfo = NULL;

    if ((new_x509CertInfo = malloc(sizeof(X509_CERTIFICATE_WITH_INFO))) == NULL)
    {
        LogError("Allocation of X509 Certificate With Info failed");
    }
    else
    {
        memset(new_x509CertInfo, 0, sizeof(*new_x509CertInfo));
        if (copy_json_string_field(&(new_x509CertInfo->certificate), root_object, X509_CERTIFICATE_WITH_INFO_JSON_KEY_CERTIFICATE) != 0)
        {
            LogError("Failed to set '%s' in X509 Certificate With Info", X509_CERTIFICATE_WITH_INFO_JSON_KEY_CERTIFICATE);
            x509CertificateWithInfo_free(new_x509CertInfo);
            new_x509CertInfo = NULL;
        }
        else if ((new_x509CertInfo->info = x509CertificateInfo_fromJson(json_object_get_object(root_object, X509_CERTIFICATE_WITH_INFO_JSON_KEY_INFO))) == NULL)
        {
            LogError("Failed to set '%s' in X509 Certificate With Info", X509_CERTIFICATE_WITH_INFO_JSON_KEY_INFO);
            x509CertificateWithInfo_free(new_x509CertInfo);
            new_x509CertInfo = NULL;
        }
    }

    return new_x509CertInfo;
}

static X509_CERTIFICATE_WITH_INFO* x509CertificateWithInfo_create(const char* cert)
{
    X509_CERTIFICATE_WITH_INFO* new_x509CertWithInfo = NULL;
    X509_CERTIFICATE_INFO* new_x509CertInfo = NULL;

    if ((new_x509CertWithInfo = malloc(sizeof(X509_CERTIFICATE_WITH_INFO))) == NULL)
        LogError("Allocating memory for X509 Certificate With Info failed");
    //else if ((new_x509CertInfo = malloc(sizeof(X509_CERTIFICATE_INFO))) == NULL)
    //{
    //    LogError("Allocating memory for X509 Certificate Info failed");
    //    free(new_x509CertWithInfo);
    //    new_x509CertWithInfo = NULL;
    //}
    else
    {
        memset(new_x509CertWithInfo, 0, sizeof(*new_x509CertWithInfo));
        //memset(new_x509CertInfo, 0, sizeof(*new_x509CertInfo));

        if ((cert != NULL) && (copy_string(&(new_x509CertWithInfo->certificate), cert) != 0))
        {
            LogError("Error setting certificate in X509CertificateWithInfo");
            x509CertificateWithInfo_free(new_x509CertWithInfo);
            new_x509CertWithInfo = NULL;
            x509CertificateInfo_free(new_x509CertInfo);
            new_x509CertInfo = NULL;
        }
        //else
        //    new_x509CertWithInfo->info = new_x509CertInfo;
    }

    return new_x509CertWithInfo;
}

static void x509Certificates_free(X509_CERTIFICATES* x509_certs)
{
    if (x509_certs->primary != NULL)
        x509CertificateWithInfo_free(x509_certs->primary);
    if (x509_certs->secondary != NULL)
        x509CertificateWithInfo_free(x509_certs->secondary);
    free(x509_certs);
}

static JSON_Value* x509Certificates_toJson(const X509_CERTIFICATES* x509_certs)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if (json_object_set_value(root_object, X509_CERTIFICATES_JSON_KEY_PRIMARY, x509CertificateWithInfo_toJson(x509_certs->primary)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string representation of X509 Certificates", X509_CERTIFICATES_JSON_KEY_PRIMARY);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((x509_certs->secondary != NULL) && (json_object_set_value(root_object, X509_CERTIFICATES_JSON_KEY_SECONDARY, x509CertificateWithInfo_toJson(x509_certs->secondary)) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of X509 Certificates", X509_CERTIFICATES_JSON_KEY_SECONDARY);
        json_value_free(root_value);
        root_value = NULL;
    }

return root_value;
}

static X509_CERTIFICATES* x509Certificates_fromJson(JSON_Object* root_object)
{
    X509_CERTIFICATES* new_x509certs = NULL;

    //Create Attestation Mechanism
    if ((new_x509certs = malloc(sizeof(X509_CERTIFICATES))) == NULL)
    {
        LogError("Allocation of X509 Certificates failed");
    }
    else
    {
        memset(new_x509certs, 0, sizeof(*new_x509certs));

        if ((new_x509certs->primary = x509CertificateWithInfo_fromJson(json_object_get_object(root_object, X509_CERTIFICATES_JSON_KEY_PRIMARY))) == NULL)
        {
            LogError("Failed to set '%s' in X509 Certificates", X509_CERTIFICATES_JSON_KEY_PRIMARY);
            x509Certificates_free(new_x509certs);
            new_x509certs = NULL;
        }
        else if (json_object_has_value(root_object, X509_CERTIFICATES_JSON_KEY_SECONDARY) && ((new_x509certs->secondary = x509CertificateWithInfo_fromJson(json_object_get_object(root_object, X509_CERTIFICATES_JSON_KEY_SECONDARY))) == NULL))
        {
            LogError("Failed to set '%s' in X509 Certificates", X509_CERTIFICATES_JSON_KEY_SECONDARY);
            x509Certificates_free(new_x509certs);
            new_x509certs = NULL;
        }
    }
    return new_x509certs;
}

static void x509Attestation_free(X509_ATTESTATION* x509_att)
{
    if (x509_att->type == CERTIFICATE_TYPE_CLIENT)
    {
        if (x509_att->certificates.client_certificates != NULL)
            x509Certificates_free(x509_att->certificates.client_certificates);
    }
    else if (x509_att->type == CERTIFICATE_TYPE_SIGNING)
    {
        if (x509_att->certificates.signing_certificates != NULL)
            x509Certificates_free(x509_att->certificates.signing_certificates);
    }
    free(x509_att);
}

static JSON_Value* x509Attestation_toJson(const X509_ATTESTATION* x509_att)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if ((x509_att->type == CERTIFICATE_TYPE_CLIENT) && (json_object_set_value(root_object, X509_ATTESTATION_JSON_KEY_CLIENT_CERTS, x509Certificates_toJson(x509_att->certificates.client_certificates)) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of X509 Attestation", X509_ATTESTATION_JSON_KEY_CLIENT_CERTS);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((x509_att->type == CERTIFICATE_TYPE_SIGNING) && (json_object_set_value(root_object, X509_ATTESTATION_JSON_KEY_SIGNING_CERTS, x509Certificates_toJson(x509_att->certificates.signing_certificates)) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of X509 Attestation", X509_ATTESTATION_JSON_KEY_SIGNING_CERTS);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static X509_ATTESTATION* x509Attestation_fromJson(JSON_Object* root_object)
{
    X509_ATTESTATION* new_x509Att = NULL;

    //Create Attestation Mechanism
    if ((new_x509Att = malloc(sizeof(X509_ATTESTATION))) == NULL)
    {
        LogError("Allocation of X509 Attestation failed");
    }
    else
    {
        memset(new_x509Att, 0, sizeof(*new_x509Att));
        if (json_object_has_value(root_object, X509_ATTESTATION_JSON_KEY_CLIENT_CERTS))
        {
            if ((new_x509Att->certificates.client_certificates = x509Certificates_fromJson(json_object_get_object(root_object, X509_ATTESTATION_JSON_KEY_CLIENT_CERTS))) == NULL)
            {
                LogError("Failed to set '%s' in X509 Attestation", X509_ATTESTATION_JSON_KEY_CLIENT_CERTS);
                x509Attestation_free(new_x509Att);
                new_x509Att = NULL;
            }
            else
                new_x509Att->type = CERTIFICATE_TYPE_CLIENT;
        }

        else if (json_object_has_value(root_object, X509_ATTESTATION_JSON_KEY_SIGNING_CERTS))
        {
            if ((new_x509Att->certificates.signing_certificates = x509Certificates_fromJson(json_object_get_object(root_object, X509_ATTESTATION_JSON_KEY_SIGNING_CERTS))) == NULL)
            {
                LogError("Failed to set '%s' in X509 Attestation", X509_ATTESTATION_JSON_KEY_SIGNING_CERTS);
                x509Attestation_free(new_x509Att);
                new_x509Att = NULL;
            }
            else
                new_x509Att->type = CERTIFICATE_TYPE_SIGNING;
        }
    }

    return new_x509Att;
}

static X509_ATTESTATION* x509Attestation_create(CERTIFICATE_TYPE cert_type, const char* primary_cert, const char* secondary_cert)
{
    X509_ATTESTATION* new_x509Att = NULL;
    X509_CERTIFICATES* new_x509Certs = NULL;

    if ((cert_type == CERTIFICATE_TYPE_NONE) || (primary_cert == NULL))
    {
        LogError("Requires valid certificate type and primary certificate to create X509 Attestation");
    }
    else if ((new_x509Att = malloc(sizeof(X509_ATTESTATION))) == NULL)
    {
        LogError("Failed to allocate memory for X509 Attestation");
    }
    else if ((new_x509Certs = malloc(sizeof(X509_CERTIFICATES))) == NULL)
    {
        LogError("Failed to allocate memory for X509 Certificates");
        free(new_x509Att);
        new_x509Att = NULL;
    }
    else
    {
        memset(new_x509Att, 0, sizeof(*new_x509Att));
        memset(new_x509Certs, 0, sizeof(*new_x509Certs));
        
        new_x509Att->type = cert_type;
        if (cert_type == CERTIFICATE_TYPE_CLIENT)
            new_x509Att->certificates.client_certificates = new_x509Certs;
        else if (cert_type == CERTIFICATE_TYPE_SIGNING)
            new_x509Att->certificates.signing_certificates = new_x509Certs;

        //Primary Cert is mandatory
        if ((new_x509Certs->primary = x509CertificateWithInfo_create(primary_cert)) == NULL)
        {
            LogError("Failed to create Primary Certificate");
            x509Attestation_free(new_x509Att);
            new_x509Att = NULL;
        }

        //Secondary Cert is optional
        else if ((secondary_cert != NULL) && ((new_x509Certs->secondary = x509CertificateWithInfo_create(secondary_cert)) == NULL))
        {
            LogError("Failed to create Secondary Certificate");
            x509Attestation_free(new_x509Att);
            new_x509Att = NULL;
        }
    }

    return new_x509Att;
}

static void tpmAttestation_free(TPM_ATTESTATION* tpm_att)
{
    free(tpm_att->endorsement_key);
    free(tpm_att);
}

static JSON_Value* tpmAttestation_toJson(const TPM_ATTESTATION* tpm_att)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if (json_object_set_string(root_object, TPM_ATTESTATION_JSON_KEY_EK, tpm_att->endorsement_key) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string representation of TPM Attestation", TPM_ATTESTATION_JSON_KEY_EK);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static TPM_ATTESTATION* tpmAttestation_fromJson(JSON_Object * root_object)
{
    TPM_ATTESTATION* new_tpmAtt = NULL;

    //Create Attestation Mechanism
    if ((new_tpmAtt = malloc(sizeof(TPM_ATTESTATION))) == NULL)
    {
        LogError("Allocation of TPM Attestation failed");
    }
    else
    {
        memset(new_tpmAtt, 0, sizeof(*new_tpmAtt));

        if (copy_json_string_field(&(new_tpmAtt->endorsement_key), root_object, TPM_ATTESTATION_JSON_KEY_EK) != 0)
        {
            LogError("Failed to set '%s' in TPM Attestation", TPM_ATTESTATION_JSON_KEY_EK);
            tpmAttestation_free(new_tpmAtt);
            new_tpmAtt = NULL;
        }
    }
    return new_tpmAtt;
}

static void attestationMechanism_free(ATTESTATION_MECHANISM* att_mech)
{
    if (att_mech->type == ATTESTATION_TYPE_TPM)
    {
        if (att_mech->attestation.tpm != NULL)
            tpmAttestation_free(att_mech->attestation.tpm);
    }
    else if (att_mech->type == ATTESTATION_TYPE_X509)
    {
        if (att_mech->attestation.x509 != NULL)
            x509Attestation_free(att_mech->attestation.x509);
    }
    free(att_mech);
}

static JSON_Value* attestationMechanism_toJson(const ATTESTATION_MECHANISM* att_mech)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if (att_mech == NULL)
    {
        LogError("enrollment is NULL");
    }
    else if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if (json_object_set_string(root_object, ATTESTATION_MECHANISM_JSON_KEY_TYPE, attestationType_toJson(att_mech->type)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string representation of Attestation Mechanism", ATTESTATION_MECHANISM_JSON_KEY_TYPE);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((att_mech->type == ATTESTATION_TYPE_TPM) && (json_object_set_value(root_object, ATTESTATION_MECHANISM_JSON_KEY_TPM, tpmAttestation_toJson(att_mech->attestation.tpm)) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of Attestation Mechanism", ATTESTATION_MECHANISM_JSON_KEY_TPM);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((att_mech->type == ATTESTATION_TYPE_X509) && (json_object_set_value(root_object, ATTESTATION_MECHANISM_JSON_KEY_X509, x509Attestation_toJson(att_mech->attestation.x509)) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string representation of Attestation Mechanism", ATTESTATION_MECHANISM_JSON_KEY_X509);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static ATTESTATION_MECHANISM* attestationMechanism_fromJson(JSON_Object* root_object)
{
    ATTESTATION_MECHANISM* new_attMech = NULL;

    //Create Attestation Mechanism
    if ((new_attMech = malloc(sizeof(ATTESTATION_MECHANISM))) == NULL)
    {
        LogError("Allocation of Attestation Mechanism failed");
    }
    else
    {
        memset(new_attMech, 0, sizeof(*new_attMech));

        if ((new_attMech->type = attestationType_fromJson(json_object_get_string(root_object, ATTESTATION_MECHANISM_JSON_KEY_TYPE))) == ATTESTATION_TYPE_NONE)
        {
            LogError("Failed to set '%s' in Attestation Mechanism", ATTESTATION_MECHANISM_JSON_KEY_TYPE);
            attestationMechanism_free(new_attMech);
            new_attMech = NULL;
        }
        else if (new_attMech->type == ATTESTATION_TYPE_TPM)
        {
            if ((new_attMech->attestation.tpm = tpmAttestation_fromJson(json_object_get_object(root_object, ATTESTATION_MECHANISM_JSON_KEY_TPM))) == NULL)
            {
                LogError("Failed to set '%s' in Attestation Mechanism", ATTESTATION_MECHANISM_JSON_KEY_TPM);
                attestationMechanism_free(new_attMech);
                new_attMech = NULL;
            }
        }
        else if (new_attMech->type == ATTESTATION_TYPE_X509)
        {
            if ((new_attMech->attestation.x509 = x509Attestation_fromJson(json_object_get_object(root_object, ATTESTATION_MECHANISM_JSON_KEY_X509))) == NULL)
            {
                LogError("Failed to set '%s' in Attestation Mechanism", ATTESTATION_MECHANISM_JSON_KEY_X509);
                attestationMechanism_free(new_attMech);
                new_attMech = NULL;
            }
        }
    }

    return new_attMech;
}

static void deviceRegistrationStatus_free(DEVICE_REGISTRATION_STATUS* device_reg_status)
{
    free(device_reg_status->registration_id);
    free(device_reg_status->created_date_time_utc);
    free(device_reg_status->device_id);
    free(device_reg_status->updated_date_time_utc);
    free(device_reg_status->error_message);
    free(device_reg_status->etag);
    free(device_reg_status);
}

static DEVICE_REGISTRATION_STATUS* deviceRegistrationStatus_fromJson(JSON_Object* root_object)
{
    DEVICE_REGISTRATION_STATUS* new_device_reg_status = NULL;

    if ((new_device_reg_status = malloc(sizeof(DEVICE_REGISTRATION_STATUS))) == NULL)
    {
        LogError("Allocation of Device Registration Status failed");
    }
    else
    {
        memset(new_device_reg_status, 0, sizeof(*new_device_reg_status));

        if (copy_json_string_field(&(new_device_reg_status->registration_id), root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_REG_ID) != 0)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_REG_ID);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else if (copy_json_string_field(&(new_device_reg_status->created_date_time_utc), root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_CREATED_TIME) != 0)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_CREATED_TIME);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else if (copy_json_string_field(&(new_device_reg_status->device_id), root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_DEVICE_ID) != 0)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_DEVICE_ID);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else if ((new_device_reg_status->status = registrationStatus_fromJson(json_object_get_string(root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_REG_STATUS))) == REGISTRATION_STATUS_NONE)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_REG_STATUS);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else if (copy_json_string_field(&(new_device_reg_status->updated_date_time_utc), root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_UPDATED_TIME) != 0)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_UPDATED_TIME);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else if (copy_json_string_field(&(new_device_reg_status->error_message), root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_ERROR_MSG) != 0)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_ERROR_MSG);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else if (copy_json_string_field(&(new_device_reg_status->etag), root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_ETAG) != 0)
        {
            LogError("Failed to set '%s' in Device Registration Status", DEVICE_REGISTRATION_STATUS_JSON_KEY_ETAG);
            deviceRegistrationStatus_free(new_device_reg_status);
            new_device_reg_status = NULL;
        }
        else
            new_device_reg_status->error_code = (int)json_object_get_number(root_object, DEVICE_REGISTRATION_STATUS_JSON_KEY_ERROR_CODE);
    }

    return new_device_reg_status;
}

static JSON_Value* individualEnrollment_toJson(const INDIVIDUAL_ENROLLMENT* enrollment)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if (enrollment == NULL)
    {
        LogError("enrollment is NULL");
    }
    else if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if (json_object_set_string(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_ID, enrollment->registration_id) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_ID);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((enrollment->device_id != NULL) && (json_object_set_string(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_DEVICE_ID, enrollment->device_id) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON String", INDIVIDUAL_ENROLLMENT_JSON_KEY_DEVICE_ID);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_value(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_ATTESTATION, attestationMechanism_toJson(enrollment->attestation_mechanism)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON String", INDIVIDUAL_ENROLLMENT_JSON_KEY_ATTESTATION);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((enrollment->etag != NULL) && (json_object_set_string(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_ETAG, enrollment->etag) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON String", INDIVIDUAL_ENROLLMENT_JSON_KEY_ETAG);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_PROV_STATUS, provisioningStatus_toJson(enrollment->provisioning_status)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON String", INDIVIDUAL_ENROLLMENT_JSON_KEY_PROV_STATUS);
        json_value_free(root_value);
        root_value = NULL;
    }
    //Do not set create_date_time_utc or update_date_time_utc as they are READ ONLY

    return root_value;
}

static INDIVIDUAL_ENROLLMENT* individualEnrollment_fromJson(JSON_Object* root_object)
{
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;

    if ((new_enrollment = malloc(sizeof(INDIVIDUAL_ENROLLMENT))) == NULL)
    {
        LogError("Allocation of Individual Enrollment failed");
    }
    else
    {
        memset(new_enrollment, 0, sizeof(*new_enrollment));

        if (copy_json_string_field(&(new_enrollment->registration_id), root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_ID) != 0)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_ID);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->device_id), root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_DEVICE_ID) != 0)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_DEVICE_ID);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if ((json_object_has_value(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_STATUS)) && (new_enrollment->registration_status = deviceRegistrationStatus_fromJson(json_object_get_object(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_STATUS))) == NULL)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_REG_STATUS);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if ((new_enrollment->attestation_mechanism = attestationMechanism_fromJson(json_object_get_object(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_ATTESTATION))) == NULL)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_ATTESTATION);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->etag), root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_ETAG) != 0)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_ETAG);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if ((new_enrollment->provisioning_status = provisioningStatus_fromJson(json_object_get_string(root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_PROV_STATUS))) == PROVISIONING_STATUS_NONE)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_PROV_STATUS);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->created_date_time_utc), root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_CREATED_TIME) != 0)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_CREATED_TIME);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->updated_date_time_utc), root_object, INDIVIDUAL_ENROLLMENT_JSON_KEY_UPDATED_TIME) != 0)
        {
            LogError("Failed to set '%s' in Individual Enrollment", INDIVIDUAL_ENROLLMENT_JSON_KEY_UPDATED_TIME);
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
    }

    return new_enrollment;
}

static JSON_Value* enrollmentGroup_toJson(const ENROLLMENT_GROUP* enrollment)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    //Setup
    if (enrollment == NULL)
    {
        LogError("enrollment is NULL");
    }
    else if ((root_value = json_value_init_object()) == NULL)
    {
        LogError("json_value_init_object failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        json_value_free(root_value);
        root_value = NULL;
    }

    //Set data
    else if (json_object_set_string(root_object, ENROLLMENT_GROUP_JSON_KEY_GROUP_NAME, enrollment->group_name) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", ENROLLMENT_GROUP_JSON_KEY_GROUP_NAME);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_value(root_object, ENROLLMENT_GROUP_JSON_KEY_ATTESTATION, attestationMechanism_toJson(enrollment->attestation_mechanism)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", ENROLLMENT_GROUP_JSON_KEY_ATTESTATION);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((enrollment->etag != NULL) && (json_object_set_string(root_object, ENROLLMENT_GROUP_JSON_KEY_ETAG, enrollment->etag) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON string", ENROLLMENT_GROUP_JSON_KEY_ETAG);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, ENROLLMENT_GROUP_JSON_KEY_PROV_STATUS, provisioningStatus_toJson(enrollment->provisioning_status)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", ENROLLMENT_GROUP_JSON_KEY_PROV_STATUS);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static ENROLLMENT_GROUP* enrollmentGroup_fromJson(JSON_Object* root_object)
{
    ENROLLMENT_GROUP* new_enrollment = NULL;

    if ((new_enrollment = malloc(sizeof(ENROLLMENT_GROUP))) == NULL)
    {
        LogError("Allocation of Enrollment Group failed");
    }
    else
    {
        memset(new_enrollment, 0, sizeof(*new_enrollment));

        if (copy_json_string_field(&(new_enrollment->group_name), root_object, ENROLLMENT_GROUP_JSON_KEY_GROUP_NAME) != 0)
        {
            LogError("Failed to set '%s' in Enrollment Group", ENROLLMENT_GROUP_JSON_KEY_GROUP_NAME);
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if ((new_enrollment->attestation_mechanism = attestationMechanism_fromJson(json_object_get_object(root_object, ENROLLMENT_GROUP_JSON_KEY_ATTESTATION))) == NULL)
        {
            LogError("Failed to set '%s' in Enrollment Group", ENROLLMENT_GROUP_JSON_KEY_ATTESTATION);
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->etag), root_object, ENROLLMENT_GROUP_JSON_KEY_ETAG) != 0)
        {
            LogError("Failed to set '%s' in Enrollment Group", ENROLLMENT_GROUP_JSON_KEY_ETAG);
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if ((new_enrollment->provisioning_status = provisioningStatus_fromJson(json_object_get_string(root_object, ENROLLMENT_GROUP_JSON_KEY_PROV_STATUS))) == PROVISIONING_STATUS_NONE)
        {
            LogError("Failed to set '%s' in Enrollment Group", ENROLLMENT_GROUP_JSON_KEY_PROV_STATUS);
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->created_date_time_utc), root_object, ENROLLMENT_GROUP_JSON_KEY_CREATED_TIME) != 0)
        {
            LogError("Failed to set '%s' in Enrollment Group", ENROLLMENT_GROUP_JSON_KEY_CREATED_TIME);
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
        else if (copy_json_string_field(&(new_enrollment->updated_date_time_utc), root_object, ENROLLMENT_GROUP_JSON_KEY_UPDATED_TIME) != 0)
        {
            LogError("Failed to set '%s' in Enrollment Group", ENROLLMENT_GROUP_JSON_KEY_UPDATED_TIME);
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
    }

    return new_enrollment;
}

INDIVIDUAL_ENROLLMENT* individualEnrollment_create(const char* reg_id)
{
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;
    ATTESTATION_MECHANISM* att_mech = NULL;

    if (reg_id == NULL)
    {
        LogError("reg_id invalid");
    }
    else if ((new_enrollment = malloc(sizeof(INDIVIDUAL_ENROLLMENT))) == NULL)
    {
        LogError("Allocation of individual enrollment failed");
        new_enrollment = NULL;
    }
    else if ((att_mech = malloc(sizeof(ATTESTATION_MECHANISM))) == NULL)
    {
        LogError("Allocation of attestation mechanism failed");
        free(new_enrollment);
        new_enrollment = NULL;
    }
    else
    {
        memset(new_enrollment, 0, sizeof(*new_enrollment));
        memset(att_mech, 0, sizeof(*att_mech));

        if (copy_string(&(new_enrollment->registration_id), reg_id) != 0)
        {
            LogError("Allocation of registration id failed");
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else
        {
            new_enrollment->attestation_mechanism = att_mech;
            new_enrollment->provisioning_status = PROVISIONING_STATUS_ENABLED;
        }
    }

    return new_enrollment;
}

INDIVIDUAL_ENROLLMENT* individualEnrollment_create_tpm(const char* reg_id, const char* endorsement_key)
{
    TPM_ATTESTATION* tpm_attestation = NULL;
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;
    
    if (reg_id == NULL)
    {
        LogError("reg_id invalid");
    }
    else if ((new_enrollment = individualEnrollment_create(reg_id)) == NULL)
    {
        LogError("Allocation of individual enrollment failed");
    }
    else if ((tpm_attestation = malloc(sizeof(TPM_ATTESTATION))) == NULL)
    {
        LogError("Allocation of TPM attestation failed");
        individualEnrollment_free(new_enrollment);
        new_enrollment = NULL;
    }
    else
    {
        memset(tpm_attestation, 0, sizeof(*tpm_attestation));

        if (copy_string(&(tpm_attestation->endorsement_key), endorsement_key) != 0)
        {
            LogError("Setting endorsement key in individual enrollment failed");
            individualEnrollment_free(new_enrollment);
            new_enrollment = NULL;
        }
        else
        {
            new_enrollment->attestation_mechanism->type = ATTESTATION_TYPE_TPM;
            new_enrollment->attestation_mechanism->attestation.tpm = tpm_attestation;
        }
    }

    return new_enrollment;
}

INDIVIDUAL_ENROLLMENT* individualEnrollment_create_x509(const char* reg_id, const char* primary_cert, const char* secondary_cert)
{
    X509_ATTESTATION* x509_attestation = NULL;
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;

    if (reg_id == NULL)
        LogError("reg_id invalid");
    else if (primary_cert == NULL)
        LogError("primary_cert invalid");
    else if ((new_enrollment = individualEnrollment_create(reg_id)) == NULL)
        LogError("Allocation of individual enrollment failed");
    else if ((x509_attestation = x509Attestation_create(CERTIFICATE_TYPE_CLIENT, primary_cert, secondary_cert)) == NULL)
    {
        LogError("Allocation of x509 Attestation failed");
        individualEnrollment_free(new_enrollment);
        new_enrollment = NULL;
    }
    else
    {
        new_enrollment->attestation_mechanism->type = ATTESTATION_TYPE_X509;
        new_enrollment->attestation_mechanism->attestation.x509 = x509_attestation;
    }

    return new_enrollment;
}

void individualEnrollment_free(INDIVIDUAL_ENROLLMENT* enrollment)
{
    //free dynamically allocated fields
    free(enrollment->registration_id);
    free(enrollment->device_id);
    free(enrollment->etag);
    free(enrollment->created_date_time_utc);
    free(enrollment->updated_date_time_utc);

    //free nested structures
    if (enrollment->attestation_mechanism != NULL)
        attestationMechanism_free(enrollment->attestation_mechanism);
    if (enrollment->registration_status != NULL)
        deviceRegistrationStatus_free(enrollment->registration_status);
    //free twin state

    free(enrollment);
}

int individualEnrollment_setDeviceId(INDIVIDUAL_ENROLLMENT* enrollment, const char* device_id)
{
    int result = 0;

    if (device_id == NULL)
    {
        LogError("Invalid device id");
        result = __LINE__;
    }
    else if (copy_string(&(enrollment->device_id), device_id) != 0)
    {
        LogError("Failed to set device id");
        result = __LINE__;
    }

    return result;
}

int individualEnrollment_setEtag(INDIVIDUAL_ENROLLMENT* enrollment, const char* etag)
{
    int result = 0;

    if (etag == NULL)
    {
        LogError("Invalid etag");
        result = __LINE__;
    }
    else if (copy_string(&(enrollment->etag), etag) != 0)
    {
        LogError("Failed to set etag");
        result = __LINE__;
    }

    return result;
}

const char* individualEnrollment_serialize(const INDIVIDUAL_ENROLLMENT* enrollment)
{
    char* result = NULL;
    JSON_Value* root_value = NULL;

    if (enrollment == NULL)
    {
        LogError("Cannot serialize NULL");
    }
    else if ((root_value = individualEnrollment_toJson(enrollment)) == NULL)
    {
        LogError("Creating json object failed");
    }
    else if ((result = json_serialize_to_string(root_value)) == NULL)
    {
        LogError("Failed to serialize to JSON");
    }
    if (root_value != NULL)
    {
        json_value_free(root_value); 
        root_value = NULL;
    }

    return result;
}

INDIVIDUAL_ENROLLMENT* individualEnrollment_deserialize(const char* json_string)
{
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    if (json_string == NULL)
    {
        LogError("Cannot deserialize NULL");
    }
    else if ((root_value = json_parse_string(json_string)) == NULL)
    {
        LogError("Parsong JSON string failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("Creating JSON object failed");
    }
    else
    {
        if ((new_enrollment = individualEnrollment_fromJson(root_object)) == NULL)
        {
            LogError("Creating new Individual Enrollment failed");
        }
        json_value_free(root_value); //implicitly frees root_object
        root_value = NULL;
    }

    return new_enrollment;
}

ENROLLMENT_GROUP* enrollmentGroup_create(const char* group_name)
{
    ENROLLMENT_GROUP* new_enrollment = NULL;
    ATTESTATION_MECHANISM* att_mech = NULL;

    if ((new_enrollment = malloc(sizeof(ENROLLMENT_GROUP))) == NULL)
    {
        LogError("Allocation of enrollment group failed");
        new_enrollment = NULL;
    }
    else if ((att_mech = malloc(sizeof(ATTESTATION_MECHANISM))) == NULL)
    {
        LogError("Allocation of attestation mechanism failed");
        free(new_enrollment);
        new_enrollment = NULL;
    }
    else
    {
        memset(new_enrollment, 0, sizeof(*new_enrollment));
        memset(att_mech, 0, sizeof(*att_mech));

        if (copy_string(&(new_enrollment->group_name), group_name) != 0)
        {
            LogError("Allocation of group name failed");
            enrollmentGroup_free(new_enrollment);
            new_enrollment = NULL;
        }
        else
        {
            new_enrollment->attestation_mechanism = att_mech;
            new_enrollment->provisioning_status = PROVISIONING_STATUS_ENABLED;
        }
    }

    return new_enrollment;
}

ENROLLMENT_GROUP* enrollmentGroup_create_x509(const char* group_name, const char* primary_cert, const char* secondary_cert)
{
    X509_ATTESTATION* x509_attestation = NULL;
    ENROLLMENT_GROUP* new_enrollment = NULL;

    if ((new_enrollment = enrollmentGroup_create(group_name)) == NULL)
    {
        LogError("Allocation of individual enrollment failed");
    }

    else if ((x509_attestation = x509Attestation_create(CERTIFICATE_TYPE_SIGNING, primary_cert, secondary_cert)) == NULL)
    {
        LogError("Allocation of x509 Attestation failed");
        enrollmentGroup_free(new_enrollment);
        new_enrollment = NULL;
    }
    else
    {
        new_enrollment->attestation_mechanism->type = ATTESTATION_TYPE_X509;
        new_enrollment->attestation_mechanism->attestation.x509 = x509_attestation;
    }

    return new_enrollment;
}

void enrollmentGroup_free(ENROLLMENT_GROUP* enrollment)
{
    free(enrollment->group_name);
    attestationMechanism_free(enrollment->attestation_mechanism);
    free(enrollment->etag);
    free(enrollment->created_date_time_utc);
    free(enrollment->updated_date_time_utc);
    free(enrollment);
}

int enrollmentGroup_setEtag(ENROLLMENT_GROUP* enrollment, const char* etag)
{
    int result = 0;

    if (etag == NULL)
    {
        LogError("Invalid etag");
        result = __LINE__;
    }
    else if (copy_string(&(enrollment->etag), etag) != 0)
    {
        LogError("Failed to set etag");
        result = __LINE__;
    }

    return result;
}

const char* enrollmentGroup_serialize(const ENROLLMENT_GROUP* enrollment)
{
    char* result = NULL;
    JSON_Value* root_value = NULL;

    if (enrollment == NULL)
    {
        LogError("Cannot serialize NULL");
    }
    else if ((root_value = enrollmentGroup_toJson(enrollment)) == NULL)
    {
        LogError("Creating json object failed");
    }
    else if ((result = json_serialize_to_string(root_value)) == NULL)
    {
        LogError("Serializing to JSON failed");
    }
    if (root_value != NULL)
    {
        json_value_free(root_value);
        root_value = NULL;
    }

    return result;
}

ENROLLMENT_GROUP* enrollmentGroup_deserialize(const char* json_string)
{
    ENROLLMENT_GROUP* new_enrollment = NULL;
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    if (json_string == NULL)
    {
        LogError("Cannot deserialize NULL");
    }
    else if ((root_value = json_parse_string(json_string)) == NULL)
    {
        LogError("Parsong JSON string failed");
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("Creating JSON object failed");
    }
    else
    {
        if ((new_enrollment = enrollmentGroup_fromJson(root_object)) == NULL)
        {
            LogError("Creating new Enrollment Group failed");
        }
        json_value_free(root_value); //implicitly frees root_object
        root_value = NULL;
    }

    return new_enrollment;
}
