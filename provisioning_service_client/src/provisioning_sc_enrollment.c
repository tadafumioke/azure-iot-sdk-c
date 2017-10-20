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

static const char* ENROLLMENT_JSON_KEY_REG_ID = "registrationId";
static const char* ENROLLMENT_JSON_KEY_DEVICE_ID = "deviceId";
//static const char* ENROLLMENT_JSON_KEY_REG_STATE
static const char* ENROLLMENT_JSON_KEY_ATTESTATION = "attestation";
static const char* ENROLLMENT_JSON_KEY_ETAG = "etag";
static const char* ENROLLMENT_JSON_KEY_PROV_STATUS = "provisioningStatus";
static const char* ENROLLMENT_JSON_KEY_CREATED_TIME = "createdDateTimeUtc";
static const char* ENROLLMENT_JSON_KEY_UPDATED_TIME = "lastUpdatedDateTimeUtc";

static const char* ATTESTATION_MECHANISM_JSON_KEY_TYPE = "type";
static const char* ATTESTATION_MECHANISM_JSON_KEY_TPM = "tpm";
static const char* ATTESTATION_MECHANISM_JSON_KEY_X509 = "x509";

static const char* TPM_ATTESTATION_JSON_KEY_EK = "endorsementKey";


static char* copy_string(const char* string)
{
    char* new_copy = NULL;

    if (string != NULL)
    {
        size_t len = strlen(string);
        if ((new_copy = malloc(len + 1)) == NULL)
        {
            LogError("Allocating string for value '%s' failed");
        }
        else if ((strncpy(new_copy, string, len + 1)) == NULL)
        {
            LogError("Failed to copy value '%s'");
            new_copy = NULL;
        }
    }

    return new_copy;
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

    if (strcmp(str_rep, PROVISIONING_STATUS_JSON_VALUE_ENABLED) == 0)
        new_status = PROVISIONING_STATUS_ENABLED;
    else if (strcmp(str_rep, PROVISIONING_STATUS_JSON_VALUE_DISABLED) == 0)
        new_status = PROVISIONING_STATUS_DISABLED;
    else
        LogError("Could not convert '%s' from JSON", str_rep);

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

    if (strcmp(str_rep, ATTESTATION_TYPE_JSON_VALUE_TPM) == 0)
        new_type = ATTESTATION_TYPE_TPM;
    else if (strcmp(str_rep, ATTESTATION_TYPE_JSON_VALUE_X509) == 0)
        new_type = ATTESTATION_TYPE_X509;
    else
        LogError("Could not convert '%s' from JSON", str_rep);
    return new_type;
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

    UNREFERENCED_PARAMETER(x509_att);
    return root_value;
}

static X509_ATTESTATION* x509Attestation_fromJson(JSON_Object * root_object)
{
    X509_ATTESTATION* new_x509Att = NULL;
    UNREFERENCED_PARAMETER(root_object);

    //Create Attestation Mechanism
    if ((new_x509Att = malloc(sizeof(X509_ATTESTATION))) == NULL)
    {
        LogError("Allocation of X509 Attestation failed");
    }

    //fill fields

    return new_x509Att;
}

static void x509Attestation_free(X509_ATTESTATION* x509_att)
{
    free(x509_att);
    LogError("Unimplemented");
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
        LogError("Failed to set '%s' in JSON string representation of Attestation Mechanism", TPM_ATTESTATION_JSON_KEY_EK);
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
    new_tpmAtt->endorsement_key = copy_string(json_object_get_string(root_object, TPM_ATTESTATION_JSON_KEY_EK));

    return new_tpmAtt;
}

static void tpmAttestation_free(TPM_ATTESTATION* tpm_att)
{
    free(tpm_att->endorsement_key);
    free(tpm_att);
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
    new_attMech->type = attestationType_fromJson(json_object_get_string(root_object, ATTESTATION_MECHANISM_JSON_KEY_TYPE));
    if (new_attMech->type == ATTESTATION_TYPE_TPM)
        new_attMech->attestation.tpm = tpmAttestation_fromJson(json_object_get_object(root_object, ATTESTATION_MECHANISM_JSON_KEY_TPM));
    else if (new_attMech->type == ATTESTATION_TYPE_X509)
        new_attMech->attestation.x509 = x509Attestation_fromJson(json_object_get_object(root_object, ATTESTATION_MECHANISM_JSON_KEY_X509));

    return new_attMech;
}

static void attestationMechanism_free(ATTESTATION_MECHANISM* att_mech)
{
    if (att_mech->type == ATTESTATION_TYPE_TPM)
    {
        tpmAttestation_free(att_mech->attestation.tpm);
    }
    else if (att_mech->type == ATTESTATION_TYPE_X509)
    {
        x509Attestation_free(att_mech->attestation.x509);
    }
    free(att_mech);
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
    else if (json_object_set_string(root_object, ENROLLMENT_JSON_KEY_REG_ID, enrollment->registration_id) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON string", ENROLLMENT_JSON_KEY_REG_ID);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((enrollment->device_id != NULL) && (json_object_set_string(root_object, ENROLLMENT_JSON_KEY_DEVICE_ID, enrollment->device_id) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON String", ENROLLMENT_JSON_KEY_DEVICE_ID);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_value(root_object, ENROLLMENT_JSON_KEY_ATTESTATION, attestationMechanism_toJson(enrollment->attestation_mechanism)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON String", ENROLLMENT_JSON_KEY_ATTESTATION);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if ((enrollment->etag != NULL) && (json_object_set_string(root_object, ENROLLMENT_JSON_KEY_ETAG, enrollment->etag) != JSONSuccess))
    {
        LogError("Failed to set '%s' in JSON String", ENROLLMENT_JSON_KEY_ETAG);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_object_set_string(root_object, ENROLLMENT_JSON_KEY_PROV_STATUS, provisioningStatus_toJson(enrollment->provisioning_status)) != JSONSuccess)
    {
        LogError("Failed to set '%s' in JSON String", ENROLLMENT_JSON_KEY_PROV_STATUS);
        json_value_free(root_value);
        root_value = NULL;
    }
    //Do not set create_date_time_utc or update_date_time_utc as they are READ ONLY

    return root_value;
}

static INDIVIDUAL_ENROLLMENT* individualEnrollment_fromJson(JSON_Object* root_object)
{
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;

    //Create Individual Enrollment
    if ((new_enrollment = malloc(sizeof(INDIVIDUAL_ENROLLMENT))) == NULL)
    {
        LogError("Allocation of Individual Enrollment failed");
    }
    else
    {
        memset(new_enrollment, 0, sizeof(*new_enrollment));
        new_enrollment->registration_id = copy_string(json_object_get_string(root_object, ENROLLMENT_JSON_KEY_REG_ID));
        new_enrollment->device_id = copy_string(json_object_get_string(root_object, ENROLLMENT_JSON_KEY_DEVICE_ID));
        new_enrollment->attestation_mechanism = attestationMechanism_fromJson(json_object_get_object(root_object, ENROLLMENT_JSON_KEY_ATTESTATION));
        new_enrollment->etag = copy_string(json_object_get_string(root_object, ENROLLMENT_JSON_KEY_ETAG));
        new_enrollment->provisioning_status = provisioningStatus_fromJson(json_object_get_string(root_object, ENROLLMENT_JSON_KEY_PROV_STATUS));
        new_enrollment->created_date_time_utc = copy_string(json_object_get_string(root_object, ENROLLMENT_JSON_KEY_CREATED_TIME));
        new_enrollment->updated_date_time_utc = copy_string(json_object_get_string(root_object, ENROLLMENT_JSON_KEY_UPDATED_TIME));
    }

    return new_enrollment;
}

INDIVIDUAL_ENROLLMENT* individualEnrollment_create(const char* reg_id)
{
    INDIVIDUAL_ENROLLMENT* new_enrollment = NULL;
    ATTESTATION_MECHANISM* att_mech = NULL;

    if ((new_enrollment = malloc(sizeof(INDIVIDUAL_ENROLLMENT))) == NULL)
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

        if ((new_enrollment->registration_id = copy_string(reg_id)) == NULL)
        {
            LogError("Allocation of registration id failed");
            individualEnrollment_free(new_enrollment);
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
    
    if ((new_enrollment = individualEnrollment_create(reg_id)) == NULL)
    {
        LogError("Allocation of individual enrollment failed");
    }
    else if ((tpm_attestation = malloc(sizeof(TPM_ATTESTATION))) == NULL)
    {
        LogError("Allocation of TPM attestation failed");
        individualEnrollment_free(new_enrollment);
    }
    else
    {
        memset(tpm_attestation, 0, sizeof(*tpm_attestation));

        if ((tpm_attestation->endorsement_key = copy_string(endorsement_key)) == NULL)
        {
            LogError("Allocation of endorsement key failed");
            individualEnrollment_free(new_enrollment);
        }
        else
        {
            new_enrollment->attestation_mechanism->type = ATTESTATION_TYPE_TPM;
            new_enrollment->attestation_mechanism->attestation.tpm = tpm_attestation;
        }
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
    {
        attestationMechanism_free(enrollment->attestation_mechanism);
    }
    if (enrollment->registration_status != NULL)
    {
        LogError("must implmenet");
    }

    //free twin state

    free(enrollment);
}

const char* individualEnrollment_serialize(const INDIVIDUAL_ENROLLMENT* enrollment)
{
    char* result = NULL;
    JSON_Value* root_value = NULL;

    if (enrollment == NULL)
    {
        LogError("enrollment is NULL");
        result = NULL;
    }
    else if ((root_value = individualEnrollment_toJson(enrollment)) == NULL)
    {
        LogError("something should probably go here");
    }
    else if ((result = json_serialize_to_string(root_value)) == NULL)
    {
        LogError("json_serialize_to_string_failed");
        result = NULL;
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
        LogError("json string is NULL");
        new_enrollment = NULL;
    }
    else if ((root_value = json_parse_string(json_string)) == NULL)
    {
        LogError("json_parse_string failed");
        new_enrollment = NULL;
    }
    else if ((root_object = json_value_get_object(root_value)) == NULL)
    {
        LogError("json_value_get_object failed");
        new_enrollment = NULL;
    }
    else
    {
        new_enrollment = individualEnrollment_fromJson(root_object);
        json_value_free(root_value); //implicitly frees root_object
        root_value = NULL;
        root_object = NULL;
    }
    return new_enrollment;
}
