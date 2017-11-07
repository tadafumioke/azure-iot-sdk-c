// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

void* real_malloc(size_t size)
{
    return malloc(size);
}

void real_free(void* ptr)
{
    free(ptr);
}

#include "testrunnerswitcher.h"
#include "azure_c_shared_utility/macro_utils.h"
#include "umock_c.h"
#include "umock_c_negative_tests.h"

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include "parson.h"

#include "azure_c_shared_utility/umock_c_prod.h"
MOCKABLE_FUNCTION(, JSON_Value*, json_parse_string, const char*, string);
MOCKABLE_FUNCTION(, char*, json_serialize_to_string, const JSON_Value*, value);
MOCKABLE_FUNCTION(, const char*, json_object_get_string, const JSON_Object*, object, const char *, name);
MOCKABLE_FUNCTION(, JSON_Object*, json_object_get_object, const JSON_Object*, object, const char*, name);
MOCKABLE_FUNCTION(, double, json_object_get_number, const JSON_Object*, object, const char*, name);
MOCKABLE_FUNCTION(, int, json_object_has_value, const JSON_Object*, object, const char*, name);
MOCKABLE_FUNCTION(, JSON_Status, json_object_set_value, JSON_Object*, object, const char*, name, JSON_Value*, value);
MOCKABLE_FUNCTION(, JSON_Status, json_object_set_string, JSON_Object*, object, const char*, name, const char*, string);
MOCKABLE_FUNCTION(, JSON_Status, json_object_set_number, JSON_Object*, object, const char*, name, double, number);
MOCKABLE_FUNCTION(, JSON_Value*, json_value_init_object);
MOCKABLE_FUNCTION(, void, json_value_free, JSON_Value*, value);
MOCKABLE_FUNCTION(, JSON_Object*, json_value_get_object, const JSON_Value*, value);

#undef ENABLE_MOCKS

void dummy_json_value_free(JSON_Value* val)
{
    (void)val;
}

#include "provisioning_sc_enrollment.h"
#include "provisioning_sc_enrollment_private.h"

static TEST_MUTEX_HANDLE g_testByTest;
static TEST_MUTEX_HANDLE g_dllByDll;

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s", ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

//Control Parameters
#define TEST_JSON_ROOT_VALUE (JSON_Value*)0x11111112
#define TEST_JSON_OBJECT_VALUE (JSON_Object*)0x11111113

static char* retrieved_json_string = "somestrvalue";
static char* serialized_json_string = "{json:json}";

typedef enum {MIN_CASE, MAX_CASE} testcase;
typedef enum {CLIENT, SIGNING, NOCERT} certtype;

static const char* TEST_REGID = "my-reg-id";
static const char* TEST_GRPID = "my-group-id";
static const char* TEST_DEVID = "my-dev-id";
static const char* TEST_EK = "my-ek";
static const char* TEST_CERT1 = "my-cert1";

static void register_global_mock_hooks()
{
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, real_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, real_free);

    REGISTER_GLOBAL_MOCK_HOOK(json_value_free, dummy_json_value_free);
}

static void register_global_mock_returns()
{
    //parson
    REGISTER_GLOBAL_MOCK_RETURN(json_value_init_object, TEST_JSON_ROOT_VALUE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_value_init_object, NULL);

    REGISTER_GLOBAL_MOCK_RETURN(json_value_get_object, TEST_JSON_OBJECT_VALUE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_value_get_object, NULL);

    REGISTER_GLOBAL_MOCK_RETURN(json_object_set_string, JSONSuccess);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_object_set_string, JSONFailure);

    REGISTER_GLOBAL_MOCK_RETURN(json_object_get_string, retrieved_json_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_object_get_string, NULL);

    REGISTER_GLOBAL_MOCK_RETURN(json_object_set_value, JSONSuccess);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_object_set_value, JSONFailure);

    REGISTER_GLOBAL_MOCK_RETURN(json_object_set_number, JSONSuccess);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_object_set_number, JSONFailure);

    REGISTER_GLOBAL_MOCK_RETURN(json_object_get_object, TEST_JSON_OBJECT_VALUE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_object_get_object, NULL);

    REGISTER_GLOBAL_MOCK_RETURN(json_serialize_to_string, serialized_json_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_serialize_to_string, NULL);

    REGISTER_GLOBAL_MOCK_RETURN(json_parse_string, TEST_JSON_ROOT_VALUE);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_parse_string, NULL);

    //REGISTER_GLOBAL_MOCK_RETURN(json_value_free, 1);
}

BEGIN_TEST_SUITE(provisioning_sc_enrollment_private_ut)

TEST_SUITE_INITIALIZE(TestClassInitialize)
{
    TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    umock_c_init(on_umock_c_error);

    register_global_mock_hooks();
    register_global_mock_returns();
}

TEST_SUITE_CLEANUP(TestClassCleanup)
{
    umock_c_deinit();

    TEST_MUTEX_DESTROY(g_testByTest);
    TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
}

TEST_FUNCTION_INITIALIZE(TestMethodInitialize)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("our mutex is ABANDONED. Failure in test framework");
    }

    umock_c_negative_tests_deinit();
    umock_c_reset_all_calls();
}

TEST_FUNCTION_CLEANUP(TestMethodCleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

//static helper fns
static int should_skip_index(size_t current_index, const size_t skip_array[], size_t length)
{
    int result = 0;
    for (size_t index = 0; index < length; index++)
    {
        if (current_index == skip_array[index])
        {
            result = __LINE__;
            break;
        }
    }
    return result;
}

static void expected_calls_copy_string(void)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void expected_calls_copy_json_string_field(void)
{
    STRICT_EXPECTED_CALL(json_object_get_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    expected_calls_copy_string();
}

static void expected_calls_x509CertificateInfo_toJson(testcase tc)
{
    (void)tc; //technically this is all optional
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //subject name
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //sha1
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //sha256
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //issuer name
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //not before utc
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //not after utc
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //serial no
    STRICT_EXPECTED_CALL(json_object_set_number(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)); //version
}

static void expected_calls_x509CertificateWithInfo_toJson(testcase tc)
{
    (void)tc;
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //certificate - technically optional, but not really
    expected_calls_x509CertificateInfo_toJson(tc);
    STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //info
}

static void expected_calls_x509Certificates_toJson(testcase tc)
{
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    expected_calls_x509CertificateWithInfo_toJson(tc);
    STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //primary_cert
    if (tc == MAX_CASE)
    {
        expected_calls_x509CertificateWithInfo_toJson(tc);
        STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //secondary_cert
    }
}

static void expected_calls_x509Attestation_toJson(testcase tc)
{
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    expected_calls_x509Certificates_toJson(tc);
    STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //certs_val
}

static void expected_calls_tpmAttestation_toJson(testcase tc)
{
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //endorsement key
    if (tc == MAX_CASE)
        STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //storage root key
}

static void expected_calls_attestationMechanism_toJson(ATTESTATION_TYPE att_type, testcase tc)
{
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    //call to convert attestation type has no further calls to specify, but would go here if it did
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //attestation type

    if (att_type == ATTESTATION_TYPE_TPM)
        expected_calls_tpmAttestation_toJson(tc);
    else if (att_type == ATTESTATION_TYPE_X509)
        expected_calls_x509Attestation_toJson(tc);

    STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //tpm/x509 attestation

}

static void expected_calls_individualEnrollment_toJson(ATTESTATION_TYPE att_type, testcase tc)
{
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //reg_id
    if (tc == MAX_CASE)
        STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //dev_id
    expected_calls_attestationMechanism_toJson(att_type, tc);
    STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //attestation mechanism
    if (tc == MAX_CASE)
        STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //etag
    //call to convert provisioning status has no further calls to specify, but would go here if it did
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //provisioning_status
    //create and update times are never converted in any case
}

static void expected_calls_individualEnrollment_serializeToJson(ATTESTATION_TYPE att_type, testcase tc)
{
    expected_calls_individualEnrollment_toJson(att_type, tc);
    STRICT_EXPECTED_CALL(json_serialize_to_string(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_value_free(IGNORED_PTR_ARG));
}

static void expected_calls_enrollmentGroup_toJson(ATTESTATION_TYPE att_type, testcase tc)
{
    STRICT_EXPECTED_CALL(json_value_init_object());
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //group id
    expected_calls_attestationMechanism_toJson(att_type, tc);
    STRICT_EXPECTED_CALL(json_object_set_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //attestation mechanism
    if (tc == MAX_CASE)
        STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //etag
    STRICT_EXPECTED_CALL(json_object_set_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //provisioning_status

}

static void expected_calls_enrollmentGroup_serializeToJson(ATTESTATION_TYPE att_type, testcase tc)
{
    expected_calls_enrollmentGroup_toJson(att_type, tc);
    STRICT_EXPECTED_CALL(json_serialize_to_string(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_value_free(IGNORED_PTR_ARG));
}

static void expected_calls_x509CertificateInfo_fromJson(testcase tc)
{
    (void)tc;
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    expected_calls_copy_json_string_field(); //subject name
    expected_calls_copy_json_string_field(); //sha1
    expected_calls_copy_json_string_field(); //sha256
    expected_calls_copy_json_string_field(); //issuer name
    expected_calls_copy_json_string_field(); //not before utc
    expected_calls_copy_json_string_field(); //not after utc
    expected_calls_copy_json_string_field(); //serial number
    STRICT_EXPECTED_CALL(json_object_get_number(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //version
}

static void expected_calls_x509CertificateWithInfo_fromJson(testcase tc)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    expected_calls_copy_json_string_field();
    STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //cert info
    expected_calls_x509CertificateInfo_fromJson(tc); //cert info
}

static void expected_calls_x509Certificates_fromJson(testcase tc)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //cert with info
    expected_calls_x509CertificateWithInfo_fromJson(tc); //cert with info
    STRICT_EXPECTED_CALL(json_object_has_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //checking for secondary cert
    if (tc == MAX_CASE)
    {
        STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //cert with info
        expected_calls_x509CertificateWithInfo_fromJson(tc); //cert with info
    }
}

static void expected_calls_x509Attestation_fromJson(testcase tc, certtype ct)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(json_object_has_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    if (ct == SIGNING)
        STRICT_EXPECTED_CALL(json_object_has_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //second check only if signing
    STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //x509 certs
    expected_calls_x509Certificates_fromJson(tc); //x509 certs
}

static void expected_calls_tpmAttestation_fromJson(testcase tc)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    expected_calls_copy_json_string_field(); //ek

    if (tc == MAX_CASE)
    {
        expected_calls_copy_json_string_field(); //srk
    }
}

static void expected_calls_attestationMechanism_fromJson(ATTESTATION_TYPE att_type, testcase tc, certtype ct)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(json_object_get_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //attestation type
    if (att_type == ATTESTATION_TYPE_TPM)
    {
        STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //tpm attestation
        expected_calls_tpmAttestation_fromJson(tc); //tpm attestation
    }
    else if (att_type == ATTESTATION_TYPE_X509)
    {
        STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //x509 attestation
        expected_calls_x509Attestation_fromJson(tc, ct); //x509 attestation
    }
}

static void expected_calls_deviceRegistrationState_fromJson(testcase tc)
{
    (void)tc;
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    expected_calls_copy_json_string_field(); //Reg ID
    expected_calls_copy_json_string_field(); //Created Date Time
    expected_calls_copy_json_string_field(); //Device ID
    STRICT_EXPECTED_CALL(json_object_get_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //registration status
    expected_calls_copy_json_string_field(); //updated date time
    expected_calls_copy_json_string_field(); //error msg
    expected_calls_copy_json_string_field(); //etag
    STRICT_EXPECTED_CALL(json_object_get_number(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
}

static void expected_calls_individualEnrollment_fromJson(ATTESTATION_TYPE att_type, testcase tc)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    expected_calls_copy_json_string_field(); //reg id
    expected_calls_copy_json_string_field(); //device id
    if (tc == MAX_CASE)
    {
        STRICT_EXPECTED_CALL(json_object_has_value(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //device reg state
        STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
        expected_calls_deviceRegistrationState_fromJson(tc); 
    }
    STRICT_EXPECTED_CALL(json_object_get_object(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //att mech
    expected_calls_attestationMechanism_fromJson(att_type, tc, NOCERT); //att mech
    expected_calls_copy_json_string_field(); //etag
    STRICT_EXPECTED_CALL(json_object_get_string(IGNORED_PTR_ARG, IGNORED_PTR_ARG)); //prov status
    expected_calls_copy_json_string_field(); //created time
    expected_calls_copy_json_string_field(); //updated time

    //still more to add here need to test first

}

static void expected_calls_individualEnrollment_deserializeFromJson(ATTESTATION_TYPE att_type, testcase tc)
{
    STRICT_EXPECTED_CALL(json_parse_string(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(json_value_get_object(IGNORED_PTR_ARG));
    expected_calls_individualEnrollment_fromJson(att_type, tc);
    STRICT_EXPECTED_CALL(json_value_free(IGNORED_PTR_ARG));
}

/* UNIT TESTS BEGIN */

TEST_FUNCTION(individualEnrollment_serializeToJson_error_NULL)
{
    //arrange

    //act
    const char* json = individualEnrollment_serializeToJson(NULL);

    //assert
    ASSERT_IS_NULL(json);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(individualEnrollment_serializeToJson_TpmMinCase_golden)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    expected_calls_individualEnrollment_serializeToJson(ATTESTATION_TYPE_TPM, MIN_CASE);

    //act
    const char* json = individualEnrollment_serializeToJson(ie);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, json, serialized_json_string);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    individualEnrollment_destroy(ie);
}

TEST_FUNCTION(individualEnrollment_serializeToJson_TpmMinCase_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    expected_calls_individualEnrollment_serializeToJson(ATTESTATION_TYPE_TPM, MIN_CASE);

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 13 };
    size_t count = umock_c_negative_tests_call_count();
    size_t num_cannot_fail = sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0]);

    size_t test_num = 0;
    size_t test_max = count - num_cannot_fail;

    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0])) != 0)
            continue;
        test_num++;

        char tmp_msg[128];
        sprintf(tmp_msg, "individualEnrollment_serializeToJson_TpmMinCase failure in test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        const char* json = individualEnrollment_serializeToJson(ie);

        //assert
        ASSERT_IS_NULL_WITH_MSG(json, tmp_msg);

    }

    //cleanup
    individualEnrollment_destroy(ie);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(individualEnrollment_serializeToJson_X509MinCase_golden)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    expected_calls_individualEnrollment_serializeToJson(ATTESTATION_TYPE_X509, MIN_CASE);

    //act
    const char* json = individualEnrollment_serializeToJson(ie);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, json, serialized_json_string);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    individualEnrollment_destroy(ie);
}

TEST_FUNCTION(individualEnrollment_serializeToJson_X509MinCase_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    expected_calls_individualEnrollment_serializeToJson(ATTESTATION_TYPE_X509, MIN_CASE);

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 30 };
    size_t count = umock_c_negative_tests_call_count();
    size_t num_cannot_fail = sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0]);

    size_t test_num = 0;
    size_t test_max = count - num_cannot_fail;

    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0])) != 0)
            continue;
        test_num++;

        char tmp_msg[128];
        sprintf(tmp_msg, "individualEnrollment_serializeToJson_X509MinCase failure in test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        const char* json = individualEnrollment_serializeToJson(ie);

        //assert
        ASSERT_IS_NULL_WITH_MSG(json, tmp_msg);

    }

    //cleanup
    individualEnrollment_destroy(ie);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(enrollmentGroup_serializeToJson_error_NULL)
{
    //arrange

    //act
    const char* json = enrollmentGroup_serializeToJson(NULL);

    //assert
    ASSERT_IS_NULL(json);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

TEST_FUNCTION(enrollmentGroup_serializeToJson_X509MinCase_golden)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_GRPID, am);
    umock_c_reset_all_calls();

    expected_calls_enrollmentGroup_serializeToJson(ATTESTATION_TYPE_X509, MIN_CASE);

    //act
    const char* json = enrollmentGroup_serializeToJson(eg);

    //assert
    ASSERT_IS_NOT_NULL(json);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    enrollmentGroup_destroy(eg);
}

TEST_FUNCTION(enrollmentGroup_serializeToJson_X509MinCase_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_GRPID, am);
    umock_c_reset_all_calls();

    expected_calls_enrollmentGroup_serializeToJson(ATTESTATION_TYPE_X509, MIN_CASE);

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 30 };
    size_t count = umock_c_negative_tests_call_count();
    size_t num_cannot_fail = sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0]);

    size_t test_num = 0;
    size_t test_max = count - num_cannot_fail;

    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0])) != 0)
            continue;
        test_num++;

        char tmp_msg[128];
        sprintf(tmp_msg, "enrollmentGroup_serializeToJson_X509MinCase failure in test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        const char* json = enrollmentGroup_serializeToJson(eg);

        //assert
        ASSERT_IS_NULL_WITH_MSG(json, tmp_msg);

    }

    //cleanup
    enrollmentGroup_destroy(eg);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(individualEnrollment_deserializeFromJson_error_NULL)
{
    //arrange

    //act
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_deserializeFromJson(NULL);

    //assert
    ASSERT_IS_NULL(ie);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    individualEnrollment_destroy(ie);
}

/* Testing of Serialize MAX cases, as well as all Deserialize cases require integration testing and cannot be done with pure unit testing */
END_TEST_SUITE(provisioning_sc_enrollment_private_ut)
