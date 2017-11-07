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

#include "provisioning_sc_enrollment.h"

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
static const char* TEST_EK = "test-ek";
static const char* TEST_GROUPID = "test-groupid";
static const char* TEST_DEVID = "test-devid";
static const char* TEST_ETAG = "test-etag";
static const char* TEST_REGID = "test-regid";
static const char* TEST_CERT1 = "test-cert-1";
static const char* TEST_CERT2 = "test-cert-2";

static const char* retrieved_json_string = "somestrvalue";

static void register_global_mock_hooks()
{
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, real_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, real_free);
}

static void register_global_mock_returns()
{
    //parson
    REGISTER_GLOBAL_MOCK_RETURN(json_object_get_string, retrieved_json_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(json_object_get_string, NULL);
}

BEGIN_TEST_SUITE(provisioning_sc_enrollment_ut)

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


static void copy_string_expected_calls(void)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void attestationMechanism_free_expected_calls_tpm(void)
{
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void attestationMechanism_createWithX509_expected_calls_OneCert(void)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();
}

static void attestationMechanism_createWithX509_expected_calls_TwoCerts(void)
{
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();
}

static void attestationMechanism_free_expected_calls_x509OneCert(void)
{
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}

static void attestationMechanism_free_expected_calls_x509TwoCerts(void)
{
    //cert 1
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //cert 2
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //rest of structure
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
}


/* UNIT TESTS BEGIN */

/* Tests_ENROLLMENTS_22_001: [If endorsement_key is NULL, attestationMechanism_createWithTpm shall fail and return NULL] */
TEST_FUNCTION(attestationMechanism_createWithTpm_error_NULL_ek)
{
    //arrange

    //act
    ATTESTATION_MECHANISM_HANDLE handle = attestationMechanism_createWithTpm(NULL);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    attestationMechanism_destroy(handle);
}

/* Tests_ENROLLMENTS_22_004: [ Upon successful creation of the new ATTESTATION_MECHANISM_HANDLE, attestationMechanism_createWithTpm shall return it ] */
TEST_FUNCTION(attestationMechanism_createWithTpm_golden)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    ATTESTATION_MECHANISM_HANDLE am_handle = attestationMechanism_createWithTpm(TEST_EK);

    //assert
    ASSERT_IS_NOT_NULL(am_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ASSERT_IS_TRUE(attestationMechanism_getType(am_handle) == ATTESTATION_TYPE_TPM);
    TPM_ATTESTATION_HANDLE tpm_handle = attestationMechanism_getTpmAttestation(am_handle);
    ASSERT_ARE_EQUAL(char_ptr, TEST_EK, tpmAttestation_getEndorsementKey(tpm_handle));

    //cleanup
    attestationMechanism_destroy(am_handle);
}

/* Tests_ENROLLMENTS_22_002: [ If allocating memory for the new attestation mechanism fails, attestationMechanism_createWithTpm shall fail and return NULL ] */
/* Tests_ENROLLMENTS_22_003: [ If setting initial values within the new attestation mechanism fails, attestationMechanism_createWithTpm shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_createWithTpm_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    //copy_string_expected_calls();

    umock_c_negative_tests_snapshot();

    //act
    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        char tmp_msg[128];
        sprintf(tmp_msg, "attestationMechanism_createWithTpm failure in test %zu/%zu", index+1, count);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        ATTESTATION_MECHANISM_HANDLE handle = attestationMechanism_createWithTpm(TEST_EK);

        //assert
        ASSERT_IS_NULL_WITH_MSG(handle, tmp_msg);

        //cleanup
        attestationMechanism_destroy(handle);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Tests_ENROLLMENTS_22_005: [If primary_cert is NULL, attestationMechanism_createWithX509 shall fail and return NULL] */
TEST_FUNCTION(attestationMechanism_createWithX509_error_NULL_certs)
{
    //arrange

    //act
    ATTESTATION_MECHANISM_HANDLE handle = attestationMechanism_createWithX509(NULL, NULL);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    attestationMechanism_destroy(handle);
}

/* Tests_ENROLLMENTS_22_005: [If primary_cert is NULL, attestationMechanism_createWithX509 shall fail and return NULL] */
TEST_FUNCTION(attestationMechanism_createWithX509_NULL_primary)
{
    //arrange

    //act
    ATTESTATION_MECHANISM_HANDLE handle = attestationMechanism_createWithX509(NULL, TEST_CERT2);

    //assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    attestationMechanism_destroy(handle);
}

/* Tests_ENROLLMENTS_22_008: [ Upon successful creation of the new ATTESTATION_MECHANISM_HANDLE, attestationMechanism_createWithX509 shall return it ] */
/* Tests_ENROLLMENTS_22_040: [The new ATTESTATION_MECHANISM_HANDLE will have one certificate if it was only given primary_cert and two certificates if it was also given secondary_cert] */
TEST_FUNCTION(attestationMechanism_createWithX509_golden_primary_cert)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    ATTESTATION_MECHANISM_HANDLE am_handle = attestationMechanism_createWithX509(TEST_CERT1, NULL);

    //assert
    ASSERT_IS_NOT_NULL(am_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ASSERT_IS_TRUE(attestationMechanism_getType(am_handle) == ATTESTATION_TYPE_X509);
    X509_ATTESTATION_HANDLE x509_handle = attestationMechanism_getX509Attestation(am_handle);
    ASSERT_IS_NOT_NULL(x509_handle);
    X509_CERTIFICATE_HANDLE x509_cert_h = x509Attestation_getPrimaryCertificate(x509_handle);
    ASSERT_IS_NOT_NULL(x509_cert_h); //Cert is not exposed in any way, can't actually check it equals TEST_CERT1
    
    //check that its client cert

    //cleanup
    attestationMechanism_destroy(am_handle);
}

/* Tests_ENROLLMENTS_22_006: [ If allocating memory for the new attestation mechanism fails, attestationMechanism_createWithX509 shall fail and return NULL ] */
/* Tests_ENROLLMENTS_22_007: [ If setting initial values within the new attestation mechanism fails, attestationMechanism_createWithX509 shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_createWithX509_primary_cert_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 6 };
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
        sprintf(tmp_msg, "attestationMechanism_createWithX509 failure in test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        ATTESTATION_MECHANISM_HANDLE handle = attestationMechanism_createWithX509(TEST_CERT1, NULL);

        //assert
        ASSERT_IS_NULL_WITH_MSG(handle, tmp_msg);

        //cleanup
        attestationMechanism_destroy(handle);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Tests_ENROLLMENTS_22_008: [ Upon successful creation of the new ATTESTATION_MECHANISM_HANDLE, attestationMechanism_createWithX509 shall return it ] */
/* Tests_ENROLLMENTS_22_040: [The new ATTESTATION_MECHANISM_HANDLE will have one certificate if it was only given primary_cert and two certificates if it was also given secondary_cert] */
TEST_FUNCTION(attestationMechanism_createWithX509_golden_both_certs)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    ATTESTATION_MECHANISM_HANDLE am_handle = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);

    //assert
    ASSERT_IS_NOT_NULL(am_handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ASSERT_IS_TRUE(attestationMechanism_getType(am_handle) == ATTESTATION_TYPE_X509);
    X509_ATTESTATION_HANDLE x509_handle = attestationMechanism_getX509Attestation(am_handle);
    ASSERT_IS_NOT_NULL(x509_handle);
    X509_CERTIFICATE_HANDLE x509_prim_cert_h = x509Attestation_getPrimaryCertificate(x509_handle);
    X509_CERTIFICATE_HANDLE x509_sec_cert_h = x509Attestation_getSecondaryCertificate(x509_handle);
    ASSERT_IS_NOT_NULL(x509_prim_cert_h); //Cert is not exposed in any way, can't actually check it equals TEST_CERT1
    ASSERT_IS_NOT_NULL(x509_sec_cert_h); //Cert is not exposed in any way, can't actually check it equals TEST_CERT2
    //if implemented in the future, check that is Client Cert type

    //cleanup
    attestationMechanism_destroy(am_handle);
}

/* Tests_ENROLLMENTS_22_006: [ If allocating memory for the new attestation mechanism fails, attestationMechanism_createWithX509 shall fail and return NULL ] */
/* Tests_ENROLLMENTS_22_007: [ If setting initial values within the new attestation mechanism fails, attestationMechanism_createWithX509 shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_createWithX509_both_certs_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();


    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 6, 10 };
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
        sprintf(tmp_msg, "attestationMechanism_createWithX509 failure in test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        ATTESTATION_MECHANISM_HANDLE handle = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);

        //assert
        ASSERT_IS_NULL_WITH_MSG(handle, tmp_msg);

        //cleanup
        attestationMechanism_destroy(handle);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Tests_ENROLLMENTS_22_009: [ attestationMechanism_destroy shall free all memory contained within att_handle ] */
TEST_FUNCTION(attestationMechanism_destroy_NULL)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    attestationMechanism_destroy(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_009: [ attestationMechanism_destroy shall free all memory contained within att_handle ] */
TEST_FUNCTION(attestationMechanism_destroy_golden_TPM)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am_handle = attestationMechanism_createWithTpm(TEST_EK);
    umock_c_reset_all_calls();

    attestationMechanism_free_expected_calls_tpm();

    //act
    attestationMechanism_destroy(am_handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_009: [ attestationMechanism_destroy shall free all memory contained within att_handle ] */
TEST_FUNCTION(attestationMechanism_destroy_golden_x509_one_cert)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am_handle = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    umock_c_reset_all_calls();

    attestationMechanism_free_expected_calls_x509OneCert();

    //act
    attestationMechanism_destroy(am_handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_009: [ attestationMechanism_destroy shall free all memory contained within att_handle ] */
TEST_FUNCTION(attestationMechanism_destroy_golden_x509_two_certs)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am_handle = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);
    umock_c_reset_all_calls();

    attestationMechanism_free_expected_calls_x509TwoCerts();

    //act
    attestationMechanism_destroy(am_handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_010: [ If att_handle is NULL, attestationMechanism_getTpmAttestation shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_getTpmAttestation_error_NULL_handle)
{
    //arrange

    //act
    TPM_ATTESTATION_HANDLE tpm = attestationMechanism_getTpmAttestation(NULL);

    //assert
    ASSERT_IS_NULL(tpm);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    
}

/* Tests_ENROLLMENTS_22_011: [ If the attestation type of att_handle is not TPM, attestationMechanism_getTpmAttestation shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_getTpmAttestation_error_X509_handle)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    umock_c_reset_all_calls();

    //act
    TPM_ATTESTATION_HANDLE tpm = attestationMechanism_getTpmAttestation(am);

    //assert
    ASSERT_IS_NULL(tpm);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    attestationMechanism_destroy(am);

}

/* Tests_ENROLLMENTS_22_012: [ Upon success, attestationMechanism_getTpmAttestation shall return a handle for the TPM Attestation contained in att_handle ] */
TEST_FUNCTION(attestationMechanism_getTpmAttestation_golden)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    umock_c_reset_all_calls();

    //act
    TPM_ATTESTATION_HANDLE tpm = attestationMechanism_getTpmAttestation(am);

    //assert
    ASSERT_IS_NOT_NULL(tpm);
    ASSERT_ARE_EQUAL(char_ptr, TEST_EK, tpmAttestation_getEndorsementKey(tpm));
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    attestationMechanism_destroy(am);

}

/* Tests_ENROLLMENTS_22_013: [ If att_handle is NULL, attestationMechanism_getX509Attestation shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_getX509Attestation_error_NULL_handle)
{
    //arrange

    //act
    X509_ATTESTATION_HANDLE x509 = attestationMechanism_getX509Attestation(NULL);

    //assert
    ASSERT_IS_NULL(x509);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup

}

/* Tests_ENROLLMENTS_22_014: [ If the attestation type of att_handle is not X509, attestationMechanism_getX509Attestation shall fail and return NULL ] */
TEST_FUNCTION(attestationMechanism_getX509Attestation_error_TPM_handle)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    umock_c_reset_all_calls();

    //act
    X509_ATTESTATION_HANDLE x509 = attestationMechanism_getX509Attestation(am);

    //assert
    ASSERT_IS_NULL(x509);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    attestationMechanism_destroy(am);

}

/* Tests_SRS_ENROLLMENTS_22_015: [ Upon success attestationMechanism_getTpmAttestation shall return a handle for the X509 Attestation contained in att_handle ] */
TEST_FUNCTION(attestationMechanism_getX509Attestation_golden)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);
    umock_c_reset_all_calls();

    //act
    X509_ATTESTATION_HANDLE x509 = attestationMechanism_getX509Attestation(am);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NOT_NULL(x509);
    X509_CERTIFICATE_HANDLE x509_cert = x509Attestation_getPrimaryCertificate(x509);
    ASSERT_IS_NOT_NULL(x509_cert);

    //cleanup
    attestationMechanism_destroy(am);

}

/* Tests_ENROLLMENTS_22_016: [ If reg_id is NULL, individualEnrollment_create shall fail and return NULL ] */
TEST_FUNCTION(individualEnrollment_create_error_NULL_regid)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    umock_c_reset_all_calls();

    //act
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(NULL, am);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NOT_NULL(am);
    ASSERT_IS_NULL(ie);

    //cleanup
    if (ie != NULL)
        individualEnrollment_destroy(ie);
    else
        attestationMechanism_destroy(am);
}

/* Tests_ENROLLMENTS_22_017: [ If att_handle is NULL, individualEnrollment_create shall fail and return NULL ] */
TEST_FUNCTION(individualEnrollment_create_error_NULL_att_handle)
{
    //arrange

    //act
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NULL(ie);

    //cleanup
    individualEnrollment_destroy(ie);
}

/* Test_ENROLLMENTS_22_018: [ If allocating memory for the new individual enrollment fails, individualEnrollment_create shall fail and return NULL ] */
/* Test_ENROLLMENTS_22_019: [ If setting initial values within the new individual enrollment fails, individualEnrollment_create shall fail and return NULL ] */
TEST_FUNCTION(individualEnrollment_create_fail)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    //TPM Attestation calls to be skipped
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //actual individualEnrollment calls
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 0, 1, 2, 3, 6 };
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
        char tmp_msg2[128];
        sprintf(tmp_msg, "individualEnrollment_create failure in test %zu/%zu", test_num, test_max);
        sprintf(tmp_msg2, "Unexpected attestationMechanism create failure in individualEnrollment failure test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK); //all calls in here will be skipped so will not fail
        INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);

        //assert
        ASSERT_IS_NOT_NULL_WITH_MSG(am, tmp_msg2); //this failing indicates bug in test, not fn being tested
        ASSERT_IS_NULL_WITH_MSG(ie, tmp_msg);

        //cleanup
        if (ie != NULL)
            individualEnrollment_destroy(ie);
        else
            attestationMechanism_destroy(am);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Test_ENROLLMENTS_22_020: [ Upon success, individualEnrollment_create shall return a handle for the new individual enrollment ] */
TEST_FUNCTION(individualEnrollment_create_golden_tpm)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NOT_NULL(ie);
    ASSERT_ARE_EQUAL(char_ptr, individualEnrollment_getRegistrationId(ie), TEST_REGID);
    ASSERT_IS_TRUE(individualEnrollment_getProvisioningStatus(ie) == PROVISIONING_STATUS_ENABLED);
    ASSERT_IS_TRUE(individualEnrollment_getAttestationMechanism(ie) == am);

    //cleanup
    if (ie != NULL)
        individualEnrollment_destroy(ie);
    else
        attestationMechanism_destroy(am);
}

/* Test_ENROLLMENTS_22_020: [ Upon success, individualEnrollment_create shall return a handle for the new individual enrollment ] */
TEST_FUNCTION(individualEnrollment_create_golden_x509)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NOT_NULL(ie);
    ASSERT_ARE_EQUAL(char_ptr, individualEnrollment_getRegistrationId(ie), TEST_REGID);
    ASSERT_IS_TRUE(individualEnrollment_getProvisioningStatus(ie) == PROVISIONING_STATUS_ENABLED);
    ASSERT_IS_TRUE(individualEnrollment_getAttestationMechanism(ie) == am);

    //cleanup
    if (ie != NULL)
        individualEnrollment_destroy(ie);
    else
        attestationMechanism_destroy(am);
}

/* Test_ENROLLMENTS_22_021: [ individualEnrollment_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(individualEnrollment_destroy_error_NULL)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    individualEnrollment_destroy(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Test_ENROLLMENTS_22_021: [ individualEnrollment_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(individualEnrollment_destroy_golden_TPM_attestation)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    attestationMechanism_free_expected_calls_tpm();

    //act
    individualEnrollment_destroy(ie);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Test_ENROLLMENTS_22_021: [ individualEnrollment_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(individualEnrollment_destroy_golden_X509_attestation_one_cert)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    attestationMechanism_free_expected_calls_x509OneCert();

    //act
    individualEnrollment_destroy(ie);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Test_ENROLLMENTS_22_021: [ individualEnrollment_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(individualEnrollment_destroy_golden_X509_attestation_two_certs)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    attestationMechanism_free_expected_calls_x509TwoCerts();

    //act
    individualEnrollment_destroy(ie);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_022: [ If group_id is NULL, enrollmentGroup_create shall fail and return NULL ] */
TEST_FUNCTION(enrollmentGroup_create_error_NULL_groupid)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    umock_c_reset_all_calls();

    //act
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(NULL, am);

    //assert
    ASSERT_IS_NULL(eg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    if (eg != NULL)
        enrollmentGroup_destroy(eg);
    else
        attestationMechanism_destroy(am);
}

/* Tests_ENROLLMENTS_22_023: [ If att_handle is NULL, enrollmentGroup_create shall fail and return NULL ] */
TEST_FUNCTION(enrollmentGroup_create_error_NULL_attmech)
{
    //arrange

    //act
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_GROUPID, NULL);

    //assert
    ASSERT_IS_NULL(eg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    enrollmentGroup_destroy(eg);
}

/* Tests_ENROLLMENTS_22_041: [ If att_handle has an invalid Attestation Type (e.g. TPM), enrollmentGroup_create shall fail and return NULL ] */
TEST_FUNCTION(enrollmentGroup_create_error_TPM_attmech)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithTpm(TEST_EK);
    umock_c_reset_all_calls();

    //act
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_GROUPID, am);

    //assert
    ASSERT_IS_NULL(eg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
    if (eg != NULL)
        enrollmentGroup_destroy(eg);
    else
        attestationMechanism_destroy(am);

}

/* Tests_ENROLLMENTS_22_026: [Upon success, enrollmentGroup_create shall return a handle for the new enrollment group] */
TEST_FUNCTION(enrollmentGroup_create_golden_X509_one_cert)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_GROUPID, am);

    //assert
    ASSERT_IS_NOT_NULL(eg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(char_ptr, enrollmentGroup_getGroupId(eg), TEST_GROUPID);
    ASSERT_IS_TRUE(enrollmentGroup_getProvisioningStatus(eg) == PROVISIONING_STATUS_ENABLED);

    //cleanup
    if (eg != NULL)
        enrollmentGroup_destroy(eg);
    else
        attestationMechanism_destroy(am);
}

/* Tests_ENROLLMENTS_22_026: [Upon success, enrollmentGroup_create shall return a handle for the new enrollment group] */
TEST_FUNCTION(enrollmentGroup_create_golden_X509_two_certs)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    //act
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_GROUPID, am);

    //assert
    ASSERT_IS_NOT_NULL(eg);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(char_ptr, enrollmentGroup_getGroupId(eg), TEST_GROUPID);
    ASSERT_IS_TRUE(enrollmentGroup_getProvisioningStatus(eg) == PROVISIONING_STATUS_ENABLED);

    //cleanup
    if (eg != NULL)
        enrollmentGroup_destroy(eg);
    else
        attestationMechanism_destroy(am);
}

/* Tests_ENROLLMENTS_22_024: [ If allocating memory for the new enrollment group fails, enrollmentGroup_create shall fail and return NULL ] */
/* Tests_ENROLLMENTS_22_025: [ If setting initial values within the new enrollment group fails, enrollmentGroup_create shall fail and return NULL ] */
TEST_FUNCTION(enrollmentGroup_create_fail_x509_one_cert)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    //x509 Attestation calls to be skipped
    attestationMechanism_createWithX509_expected_calls_OneCert();

    //actual individualEnrollment calls
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 0, 1, 2, 3, 4, 5, 6, 9 };
    size_t num_cannot_fail = sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0]);
    size_t count = umock_c_negative_tests_call_count();

    size_t test_num = 0;
    size_t test_max = count - num_cannot_fail;

    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, num_cannot_fail) != 0)
            continue;
        test_num++;

        char tmp_msg[128];
        char tmp_msg2[128];
        sprintf(tmp_msg, "individualEnrollment_create failure in test %zu/%zu", test_num, test_max);
        sprintf(tmp_msg2, "Unexpected attestationMechanism create failure in individualEnrollment failure test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL); //all calls in here will be skipped so will not fail
        INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);

        //assert
        ASSERT_IS_NOT_NULL_WITH_MSG(am, tmp_msg2); //this failing indicates bug in test, not fn being tested
        ASSERT_IS_NULL_WITH_MSG(ie, tmp_msg);

        //cleanup
        if (ie != NULL)
            individualEnrollment_destroy(ie);
        else
            attestationMechanism_destroy(am);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Tests_ENROLLMENTS_22_024: [ If allocating memory for the new enrollment group fails, enrollmentGroup_create shall fail and return NULL ] */
/* Tests_ENROLLMENTS_22_025: [ If setting initial values within the new enrollment group fails, enrollmentGroup_create shall fail and return NULL ] */
TEST_FUNCTION(enrollmentGroup_create_fail_x509_two_certs)
{
    //arrange
    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    //x509 Attestation calls to be skipped
    attestationMechanism_createWithX509_expected_calls_TwoCerts();

    //actual individualEnrollment calls
    STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    copy_string_expected_calls();

    umock_c_negative_tests_snapshot();

    size_t calls_cannot_fail[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13 };
    size_t count = umock_c_negative_tests_call_count();
    size_t num_cannot_fail = sizeof(calls_cannot_fail) / sizeof(calls_cannot_fail[0]);

    size_t test_num = 0;
    size_t test_max = count - num_cannot_fail;

    for (size_t index = 0; index < count; index++)
    {
        if (should_skip_index(index, calls_cannot_fail, num_cannot_fail) != 0)
            continue;
        
        test_num++;
        char tmp_msg[128];
        char tmp_msg2[128];
        sprintf(tmp_msg, "individualEnrollment_create failure in test %zu/%zu", test_num, test_max);
        sprintf(tmp_msg2, "Unexpected attestationMechanism create failure in individualEnrollment failure test %zu/%zu", test_num, test_max);

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        //act
        ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2); //all calls in here will be skipped so will not fail
        INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, am);

        //assert
        ASSERT_IS_NOT_NULL_WITH_MSG(am, tmp_msg2); //this failing indicates bug in test, not fn being tested
        ASSERT_IS_NULL_WITH_MSG(ie, tmp_msg);

        //cleanup
        if (ie != NULL)
            individualEnrollment_destroy(ie);
        else
            attestationMechanism_destroy(am);
    }

    //cleanup
    umock_c_negative_tests_deinit();
}

/* Tests_ENROLLMENTS_22_027: [ enrollmentGroup_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(enrollmentGroup_destroy_NULL)
{
    //arrange
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    enrollmentGroup_destroy(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_027: [ enrollmentGroup_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(enrollmentGroup_destroy_x509_one_cert)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    attestationMechanism_free_expected_calls_x509OneCert();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    enrollmentGroup_destroy(eg);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_027: [ enrollmentGroup_destroy shall free all memory contained within handle ] */
TEST_FUNCTION(enrollmentGroup_destroy_x509_two_certs)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE am = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);
    ENROLLMENT_GROUP_HANDLE eg = enrollmentGroup_create(TEST_REGID, am);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    attestationMechanism_free_expected_calls_x509TwoCerts();
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    //act
    enrollmentGroup_destroy(eg);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    //cleanup
}

/* Tests_ENROLLMENTS_22_042 : [When <RETURN_TYPE> is ATTESTATION_TYPE, the default return value is ATTESTATION_TYPE_NONE] */
/* Tests_ENROLLMENTS_22_028 : [If handle is NULL, the function shall return the default return value of <RETURN_TYPE>] */
/* Tests_ENROLLMENTS_22_034 : [Otherwise the function shall return the specified property, which may or may not be the same as the default value] */
TEST_FUNCTION(attestationMechanism_accessors_get)
{
    //arrange
    ATTESTATION_MECHANISM_HANDLE tpm = attestationMechanism_createWithTpm(TEST_EK);
    ATTESTATION_MECHANISM_HANDLE x509one = attestationMechanism_createWithX509(TEST_CERT1, NULL);
    ATTESTATION_MECHANISM_HANDLE x509two = attestationMechanism_createWithX509(TEST_CERT1, TEST_CERT2);

    //act
    ATTESTATION_TYPE t1 = attestationMechanism_getType(tpm);
    ATTESTATION_TYPE t2 = attestationMechanism_getType(x509one);
    ATTESTATION_TYPE t3 = attestationMechanism_getType(x509two);
    ATTESTATION_TYPE t4 = attestationMechanism_getType(NULL);

    //assert
    ASSERT_IS_TRUE(t1 == ATTESTATION_TYPE_TPM);
    ASSERT_IS_TRUE(t2 == ATTESTATION_TYPE_X509);
    ASSERT_IS_TRUE(t3 == ATTESTATION_TYPE_X509);
    ASSERT_IS_TRUE(t4 == ATTESTATION_TYPE_NONE);

    //cleanup
    attestationMechanism_destroy(tpm);
    attestationMechanism_destroy(x509one);
    attestationMechanism_destroy(x509two);
}

TEST_FUNCTION(individualEnrollment_accessors_get_golden)
{
    //assert
    ATTESTATION_MECHANISM_HANDLE tpm = attestationMechanism_createWithTpm(TEST_EK);
    INDIVIDUAL_ENROLLMENT_HANDLE ie = individualEnrollment_create(TEST_REGID, tpm);
    individualEnrollment_setDeviceId(ie, TEST_DEVID);
    individualEnrollment_setEtag(ie, TEST_ETAG);

    //act
    ATTESTATION_MECHANISM_HANDLE am = individualEnrollment_getAttestationMechanism(ie);
    const char* regid = individualEnrollment_getRegistrationId(ie);
    const char* devid = individualEnrollment_getDeviceId(ie);
    DEVICE_REGISTRATION_STATE_HANDLE drs = individualEnrollment_getDeviceRegistrationState(ie); //Note this will be null as there's no way to set it manually right now
    const char* etag = individualEnrollment_getEtag(ie);
    PROVISIONING_STATUS ps = individualEnrollment_getProvisioningStatus(ie);
    const char* created = individualEnrollment_getCreatedDateTime(ie); //Note this will be null as there's no way to set it manually (generated by provisioning client)
    const char* updated = individualEnrollment_getUpdatedDateTime(ie); //Note this will be null as there's no way to set it manually (generated by provisioning client)

    //assert
    ASSERT_IS_TRUE(tpm == am);
    ASSERT_ARE_EQUAL(char_ptr, regid, TEST_REGID);
    ASSERT_ARE_EQUAL(char_ptr, devid, TEST_DEVID);
    ASSERT_IS_TRUE(drs == NULL);
    ASSERT_ARE_EQUAL(char_ptr, etag, TEST_ETAG);
    ASSERT_IS_TRUE(ps == PROVISIONING_STATUS_ENABLED);
    ASSERT_IS_NULL(created); //note this is not a good test because while NULL is correct return val, NULL also could be incorrect - cover these cases in future integration tests
    ASSERT_IS_NULL(updated); //as above

    //cleanup
    individualEnrollment_destroy(ie);

    //finish this test when serializer works

}

END_TEST_SUITE(provisioning_sc_enrollment_ut)
