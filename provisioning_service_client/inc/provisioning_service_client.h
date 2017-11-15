// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SERVICE_CLIENT_H
#define PROVISIONING_SERVICE_CLIENT_H

#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"
#include "azure_c_shared_utility/shared_util_options.h"

#include "provisioning_sc_enrollment.h"
#include "provisioning_sc_query.h"
#include "provisioning_sc_bulk_operation.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    #define TRACING_STATUS_VALUES \
            TRACING_STATUS_ON,\
            TRACING_STATUS_OFF
    DEFINE_ENUM(TRACING_STATUS, TRACING_STATUS_VALUES);

    /** @brief  Handle to hide struct and use it in consequent APIs
    */
    typedef struct PROVISIONING_SERVICE_CLIENT_TAG* PROVISIONING_SERVICE_CLIENT_HANDLE;

    /** @brief  Creates a Provisioning Service Client handle for use in consequent APIs.
    *
    * @param    conn_string     A connection string used to establish connection with the Provisioning Service.
    *
    * @return   A non-NULL PROVISIONING_SERVICE_CLIENT_HANDLE value that is used when invoking other functions in the Provisioning Service Client
    *           and NULL on failure.
    */
    MOCKABLE_FUNCTION(, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_sc_create_from_connection_string, const char*, conn_string);

    /** @brief  Disposes of resources allocated by creating a Provisioning Service Client handle.
    *
    * @param    prov_client     The handle created by a call to the create function.
    */
    MOCKABLE_FUNCTION(, void, prov_sc_destroy, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client);

    /** @brief  Sets tracing/logging of http communications on or off.
    *
    * @param    prov_client     The handle for the connection that should be traced.
    * @param    status          The tracing status to set.
    */
    MOCKABLE_FUNCTION(, void, prov_sc_set_trace, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, TRACING_STATUS, status);

    /** @brief  Set the trusted certificate for HTTP communication with the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    certificate     The trusted certificate to be used for HTTP connections. If given as NULL, will clear a previously set certificate.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_set_certificate, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, certificate);

    /** @brief  Set the proxy options for HTTP communication with the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    proxy_options   A struct containing the desired proxy settings
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_set_proxy, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, HTTP_PROXY_OPTIONS*, proxy_options);

    /** @brief Creates or updates an individual device enrollment record on the Provisioning Service, reflecting the changes in the given struct.
    *
    * @param    prov_client         The handle used for connecting to the Provisioning Service.
    * @param    enrollment_ptr      Pointer to a handle for a new or updated individual enrollment (will be updated with new info from the Provisioning Service).
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_create_or_update_individual_enrollment, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, INDIVIDUAL_ENROLLMENT_HANDLE*, enrollment_ptr);

    /** @brief  Deletes a individual device enrollment record on the Provisioning Service.
    *
    * @param    prov_client    The handle used for connecting to the Provisioning Service.
    * @param    enrollment     The handle for the target individual enrollment. Will be matched based on registration id and etag.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_individual_enrollment, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, INDIVIDUAL_ENROLLMENT_HANDLE, enrollment);

    /** @brief  Deletes an individual device enrollment record on the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    reg_id          The registration id of the target individual enrollment.
    * @param    etag            The etag of the target individual enrollment. If given as "*", will match any etag. If given as NULL, will be ignored.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_individual_enrollment_by_param, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, reg_id, const char*, etag);

    /** @breif  Retreives an individual device enrollment record from the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    reg_id          The registration id of the target individual enrollment.
    * @param    enrollment      Pointer to a handle for an individual enrollment, to be filled with retreived data.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_get_individual_enrollment, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, reg_id, INDIVIDUAL_ENROLLMENT_HANDLE*, enrollment_ptr);

    /** @brief Creates a Provisioning Service query for individual device enrollment records.
    *
    * @param    prov_client             The handle used for connecting to the Provisioning Service.
    * @param    query_spec              A struct defining the parameters of the query.
    *
    * @return   A non-NULL handle for the query, which can subsequently be run, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, PROVISIONING_QUERY_HANDLE, prov_sc_create_individual_enrollment_query, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, PROVISIONING_QUERY_SPECIFICATION*, query_spec);

    /** @brief  Performs a bulk operation on individual device enrollment records from the Provisioning Service.
    *
    * @param    prov_client             The handle used for connecting to the Provisioning Service.
    * @param    mode                    The operation to be executed.
    * @param    enrollment_list         An array of enrollments for the given operation to be executed on.
    * @param    list_len                The number of enrollments in the list.
    *
    * @return   A non-NULL handle for accessing the results of the bulk operation, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, BULK_OPERATION_RESULT_HANDLE, prov_sc_run_individual_enrollment_bulk_op, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, BULK_OPERATION_MODE, mode, INDIVIDUAL_ENROLLMENT_HANDLE*, enrollment_list, size_t, list_len);

    /** @brief  Creates or updates a device enrollment group record on the Provisioning Service.
    *
    * @param    prov_client         The handle used for connecting to the Provisioning Service.
    * @param    enrollment_ptr      Pointer to a handle for a new or updated enrollment group.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_create_or_update_enrollment_group, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, ENROLLMENT_GROUP_HANDLE*, enrollment_ptr);

    /** @brief  Deletes a device enrollment group record on the Provisioning Service.
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    enrollment      The handle for the target enrollment group
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_enrollment_group, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, ENROLLMENT_GROUP_HANDLE, enrollment);

    /** @brief  Deletes a device enrollment group record on the Provisioning Service.
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    group_id        The enrollment group id of the target enrollment group.
    * @param    etag            The etag of the target enrollment group. If given as "*", will match any etag.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_enrollment_group_by_param, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, group_id, const char*, etag);

    /** @brief  Retreives a device enrollment group record from the Provisioning Service.
    *
    * @param    prov_client         The handle used for connecting to the Provisioning Service.
    * @param    group_id            The enrollment group id of the target enrollment group.
    * @param    enrollment_ptr      A pointer to a handle for an enrollment group, to be filled with the retreived data.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_get_enrollment_group, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, group_id, ENROLLMENT_GROUP_HANDLE*, enrollment_ptr);

    /** @brief  Creates a Provisioning Service query for device enrollment group records.
    *
    * @param    prov_client             The handle used for connecting to the Provisioning Service.
    * @param    query_spec              A struct defining the parameters of the query
    *
    * @return   A non-NULL handle for accessing the results of the query, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, PROVISIONING_QUERY_HANDLE, prov_sc_create_enrollment_group_query, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, PROVISIONING_QUERY_SPECIFICATION*, query_spec);

     /** @brief  Deletes a device registration status on the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    id              The registration id of the target individual enrollment.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_device_registration_status, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, id);

    /** @brief  Retreives a device registration status from the Provisioning Service.
    *
    * @param    prov_client     A handle used for connecting to the Provisioning Service.
    * @param    id              The registration id of the target registration status.
    * @param    reg_state       A pointer to a handle for a registration state, to be filled with retreived data.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_get_device_registration_status, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, id, DEVICE_REGISTRATION_STATE_HANDLE*, reg_state_ptr);

    /** @brief  Creates a Provisioning Service query for device registration status records.
    *
    * @param    prov_client             The handle used for connecting to the Provisioning Service.
    * @param    query_spec              A struct defining the parameters of the query.
    *
    * @return   A non-NULL handle for accessing the results of the query, and NULL on failure.
    */
    MOCKABLE_FUNCTION(, PROVISIONING_QUERY_HANDLE, prov_sc_create_device_registration_status_query, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, PROVISIONING_QUERY_SPECIFICATION*, query_spec);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SERVICE_CLIENT_H */
