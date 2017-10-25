// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SERVICE_CLIENT_H
#define PROVISIONING_SERVICE_CLIENT_H

#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/umock_c_prod.h"

#include "provisioning_sc_enrollment.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    #define BULK_OPERATION_MODE_VALUES \
        BULK_CREATE, \
        BULK_UPDATE, \
        BULK_UPDATE_IF_MATCH_ETAG, \
        BULK_DELETE

    DEFINE_ENUM(BULK_OPERATION_MODE, BULK_OPERATION_MODE_VALUES);

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

    /** @brief Creates or updates an individual device enrollment record on the Provisioning Service, reflecting the changes in the given struct.
    *
    * @param    prov_client    The handle used for connecting to the Provisioning Service.
    * @param    enrollment     A double pointer to a struct describing the desired changes to the individual enrollment.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_create_or_update_individual_enrollment, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, INDIVIDUAL_ENROLLMENT**, enrollment_ptr);
  
    /** @brief  Deletes a individual device enrollment record on the Provisioning Service.
    *
    * @param    prov_client    The handle used for connecting to the Provisioning Service.
    * @param    enrollment     Pointer to a struct representation of the target individual enrollment.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_individual_enrollment, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, INDIVIDUAL_ENROLLMENT*, enrollment);


    /** @brief  Deletes an individual device enrollment record on the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    reg_id          The registration id of the target individual enrollment.
    * @param    etag            The etag of the target individual enrollment. If given as "*", will ignore.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_individual_enrollment_by_param, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, reg_id, const char*, etag);

    /** @breif  Retreives an individual device enrollment record from the Provisioning Service.
    *
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    id              The registration id of the target individual enrollment.
    * @param    enrollment      A double pointer to a struct representing an individual enrollment, to be filled with retreived data.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_get_individual_enrollment, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, id, INDIVIDUAL_ENROLLMENT**, enrollment_ptr);

    /** @brief  Creates or updates a device enrollment group record on the Provisioning Service.
    *
    * @param    prov_client         The handle used for connecting to the Provisioning Service.
    * @param    enrollment_ptr      A double pointer to a struct describing the desired changes to the enrollment group.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_create_or_update_enrollment_group, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, ENROLLMENT_GROUP**, enrollment_ptr);

    /** @brief  Deletes a device enrollment group record on the Provisioning Service.
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    enrollment      A struct representation of the target enrollment group
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_enrollment_group, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, ENROLLMENT_GROUP*, enrollment);

    /** @brief  Deletes a device enrollment group record on the Provisioning Service.
    * @param    prov_client     The handle used for connecting to the Provisioning Service.
    * @param    group_name      The enrollment group name of the target enrollment group.
    * @param    etag            The etag of the target enrollment group. If given as "*", will ignore.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_delete_enrollment_group_by_param, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, group_name, const char*, etag);

    /** @brief  Retreives a device enrollment group record from the Provisioning Service.
    *
    * @param    prov_client         The handle used for connecting to the Provisioning Service.
    * @param    group_name          The enrollment group name of the target enrollment group.
    * @param    enrollment_ptr      A double pointer to a struct representing an enrollment group, to be filled with the retreived data.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_get_enrollment_group, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, group_name, ENROLLMENT_GROUP**, enrollment_ptr);

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
    * @param    reg_status      A double pointer to a struct representing a registration status, to be filled with retreived data.
    *
    * @return   0 upon success, a non-zero number upon failure.
    */
    MOCKABLE_FUNCTION(, int, prov_sc_get_device_registration_status, PROVISIONING_SERVICE_CLIENT_HANDLE, prov_client, const char*, id, DEVICE_REGISTRATION_STATUS**, reg_status_ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SERVICE_CLIENT_H */
