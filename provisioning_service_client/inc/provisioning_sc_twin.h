// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_TWIN_H
#define PROVISIONING_SC_TWIN_H

#include "azure_c_shared_utility/macro_utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct INITIAL_TWIN_TAG* INITIAL_TWIN_HANDLE;

 /* Initial Twin Operation Functions */

/** @brief  Creates an Initial Twin handle for use in consequent APIs.
*
* @param    tags                    The json string for the tags of the initial Twin State
* @param    desired_properties      The json string for the desired properties of the initial Twin State
*
* @return   A non-NULL handle representing an Initial Twin for use with Provisioning Service, and NULL on failure.
*/
MOCKABLE_FUNCTION(, INITIAL_TWIN_HANDLE, initialTwin_create, const char*, tags, const char*, desired_properties);

/** @brief  Destroys an Initial Twin handle, freeing all associated memory. Please note that this will also cause any Enrollment 
*           that the Initial Twin has been attached to to have unexpected behvaiours. Do not use this function
*           unless the Initial Twin is unattached.
*
* @param    handle      The handle of the Initial Twin to be destroyed
*/
MOCKABLE_FUNCTION(, void, initialTwin_destroy, INITIAL_TWIN_HANDLE, handle);

/* Initial Twin Accessor Functions */
MOCKABLE_FUNCTION(, const char*, initialTwin_getTags, INITIAL_TWIN_HANDLE, handle);
MOCKABLE_FUNCTION(, int, initialTwin_setTags, INITIAL_TWIN_HANDLE, handle, const char*, tags);
MOCKABLE_FUNCTION(, const char*, initialTwin_getDesiredProperties, INITIAL_TWIN_HANDLE, handle);
MOCKABLE_FUNCTION(, int, initialTwin_setDesiredProperties, INITIAL_TWIN_HANDLE, handle, const char*, desiredProperties);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_TWIN_H */
