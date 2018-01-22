// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_JSON_H
#define PROVISIONING_SC_JSON_H

#include "azure_c_shared_utility/macro_utils.h"
#include "parson.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

MOCKABLE_FUNCTION(, INITIAL_TWIN_HANDLE, initialTwinState_fromJson, JSON_Object*, root_object);
MOCKABLE_FUNCTION(, JSON_Value*, initialTwinState_toJson, INITIAL_TWIN_HANDLE, twin_state);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_JSON_H */