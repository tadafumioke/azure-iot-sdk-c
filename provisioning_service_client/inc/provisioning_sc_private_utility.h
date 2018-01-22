// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_PRIVATE_UTILITY_H
#define PROVISIONING_SC_PRIVATE_UTILITY_H

#include "parson.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum NECESSITY_TAG
{
    REQUIRED,
    OPTIONAL
} NECESSITY;

MOCKABLE_FUNCTION(, int, copy_string, char**, dest, const char*, string);
MOCKABLE_FUNCTION(, int, copy_json_string_field, char**, dest, JSON_Object*, root_object, const char*, json_key);
MOCKABLE_FUNCTION(, int, json_serialize_and_set_struct, JSON_Object*, root_object, const char*, json_key, void*, structure, void*, (*toJson)(void*), NECESSITY, necessity);
MOCKABLE_FUNCTION(, int, json_deserialize_and_get_struct, void**, dest, JSON_Object*, root_object, const char*, json_key, void*, (*fromJson)(void*), NECESSITY, necessity);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_PRIVATE_UTILITY_H */