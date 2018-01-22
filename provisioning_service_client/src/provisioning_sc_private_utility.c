// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>  

#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/gballoc.h"

#include "parson.h"

#include "provisioning_sc_private_utility.h"

int copy_string(char** dest, const char* string)
{
    int result = 0;
    char* new_copy = NULL;
    char* old_val = *dest;

    if (string != NULL)
    {
        size_t len = strlen(string);
        if ((new_copy = malloc(len + 1)) == NULL)
        {
            LogError("Allocating string for value '%s' failed", string);
            result = __FAILURE__;
        }
        else if ((strncpy(new_copy, string, len + 1)) == NULL)
        {
            LogError("Failed to copy value '%s'", string);
            free(new_copy);
            new_copy = NULL;
            result = __FAILURE__;
        }
        else
        {
            free(old_val);
        }
    }

    *dest = new_copy;
    return result;
}

int copy_json_string_field(char** dest, JSON_Object* root_object, const char* json_key)
{
    int result = 0;

    const char* string = json_object_get_string(root_object, json_key);
    if (string != NULL)
    {
        if (copy_string(dest, string) != 0)
        {
            result = __FAILURE__;
        }
    }

    return result;
}

int json_serialize_and_set_struct(JSON_Object* root_object, const char* json_key, void* structure, void*(*toJson)(void*), NECESSITY necessity)
{
    int result;

    if (necessity == OPTIONAL && structure == NULL)
    {
        result = 0;
    }
    else
    {
        JSON_Value* struct_val;
        if (structure == NULL)
        {
            LogError("NULL structure");
            result = __FAILURE__;
        }
        else if ((struct_val = toJson(structure)) == NULL)
        {
            LogError("Failed converting structure to JSON Value");
            result = __FAILURE__;
        }
        else if (json_object_set_value(root_object, json_key, struct_val) != JSONSuccess)
        {
            LogError("Failed to set JSON Value in JSON Object");
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int json_deserialize_and_get_struct(void** dest, JSON_Object* root_object, const char* json_key, void*(*fromJson)(void*), NECESSITY necessity)
{
    int result;

    JSON_Object* struct_object = json_object_get_object(root_object, json_key);

    if (necessity == OPTIONAL && struct_object == NULL)
    {
        result = 0;
    }
    else if (necessity == REQUIRED && struct_object == NULL)
    {
        LogError("object required");
        result = __FAILURE__;
    }
    else
    {
        if ((*dest = fromJson(struct_object)) == NULL)
        {
            LogError("Failed to deserialize from JSON");
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}