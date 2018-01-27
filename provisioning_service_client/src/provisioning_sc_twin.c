// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>  

#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/crt_abstractions.h"

#include "provisioning_sc_twin.h"
#include "provisioning_sc_models_internal.h"
#include "provisioning_sc_json_const.h"
#include "provisioning_sc_private_utility.h"
#include "parson.h"

typedef struct TWIN_COLLECTION_TAG
{
    char* json;
} TWIN_COLLECTION;

typedef struct INITIAL_TWIN_PROPERTIES_TAG
{
    TWIN_COLLECTION* desired;
} INITIAL_TWIN_PROPERTIES;

typedef struct INITIAL_TWIN_TAG
{
    TWIN_COLLECTION* tags;
    INITIAL_TWIN_PROPERTIES* properties;
} INITIAL_TWIN;

static void twinCollection_free(TWIN_COLLECTION* twin_collection)
{
    if (twin_collection != NULL)
    {
        free(twin_collection->json);
        free(twin_collection);
    }
}

static JSON_Value* twinCollection_toJson(const TWIN_COLLECTION* twin_collection)
{
    JSON_Value* root_value = NULL;
    if ((root_value = json_parse_string(twin_collection->json)) == NULL)
    {
        LogError("Failed to parse Twin Collection json");
    }
    return root_value;
}

static TWIN_COLLECTION* twinCollection_fromJson(JSON_Object* root_object)
{
    TWIN_COLLECTION* new_twinCollection = NULL;

    if ((new_twinCollection = malloc(sizeof(TWIN_COLLECTION))) == NULL)
    {
        LogError("Allocation of Twin Collection failed");
    }
    else
    {
        memset(new_twinCollection, 0, sizeof(TWIN_COLLECTION));

        JSON_Value* root_value = NULL;
        char* json_rep = NULL;

        if ((root_value = json_object_get_wrapping_value(root_object)) == NULL)
        {
            LogError("Failed to get Twin Collection root");
            twinCollection_free(new_twinCollection);
            new_twinCollection = NULL;
        }
        else if ((json_rep = json_serialize_to_string(root_value)) == NULL)
        {
            LogError("Failed to serialize Twin Collection");
            twinCollection_free(new_twinCollection);
            new_twinCollection = NULL;
        }
        else if (mallocAndStrcpy_s(&(new_twinCollection->json), json_rep) != 0)
        {
            LogError("Failed to copy Twin Collection json");
            twinCollection_free(new_twinCollection);
            new_twinCollection = NULL;
        }
        json_free_serialized_string(json_rep);
    }

    return new_twinCollection;
}

static TWIN_COLLECTION* twinCollection_create(const char* json)
{
    TWIN_COLLECTION* new_twinCollection = NULL;

    if ((new_twinCollection = malloc(sizeof(TWIN_COLLECTION))) == NULL)
    {
        LogError("Allocation of Twin Collection failed");
    }
    else
    {
        memset(new_twinCollection, 0, sizeof(TWIN_COLLECTION));

        if (mallocAndStrcpy_s(&(new_twinCollection->json), json) != 0)
        {
            LogError("Failed to set json in Twin Collection");
            twinCollection_free(new_twinCollection);
            new_twinCollection = NULL;
        }
    }

    return new_twinCollection;
}

static void twinProperties_free(INITIAL_TWIN_PROPERTIES* twin_properties)
{
    if (twin_properties != NULL)
    {
        twinCollection_free(twin_properties->desired);
        free(twin_properties);
    }
}

static INITIAL_TWIN_PROPERTIES* twinProperties_create(const char* desired_properties)
{
    INITIAL_TWIN_PROPERTIES* new_twinProperties = NULL;

    if ((new_twinProperties = malloc(sizeof(INITIAL_TWIN_PROPERTIES))) == NULL)
    {
        LogError("Allocation of Twin Properties failed");
    }
    else
    {
        memset(new_twinProperties, 0, sizeof(INITIAL_TWIN_PROPERTIES));

        if ((new_twinProperties->desired = twinCollection_create(desired_properties)) == NULL)
        {
            LogError("Failed to set desired properties in Twin Properties");
            twinProperties_free(new_twinProperties);
            new_twinProperties = NULL;
        }
    }

    return new_twinProperties;
}

static JSON_Value* twinProperties_toJson(INITIAL_TWIN_PROPERTIES* twin_properties)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

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
    else if (json_serialize_and_set_struct(root_object, INITIAL_TWIN_PROPERTIES_JSON_KEY_DESIRED, twin_properties->desired, twinCollection_toJson, OPTIONAL) != 0)
    {
        LogError("Failed to set '%s' in JSON string representation of Twin Properties", INITIAL_TWIN_PROPERTIES_JSON_KEY_DESIRED);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

static INITIAL_TWIN_PROPERTIES* twinProperties_fromJson(JSON_Object* root_object)
{
    INITIAL_TWIN_PROPERTIES* new_twinProperties = NULL;

    if ((new_twinProperties = malloc(sizeof(INITIAL_TWIN_PROPERTIES))) == NULL)
    {
        LogError("Allocation of Twin Properties failed");
    }
    else
    {
        memset(new_twinProperties, 0, sizeof(INITIAL_TWIN_PROPERTIES));

        if (json_deserialize_and_get_struct(&(new_twinProperties->desired), root_object, INITIAL_TWIN_PROPERTIES_JSON_KEY_DESIRED, twinCollection_fromJson, OPTIONAL) != 0)
        {
            LogError("Failed to set '%s' in Twin Properties", INITIAL_TWIN_PROPERTIES_JSON_KEY_DESIRED);
            twinProperties_free(new_twinProperties);
            new_twinProperties = NULL;
        }
    }

    return new_twinProperties;
}

static void initialTwin_free(INITIAL_TWIN* twin_state)
{
    if (twin_state != NULL)
    {
        twinCollection_free(twin_state->tags);
        twinProperties_free(twin_state->properties);
        free(twin_state);
    }
}

/* Serialization Functions */
JSON_Value* initialTwin_toJson(const INITIAL_TWIN_HANDLE twin_state)
{
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

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
    else if (json_serialize_and_set_struct(root_object, INITIAL_TWIN_JSON_KEY_TAGS, twin_state->tags, twinCollection_toJson, OPTIONAL) != 0)
    {
        LogError("Failed to set '%s' in JSON string representation", INITIAL_TWIN_JSON_KEY_TAGS);
        json_value_free(root_value);
        root_value = NULL;
    }
    else if (json_serialize_and_set_struct(root_object, INITIAL_TWIN_JSON_KEY_PROPERTIES, twin_state->properties, twinProperties_toJson, OPTIONAL) != 0)
    {
        LogError("Failed to set '%s' in JSON string representation", INITIAL_TWIN_JSON_KEY_PROPERTIES);
        json_value_free(root_value);
        root_value = NULL;
    }

    return root_value;
}

INITIAL_TWIN_HANDLE initialTwin_fromJson(JSON_Object* root_object)
{
    INITIAL_TWIN* new_initialTwin = NULL;

    if ((new_initialTwin = malloc(sizeof(INITIAL_TWIN))) == NULL)
    {
        LogError("Allocation of Twin State failed");
    }
    else
    {
        memset(new_initialTwin, 0, sizeof(INITIAL_TWIN));

        if (json_deserialize_and_get_struct(&(new_initialTwin->tags), root_object, INITIAL_TWIN_JSON_KEY_TAGS, twinCollection_fromJson, OPTIONAL) != 0)
        {
            LogError("Failed to set '%s' in Twin State", INITIAL_TWIN_JSON_KEY_TAGS);
            initialTwin_free(new_initialTwin);
            new_initialTwin = NULL;
        }
        else if (json_deserialize_and_get_struct(&(new_initialTwin->properties), root_object, INITIAL_TWIN_JSON_KEY_PROPERTIES, twinProperties_fromJson, OPTIONAL) != 0)
        {
            LogError("Failed to set '%s' in Twin State", INITIAL_TWIN_JSON_KEY_PROPERTIES);
            initialTwin_free(new_initialTwin);
            new_initialTwin = NULL;
        }
    }

    return new_initialTwin;
}

/* Exposed Twin API */
INITIAL_TWIN_HANDLE initialTwin_create(const char* tags, const char* desired_properties)
{
    INITIAL_TWIN* new_twin = NULL;

    if ((tags != NULL) && (strcmp(tags, "{}") == 0))
    {
        tags = NULL;
    }
    else if ((desired_properties != NULL) && (strcmp(desired_properties, "{}") == 0))
    {
        desired_properties = NULL;
    }
    else if (tags == NULL && desired_properties == NULL)
    {
        LogError("no inputs");
    }
    //if adding input validation, add here
    else if ((new_twin = malloc(sizeof(INITIAL_TWIN))) == NULL)
    {
        LogError("Allocation of Twin State failed");
    }
    else
    {
        memset(new_twin, 0, sizeof(INITIAL_TWIN));

        if (tags != NULL && ((new_twin->tags = twinCollection_create(tags)) == NULL))
        {
            LogError("Failed to create tags");
            initialTwin_free(new_twin);
            new_twin = NULL;
        }
        else if (desired_properties != NULL && ((new_twin->properties = twinProperties_create(desired_properties)) == NULL))
        {
            LogError("Failed to create desired properties");
            initialTwin_free(new_twin);
            new_twin = NULL;
        }
    }

    return new_twin;
}

void initialTwin_destroy(INITIAL_TWIN_HANDLE handle)
{
    INITIAL_TWIN* twin = (INITIAL_TWIN*)handle;
    initialTwin_free(twin);
}

const char* initialTwin_getTags(INITIAL_TWIN_HANDLE handle)
{
    char* result = NULL;
    INITIAL_TWIN* twin = (INITIAL_TWIN*)handle;

    if (twin == NULL)
    {
        LogError("Twin State is NULL");
    }
    else if (twin->tags == NULL)
    {
        LogError("No tags in Twin State");
    }
    else
    {
        result = twin->tags->json;
    }

    return result;
}

int initialTwin_setTags(INITIAL_TWIN_HANDLE handle, const char* tags)
{
    int result = 0;
    INITIAL_TWIN* twin = (INITIAL_TWIN*)handle;

    if (twin == NULL)
    {
        LogError("TwinState is NULL");
        result = __FAILURE__;
    }
    else if (tags == NULL)
    {
        LogError("Tags are NULL");
        result = __FAILURE__;
    }
    else if (twin->tags == NULL)
    {
        if ((twin->tags = twinCollection_create(tags)) == NULL)
        {
            LogError("Failure creating Twin Collection for tags");
            result = __FAILURE__;
        }
    }
    else
    {
        if (mallocAndStrcpy_overwrite(&(twin->tags->json), tags) != 0)
        {
            LogError("Failure setting tags");
            result = __FAILURE__;
        }
    }

    return result;
}

const char* initialTwin_getDesiredProperties(INITIAL_TWIN_HANDLE handle)
{
    char* result = NULL;
    INITIAL_TWIN* twin = (INITIAL_TWIN*)handle;

    if (twin == NULL)
    {
        LogError("Twin State is NULL");
    }
    else if ((twin->properties == NULL) || (twin->properties->desired == NULL))
    {
        LogError("No Desired Properties in Twin State");
    }
    else
    {
        result = twin->properties->desired->json;
    }

    return result;
}

int initialTwin_setDesiredProperties(INITIAL_TWIN_HANDLE handle, const char* desired_properties)
{
    int result = 0;
    INITIAL_TWIN* twin = (INITIAL_TWIN*)handle;

    if (twin == NULL)
    {
        LogError("TwinState is NULL");
        result = __FAILURE__;
    }
    else if (desired_properties == NULL)
    {
        LogError("Desired properties are NULL");
        result = __FAILURE__;
    }
    else if (twin->properties == NULL)
    {
        if ((twin->properties = twinProperties_create(desired_properties)) == NULL)
        {
            LogError("Failure creating Twin Properties");
            result = __FAILURE__;
        }
    }
    else if (twin->properties->desired == NULL)
    {
        if ((twin->properties->desired = twinCollection_create(desired_properties)) == NULL)
        {
            LogError("Failure creating Twin Collection for desired properties");
            result = __FAILURE__;
        }
    }
    else
    {
        if (mallocAndStrcpy_overwrite(&(twin->properties->desired->json), desired_properties) != 0)
        {
            LogError("Failure setting desired properties");
            result = __FAILURE__;
        }
    }

    return result;
}
