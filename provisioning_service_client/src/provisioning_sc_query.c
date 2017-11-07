// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>  

#include "azure_c_shared_utility/xlogging.h"

#include "provisioning_sc_query.h"

typedef struct PROVISIONING_QUERY_TAG
{
    int dummy;
} PROVISIONING_QUERY;

typedef struct PROVISIONING_QUERY_RESULT_TAG
{
    char* continuation_token;
} PROVISIONING_QUERY_RESULT;