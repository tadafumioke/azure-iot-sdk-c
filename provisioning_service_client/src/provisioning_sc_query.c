// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>  

#include "azure_c_shared_utility/xlogging.h"

#include "provisioning_sc_query.h"

typedef struct QUERY_RESULT_TAG
{
    char* continuation_token;
} QUERY_RESULT;