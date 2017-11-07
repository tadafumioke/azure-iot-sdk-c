// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_QUERY_H
#define PROVISIONING_SC_QUERY_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    //typedef struct PROVISIONING_QUERY_SPECIFICATION* PROVISIONING_QUERY_SPECIFICATION_HANDLE;
    
    typedef struct PROVISIONING_QUERY_SPECIFICATION_TAG
    {
        int dummy;
    } PROVISIONING_QUERY_SPECIFICATION;
    
    typedef struct PROVISIONING_QUERY* PROVISIONING_QUERY_HANDLE;
    typedef struct PROVISIONING_QUERY_RESULT* PROVISIONING_QUERY_RESULT_HANDLE;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_QUERY_H */
