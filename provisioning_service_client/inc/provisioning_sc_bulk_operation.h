// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_BULK_OPERATION_H
#define PROVISIONING_SC_BULK_OPERATION_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    #define BULK_OPERATION_MODE_VALUES \
    BULK_CREATE, \
    BULK_UPDATE, \
    BULK_UPDATE_IF_MATCH_ETAG, \
    BULK_DELETE

    DEFINE_ENUM(BULK_OPERATION_MODE, BULK_OPERATION_MODE_VALUES);

    typedef struct BULK_OPERATION_RESULT* BULK_OPERATION_RESULT_HANDLE;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_BULK_OPERATION_H */