// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROVISIONING_SC_BULK_OPERATION_H
#define PROVISIONING_SC_BULK_OPERATION_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define PROVISIONING_BULK_OPERATION_MODE_VALUES \
BULK_OP_CREATE, \
BULK_OP_UPDATE, \
BULK_OP_UPDATE_IF_MATCH_ETAG, \
BULK_OP_DELETE

DEFINE_ENUM(PROVISIONING_BULK_OPERATION_MODE, PROVISIONING_BULK_OPERATION_MODE_VALUES);

typedef struct PROVISIONING_BULK_OPERATION_RESULT_TAG
{
    int dummy;
} PROVISIONING_BULK_OPERATION_RESULT;

typedef struct PROVISIONING_BULK_OPERATION_TAG
{
    PROVISIONING_BULK_OPERATION_MODE mode;
    void* enrollments;
    size_t enrollments_num;
} PROVISIONING_BULK_OPERATION;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PROVISIONING_SC_BULK_OPERATION_H */