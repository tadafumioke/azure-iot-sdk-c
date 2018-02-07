// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "iothub_client_statistics.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/crt_abstractions.h"

#define INDEFINITE_TIME ((time_t)-1)

typedef struct EVENT_INFO_TAG
{
    EVENT_TYPE type;
    time_t time;
    size_t api_result;
} EVENT_INFO;

typedef struct CONNECTION_STATUS_INFO_TAG
{
    time_t time;
    IOTHUB_CLIENT_CONNECTION_STATUS status;
    IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason;
} CONNECTION_STATUS_INFO;

typedef struct IOTHUB_CLIENT_STATISTICS_TAG
{
    SINGLYLINKEDLIST_HANDLE connection_status_history;
    SINGLYLINKEDLIST_HANDLE telemetry_events;
    SINGLYLINKEDLIST_HANDLE c2d_messages;
    SINGLYLINKEDLIST_HANDLE device_methods;
    SINGLYLINKEDLIST_HANDLE twin_reported_properties;
    SINGLYLINKEDLIST_HANDLE twin_desired_properties;
} IOTHUB_CLIENT_STATISTICS;

static bool destroy_connection_status_info(const void* item, const void* match_context, bool* continue_processing)
{
    (void)match_context;
    free((void*)item);
    *continue_processing = true;
    return true;
}

static bool destroy_telemetry_event(const void* item, const void* match_context, bool* continue_processing)
{
    (void)match_context;
    free((void*)item);
    *continue_processing = true;
    return true;
}

static bool destroy_c2d_message_info(const void* item, const void* match_context, bool* continue_processing)
{
    (void)match_context;
    free((void*)item);
    *continue_processing = true;
    return true;
}

static bool destroy_device_method_info(const void* item, const void* match_context, bool* continue_processing)
{
    (void)match_context;
    free((void*)item);
    *continue_processing = true;
    return true;
}

static bool destroy_twin_reported_property_info(const void* item, const void* match_context, bool* continue_processing)
{
    (void)match_context;
    free((void*)item);
    *continue_processing = true;
    return true;
}

static bool destroy_twin_desired_property_info(const void* item, const void* match_context, bool* continue_processing)
{
    (void)match_context;
    free((void*)item);
    *continue_processing = true;
    return true;
}

void iothub_client_statistics_destroy(IOTHUB_CLIENT_STATISTICS_HANDLE handle)
{
    if (handle != NULL)
    {
        IOTHUB_CLIENT_STATISTICS_HANDLE stats = (IOTHUB_CLIENT_STATISTICS*)handle;

        if (stats->connection_status_history != NULL)
        {
            if (singlylinkedlist_remove_if(stats->connection_status_history, destroy_connection_status_info, NULL) != 0)
            {
                LogError("Failed releasing connection status history items");
            }
            singlylinkedlist_destroy(stats->connection_status_history);
        }

        if (stats->telemetry_events != NULL)
        {
            if (singlylinkedlist_remove_if(stats->telemetry_events, destroy_telemetry_event, NULL) != 0)
            {
                LogError("Failed releasing telemetry events");
            }
            singlylinkedlist_destroy(stats->telemetry_events);
        }

        if (stats->c2d_messages != NULL)
        {
            if (singlylinkedlist_remove_if(stats->c2d_messages, destroy_c2d_message_info, NULL) != 0)
            {
                LogError("Failed releasing c2d message events");
            }
            singlylinkedlist_destroy(stats->c2d_messages);
        }

        if (stats->device_methods != NULL)
        {
            if (singlylinkedlist_remove_if(stats->device_methods, destroy_device_method_info, NULL) != 0)
            {
                LogError("Failed releasing device method events");
            }
            singlylinkedlist_destroy(stats->device_methods);
        }

        if (stats->twin_reported_properties != NULL)
        {
            if (singlylinkedlist_remove_if(stats->twin_reported_properties, destroy_twin_reported_property_info, NULL) != 0)
            {
                LogError("Failed releasing twin reported property event");
            }
            singlylinkedlist_destroy(stats->twin_reported_properties);
        }

        if (stats->twin_desired_properties != NULL)
        {
            if (singlylinkedlist_remove_if(stats->twin_desired_properties, destroy_twin_desired_property_info, NULL) != 0)
            {
                LogError("Failed releasing twin desired property event");
            }
            singlylinkedlist_destroy(stats->twin_desired_properties);
        }

        free(handle);
    }
}

IOTHUB_CLIENT_STATISTICS_HANDLE iothub_client_statistics_create(void)
{
    IOTHUB_CLIENT_STATISTICS* stats;

    if ((stats = ((IOTHUB_CLIENT_STATISTICS*)malloc(sizeof(IOTHUB_CLIENT_STATISTICS)))) == NULL)
    {
        LogError("Failed allocating IOTHUB_CLIENT_STATISTICS");
    }
    else if ((stats->connection_status_history = singlylinkedlist_create()) == NULL)
    {
        LogError("Failed creating list for connection status info");
        iothub_client_statistics_destroy(stats);
        stats = NULL;
    }
    else if ((stats->telemetry_events = singlylinkedlist_create()) == NULL)
    {
        LogError("Failed creating list for telemetry events");
        iothub_client_statistics_destroy(stats);
        stats = NULL;
    }
    else if ((stats->c2d_messages = singlylinkedlist_create()) == NULL)
    {
        LogError("Failed creating list for c2d messages");
        iothub_client_statistics_destroy(stats);
        stats = NULL;
    }
    else if ((stats->device_methods = singlylinkedlist_create()) == NULL)
    {
        LogError("Failed creating list for device methods");
        iothub_client_statistics_destroy(stats);
        stats = NULL;
    }
    else if ((stats->twin_reported_properties = singlylinkedlist_create()) == NULL)
    {
        LogError("Failed creating list for twin reported properties");
        iothub_client_statistics_destroy(stats);
        stats = NULL;
    }
    else if ((stats->twin_desired_properties = singlylinkedlist_create()) == NULL)
    {
        LogError("Failed creating list for twin desired properties");
        iothub_client_statistics_destroy(stats);
        stats = NULL;
    }

    return stats;
}

char* iothub_client_statistics_to_json(IOTHUB_CLIENT_STATISTICS_HANDLE handle)
{
    char* result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = NULL;
    }
    else
    {
        //IOTHUB_CLIENT_STATISTICS_HANDLE stats = (IOTHUB_CLIENT_STATISTICS*)handle;

        result = NULL;
    }

    return result;
}

int iothub_client_statistics_add_connection_status(IOTHUB_CLIENT_STATISTICS_HANDLE handle, IOTHUB_CLIENT_CONNECTION_STATUS status, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason)
{
    int result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = __FAILURE__;
    }
    else
    {
        CONNECTION_STATUS_INFO* conn_status;

        if ((conn_status = (CONNECTION_STATUS_INFO*)malloc(sizeof(CONNECTION_STATUS_INFO))) == NULL)
        {
            LogError("Failed allocating CONNECTION_STATUS_INFO");
            result = __FAILURE__;
        }
        else
        {
            IOTHUB_CLIENT_STATISTICS_HANDLE stats = (IOTHUB_CLIENT_STATISTICS*)handle;

            if (singlylinkedlist_add(stats->connection_status_history, conn_status) != 0)
            {
                LogError("Failed adding CONNECTION_STATUS_INFO");
                result = __FAILURE__;
            }
            else
            {
                conn_status->status = status;
                conn_status->reason = reason;

                if ((conn_status->time = time(NULL)) == INDEFINITE_TIME)
                {
                    LogError("Failed setting the connection status info time");
                }

                result = 0;
            }
        }
    }

    return result;
}

static bool find_telemetry_info_by_id(LIST_ITEM_HANDLE list_item, const void* match_context)
{
    TELEMETRY_INFO* match_info = (TELEMETRY_INFO*)match_context;
    TELEMETRY_INFO* item_info = (TELEMETRY_INFO*)singlylinkedlist_item_get_value(list_item);

    return (item_info->message_id == match_info->message_id);
}

int iothub_client_statistics_add_telemetry_info(IOTHUB_CLIENT_STATISTICS_HANDLE handle, EVENT_TYPE type, TELEMETRY_INFO* info)
{
    int result;

    if (handle == NULL || info == NULL || (type != TELEMETRY_QUEUED && type != TELEMETRY_SENT && type != TELEMETRY_RECEIVED))
    {
        LogError("Invalid argument (handle=%p, type=%d, info=%p)", handle, type, info);
        result = __FAILURE__;
    }
    else
    {
        IOTHUB_CLIENT_STATISTICS_HANDLE stats = (IOTHUB_CLIENT_STATISTICS*)handle;
        TELEMETRY_INFO* queued_info;
        LIST_ITEM_HANDLE list_item = singlylinkedlist_find(stats->telemetry_events, find_telemetry_info_by_id, info);

        if (list_item == NULL)
        {
            if (type != TELEMETRY_QUEUED)
            {
                LogError("Telemetry info not found for message %d (%d)", info->message_id, type);
                result = __FAILURE__;
            }
            else if ((queued_info = (TELEMETRY_INFO*)malloc(sizeof(TELEMETRY_INFO))) == NULL)
            {
                LogError("Failed clonning the TELEMETRY_INFO");
                result = __FAILURE__;
            }
            else if (singlylinkedlist_add(stats->telemetry_events, queued_info) == NULL)
            {
                LogError("Failed adding telemetry info (message id: %d)", info->message_id);
                free(queued_info);
                result = __FAILURE__;
            }
            else
            {
                queued_info->message_id = info->message_id;
                queued_info->time_queued = info->time_queued;
                queued_info->send_result = info->send_result;
                queued_info->time_sent = INDEFINITE_TIME;
                queued_info->send_callback_result = IOTHUB_CLIENT_ERROR;
                queued_info->time_received = INDEFINITE_TIME;

                result = 0;
            }
        }
        else
        {
            if ((queued_info = (TELEMETRY_INFO*)singlylinkedlist_item_get_value(list_item)) == NULL)
            {
                LogError("Failed retrieving queued telemetry info (message id: %d)", info->message_id);
                result = __FAILURE__;
            }
            else
            {
                if (type == TELEMETRY_SENT)
                {
                    queued_info->time_sent = info->time_sent;
                    queued_info->send_callback_result = info->send_callback_result;
                }
                else if (type == TELEMETRY_RECEIVED)
                {
                    queued_info->time_received = info->time_received;
                }

                result = 0;
            }
        }
    }

    return result;
}

int iothub_client_statistics_get_telemetry_summary(
    IOTHUB_CLIENT_STATISTICS_HANDLE handle, 
    size_t* messages_sent, size_t* messages_received, double* min_travel_time, double* max_travel_time)
{
    int result;

    if (handle == NULL || messages_sent == NULL || messages_received == NULL)
    {
        LogError("Invalid argument (handle=%p, messages_sent=%p, messages_received=%p)", handle, messages_sent, messages_received);
        result = __FAILURE__;
    }
    else
    {
        IOTHUB_CLIENT_STATISTICS_HANDLE stats = (IOTHUB_CLIENT_STATISTICS*)handle;
        LIST_ITEM_HANDLE list_item;

        *messages_sent = 0;
        *messages_received = 0;
        *min_travel_time = LONG_MAX;
        *max_travel_time = 0;

        list_item = singlylinkedlist_get_head_item(stats->telemetry_events);

        while (list_item != NULL)
        {
            TELEMETRY_INFO* telemetry_info = (TELEMETRY_INFO*)singlylinkedlist_item_get_value(list_item);

            *messages_sent = *messages_sent + 1;

            if (telemetry_info->time_received != INDEFINITE_TIME)
            {
                double travel_time = difftime(telemetry_info->time_received, telemetry_info->time_sent);

                if (travel_time < *min_travel_time)
                {
                    *min_travel_time = travel_time;
                }

                if (travel_time > *max_travel_time)
                {
                    *max_travel_time = travel_time;
                }

                *messages_received = *messages_received + 1;
            }

            list_item = singlylinkedlist_get_next_item(list_item);
        }

        result = 0;
    }

    return result;
}