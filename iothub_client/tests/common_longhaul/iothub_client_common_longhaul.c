// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "iothub_client_common_longhaul.h"
#include <stdio.h>
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/uuid.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "iothub_client_options.h"
#include "iothub_client.h"
#include "iothub_message.h"
#include "iothub_service_client_auth.h"
#include "iothub_messaging.h"
#include "iothubtransport_amqp_messenger.h"
#include "iothubtest.h"

#ifdef MBED_BUILD_TIMESTAMP
#define SET_TRUSTED_CERT_IN_SAMPLES
#endif // MBED_BUILD_TIMESTAMP

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

#define INDEFINITE_TIME                      ((time_t)-1)
#define MAX_TELEMETRY_TRAVEL_TIME_SECS       300.0

typedef struct IOTHUB_LONGHAUL_RESOURCES_TAG
{
    LOCK_HANDLE lock;
    IOTHUB_ACCOUNT_INFO_HANDLE iotHubAccountInfo;
    IOTHUB_CLIENT_STATISTICS_HANDLE iotHubClientStats;
    IOTHUB_CLIENT_HANDLE iotHubClientHandle;
    IOTHUB_SERVICE_CLIENT_AUTH_HANDLE iotHubServiceClientHandle;
    size_t counter;
} IOTHUB_LONGHAUL_RESOURCES;

typedef struct SEND_TELEMETRY_CONTEXT_TAG
{
    size_t message_id;
    IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaul;
} SEND_TELEMETRY_CONTEXT;

static void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS status, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* userContextCallback)
{
    IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaul = (IOTHUB_LONGHAUL_RESOURCES*)userContextCallback;

    if (iothub_client_statistics_add_connection_status(iotHubLonghaul->iotHubClientStats, status, reason) != 0)
    {
        LogError("Failed adding connection status statistics (%s, %s)", 
            ENUM_TO_STRING(IOTHUB_CLIENT_CONNECTION_STATUS, status), ENUM_TO_STRING(IOTHUB_CLIENT_CONNECTION_STATUS_REASON, reason));
    }
}

static IOTHUBMESSAGE_DISPOSITION_RESULT c2d_message_received_callback(IOTHUB_MESSAGE_HANDLE message, void* userContextCallback)
{
    (void)message;
    (void)userContextCallback;
    //int* counter = (int*)userContextCallback;
    //const unsigned char* buffer = NULL;
    //size_t size = 0;
    //const char* messageId;
    //const char* correlationId;
    //const char* userDefinedContentType;
    //const char* userDefinedContentEncoding;

    //// Message properties
    //if ((messageId = IoTHubMessage_GetMessageId(message)) == NULL)
    //{
    //    messageId = "<null>";
    //}

    //if ((correlationId = IoTHubMessage_GetCorrelationId(message)) == NULL)
    //{
    //    correlationId = "<null>";
    //}

    //if ((userDefinedContentType = IoTHubMessage_GetContentTypeSystemProperty(message)) == NULL)
    //{
    //    userDefinedContentType = "<null>";
    //}

    //if ((userDefinedContentEncoding = IoTHubMessage_GetContentEncodingSystemProperty(message)) == NULL)
    //{
    //    userDefinedContentEncoding = "<null>";
    //}

    //// Message content
    //IOTHUBMESSAGE_CONTENT_TYPE contentType = IoTHubMessage_GetContentType(message);

    //if (contentType == IOTHUBMESSAGE_BYTEARRAY)
    //{
    //    if (IoTHubMessage_GetByteArray(message, &buffer, &size) == IOTHUB_MESSAGE_OK)
    //    {
    //        (void)printf("Received Message [%d]\r\n Message ID: %s\r\n Correlation ID: %s\r\n Content-Type: %s\r\n Content-Encoding: %s\r\n BINARY Data: <<<%.*s>>> & Size=%d\r\n",
    //            *counter, messageId, correlationId, userDefinedContentType, userDefinedContentEncoding, (int)size, buffer, (int)size);
    //    }
    //    else
    //    {
    //        (void)printf("Failed getting the BINARY body of the message received.\r\n");
    //    }
    //}
    //else if (contentType == IOTHUBMESSAGE_STRING)
    //{
    //    if ((buffer = (const unsigned char*)IoTHubMessage_GetString(message)) != NULL && (size = strlen((const char*)buffer)) > 0)
    //    {
    //        (void)printf("Received Message [%d]\r\n Message ID: %s\r\n Correlation ID: %s\r\n Content-Type: %s\r\n Content-Encoding: %s\r\n STRING Data: <<<%.*s>>> & Size=%d\r\n",
    //            *counter, messageId, correlationId, userDefinedContentType, userDefinedContentEncoding, (int)size, buffer, (int)size);

    //        // If we receive the work 'quit' then we stop running
    //    }
    //    else
    //    {
    //        (void)printf("Failed getting the STRING body of the message received.\r\n");
    //    }
    //}
    //else
    //{
    //    (void)printf("Failed getting the body of the message received (type %i).\r\n", contentType);
    //}

    //// Retrieve properties from the message
    //MAP_HANDLE mapProperties = IoTHubMessage_Properties(message);
    //if (mapProperties != NULL)
    //{
    //    const char*const* keys;
    //    const char*const* values;
    //    size_t propertyCount = 0;
    //    if (Map_GetInternals(mapProperties, &keys, &values, &propertyCount) == MAP_OK)
    //    {
    //        if (propertyCount > 0)
    //        {
    //            size_t index;

    //            printf(" Message Properties:\r\n");
    //            for (index = 0; index < propertyCount; index++)
    //            {
    //                printf("\tKey: %s Value: %s\r\n", keys[index], values[index]);
    //            }
    //            printf("\r\n");
    //        }
    //    }
    //}

    //if (size == (strlen("quit") * sizeof(char)) && memcmp(buffer, "quit", size) == 0)
    //{
    //}

    ///* Some device specific action code goes here... */
    //(*counter)++;
    return IOTHUBMESSAGE_ACCEPTED;
}

static size_t generate_unique_id(IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaul)
{
    size_t result;

    if (Lock(iotHubLonghaul->lock) != LOCK_OK)
    {
        LogError("Failed to lock");
        result = 0;
    }
    else
    {
        result = (++iotHubLonghaul->counter); // Increment first then assign.

        if (Unlock(iotHubLonghaul->lock) != LOCK_OK)
        {
            LogError("Failed to unlock (%d)", result);
        }
    }

    return result;
}

typedef int(*RUN_ON_LOOP_ACTION)(const void* context);

static int run_on_loop(RUN_ON_LOOP_ACTION action, size_t iterationDurationInSeconds, size_t totalDurationInSeconds, const void* action_context)
{
    int result;
    time_t start_time;

    if ((start_time = time(NULL)) == INDEFINITE_TIME)
    {
        LogError("Failed setting start time");
        result = __FAILURE__;
    }
    else
    {
        time_t current_time;
        time_t iteration_start_time;

        result = 0;

        do
        {
            if ((iteration_start_time = time(NULL)) == INDEFINITE_TIME)
            {
                LogError("Failed setting iteration start time");
                result = __FAILURE__;
                break;
            }
            else if (action(action_context) != 0)
            {
                LogError("Loop terminated by action function result");
                result = __FAILURE__;
                break;
            }
            else if ((current_time = time(NULL)) == INDEFINITE_TIME)
            {
                LogError("Failed getting current time");
                result = __FAILURE__;
                break;
            }
            else
            {
                double wait_time_secs = iterationDurationInSeconds - difftime(current_time, iteration_start_time);

                if (wait_time_secs > 0)
                {
                    ThreadAPI_Sleep((unsigned int)(1000 * wait_time_secs));
                }

                // We should get the current time again to be 100% precise, but we will optimize here since wait_time_secs is supposed to be way smaller than totalDurationInSeconds.
            }
        } while (difftime(current_time, start_time) < totalDurationInSeconds);
    }

    return result;
}

// Public APIs

IOTHUB_ACCOUNT_INFO_HANDLE longhaul_get_account_info(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle)
{
    IOTHUB_ACCOUNT_INFO_HANDLE result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = NULL;
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaulRsrcs = (IOTHUB_LONGHAUL_RESOURCES*)handle;
        result = iotHubLonghaulRsrcs->iotHubAccountInfo;
    }

    return result;
}

IOTHUB_CLIENT_HANDLE longhaul_get_iothub_client_handle(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle)
{
    IOTHUB_CLIENT_HANDLE result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = NULL;
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaulRsrcs = (IOTHUB_LONGHAUL_RESOURCES*)handle;
        result = iotHubLonghaulRsrcs->iotHubClientHandle;
    }

    return result;
}

IOTHUB_CLIENT_STATISTICS_HANDLE longhaul_get_statistics(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle)
{
    IOTHUB_CLIENT_STATISTICS_HANDLE result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = NULL;
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaulRsrcs = (IOTHUB_LONGHAUL_RESOURCES*)handle;
        result = iotHubLonghaulRsrcs->iotHubClientStats;
    }

    return result;
}

void longhaul_tests_deinit(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle)
{
    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaulRsrcs = (IOTHUB_LONGHAUL_RESOURCES*)handle;

        if (iotHubLonghaulRsrcs->lock != NULL)
        {
            Lock_Deinit(iotHubLonghaulRsrcs->lock);
            iotHubLonghaulRsrcs->lock = NULL;
        }

        if (iotHubLonghaulRsrcs->iotHubClientHandle != NULL)
        {
            IoTHubClient_Destroy(iotHubLonghaulRsrcs->iotHubClientHandle);
            iotHubLonghaulRsrcs->iotHubClientHandle = NULL;
        }

        if (iotHubLonghaulRsrcs->iotHubAccountInfo != NULL)
        {
            IoTHubAccount_deinit(iotHubLonghaulRsrcs->iotHubAccountInfo);
            iotHubLonghaulRsrcs->iotHubAccountInfo = NULL;
        }

        if (iotHubLonghaulRsrcs->iotHubClientStats != NULL)
        {
            iothub_client_statistics_destroy(iotHubLonghaulRsrcs->iotHubClientStats);
            iotHubLonghaulRsrcs->iotHubClientStats = NULL;
        }

        // Need a double deinit
        platform_deinit();
        platform_deinit();

        free((void*)handle);
    }
}

IOTHUB_LONGHAUL_RESOURCES_HANDLE longhaul_tests_init()
{
    IOTHUB_LONGHAUL_RESOURCES* result;

    if ((result = (IOTHUB_LONGHAUL_RESOURCES*)malloc(sizeof(IOTHUB_LONGHAUL_RESOURCES))) == NULL)
    {
        LogError("Failed to allocate IOTHUB_LONGHAUL_RESOURCES struct");
    }
    else
    {
        memset(result, 0, sizeof(IOTHUB_LONGHAUL_RESOURCES));

        if (platform_init() != 0)
        {
            LogError("Platform init failed");
            longhaul_tests_deinit(result);
            result = NULL;
        }
        else if ((result->lock = Lock_Init()) == NULL)
        {
            LogError("Failed creating lock");
            longhaul_tests_deinit(result);
            result = NULL;
        }
        else if ((result->iotHubAccountInfo = IoTHubAccount_Init()) == NULL)
        {
            LogError("Failed initializing accounts");
            longhaul_tests_deinit(result);
            result = NULL;
        }
        else if ((result->iotHubClientStats = iothub_client_statistics_create()) == NULL)
        {
            LogError("Failed initializing statistics");
            longhaul_tests_deinit(result);
            result = NULL;
        }
        else
        {
            platform_init();
        }
    }

    return result;
}

IOTHUB_CLIENT_HANDLE longhaul_create_and_connect_device_client(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle, IOTHUB_PROVISIONED_DEVICE* deviceToUse, IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol)
{
    IOTHUB_CLIENT_HANDLE result;

    if (handle == NULL || deviceToUse == NULL)
    {
        LogError("Invalid argument (handle=%p, deviceToUse=%p)", handle, deviceToUse);
        result = NULL;
    }
    else if ((result = IoTHubClient_CreateFromConnectionString(deviceToUse->connectionString, protocol)) == NULL)
    {
        LogError("Could not create IoTHubClient");
    }
    else if (deviceToUse->howToCreate == IOTHUB_ACCOUNT_AUTH_X509 &&
        (IoTHubClient_SetOption(result, OPTION_X509_CERT, deviceToUse->certificate) != IOTHUB_CLIENT_OK ||
            IoTHubClient_SetOption(result, OPTION_X509_PRIVATE_KEY, deviceToUse->primaryAuthentication) != IOTHUB_CLIENT_OK))
    {
        LogError("Could not set the device x509 certificate or privateKey");
        IoTHubClient_Destroy(result);
        result = NULL;
    }
    else
    {
        bool trace = true;
        unsigned int svc2cl_keep_alive_timeout_secs = 120; // service will send pings at 120 x 7/8 = 105 seconds. Higher the value, lesser the frequency of service side pings.
        double cl2svc_keep_alive_send_ratio = 1.0 / 2.0; // Set it to 120 seconds (240 x 1/2 = 120 seconds) for 4 minutes remote idle. 

        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaulRsrcs = (IOTHUB_LONGHAUL_RESOURCES*)handle;
        iotHubLonghaulRsrcs->iotHubClientHandle = result;

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
        (void)IoTHubClient_SetOption(result, OPTION_TRUSTED_CERT, certificates);
#endif
        (void)IoTHubClient_SetOption(result, OPTION_LOG_TRACE, &trace);
        (void)IoTHubClient_SetOption(result, OPTION_PRODUCT_INFO, "C-SDK-LongHaul");
        (void)IoTHubClient_SetOption(result, OPTION_SERVICE_SIDE_KEEP_ALIVE_FREQ_SECS, &svc2cl_keep_alive_timeout_secs);
        (void)IoTHubClient_SetOption(result, OPTION_REMOTE_IDLE_TIMEOUT_RATIO, &cl2svc_keep_alive_send_ratio);

        if (IoTHubClient_SetConnectionStatusCallback(result, connection_status_callback, handle) != IOTHUB_CLIENT_OK)
        {
            LogError("Failed setting the connection status callback");
            IoTHubClient_Destroy(result);
            iotHubLonghaulRsrcs->iotHubClientHandle = NULL;
            result = NULL;
        }
        else if (IoTHubClient_SetMessageCallback(result, c2d_message_received_callback, handle) != IOTHUB_CLIENT_OK)
        {
            LogError("Failed to set the cloud-to-device message callback");
            IoTHubClient_Destroy(result);
            iotHubLonghaulRsrcs->iotHubClientHandle = NULL;
            result = NULL;
        }
    }

    return result;
}

static void on_service_client_messaging_opened(void* context)
{
    (void)context;
}


int longhaul_start_listening_for_telemetry_messages(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle)
{
    int result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = __FAILURE__;
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaul = (IOTHUB_LONGHAUL_RESOURCES*)handle;

        if (iotHubLonghaul->iotHubServiceClientHandle == NULL && 
            (iotHubLonghaul->iotHubServiceClientHandle = IoTHubServiceClientAuth_CreateFromConnectionString(IoTHubAccount_GetIoTHubConnString(iotHubLonghaul->iotHubAccountInfo))) == NULL)
        {
            LogError("Failed to create IoT hub service client and establish connection");
            result = __FAILURE__;
        }
        else
        {
            IOTHUB_MESSAGING_CLIENT_HANDLE iotHubMsgClientHandle = IoTHubMessaging_Create(iotHubLonghaul->iotHubServiceClientHandle);
            IOTHUB_MESSAGING_RESULT iotHubMsgResult = IoTHubMessaging_Open(iotHubMsgClientHandle, on_service_client_messaging_opened, (void*)"Context string for open");

            // iotHubMsgResult = IoTHubMessaging_SetFeedbackMessageCallback(iotHubMsgClientHandle, on_telemetry_message_received, NULL);

        }

        // TODO: continue from here.
    }

    return result;
}

int longhaul_stop_listening_for_telemetry_messages(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle)
{
    int result;

    if (handle == NULL)
    {
        LogError("Invalid argument (handle is NULL)");
        result = __FAILURE__;
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaul = (IOTHUB_LONGHAUL_RESOURCES*)handle;


    }

    return result;
}

// Conveniency *run* functions

static void send_confirmation_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    if (userContextCallback == NULL)
    {
        LogError("Invalid argument (userContextCallback is NULL)");
    }
    else
    {
        SEND_TELEMETRY_CONTEXT* message_info = (SEND_TELEMETRY_CONTEXT*)userContextCallback;

        TELEMETRY_INFO telemetry_info;
        telemetry_info.message_id = message_info->message_id;
        telemetry_info.send_result = result;
        telemetry_info.time_sent = time(NULL);

        if (telemetry_info.time_sent == INDEFINITE_TIME)
        {
            LogError("Failed setting the time telemetry was sent");
        }
        else if (iothub_client_statistics_add_telemetry_info(message_info->iotHubLonghaul->iotHubClientStats, TELEMETRY_SENT, &telemetry_info) != 0)
        {
            LogError("Failed adding telemetry statistics info (message_id=%d)", message_info->message_id);
        }

        free(message_info);
    }
}

static IOTHUB_MESSAGE_HANDLE create_telemetry_message(size_t message_id)
{
    IOTHUB_MESSAGE_HANDLE result;
    char msg_text[11];

    if (sprintf_s(msg_text, sizeof(msg_text), "%d", message_id) <= 0)
    {
        LogError("Failed creating text for iothub message");
        result = NULL;
    }
    else if ((result = IoTHubMessage_CreateFromByteArray((const unsigned char*)msg_text, strlen(msg_text))) == NULL)
    {
        LogError("Failed creating IOTHUB_MESSAGE_HANDLE");
    }

    return result;
}

static SEND_TELEMETRY_CONTEXT* create_telemetry_message_context(IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaul)
{
    SEND_TELEMETRY_CONTEXT* result;

    if ((result = (SEND_TELEMETRY_CONTEXT*)malloc(sizeof(SEND_TELEMETRY_CONTEXT))) == NULL)
    {
        LogError("Failed allocating telemetry message context");
    }
    else
    {
        result->message_id = iotHubLonghaul->counter;
        result->iotHubLonghaul = iotHubLonghaul;
    }

    return result;
}

static int send_telemetry(const void* context)
{
    int result;
    IOTHUB_LONGHAUL_RESOURCES* longhaulResources = (IOTHUB_LONGHAUL_RESOURCES*)context;
    size_t message_id;

    if ((message_id = generate_unique_id(longhaulResources)) == 0)
    {
        LogError("Failed generating telemetry message id");
        result = __FAILURE__;
    }
    else
    {
        IOTHUB_MESSAGE_HANDLE message;

        if ((message = create_telemetry_message(message_id)) == NULL)
        {
            LogError("Failed creating telemetry message");
            result = __FAILURE__;
        }
        else
        {
            SEND_TELEMETRY_CONTEXT* message_info;

            if ((message_info = (SEND_TELEMETRY_CONTEXT*)malloc(sizeof(SEND_TELEMETRY_CONTEXT))) == NULL)
            {
                LogError("Failed allocating context for telemetry message");
                result = __FAILURE__;
            }
            else
            {
                TELEMETRY_INFO telemetry_info;
                telemetry_info.message_id = message_id;
                telemetry_info.time_queued = time(NULL);

                message_info->message_id = message_id;
                message_info->iotHubLonghaul = longhaulResources;

                if (IoTHubClient_SendEventAsync(longhaulResources->iotHubClientHandle, message, send_confirmation_callback, message_info) != IOTHUB_CLIENT_OK)
                {
                    LogError("Failed sending telemetry message");
                    free(message_info);
                    result = __FAILURE__;
                }
                else
                {
                    result = 0;
                }

                telemetry_info.send_result = result;

                if (iothub_client_statistics_add_telemetry_info(longhaulResources->iotHubClientStats, TELEMETRY_QUEUED, &telemetry_info) != 0)
                {
                    LogError("Failed adding telemetry statistics info (message_id=%d)", message_id);
                    result = __FAILURE__;
                }
            }

            IoTHubMessage_Destroy(message);
        }
    }

    return result;
}

int longhaul_run_telemetry_tests(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle, size_t iterationDurationInSeconds, size_t totalDurationInSeconds)
{
    int result;

    if (handle == NULL)
    {
        LogError("Invalig argument (handle is NULL)");
        result = __FAILURE__;
    }
    else
    {
        IOTHUB_LONGHAUL_RESOURCES* iotHubLonghaulRsrcs = (IOTHUB_LONGHAUL_RESOURCES*)handle;

        if (iotHubLonghaulRsrcs->iotHubClientHandle == NULL)
        {
            LogError("IoTHubClient not initialized.");
            result = __FAILURE__;
        }
        else
        {
            int loop_result;
            IOTHUB_CLIENT_STATISTICS_HANDLE stats_handle;
            
            loop_result = run_on_loop(send_telemetry, iterationDurationInSeconds, totalDurationInSeconds, iotHubLonghaulRsrcs);
            
            stats_handle = longhaul_get_statistics(iotHubLonghaulRsrcs);

            LogInfo("Longhaul telemetry stats: %s", iothub_client_statistics_to_json(stats_handle));

            if (loop_result != 0)
            {
                result = __FAILURE__;
            }
            else
            {
                size_t messages_sent;
                size_t messages_received;
                double min_travel_time_secs;
                double max_travel_time_secs;

                if (iothub_client_statistics_get_telemetry_summary(
                    stats_handle, &messages_sent, &messages_received, &min_travel_time_secs, &max_travel_time_secs) != 0)
                {
                    LogError("Failed gettting statistics summary");
                    result = __FAILURE__;
                }
                else if (messages_received != messages_sent || max_travel_time_secs > MAX_TELEMETRY_TRAVEL_TIME_SECS)
                {
                    LogError("Messages sent=%d, received=%d; travel time: min=%f secs, max=%f secs", messages_sent, messages_received, min_travel_time_secs, max_travel_time_secs);
                    result = __FAILURE__;
                }
                else
                {
                    result = 0;
                }
            }
        }
    }

    return result;
}
//
//int longhaul_run_c2d_tests(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle, size_t durationInSeconds)
//{
//}
//
//int longhaul_run_device_methods_tests(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle, size_t durationInSeconds)
//{
//}
//
//int longhaul_run_twin_desired_properties_tests(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle, size_t durationInSeconds)
//{
//}
//
//int longhaul_run_twin_reported_properties_tests(IOTHUB_LONGHAUL_RESOURCES_HANDLE handle, size_t durationInSeconds)
//{
//}