#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

#this is CMakeLists.txt for devicetwin_simplesample

compileAsC99()

if (${use_mqtt})
	set(libpart "mqtt")
elseif (${use_amqp})
	set(libpart "amqp")
else()
    message(FATAL_ERROR "devicetwin_simplesample being generated without mqtt and amqp support")
endif()

set(devicetwin_simplesample_c_files
    devicetwin_simplesample.c
)

set(devicetwin_simplesample_h_files
    devicetwin_simplesample.h
)

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
ENDIF(WIN32)

include_directories(. ${SERIALIZER_INC_FOLDER} ${SHARED_UTIL_INC_FOLDER} ${IOTHUB_CLIENT_INC_FOLDER})

add_executable(devicetwin_simplesample ${devicetwin_simplesample_c_files} ${devicetwin_simplesample_h_files})

if (build_as_dynamic)
    target_link_libraries(devicetwin_simplesample 
        "iothub_client_${libpart}_transport_dll"
        serializer_dll
    )
else()
    target_link_libraries(devicetwin_simplesample 
        "iothub_client_${libpart}_transport"
        serializer 
        iothub_client
        parson_lib
        "u${libpart}"
    )
endif(build_as_dynamic)
