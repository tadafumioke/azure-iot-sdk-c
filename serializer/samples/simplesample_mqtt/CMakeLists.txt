#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

#this is CMakeLists.txt for simplesample_mqtt sample

compileAsC99()

if(NOT ${use_mqtt})
	message(FATAL_ERROR "simplesample_mqtt being generated without mqtt support")
endif()

set(simplesample_mqtt_c_files
	simplesample_mqtt.c
)

if(WIN32)
	set(simplesample_mqtt_c_files ${simplesample_mqtt_c_files} ./windows/main.c)
else()
	set(simplesample_mqtt_c_files ${simplesample_mqtt_c_files} ./linux/main.c)
endif()

set(simplesample_mqtt_h_files
	simplesample_mqtt.h
)

IF(WIN32)
	#windows needs this define
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
ENDIF(WIN32)

# Conditionally use the SDK trusted certs in the samples
if(${set_trusted_cert_in_samples})
    add_definitions(-DSET_TRUSTED_CERT_IN_SAMPLES)
	include_directories(${PROJECT_SOURCE_DIR}/certs)
	set(samples_cert_file ${PROJECT_SOURCE_DIR}/certs/certs.c)
endif()

include_directories(. ${SHARED_UTIL_INC_FOLDER} ${IOTHUB_CLIENT_INC_FOLDER})

add_executable(simplesample_mqtt ${simplesample_mqtt_c_files} ${simplesample_mqtt_h_files} ${samples_cert_file})

if (build_as_dynamic)
	target_link_libraries(simplesample_mqtt
		iothub_client_mqtt_transport_dll
		serializer_dll
	)
else()
	target_link_libraries(simplesample_mqtt  
		iothub_client 
		iothub_client_mqtt_transport
		serializer
		parson_lib
		umqtt
	)
endif()
