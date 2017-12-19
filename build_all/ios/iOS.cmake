# This file is based off of the Platform/Darwin.cmake and Platform/UnixPaths.cmake
# files which are included with CMake 2.8.4
# It has been altered for iOS development

# Options:
#
# simulator_build = OFF (default)
#   This decides if SDKS will be selected from the iPhoneOS.platform or iPhoneSimulator.platform folders
#   OFF - the default, used to build for iPhone and iPad physical devices, which have an arm arch.
#   ON - used to build for the Simulator platforms, which have an i386 and x86_64 arch.
#
# CMAKE_IOS_DEVELOPER_ROOT = automatic(default) or /path/to/platform/Developer folder
#   By default this location is automatcially chosen based on the IOS_PLATFORM value above.
#   If set manually, it will override the default location and force the user of a particular Developer Platform
#
# CMAKE_IOS_SDK_ROOT = automatic(default) or /path/to/platform/Developer/SDKs/SDK folder
#   By default this location is automatcially chosen based on the CMAKE_IOS_DEVELOPER_ROOT value.
#   In this case it will always be the most up-to-date SDK found in the CMAKE_IOS_DEVELOPER_ROOT path.
#   If set manually, this will force the use of a specific SDK version

cmake_policy(SET CMP0054 NEW)

option(simulator_build "use to build for simulator rather than device" OFF)

# Standard settings
set (CMAKE_SYSTEM_NAME Darwin)
set (CMAKE_SYSTEM_VERSION 1)
set (UNIX True)
set (APPLE True)
set (IOS True)

# Required as of cmake 2.8.10
set (CMAKE_OSX_DEPLOYMENT_TARGET "" CACHE STRING "Force unset of the deployment target for iOS" FORCE)
set (use_openssl "OFF" CACHE STRING "Force no SSL library for iOS" FORCE)
#set (use_http "OFF" CACHE STRING "Force no HTTP for iOS (for now)" FORCE)

# Determine the cmake host system version so we know where to find the iOS SDKs
find_program (CMAKE_UNAME uname /bin /usr/bin /usr/local/bin)
if (CMAKE_UNAME)
	exec_program(uname ARGS -r OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_VERSION)
	string (REGEX REPLACE "^([0-9]+)\\.([0-9]+).*$" "\\1" DARWIN_MAJOR_VERSION "${CMAKE_HOST_SYSTEM_VERSION}")
endif (CMAKE_UNAME)

set(MACOSX_BUNDLE_GUI_IDENTIFIER com.microsoft)
set(CMAKE_MACOSX_BUNDLE YES)
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer")

# Set up compilers to use Clang
set (CMAKE_C_COMPILER "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang")
set (CMAKE_CXX_COMPILER "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang")

set(CMAKE_AR ar CACHE FILEPATH "" FORCE)

# Skip the platform compiler checks for cross compiling
set (CMAKE_CXX_COMPILER_WORKS TRUE)
set (CMAKE_C_COMPILER_WORKS TRUE)

# All iOS/Darwin specific settings - some may be redundant
set (CMAKE_SHARED_LIBRARY_PREFIX "lib")
set (CMAKE_SHARED_LIBRARY_SUFFIX ".dylib")
set (CMAKE_SHARED_MODULE_PREFIX "lib")
set (CMAKE_SHARED_MODULE_SUFFIX ".so")
set (CMAKE_MODULE_EXISTS 1)
set (CMAKE_DL_LIBS "")

set (CMAKE_C_OSX_COMPATIBILITY_VERSION_FLAG "-compatibility_version ")
set (CMAKE_C_OSX_CURRENT_VERSION_FLAG "-current_version ")
set (CMAKE_CXX_OSX_COMPATIBILITY_VERSION_FLAG "${CMAKE_C_OSX_COMPATIBILITY_VERSION_FLAG}")
set (CMAKE_CXX_OSX_CURRENT_VERSION_FLAG "${CMAKE_C_OSX_CURRENT_VERSION_FLAG}")

# Hidden visibilty is required for cxx on iOS 
set (CMAKE_C_FLAGS_INIT "-Wno-unused-variable -Wno-unused-function")
set (CMAKE_CXX_FLAGS_INIT "-fvisibility=hidden -fvisibility-inlines-hidden -Wno-unused-variable -Wno-unused-function")

set (CMAKE_C_LINK_FLAGS "-Wl,-search_paths_first ${CMAKE_C_LINK_FLAGS}")
set (CMAKE_CXX_LINK_FLAGS "-Wl,-search_paths_first ${CMAKE_CXX_LINK_FLAGS}")

set (CMAKE_PLATFORM_HAS_INSTALLNAME 1)
set (CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "-dynamiclib -headerpad_max_install_names")
set (CMAKE_SHARED_MODULE_CREATE_C_FLAGS "-bundle -headerpad_max_install_names")
set (CMAKE_SHARED_MODULE_LOADER_C_FLAG "-Wl,-bundle_loader,")
set (CMAKE_SHARED_MODULE_LOADER_CXX_FLAG "-Wl,-bundle_loader,")
set (CMAKE_FIND_LIBRARY_SUFFIXES ".dylib" ".so" ".a")

# Do not attempt to build samples on iOS platform
set(skip_samples ON CACHE BOOL "set skip_samples to ON to skip building samples (default is OFF)[if possible, they are always built]" FORCE)
set(suppress_header_searches ON CACHE BOOL "do not try to find headers - used when compiler check will fail" FORCE)
set(use_builtin_httpapi ON CACHE BOOL "set use_builtin_httpapi to ON to use the built-in httpapi_compact that comes with C shared utility (default is OFF)" FORCE)

# hack: if a new cmake (which uses CMAKE_INSTALL_NAME_TOOL) runs on an old build tree
# (where install_name_tool was hardcoded) and where CMAKE_INSTALL_NAME_TOOL isn't in the cache
# and still cmake didn't fail in CMakeFindBinUtils.cmake (because it isn't rerun)
# hardcode CMAKE_INSTALL_NAME_TOOL here to install_name_tool, so it behaves as it did before, Alex
if (NOT DEFINED CMAKE_INSTALL_NAME_TOOL)
	find_program(CMAKE_INSTALL_NAME_TOOL install_name_tool)
endif (NOT DEFINED CMAKE_INSTALL_NAME_TOOL)

# Set up for building simulator or device image
if (${simulator_build})
	set (IOS_PLATFORM_LOCATION "iPhoneSimulator.platform")
	set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")
else (${simulator_build})
	set (IOS_PLATFORM_LOCATION "iPhoneOS.platform")
	set (CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphoneos")
endif (${simulator_build})

# Setup iOS developer location unless specified manually with CMAKE_IOS_DEVELOPER_ROOT
# Note Xcode 4.3 changed the installation location, choose the most recent one available
exec_program(/usr/bin/xcode-select ARGS -print-path OUTPUT_VARIABLE CMAKE_XCODE_DEVELOPER_DIR)
set (XCODE_POST_43_ROOT "${CMAKE_XCODE_DEVELOPER_DIR}/Platforms/${IOS_PLATFORM_LOCATION}/Developer")
set (XCODE_PRE_43_ROOT "/Developer/Platforms/${IOS_PLATFORM_LOCATION}/Developer")

if (NOT DEFINED CMAKE_IOS_DEVELOPER_ROOT)
	if (EXISTS ${XCODE_POST_43_ROOT})
		set (CMAKE_IOS_DEVELOPER_ROOT ${XCODE_POST_43_ROOT})
	elseif(EXISTS ${XCODE_PRE_43_ROOT})
		set (CMAKE_IOS_DEVELOPER_ROOT ${XCODE_PRE_43_ROOT})
	endif (EXISTS ${XCODE_POST_43_ROOT})
endif (NOT DEFINED CMAKE_IOS_DEVELOPER_ROOT)

set (CMAKE_IOS_DEVELOPER_ROOT ${CMAKE_IOS_DEVELOPER_ROOT} CACHE PATH "Location of iOS Platform")

# Find and use the most recent iOS sdk unless specified manually with CMAKE_IOS_SDK_ROOT
if (NOT DEFINED CMAKE_IOS_SDK_ROOT)
	file (GLOB _CMAKE_IOS_SDKS "${CMAKE_IOS_DEVELOPER_ROOT}/SDKs/*")
	if (_CMAKE_IOS_SDKS) 
		list (SORT _CMAKE_IOS_SDKS)
		list (REVERSE _CMAKE_IOS_SDKS)
		list (GET _CMAKE_IOS_SDKS 0 CMAKE_IOS_SDK_ROOT)
	else (_CMAKE_IOS_SDKS)
		message (FATAL_ERROR "No iOS SDK's found in default search path ${CMAKE_IOS_DEVELOPER_ROOT}. Manually set CMAKE_IOS_SDK_ROOT or install the iOS SDK.")
	endif (_CMAKE_IOS_SDKS)
	message (STATUS "Toolchain using default iOS SDK: ${CMAKE_IOS_SDK_ROOT}")
endif (NOT DEFINED CMAKE_IOS_SDK_ROOT)

# Extract the SDK version
string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.sdk$" IOS_SDK_VERSION ${CMAKE_IOS_SDK_ROOT})

if(NOT CMAKE_MATCH_1 OR NOT CMAKE_MATCH_2)
	message(FATAL_ERROR "Unable to determine SDK version")
endif()

set(IOS_SDK_VERSION_MAJOR ${CMAKE_MATCH_1})
set(IOS_SDK_VERSION_MINOR ${CMAKE_MATCH_2})

set (CMAKE_IOS_SDK_ROOT ${CMAKE_IOS_SDK_ROOT} CACHE PATH "Location of the selected iOS SDK")

# Set up for building simulator or device image
if (${simulator_build})
    set (IOS_ARCH x86_64)
	
	# 32 bit not supported at 11 or above
	if (IOS_SDK_VERSION_MAJOR LESS 11)
		set(IOS_ARCH ${IOS_ARCH} i386)
	endif()
else (${simulator_build})
    set (IOS_ARCH arm64)
	
	# 32 bit not supported at 11 or above
	if (IOS_SDK_VERSION_MAJOR LESS 11)
		set(IOS_ARCH ${IOS_ARCH} armv7s)
	endif()
endif (${simulator_build})

# Set the sysroot default to the most recent SDK
set (CMAKE_OSX_SYSROOT ${CMAKE_IOS_SDK_ROOT} CACHE PATH "Sysroot used for iOS support")
set (CMAKE_OSX_ARCHITECTURES ${IOS_ARCH} CACHE string  "Build architecture for iOS")

if (NOT DEFINED OPENSSL_ROOT_DIR)
    set (OPENSSL_ROOT_DIR "$ENV{HOME}/Desktop/openssl-ios-dist/")
endif (NOT DEFINED OPENSSL_ROOT_DIR)

if (NOT DEFINED CURL_ROOT_DIR)
    set (CURL_ROOT_DIR "$ENV{HOME}/Desktop/libcurl-ios-dist/")
endif (NOT DEFINED CURL_ROOT_DIR)

# Set the find root to the iOS developer roots and to user defined paths
set (CMAKE_FIND_ROOT_PATH ${CMAKE_IOS_DEVELOPER_ROOT} ${CMAKE_IOS_SDK_ROOT} ${CMAKE_PREFIX_PATH} ${OPENSSL_ROOT_DIR} ${CURL_ROOT_DIR} CACHE string  "iOS find search path root")

# default to searching for frameworks first
set (CMAKE_FIND_FRAMEWORK FIRST)

# set up the default search directories for frameworks
set (CMAKE_SYSTEM_FRAMEWORK_PATH
	${CMAKE_IOS_SDK_ROOT}/System/Library/Frameworks
	${CMAKE_IOS_SDK_ROOT}/System/Library/PrivateFrameworks
	${CMAKE_IOS_SDK_ROOT}/Developer/Library/Frameworks
)

# only search the iOS sdks, not the remainder of the host filesystem
set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
