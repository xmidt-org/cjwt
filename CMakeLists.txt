# SPDX-FileCopyrightText: 2010-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")

project(cjwt VERSION 2.0.0)

include(BitwiseVersion)
include(CTest)
include(FindcJSON)
include(FindTrowerBase64)
include(LicenseLinterTarget)
include(Coverage)

add_definitions(-std=c99)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Werror -Wall -Wpedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -Wpedantic")

add_library(cjwt SHARED "")

################################################################################
# Find or acquire software dependencies
################################################################################

find_cjson(        PATH ${CJSON_PATH}   VERSION "1.7.14" GIT_TAG "")
find_trower_base64(PATH ${TROWER_PATH}  VERSION "1.2.0"  GIT_TAG "")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

################################################################################
# Process the subdirectories now
################################################################################

add_subdirectory(src)

if (BUILD_TESTING)
    include(FindCunit)
	add_subdirectory(tests)
endif (BUILD_TESTING)
