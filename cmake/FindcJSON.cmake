# SPDX-FileCopyrightText: 2010-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

# find_cjson( [PATH "path"] [VERSION "1.1.2"] [GIT_TAG "v1.2.3"] )
#   PATH    - An alternate path to examine for the cjson package
#   VERSION - The expected version of the cjson package
#   GIT_TAG - The specific git tag to checkout if it comes to that

# Search Order:
#   1. User specified path
#   2. Existing installed path
#   3. Fetch a working copy & build it

function(find_cjson)

    cmake_parse_arguments(CJSON "" "PATH;VERSION;GIT_TAG" "" ${ARGN})

    include(LocalInstallPaths)

    #message(STATUS "CJSON_PATH    = \"${CJSON_PATH}\"")
    #message(STATUS "CJSON_VERSION = \"${CJSON_VERSION}\"")
    #message(STATUS "CJSON_GIT_TAG = \"${CJSON_GIT_TAG}\"")

    if (NOT DEFINED CJSON_VERSION)
        set(CJSON_ENFORCE_VERSION "libcjson")
        if (NOT DEFINED CJSON_GIT_TAG)
            set(CJSON_GIT_TAG "")
        endif()
    else ()
        set(CJSON_ENFORCE_VERSION "libcjson>=${CJSON_VERSION}")
        if (NOT DEFINED CJSON_GIT_TAG)
            set(CJSON_GIT_TAG "v${CJSON_VERSION}")
        endif()
    endif()

    find_path(CJSON_INCLUDE_DIR
        NAMES "cjson/cJSON.h"
        PATHS "${CMAKE_CURRENT_BINARY_DIR}/${CJSON_PATH}"
        PATH_SUFFIXES "include"
        NO_DEFAULT_PATH)

    find_library(CJSON_LIBRARY_DIR
                 NAMES "libcjson.so"
                 PATHS "${CMAKE_CURRENT_BINARY_DIR}/${CJSON_PATH}"
                 PATH_SUFFIXES "lib" "lib64"
                 NO_DEFAULT_PATH)

    if (NOT (CJSON_INCLUDE_DIR MATCHES "-NOTFOUND" OR CJSON_LIBRARY_DIR MATCHES "-NOTFOUND"))
        message(STATUS "Found user specified cjson (at: \"${CJSON_PATH}\")")
        include_directories(SYSTEM ${CJSON_INCLUDE_DIR})
        set(CJSON_LIBRARIES ${CJSON_LIBRARY_DIR} PARENT_SCOPE)
    else()
        include(FindPkgConfig)

        pkg_check_modules(CJSON QUIET ${CJSON_ENFORCE_VERSION})
        if (CJSON_FOUND EQUAL 1)
            message(STATUS "Using system provided cjson (found version \"${CJSON_VERSION}\")")
            include_directories(SYSTEM ${CJSON_INCLUDE_DIRS})
        else()
            include(ExternalProject)
            
            message(STATUS "Fetching upstream cjson")
            ExternalProject_Add(cjson
                PREFIX ${LOCAL_PREFIX_DIR}/cjson
                GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
                GIT_TAG ${CJSON_GIT_TAG}
                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${LOCAL_INSTALL_DIR} -DBUILD_TESTING=OFF)
            add_library(libcjson STATIC IMPORTED)
            add_dependencies(libcjson cjson)
            add_dependencies(${CMAKE_PROJECT_NAME} cjson)
            include_directories(SYSTEM ${LOCAL_INCLUDE_DIR})
            set(CJSON_LIBRARIES "${LOCAL_LIBRARY_DIR}/libcjson.so" PARENT_SCOPE)
        endif()
    endif()
endfunction()
