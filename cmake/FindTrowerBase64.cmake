# SPDX-FileCopyrightText: 2010-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

# find_trower_base64( [PATH "path"] [VERSION "1.1.2"] [GIT_TAG "v1.2.3"] )
#   PATH    - An alternate path to examine for the trower-base64 package
#   VERSION - The expected version of the trower-base64 package
#   GIT_TAG - The specific git tag to checkout if it comes to that

# Search Order:
#   1. User specified path
#   2. Existing installed path
#   3. Fetch a working copy & build it

function(find_trower_base64)

    cmake_parse_arguments(TROWER "" "PATH;VERSION;GIT_TAG" "" ${ARGN})

    include(LocalInstallPaths)

    #message(STATUS "TROWER_PATH    = \"${TROWER_PATH}\"")
    #message(STATUS "TROWER_VERSION = \"${TROWER_VERSION}\"")
    #message(STATUS "TROWER_GIT_TAG = \"${TROWER_GIT_TAG}\"")

    if (NOT DEFINED TROWER_VERSION)
        set(TROWER_ENFORCE_VERSION "trower-base64")
        if (NOT DEFINED TROWER_GIT_TAG)
            set(TROWER_GIT_TAG "")
        endif()
    else ()
        set(TROWER_ENFORCE_VERSION "trower-base64>=${TROWER_VERSION}")
        if (NOT DEFINED TROWER_GIT_TAG)
            set(TROWER_GIT_TAG "v${TROWER_VERSION}")
        endif()
    endif()

    find_path(TROWER_INCLUDE_DIR
              NAMES "trower-base64/base64.h"
              PATHS "${CMAKE_CURRENT_BINARY_DIR}/${TROWER_PATH}"
              PATH_SUFFIXES "include"
              NO_DEFAULT_PATH)

    find_library(TROWER_LIBRARY_DIR
                 NAMES "libtrower-base64.so"
                 PATHS "${CMAKE_CURRENT_BINARY_DIR}/${TROWER_PATH}"
                 PATH_SUFFIXES "lib" "lib64"
                 NO_DEFAULT_PATH)

    set(TROWER_LIBRARIES ${TROWER_LIBRARIES} PARENT_SCOPE)
    if (NOT (TROWER_INCLUDE_DIR MATCHES "-NOTFOUND" OR TROWER_LIBRARY_DIR MATCHES "-NOTFOUND"))
        message(STATUS "Found user specified trower-base64 (at: \"${TROWER_PATH}\")")
        include_directories(SYSTEM ${TROWER_INCLUDE_DIR})
        set(TROWER_LIBRARIES ${TROWER_LIBRARY_DIR} PARENT_SCOPE)
    else()
        include(FindPkgConfig)

        pkg_check_modules(TROWER_BASE64 QUIET ${TROWER_ENFORCE_VERSION})
        if (TROWER_BASE64_FOUND EQUAL 1)
            message(STATUS "Using system provided trower-base64 (found version \"${TROWER_BASE64_VERSION}\")")
            include_directories(SYSTEM ${TROWER_BASE64_INCLUDE_DIRS})
        else()
            include(ExternalProject)

            message(STATUS "Fetching upstream trower-base64 (tag \"${TROWER_GIT_TAG}\")")
            ExternalProject_Add(trower-base64
                PREFIX ${LOCAL_PREFIX_DIR}/trower-base64
                GIT_REPOSITORY https://github.com/xmidt-org/trower-base64.git
                GIT_TAG ${TROWER_GIT_TAG}
                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${LOCAL_INSTALL_DIR} -DBUILD_TESTING=OFF)
            add_library(libtrower-base64 STATIC IMPORTED)
            add_dependencies(libtrower-base64 trower-base64)
            add_dependencies(${CMAKE_PROJECT_NAME} trower-base64)
            include_directories(SYSTEM ${LOCAL_INCLUDE_DIR})
            set(TROWER_LIBRARIES "${LOCAL_LIBRARY_DIR}/libtrower-base64.so" PARENT_SCOPE)
        endif()
    endif()
endfunction()
