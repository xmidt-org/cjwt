# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED LOCAL_INSTALL_DIR)
    set(LOCAL_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/_install")
endif()
if (NOT DEFINED LOCAL_PREFIX_DIR)
    set(LOCAL_PREFIX_DIR "${CMAKE_CURRENT_BINARY_DIR}/_prefix")
endif()
set(LOCAL_LIBRARY_DIR "${LOCAL_INSTALL_DIR}/lib${LIB_SUFFIX}")
set(LOCAL_INCLUDE_DIR "${LOCAL_INSTALL_DIR}/include")
