# SPDX-FileCopyrightText: 2010-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

include(FindPkgConfig)

pkg_check_modules(CUNIT REQUIRED QUIET cunit)
include_directories(${CUNIT_INCLUDE_DIRS})
message(STATUS "Using system provided CUnit (found version \"${CUNIT_VERSION}\")")
