# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

add_custom_target(coverage
                  COMMAND lcov -q --capture
                          --directory ${CMAKE_CURRENT_BINARY_DIR}/
                          --output-file coverage.info
                  COMMAND genhtml coverage.info
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
