# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

version = meson.project_version()
version_arr = version.split('.')
major = version_arr[0].to_int()
minor = version_arr[1].to_int()
patch = version_arr[2].to_int()

hex = '0123456789abcdef'
ver = '0x@0@@1@@2@@3@@4@@5@'
bitwise = ver.format(hex[major / 16], hex[major % 16],
                     hex[minor / 16], hex[minor % 16],
                     hex[patch / 16], hex[patch % 16])

cfg = configuration_data()
cfg.set( meson.project_name()+'_VERSION', version)
cfg.set( meson.project_name()+'_VERSION_MAJOR', major)
cfg.set( meson.project_name()+'_VERSION_MINOR', minor)
cfg.set( meson.project_name()+'_VERSION_PATCH', patch)
cfg.set( meson.project_name()+'_BITWISE_VERSION', bitwise)

ver_h = configure_file(input:  'cjwtver.h.in',
                       output: 'cjwtver.h',
                       configuration: cfg)
