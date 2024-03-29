# Meson build file
#
# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

project('cjwt', 'c',
        version: '2.2.1',
        license: ['Apache-2.0'],
        meson_version: '>= 0.60.3',
        default_options: ['c_std=c99',
                          'b_coverage=true'])

if not meson.is_subproject()
  # We want strict flags
  warning_level = 3   # -Wall
  werror = true
endif

################################################################################
# Common variable definitions
################################################################################

inc_base = 'include/'+meson.project_name()

################################################################################
# Generate the version header file
################################################################################

subdir('include/'+meson.project_name())

################################################################################
# Define the dependencies
################################################################################
openssl = dependency('openssl', version: '>=1.1.1', fallback:['openssl', 'openssl_dep'])
libcjson_dep = dependency('libcjson', version: '>=1.7.14', fallback: ['cjson', 'libcjson_dep'])
libtrower_base64_dep = dependency('trower-base64', version: '>=1.2.7')

################################################################################
# Define the libraries
################################################################################

inc = include_directories([inc_base])

install_headers([inc_base+'/cjwt.h', ver_h], subdir: meson.project_name())

tls = []
if openssl.version().startswith('1.1')
  tls = [ 'src/jws_openssl_1.c' ]
else
  tls = [ 'src/jws_openssl_3.c' ]
endif

sources = ['src/cjwt.c',
           'src/print.c',
           'src/utils.c',
           tls ]

libcjwt = library(meson.project_name(),
                  sources,
                  include_directories: inc,
                  dependencies: [libcjson_dep, libtrower_base64_dep, openssl],
                  install: true)

################################################################################
# Define the examples
################################################################################
if not meson.is_subproject()
  examples = ['hs_example', 'rs_example', 'es_example']

  foreach e : examples
    executable(e, ['examples/basic/'+e+'.c'], 
               include_directories: inc,
               dependencies: [libcjson_dep, libtrower_base64_dep, openssl],
               link_with: libcjwt)
  endforeach
endif

################################################################################
# Define the tests
################################################################################

if not meson.is_subproject()
  test_args = ['-fprofile-arcs', '-ftest-coverage', '-O0']
  
  if meson.get_compiler('c').get_id() != 'clang'
    if host_machine.system().contains('linux')
      v = run_command('valgrind', '--version', check: false)
      if v.returncode() == 0
        add_test_setup('valgrind',
                       is_default: true,
                       exe_wrapper: [ 'valgrind',
                                      '--leak-check=full',
                                      '--show-reachable=yes',
                                      '--error-exitcode=1' ],
                       timeout_multiplier: 4)
      endif
    endif
  endif

  cunit_dep = dependency('cunit')
  common_deps = [cunit_dep, libcjson_dep, libtrower_base64_dep, openssl]

  test('test utils',
       executable('test_utils',
                  ['tests/test_utils.c',
                   'src/utils.c'],
                  include_directories: inc,
                  dependencies: cunit_dep,
                  link_args: test_args))


  test('test print',
       executable('test_print',
                  ['tests/test_print.c',
                   'src/cjwt.c',
                   'src/print.c',
                   'src/utils.c',
                   tls ],
                  include_directories: inc,
                  dependencies: common_deps,
                  link_args: test_args))

  test('test cjwt new',
       executable('test_cjwt_new',
                  ['tests/test_cjwt_new.c',
                   'src/cjwt.c',
                   'src/utils.c',
                   tls ],
                  include_directories: inc,
                  dependencies: common_deps,
                  link_args: test_args))

  test('test cjwt',
       executable('test_cjwt',
                  ['tests/test_cjwt.c',
                   'src/cjwt.c',
                   'src/utils.c',
                   tls ],
                  include_directories: inc,
                  dependencies: common_deps,
                  link_args: test_args))

  test('test map',
       executable('test_map',
                  ['tests/test_map.c',
                   'src/cjwt.c',
                   'src/utils.c',
                   tls ],
                  include_directories: inc,
                  dependencies: common_deps,
                  link_args: test_args))


endif

################################################################################
# Add the license check target
################################################################################

reuse_bin = find_program('reuse', required: false)
if reuse_bin.found()
  custom_target('license',
                command: [reuse_bin, 'lint'],
                build_always_stale: true,
                output: ['license'])
endif

################################################################################
# Add the coverity check target
################################################################################

alias_target('coverity', libcjwt )

################################################################################
# External/consumer definitions
################################################################################

libcjwt_dep = declare_dependency(include_directories: ['include'],
                                          link_with: libcjwt)

if meson.version().version_compare('>=0.54.0')
  meson.override_dependency(meson.project_name(), libcjwt_dep)
endif
