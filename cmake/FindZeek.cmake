# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
#
# CMake helpers to find Zeek and build Zeek plugins.
#
# To have this find Zeek, either set PATH to contain zeek-config, set
# ZEEK_ROOT_DIR to the Zeek installation, or set ZEEK_CONFIG to the binary.
#
# Output:
#     ZEEK_FOUND                 true if Zeek has been found
#
#     If ZEEK_FOUND is true:
#
#       ZEEK_CONFIG       Path to Zeek configuration.
#       ZEEK_CXX_FLAGS    C++ flags to compile a Zeek plugin.
#       ZEEK_CMAKE_DIR    Path to Zeek's CMake files.
#       ZEEK_INCLUDE_DIRS Path to Zeek's headers.
#       ZEEK_PLUGIN_DIR   Path to Zeek's plugin directory.
#       ZEEK_PREFIX       Path to Zeek's installation prefix.
#       ZEEK_VERSION      Version string of Zeek.
#       ZEEK_VERSION_NUMBER Numerical version of Zeek.
#       ZEEK_DEBUG_BUILD  true if Zeek was build in debug mode
#       ZEEK_EXE          Path to zeek executale
#       BifCl_EXE         Path to bifcl

### Functions

macro(configure)
    ### Find zeek-config
    if ( NOT ZEEK_CONFIG )
        set(ZEEK_CONFIG "$ENV{ZEEK_CONFIG}")
    endif ()

    if ( ZEEK_CONFIG )
        if ( EXISTS "${ZEEK_CONFIG}" )
            set(zeek_config "${ZEEK_CONFIG}")
        else ()
            message(STATUS "'${ZEEK_CONFIG}' does not exist")
        endif ()
    else ()
        find_program(zeek_config zeek-config
            HINTS
                ${ZEEK_ROOT_DIR}/bin
                ${ZEEK_ROOT_DIR}/build/bin
                $ENV{ZEEK_ROOT_DIR}/bin
                $ENV{ZEEK_ROOT_DIR}/build/bin
                /usr/local/zeek/bin
            )
    endif ()

    if ( NOT zeek_config )
        message(STATUS "Cannot determine location of Zeek installation")
        set(HAVE_ZEEK no)
    else ()
        message(STATUS "Found zeek-config: ${zeek_config}")
        set(HAVE_ZEEK yes)
        set(ZEEK_CONFIG "${zeek_config}" CACHE FILEPATH "" FORCE)

        ### Determine properties.

        run_zeek_config(ZEEK_INCLUDE_DIRS "--include_dir")
        run_zeek_config(ZEEK_CMAKE_DIR "--cmake_dir")
        run_zeek_config(ZEEK_PREFIX "--prefix")
        run_zeek_config(ZEEK_PLUGIN_DIR "--plugin_dir")
        run_zeek_config(ZEEK_VERSION "--version")
        run_zeek_config(ZEEK_BUILD_TYPE "--build_type")

        if ( "${ZEEK_BUILD_TYPE}" STREQUAL "debug" )
            set(ZEEK_DEBUG_BUILD yes)
        else ()
            set(ZEEK_DEBUG_BUILD no)
        endif ()

        string(REPLACE " " ";" ZEEK_INCLUDE_DIRS "${ZEEK_INCLUDE_DIRS}")
        #list(TRANSFORM ZEEK_CXX_FLAGS PREPEND "-I")
        #string(REPLACE ";" " " ZEEK_CXX_FLAGS "${ZEEK_CXX_FLAGS}")

        # Copied from Zeek to generate numeric version number.
        string(REGEX REPLACE "[.-]" " " version_numbers "${ZEEK_VERSION}")
        separate_arguments(version_numbers)
        list(GET version_numbers 0 VERSION_MAJOR)
        list(GET version_numbers 1 VERSION_MINOR)
        list(GET version_numbers 2 VERSION_PATCH)
        set(VERSION_MAJ_MIN "${VERSION_MAJOR}.${VERSION_MINOR}")
        math(EXPR ZEEK_VERSION_NUMBER
         "${VERSION_MAJOR} * 10000 + ${VERSION_MINOR} * 100 + ${VERSION_PATCH}")

        find_program(BifCl_EXE bifcl HINTS ${ZEEK_PREFIX}/bin NO_DEFAULT_PATH)
        find_program(ZEEK_EXE zeek HINTS ${ZEEK_PREFIX}/bin NO_DEFAULT_PATH)
    endif ()
endmacro ()

function(zeek_require_version version version_number)
    if ( "${ZEEK_VERSION_NUMBER}" LESS "${version_number}" )
        message(FATAL_ERROR "Package requires at least Zeek version ${version}, have ${ZEEK_VERSION}")
    endif ()
endfunction()

function(run_zeek_config output)
    execute_process(COMMAND "${zeek_config}" ${ARGN}
        OUTPUT_VARIABLE output_
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    set(${output} "${output_}" PARENT_SCOPE)
endfunction ()

function(zeek_print_summary)
    message(
        "\n====================|  Zeek Installation Summary  |===================="
        "\n"
        "\nFound Zeek:            ${HAVE_ZEEK}"
        )

    if ( HAVE_ZEEK )
        message(
                "\nVersion:          ${ZEEK_VERSION} (${ZEEK_VERSION_NUMBER})"
                "\nPrefix:           ${ZEEK_PREFIX}"
                "\nBuild type:       ${ZEEK_BUILD_TYPE}"
                )
    else ()
        message("\n    Make sure zeek-config is in your PATH, or set ZEEK_CONFIG to its location.")
    endif ()

    message("\n========================================================================\n")
endfunction ()

### Main

configure ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zeek DEFAULT_MSG HAVE_ZEEK ZEEK_CONFIG)
set(ZEEK_FOUND "${ZEEK_FOUND}" CACHE BOOL "")