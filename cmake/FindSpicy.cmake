# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
#
# CMake helpers to find Spicy and build Spicy code.
#
# To have this find the Spicy toolchain, either set PATH to contain
# spicy-config, set SPICY_ROOT_DIR to the Spicy installation, or set
# SPICY_CONFIG to the binary.
#
# Output:
#     SPICY_FOUND                 true if Spicy has been found
#
#     If SPICY_FOUND is true:
#
#         SPICYC                      full path to spicyc
#         SPICY_BUILD_MODE            Spicy's debug/release build mode
#         SPICY_HAVE_ZEEK             true if Spicy was compiled with Zeek support
#         SPICY_INCLUDE_DIRECTORIES   Spicy C++ include directories
#         SPICY_PREFIX                Spicy installation prefix
#         SPICY_VERSION               Spicy version as a string
#         SPICY_VERSION_NUMBER        Spicy version as a numerical value
#         SPICY_MODULE_OUTPUT_DIR     directory where our functions place compiled modules
#
#     If SPICY_HAVE_ZEEK is true:
#
#         SPICYZ                      full path to spicyz
#         SPICYZ_FLAGS                flags for spicyz
#         SPICY_ZEEK                  Zeek binary that Spicy was compiled against.
#         SPICY_ZEEK_PLUGIN_PATH      path to the Spicy plugin for Zeel
#         SPICY_ZEEK_VERSION_NUMBER   numerical Zeek version Spicy was compiled against

### Functions

function(run_spicy_config output)
    execute_process(COMMAND "${spicy_config}" ${ARGN}
        OUTPUT_VARIABLE output_
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    set(${output} "${output_}" PARENT_SCOPE)
endfunction ()

# Add target to build analyzer. Arguments are the name of the analyzer and a
# variable number of source files for `spicyz`.
function(spicy_add_analyzer name)
    set(sources "${ARGN}")
    set(output "${SPICY_MODULE_OUTPUT_DIR}/${name}.hlto")

    add_custom_command(
        OUTPUT ${output}
        DEPENDS ${sources} spicyz
        COMMENT "Compiling ${name} analyzer"
        COMMAND mkdir -p ${SPICY_MODULE_OUTPUT_DIR}
        COMMAND spicyz -o ${output} ${SPICYZ_FLAGS} ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

    add_custom_target(${name} ALL DEPENDS ${output})

    get_property(tmp GLOBAL PROPERTY __spicy_included_analyzers)
    list(APPEND tmp "${name}")
    set_property(GLOBAL PROPERTY __spicy_included_analyzers "${tmp}")
endfunction()

# Flag that analyzer is *not* being built. This is purely informational:
# the cmake output will contain a corresponding note. Arguments are the
# name of the analyzers and a descriptive string explaining why it's
# being skipped.
function(spicy_skip_analyzer name reason)
    get_property(tmp GLOBAL PROPERTY __spicy_skipped_analyzers)
    list(APPEND tmp "${name} ${reason}")
    set_property(GLOBAL PROPERTY __spicy_skipped_analyzers "${tmp}")
endfunction()

macro(configure)
    ### Find spicy-config

    if ( NOT SPICY_CONFIG )
        set(SPICY_CONFIG "$ENV{SPICY_CONFIG}")
    endif ()

    if ( SPICY_CONFIG )
        if ( EXISTS "${SPICY_CONFIG}" )
            set(spicy_config "${SPICY_CONFIG}")
        else ()
            message(STATUS "'${SPICY_CONFIG}' does not exist")
        endif ()
    else ()
        find_program(spicy_config spicy-config
            PATHS
                ${SPICY_ROOT_DIR}/bin
                ${SPICY_ROOT_DIR}/build/bin
                $ENV{SPICY_ROOT_DIR}/bin
                $ENV{SPICY_ROOT_DIR}/build/bin
            )
    endif ()

    if ( NOT spicy_config )
        message(STATUS "cannot determine location of Spicy installation")
        set(HAVE_SPICY no)
    else ()
        set(HAVE_SPICY yes)

        ### Determine properties.

        run_spicy_config(SPICYC "--spicyc")
        run_spicy_config(SPICY_BUILD_MODE "--build")
        run_spicy_config(SPICY_PREFIX "--prefix")
        run_spicy_config(SPICY_VERSION "--version")
        run_spicy_config(SPICY_VERSION_NUMBER "--version-number")
        run_spicy_config(SPICY_ZEEK_PLUGIN_PATH "--zeek-plugin-path")
        run_spicy_config(SPICY_ZEEK_VERSION "--zeek-version")
        run_spicy_config(SPICY_ZEEK_VERSION_NUMBER "--zeek-version-number")

        if ( SPICY_ZEEK_VERSION_NUMBER GREATER 0 )
            set(SPICY_HAVE_ZEEK yes)
        else ()
            set(SPICY_HAVE_ZEEK no)
        endif ()

        get_filename_component(bindir "${SPICYC}" DIRECTORY)
        find_program(SPICYZ spicyz PATHS ${bindir} NO_DEFAULT_PATH)

        run_spicy_config(SPICY_INCLUDE_DIRECTORIES --include-dirs --zeek-include-dirs)
        string(REPLACE " " ";" SPICY_INCLUDE_DIRECTORIES "${SPICY_INCLUDE_DIRECTORIES}")
        list(TRANSFORM SPICY_INCLUDE_DIRECTORIES PREPEND "-I")
        string(REPLACE ";" " " SPICY_INCLUDE_DIRECTORIES "${SPICY_INCLUDE_DIRECTORIES}")
    endif ()
endmacro ()

function(print_summary)
    message(
        "\n====================|  Spicy Installation Summary  |===================="
        "\n"
        "\nFound Spicy:           ${HAVE_SPICY}"
        )

    if ( HAVE_SPICY )
        message(
            "\nVersion:               ${SPICY_VERSION} (${SPICY_VERSION_NUMBER})"
            "\nPrefix:                ${SPICY_PREFIX}"
            "\nBuild mode:            ${SPICY_BUILD_MODE}"
            "\nSpicy compiler:        ${SPICYC}"
            #        "\nC++ include dirs:      ${SPICY_INCLUDE_DIRECTORIES}"
            "\n"
            "\nZeek support:          ${SPICY_HAVE_ZEEK}"
            )

        if ( SPICY_HAVE_ZEEK )
            message(
                "Zeek version:          ${SPICY_ZEEK_VERSION} (${SPICY_ZEEK_VERSION_NUMBER})"
                "\nZeek plugin path:      ${SPICY_ZEEK_PLUGIN_PATH}"
                "\nZeek compiler:         ${SPICYZ} ${SPICYZ_FLAGS}"
                )
        endif ()

    else ()
        message("\n    Make sure spicy-config is in your PATH, or set SPICY_CONFIG to its location.")
    endif ()

    message("\n========================================================================\n")
endfunction ()

function(spicy_print_analyzers)
    message("\n======================|  Spicy Analyzer Summary  |======================")

    get_property(included GLOBAL PROPERTY __spicy_included_analyzers)
    message("\nAvailable analyzers:\n")
    foreach ( x "${included}")
        message("    ${x}")
    endforeach ()

    get_property(skipped GLOBAL PROPERTY __spicy_skipped_analyzers)
    if ( skipped )
        message("\nSkipped analyzers:\n")
        foreach ( x ${skipped})
            message("    ${x}")
        endforeach ()
    endif ()

    message("\n========================================================================\n")
endfunction()

### Main

option(SPICY_IN_TREE_BUILD "Internal option to flag building from within the Spicy source tree" no)

set(SPICY_MODULE_OUTPUT_DIR "${PROJECT_BINARY_DIR}/spicy-modules")

set_property(GLOBAL PROPERTY __spicy_included_analyzers)
set_property(GLOBAL PROPERTY __spicy_skipped_analyzers)

if ( "${SPICY_IN_TREE_BUILD}" )
else ()
    configure ()
    print_summary ()

    if ( ${HAVE_SPICY} )
        add_executable(spicyz IMPORTED)
        set_property(TARGET spicyz PROPERTY IMPORTED_LOCATION "${SPICYZ}")
    endif ()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Spicy DEFAULT_MSG HAVE_SPICY SPICY_HAVE_ZEEK)
endif()


if ( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" )
    set(SPICYZ_FLAGS "-d")
else ()
    set(SPICYZ_FLAGS "")
endif ()

