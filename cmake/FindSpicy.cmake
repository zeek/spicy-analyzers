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

function(spicy_add_analyzer name)
    set(sources "${ARGN}")
    set(output "${SPICY_MODULE_OUTPUT_DIR}/${name}.hlto")

    add_custom_target(${name} ALL
        DEPENDS ${sources}
        COMMAND mkdir -p ${SPICY_MODULE_OUTPUT_DIR}
        COMMAND ${SPICYZ} -o ${output} ${SPICYZ_FLAGS} ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
endfunction()

### Find spicy-config.

find_program(spicy_config spicy-config HINTS
    ${SPICY_ROOT_DIR}/bin
    ${SPICY_ROOT_DIR}/build/bin
    ${SPICY_CONFIG}
    )

if ( NOT spicy_config )
    message(ERROR "cannot determine location of Spicy installation")
    set(SPICY_FOUND no)
else ()
    set(SPICY_FOUND yes)

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

    set ( SPICYZ_FLAGS "")
    if ( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" )
        set(SPICYZ_FLAGS "-d ${SPICYZ_FLAGS}")
    endif ()

    run_spicy_config(SPICY_INCLUDE_DIRECTORIES --include-dirs --zeek-include-dirs)
    string(REPLACE " " ";" SPICY_INCLUDE_DIRECTORIES "${SPICY_INCLUDE_DIRECTORIES}")
    list(TRANSFORM SPICY_INCLUDE_DIRECTORIES PREPEND "-I")
    string(REPLACE ";" " " SPICY_INCLUDE_DIRECTORIES "${SPICY_INCLUDE_DIRECTORIES}")

    set(SPICY_MODULE_OUTPUT_DIR "${PROJECT_BINARY_DIR}/spicy-modules")
endif ()

### Output summary

message(
    "\n====================|  Spicy Installation Summary  |===================="
    "\n"
    "\nFound Spicy:           ${SPICY_FOUND}"
)

if ( SPICY_FOUND )
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
endif ()

message("\n================================================================\n")
