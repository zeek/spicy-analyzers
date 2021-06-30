# Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
#
# Helpers for building analyzers.

include(GNUInstallDirs)

# Add target to build analyzer. Arguments are the name of the analyzer and a
# variable number of source files for `spicyz`.
function(spicy_add_analyzer name)
    set(sources "${ARGN}")
    string(TOLOWER "${name}" name_lower)
    set(output "${SPICY_MODULE_OUTPUT_DIR}/${name_lower}.hlto")
    set(output_install "${SPICY_MODULE_OUTPUT_DIR_INSTALL}/${name_lower}.hlto")

    if ( "${SPICY_IN_TREE_BUILD}" )
        set(deps "spicyz;zeek-spicy-plugin") # ensure the plugin's built already
    else ()
        set(deps "spicyz")
    endif ()

    add_custom_command(
        OUTPUT ${output}
        DEPENDS ${sources} ${deps}
        COMMENT "Compiling ${name} analyzer"
        COMMAND mkdir -p ${SPICY_MODULE_OUTPUT_DIR}
        COMMAND ${SPICYZ} -o ${output} ${SPICYZ_FLAGS} ${sources}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

    add_custom_target(${name} ALL DEPENDS ${output})
    add_dependencies(build-spicy-analyzers ${name})

    if ( SPICY_MODULE_OUTPUT_DIR_INSTALL )
        if ( SPICY_IN_TREE_BUILD )
            # Do not install by default but tie to install-spicy-analyzers target.
            install(FILES ${output} DESTINATION "${SPICY_MODULE_OUTPUT_DIR_INSTALL}"
                    COMPONENT spicy-analyzers EXCLUDE_FROM_ALL)
        else ()
            install(FILES ${output} DESTINATION "${SPICY_MODULE_OUTPUT_DIR_INSTALL}")
        endif()
    endif ()

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

function(print_analyzers include_list)
    message("\n======================|  Spicy Analyzer Summary  |======================")

    message(
        "\nspicy-config:          ${SPICY_CONFIG}"
        "\nzeek-config:           ${ZEEK_CONFIG}"
        "\nSpicy compiler:        ${SPICYZ}"
        "\nModule directory:      ${SPICY_MODULE_OUTPUT_DIR_INSTALL}"
        "\nScripts directory:     ${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}"
        )

    if ( NOT "${SPICY_IN_TREE_BUILD}" )
        message(
            "\nPlugin version:        ${SPICY_ZEEK_PLUGIN_VERSION} (${SPICY_ZEEK_PLUGIN_VERSION_NUMBER})"
            )
    endif ()

    if ( NOT SPICYZ )
        message("\n    Make sure spicyz is in your PATH, or set SPICYZ to its location.")
    endif ()

    if ( include_list )
        get_property(included GLOBAL PROPERTY __spicy_included_analyzers)
        message("\nAvailable analyzers:\n")
        foreach ( x ${included})
            message("    ${x}")
        endforeach ()

        get_property(skipped GLOBAL PROPERTY __spicy_skipped_analyzers)
        if ( skipped )
            message("\nSkipped analyzers:\n")
            foreach ( x ${skipped})
                message("    ${x}")
            endforeach ()
        endif ()
    endif ()

    message("\n========================================================================\n")
endfunction()

### Main

set_property(GLOBAL PROPERTY __spicy_included_analyzers)
set_property(GLOBAL PROPERTY __spicy_skipped_analyzers)

if ( "${SPICY_IN_TREE_BUILD}" )
    set(SPICYZ "${CMAKE_BINARY_DIR}/bin/spicyz")
else ()
    if ( NOT SPICYZ )
        set(SPICYZ "$ENV{SPICYZ}")
    endif ()

    if ( SPICYZ )
        if ( EXISTS "${SPICYZ}" )
            set(spicyz "${SPICYZ}")
        else ()
            message(STATUS "'${SPICYZ}' does not exist")
        endif ()
    else ()
        find_program(spicyz spicyz
            HINTS
                ${SPICY_ZEEK_ROOT_DIR}/bin
                ${SPICY_ZEEK_ROOT_DIR}/build/bin
                $ENV{SPICY_ZEEK_ROOT_DIR}/bin
                $ENV{SPICY_ZEEK_ROOT_DIR}/build/bin
                ${PROJECT_SOURCE_DIR}/../../build/bin   # Try build directory of Spicy distribution we may be part of
            )
    endif ()

    if ( spicyz )
        set(SPICYZ "${spicyz}" CACHE FILEPATH "")
        add_executable(spicyz IMPORTED)
        set_property(TARGET spicyz PROPERTY IMPORTED_LOCATION "${SPICYZ}")
    endif ()
endif ()

set(SPICYZ "${SPICYZ}" CACHE FILEPATH "") # make it globally available

if ( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" )
    set(SPICYZ_FLAGS "-d")
else ()
    set(SPICYZ_FLAGS "")
endif ()

set(SPICY_MODULE_OUTPUT_DIR "${PROJECT_BINARY_DIR}/spicy-modules")

if ( SPICY_IN_TREE_BUILD )
    set(SPICY_MODULE_OUTPUT_DIR_INSTALL "${SPICY_ZEEK_MODULE_DIR}" CACHE STRING "")
    set(SPICY_SCRIPTS_OUTPUT_DIR_INSTALL "${SPICY_ZEEK_SCRIPTS_DIR}" CACHE STRING "")
elseif ( SPICYZ )
    execute_process(COMMAND "${SPICYZ}" "--print-module-path"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(SPICY_MODULE_OUTPUT_DIR_INSTALL "${output}" CACHE STRING "")

    execute_process(COMMAND "${SPICYZ}" "--print-scripts-path"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(SPICY_SCRIPTS_OUTPUT_DIR_INSTALL "${output}" CACHE STRING "")

    execute_process(COMMAND "${SPICYZ}" "--version"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(SPICY_ZEEK_PLUGIN_VERSION "${output}" CACHE STRING "")

    execute_process(COMMAND "${SPICYZ}" "--version-number"
        OUTPUT_VARIABLE output
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(SPICY_ZEEK_PLUGIN_VERSION_NUMBER "${output}" CACHE STRING "")
else ()
    set(SPICY_MODULE_OUTPUT_DIR_INSTALL "" CACHE STRING "")
    set(SPICY_SCRIPTS_OUTPUT_DIR_INSTALL "" CACHE STRING "")
endif ()

add_custom_target(build-spicy-analyzers)

if ( "${SPICY_IN_TREE_BUILD}" )
    # Separate installation target to install the analyzers, which are normally excluded.
    add_custom_target(install-spicy-analyzers
                      DEPENDS build-spicy-analyzers
                      COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=spicy-analyzers -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_install.cmake")
endif ()
