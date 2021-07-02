# Find the Spicy plugin to get access to the infrastructure it provides.
#
# Most of the actual CMake logic for building analyzers comes with the Spicy
# plugin for Zeek, but we need to bootstrap by asking "spicyz" for the plugin's
# location. Either make sure that "spicyz" is in PATH, set the environment
# variable SPICYZ to point to its location, or set variable SPICY_ZEEK_ROOT_DIR
# in either CMake or environment to point to its installation or build
# directory.
#
# This exports:
#
#     SPICY_PLUGIN_FOUND            True if plugin and all dependencies were found
#     SPICYZ                        Path to spicyz
#     SPICY_PLUGIN_VERSION          Version string of plugin
#     SPICY_PLUGIN_VERSION_NUMBER   Numerical version number of plugin

function(run_spicycz output)
     execute_process(COMMAND "${SPICYZ}" ${ARGN}
        OUTPUT_VARIABLE output_
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    string(STRIP "${output_}" output_)
    set(${output} "${output_}" PARENT_SCOPE)
endfunction ()

function(spicy_plugin_require_version version)
    string(REGEX MATCH "([0-9]*)\.([0-9]*)\.([0-9]*).*" _ ${version})
    math(EXPR version_number "${CMAKE_MATCH_1} * 10000 + ${CMAKE_MATCH_2} * 100 + ${CMAKE_MATCH_3}")
    if ( "${SPICY_PLUGIN_VERSION_NUMBER}" LESS "${version_number}" )
        message(FATAL_ERROR "Package requires at least Spicy plugin version ${version}, have ${SPICY_PLUGIN_VERSION}")
    endif ()
endfunction()

if ( NOT SPICY_IN_TREE_BUILD )
    if ( NOT SPICYZ )
        set(SPICYZ "$ENV{SPICYZ}")
    endif ()

    if ( NOT SPICYZ )
        find_program(spicyz spicyz
                            HINTS
                                ${SPICY_ZEEK_ROOT_DIR}/bin
                                ${SPICY_ZEEK_ROOT_DIR}/build/bin
                                $ENV{SPICY_ZEEK_ROOT_DIR}/bin
                                $ENV{SPICY_ZEEK_ROOT_DIR}/build/bin
                                ${PROJECT_SOURCE_DIR}/../../build/bin) # support an in-tree Spicy build
        set(SPICYZ "${spicyz}")
    endif ()

    if ( NOT SPICYZ )
        message(FATAL_ERROR "cannot find spicyz, make sure it is in PATH or set SPICYZ")
    endif ()

    if ( NOT EXISTS "${SPICYZ}" )
        message(FATAL_ERROR "'${SPICYZ}' does not exist")
    endif ()

    set(SPICYZ "${SPICYZ}" CACHE PATH "")
    message(STATUS "Found spicyz: ${SPICYZ}")

    run_spicycz(spicy_plugin_cmake_path     "--print-cmake-path")
    run_spicycz(SPICY_PLUGIN_VERSION        "--version")
    run_spicycz(SPICY_PLUGIN_VERSION_NUMBER "--version-number")

else ()
    set(SPICY_PLUGIN_VERSION        "${SPICY_ZEEK_PLUGIN_VERSION_MAIN}")
    set(SPICY_PLUGIN_VERSION_NUMBER "${SPICY_ZEEK_PLUGIN_VERSION_NUMBER}")
    set(spicy_plugin_cmake_path     "${PROJECT_SOURCE_DIR}/../spicy-plugin/cmake")
    set(SPICYZ "<in-tree>")
    get_filename_component(spicy_plugin_cmake_path "${spicy_plugin_cmake_path}" REALPATH ABSOLUTE)
endif ()

message(STATUS "Zeek plugin version: ${SPICY_PLUGIN_VERSION}")
message(STATUS "Zeek plugin CMake path: ${spicy_plugin_cmake_path}")

list(PREPEND CMAKE_MODULE_PATH "${spicy_plugin_cmake_path}")
find_package(Zeek)
find_package(Spicy)
include(SpicyZeekAnalyzers)

if ( NOT SPICY_IN_TREE_BUILD )
    zeek_print_summary()
    spicy_print_summary()
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SPICY_PLUGIN DEFAULT_MSG SPICYZ ZEEK_FOUND)
