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
#         SPICYC                        full path to spicyc
#         SPICY_BUILD_MODE              Spicy's debug/release build mode
#         SPICY_INCLUDE_DIRS_RUNTIME    Spicy C++ include directories for the runtime
#         SPICY_INCLUDE_DIRS_TOOLCHAIN  Spicy C++ include directories for the toolchain
#         SPICY_CXX_LIBRARY_DIRS_TOOLCHAIN        Spicy C++ library directories
#         SPICY_CXX_LIBRARY_DIRS_RUNTIME        Spicy C++ library directories
#         SPICY_CXX_FLAGS               Spicy C++ flags with include directories
#         SPICY_PREFIX                  Spicy installation prefix
#         SPICY_VERSION                 Spicy version as a string
#         SPICY_VERSION_NUMBER          Spicy version as a numerical value
#         SPICY_CMAKE_PATH              Spicy cmake directory
#         SPICY_HAVE_TOOLCHAIN          True if the compiler is available

### Functions

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
            HINTS
                ${SPICY_ROOT_DIR}/bin
                ${SPICY_ROOT_DIR}/build/bin
                $ENV{SPICY_ROOT_DIR}/bin
                $ENV{SPICY_ROOT_DIR}/build/bin
                ${PROJECT_SOURCE_DIR}/../../build/bin   # Try build directory of Spicy distribution we may be part of
            )
    endif ()

    if ( NOT spicy_config )
        message(STATUS "cannot determine location of Spicy installation")
        set(HAVE_SPICY no)
    else ()
        message(STATUS "Found spicy-config: ${spicy_config}")
        set(HAVE_SPICY yes)
        set(SPICY_CONFIG "${spicy_config}" CACHE FILEPATH "")

        ### Determine properties.

        run_spicy_config(SPICYC "--spicyc")
        run_spicy_config(SPICY_BUILD_MODE "--build")
        run_spicy_config(SPICY_PREFIX "--prefix")
        run_spicy_config(SPICY_VERSION "--version")
        run_spicy_config(SPICY_VERSION_NUMBER "--version-number")
        run_spicy_config(SPICY_CMAKE_PATH "--cmake-path")
        run_spicy_config(SPICY_HAVE_TOOLCHAIN "--have-toolchain")

        run_spicy_config(SPICY_INCLUDE_DIRS_RUNTIME --include-dirs)
        string(REPLACE " " ";" SPICY_INCLUDE_DIRS_RUNTIME "${SPICY_INCLUDE_DIRS_RUNTIME}")

        run_spicy_config(SPICY_LIBRARY_DIRS_RUNTIME --libdirs-cxx-runtime)
        string(REPLACE " " ";" SPICY_LIBRARY_DIRS_RUNTIME "${SPICY_LIBRARY_DIRS_RUNTIME}")

        run_spicy_config(SPICY_INCLUDE_DIRS_TOOLCHAIN --include-dirs-toolchain)
        string(REPLACE " " ";" SPICY_INCLUDE_DIRS_TOOLCHAIN "${SPICY_INCLUDE_DIRS_TOOLCHAIN}")

        run_spicy_config(SPICY_LIBRARY_DIRS_TOOLCHAIN --libdirs-cxx-toolchain)
        string(REPLACE " " ";" SPICY_LIBRARY_DIRS_TOOLCHAIN "${SPICY_LIBRARY_DIRS_TOOLCHAIN}")

        #list(TRANSFORM SPICY_INCLUDE_DIRS PREPEND "-I" OUTPUT_VARIABLE SPICY_CXX_FLAGS)
        #string(REPLACE ";" " " SPICY_CXX_FLAGS "${SPICY_CXX_FLAGS}")
    endif ()
endmacro ()

function(spicy_require_version version version_number)
    if ( "${SPICY_VERSION_NUMBER}" LESS "${version_number}" )
        message(FATAL_ERROR "Package requires at least Spicy version ${version}, have ${SPICY_VERSION}")
    endif ()
endfunction()

function(spicy_include_directories target)
    if ( NOT SPICY_IN_TREE_BUILD )
        target_include_directories(${target} "${ARGN}" ${SPICY_INCLUDE_DIRS_TOOLCHAIN} ${SPICY_INCLUDE_DIRS_RUNTIME})
    endif ()
endfunction ()

function(spicy_link_libraries lib)
    if ( SPICY_IN_TREE_BUILD )
        if ( SPICY_HAVE_TOOLCHAIN )
            hilti_link_libraries_in_tree(${lib} "${ARGN}")
            spicy_link_libraries_in_tree(${lib} "${ARGN}")
        else ()
            hilti_link_object_libraries_in_tree(${lib} "${ARGN}")
            spicy_link_object_libraries_in_tree(${lib} "${ARGN}")
        endif ()
    else ()
        target_link_directories(${lib} PRIVATE ${SPICY_LIBRARY_DIRS_TOOLCHAIN} ${SPICY_LIBRARY_DIRS_RUNTIME})

        if ( SPICY_HAVE_TOOLCHAIN )
            target_link_libraries(${lib} "${ARGN}" hilti spicy)
        endif ()
    endif ()
endfunction ()

function(spicy_link_executable exe)
    if ( SPICY_IN_TREE_BUILD )
        spicy_link_executable_in_tree(${exe} PRIVATE)
    else ()
        spicy_link_libraries(${exe} PRIVATE)
        set_property(TARGET ${exe} PROPERTY ENABLE_EXPORTS true)
    endif ()
endfunction ()

function(run_spicy_config output)
    execute_process(COMMAND "${spicy_config}" ${ARGN}
        OUTPUT_VARIABLE output_
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    set(${output} "${output_}" PARENT_SCOPE)
endfunction ()

function(spicy_print_summary)
    message(
        "\n====================|  Spicy Installation Summary  |===================="
        "\n"
        "\nFound Spicy:           ${HAVE_SPICY}"
        )

    if ( HAVE_SPICY )
        message(
            "\nVersion:               ${SPICY_VERSION} (${SPICY_VERSION_NUMBER})"
            "\nPrefix:                ${SPICY_PREFIX}"
            "\nBuild type:            ${SPICY_BUILD_MODE}"
            "\nHave toolchain:        ${SPICY_HAVE_TOOLCHAIN}"
            "\nSpicy compiler:        ${SPICYC}"
            )
    else ()
        message("\n    Make sure spicy-config is in your PATH, or set SPICY_CONFIG to its location.")
    endif ()

    message("\n========================================================================\n")
endfunction ()

### Main

option(SPICY_IN_TREE_BUILD "Internal option to flag building from within the Spicy source tree" no)

if ( "${SPICY_IN_TREE_BUILD}" )
else ()
    configure ()
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Spicy DEFAULT_MSG HAVE_SPICY SPICY_CONFIG)
endif()
