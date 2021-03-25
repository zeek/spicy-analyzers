# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(SpicyAnalyzers LANGUAGES C)

set(mininmum_spicy_version        "0.4")
set(mininmum_spicy_version_number 00400)

set(mininmum_spicy_plugin_version        "0.99")
set(mininmum_spicy_plugin_version_number 009900)

set(mininmum_zeek_version         "3.0")
set(mininmum_zeek_version_number  30000)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(Zeek)
find_package(Spicy)

if ( NOT ZEEK_FOUND )
    if ( "${SPICY_IN_TREE_BUILD}" )
        # Ok to build without Zeek
        return ()
    else ()
        message(FATAL_ERROR "cannot find Zeek, aborting")
    endif ()
endif()

if ( NOT "${SPICY_IN_TREE_BUILD}" )
    if ( NOT CMAKE_BUILD_TYPE )
        set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
    endif ()

    if ( "${SPICY_VERSION_NUMBER}" LESS ${mininmum_spicy_version} )
        message(FATAL_ERROR "Spicy analyzers require at least Spicy version ${mininmum_spicy_version}, have ${SPICY_VERSION}")
    endif ()

    if ( "${SPICY_ZEEK_VERSION_NUMBER}" LESS ${mininmum_zeek_version} )
        message(FATAL_ERROR "Spicy analyzers require at least Zeek version ${mininmum_zeek_version}, but Spicy was compiled against ${SPICY_ZEEK_VERSION}")
    endif ()
endif ()

if ( NOT SPICY_IN_TREE_BUILD )
    zeek_print_summary()
    spicy_print_summary()

    if ( "${SPICY_ZEEK_PLUGIN_VERSION_NUMBER}" LESS "${mininmum_spicy_plugin_version_number}" )
        message(FATAL_ERROR "Package requires at least Spicy Zeek plugin version ${mininmum_spicy_plugin_version}, have ${SPICY_ZEEK_PLUGIN_VERSION}")
    endif ()
endif ()

include(AnalyzerUtils)
add_subdirectory(analyzer)


if ( SPICY_IN_TREE_BUILD )
    print_analyzers(false)
else ()
    print_analyzers(true)

    if ( NOT SPICYZ )
        message(FATAL_ERROR "spicyz missing")
    endif ()
endif ()
