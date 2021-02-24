cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(SpicyAnalyzers NONE)

set(mininmum_spicy_version        "0.4")
set(mininmum_spicy_version_number 00400)

set(mininmum_zeek_version         "3.0")
set(mininmum_zeek_version_number  30000)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(Spicy REQUIRED)

if ( NOT "${SPICY_IN_TREE_BUILD}" )
    if ( NOT CMAKE_BUILD_TYPE )
        set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
    endif ()

    if ( "${SPICY_VERSION_NUMBER}" LESS ${mininmum_spicy_version} )
        message(FATAL_ERROR "Spicy analyzers require at least Spicy version ${mininmum_spicy_version}, have ${SPICY_VERSION}")
    endif ()

    if ( NOT SPICY_HAVE_ZEEK )
        message(FATAL_ERROR "Spicy installation was not compiled with Zeek support")
    endif ()

    if ( "${SPICY_ZEEK_VERSION_NUMBER}" LESS ${mininmum_zeek_version} )
        message(FATAL_ERROR "Spicy analyzers require at least Zeek version ${mininmum_zeek_version}, but Spicy was compiled against ${SPICY_ZEEK_VERSION}")
    endif ()
endif ()

add_subdirectory(analyzer)
