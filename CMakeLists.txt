cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(SpicyAnalyzers LANGUAGES C)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(SpicyPlugin)

# Set mininum versions that this plugin needs. Make sure to use "x.y.z" format.
spicy_require_version("0.4.0")
spicy_plugin_require_version("0.99.0")
zeek_require_version("3.0.0")

if ( NOT CMAKE_BUILD_TYPE AND NOT "${SPICY_IN_TREE_BUILD}" )
    # Default to release build.
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "")
endif ()

add_subdirectory(analyzer)
print_analyzers()

if ( NOT SPICY_PLUGIN_FOUND )
    message(FATAL_ERROR "could not find Spicy plugin, aborting")
endif ()
