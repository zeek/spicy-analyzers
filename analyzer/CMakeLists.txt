# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

add_subdirectory(file)
add_subdirectory(protocol)

if ( SPICY_SCRIPTS_OUTPUT_DIR_INSTALL )
    if ( SPICY_IN_TREE_BUILD )
        # Do not install by default but tie to install-spicy-analyzers target.
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION "${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}/spicy-analyzers/"
            COMPONENT spicy-analyzers EXCLUDE_FROM_ALL
            FILES_MATCHING PATTERN "*.zeek" PATTERN "*.sig")
    else ()
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION "${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}/spicy-analyzers"
            FILES_MATCHING PATTERN "*.zeek" PATTERN "*.sig"
            )
    endif()
endif ()
