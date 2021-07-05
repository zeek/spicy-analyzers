# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

add_subdirectory(file)
add_subdirectory(protocol)

# TODO: Should probably switch to listing the scripts to be installed.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
            DESTINATION "${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}/spicy-analyzers"
            FILES_MATCHING PATTERN "*.zeek" PATTERN "*.sig"
        )
