# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

if ( SPICY_VERSION_NUMBER GREATER_EQUAL 10100 AND ZEEK_SPICY_PLUGIN_VERSION_NUMBER GREATER_EQUAL 10100)
    spicy_add_analyzer(
        NAME ZIP
        PACKAGE_NAME ${PACKAGE_NAME}
        SOURCES zip.spicy zip.evt
        SCRIPTS main.zeek __load__.zeek)
else ()
    spicy_skip_analyzer(ZIP "needs Spicy >= 1.1 and Zeek plugin >= 1.1")
endif ()
