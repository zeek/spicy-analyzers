if ( SPICY_VERSION_NUMBER GREATER_EQUAL 10100 AND SPICY_ZEEK_PLUGIN_VERSION_NUMBER GREATER_EQUAL 10100)
    spicy_add_analyzer(ZIP zip.spicy zip.evt)
else ()
    spicy_skip_analyzer(ZIP "needs Spicy >= 1.1 and Zeek plugin >= 1.1")
endif ()
