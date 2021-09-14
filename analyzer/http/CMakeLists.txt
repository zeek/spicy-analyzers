# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME HTTP
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES http.spicy http.evt zeek_http.spicy
    SCRIPTS __load__.zeek)
