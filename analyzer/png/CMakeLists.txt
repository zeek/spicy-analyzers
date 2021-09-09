# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME PNG
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES PNG.spicy Zeek_PNG.spicy PNG.evt
    SCRIPTS main.zeek __load__.zeek)
