# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME TFTP
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES tftp.spicy tftp.evt zeek_tftp.spicy
    SCRIPTS tftp.zeek __load__.zeek)
