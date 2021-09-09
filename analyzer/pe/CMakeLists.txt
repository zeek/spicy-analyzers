# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME PE
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES pe.spicy zeek_pe.spicy pe.evt
    SCRIPTS main.zeek __load__.zeek)
