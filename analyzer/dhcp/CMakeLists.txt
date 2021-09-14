# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME DHCP
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES dhcp.spicy dhcp.evt zeek_dhcp.spicy
    SCRIPTS __load__.zeek)
