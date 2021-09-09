# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME DNS
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES dns.spicy dns.evt zeek_dns.spicy
    SCRIPTS __load__.zeek)
