# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME STUN
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES stun.spicy stun_zeek.spicy stun.evt
    SCRIPTS consts.zeek dpd.sig main.zeek __load__.zeek)
