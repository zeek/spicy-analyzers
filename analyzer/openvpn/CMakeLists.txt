# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME OpenVPN
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES openvpn.spicy openvpn_zeek.spicy openvpn.evt
    SCRIPTS dpd.sig main.zeek __load__.zeek)
