# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

set(SPICYZ_FLAGS ${SPICYZ_FLAGS} -L${CMAKE_CURRENT_SOURCE_DIR}/../wireguard)
spicy_add_analyzer(
    NAME Tailscale
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES tailscale.spicy tailscale_zeek.spicy tailscale.evt ../wireguard/wireguard.spicy
    SCRIPTS dpd.sig main.zeek __load__.zeek)
