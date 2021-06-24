# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

set(SPICYZ_FLAGS ${SPICYZ_FLAGS} -L${CMAKE_CURRENT_SOURCE_DIR}/../wireguard)
spicy_add_analyzer(Tailscale tailscale.spicy tailscale_zeek.spicy tailscale.evt ../wireguard/wireguard.spicy)
