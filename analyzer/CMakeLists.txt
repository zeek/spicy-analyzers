# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

set(PACKAGE_NAME "spicy-analyzers")

add_subdirectory(dhcp)
add_subdirectory(dns)
add_subdirectory(facefish_rootkit)
add_subdirectory(http)
add_subdirectory(ipsec)
add_subdirectory(ldap)
add_subdirectory(openvpn)
add_subdirectory(pe)
add_subdirectory(png)
add_subdirectory(stun)
add_subdirectory(tailscale)
add_subdirectory(tftp)
add_subdirectory(wireguard)
add_subdirectory(zip)

install(
    FILES __load__.zeek
    DESTINATION "${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}/${PACKAGE_NAME}/")
