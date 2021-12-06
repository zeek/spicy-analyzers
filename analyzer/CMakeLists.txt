# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

set(PACKAGE_NAME "spicy-analyzers")

add_subdirectory(dhcp)
add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(png)
add_subdirectory(tftp)
add_subdirectory(zip)

install(FILES __load__.zeek DESTINATION "${SPICY_SCRIPTS_OUTPUT_DIR_INSTALL}/${PACKAGE_NAME}/")
