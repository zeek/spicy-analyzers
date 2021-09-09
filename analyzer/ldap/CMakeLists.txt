# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME LDAP
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES ldap.spicy ldap_zeek.spicy ldap.evt
    SCRIPTS main.zeek __load__.zeek)
