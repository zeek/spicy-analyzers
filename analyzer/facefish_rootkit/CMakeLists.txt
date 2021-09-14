# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME Facefish_Rootkit
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES facefish_rootkit.spicy facefish_rootkit_zeek.spicy facefish_rootkit.evt
    SCRIPTS consts.zeek dpd.sig main.zeek __load__.zeek)
