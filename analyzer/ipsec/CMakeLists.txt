# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

spicy_add_analyzer(
    NAME IPSec
    PACKAGE_NAME ${PACKAGE_NAME}
    SOURCES ipsec.spicy ipsec_zeek.spicy ipsec.evt
    SCRIPTS consts.zeek dpd.sig main.zeek __load__.zeek)
