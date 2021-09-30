# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# Signatures are copied from Zeek.

signature spicy_dhcp_cookie {
  ip-proto == udp
  payload /^.{236}\x63\x82\x53\x63/
  enable "spicy_DHCP"
}
