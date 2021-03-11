# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature wireguard_packet {
  ip-proto == udp
  payload /^(\x01|\x02|\x03|\x04)\x00\x00\x00/
  enable "spicy_Wireguard"
}
