# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature dpd_openvpn_udp_client {
  ip-proto == udp
  payload /^\x38.{8}\x00\x00\x00\x00\x00/
  enable "spicy_OpenVPN_UDP"
}

signature dpd_openvpnhmac_udp_client {
  ip-proto == udp
  payload /^\x38.{36}\x00\x00\x00\x00\x00/
  enable "spicy_OpenVPN_UDP_HMAC"
}

signature dpd_openvpn_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{8}\x00\x00\x00\x00\x00/
  enable "spicy_OpenVPN_TCP"
}

signature dpd_openvpnhmac_tcp_client {
  ip-proto == tcp
  payload /^..\x38.{36}\x00\x00\x00\x00\x00/
  enable "spicy_OpenVPN_TCP_HMAC"
}
