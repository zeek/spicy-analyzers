# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature ipsec_packet_udp {
  ip-proto == udp

  # Concepts from this file have been copied from https://github.com/ukncsc/zeek-plugin-ikev2/blob/master/scripts/dpd.sig
  # See LICENSE.3rdparty.
  #
  # A signature to identify IKE traffic
  #
  # 17th byte is next payload in the IKE header.
  # - We expect to see something in the range 1 to 54 (0x36)
  #
  # 18th byte is version number in the IKE header
  # - Set to v1 or v2 (0x10 is version1, 0x20 is version 2)
  #
  # 19th byte is exchange type in the IKE header.
  # - We expect to see something in the range 1 to 5, and 34 (0x22) to 54 (0x36)
  #
  # 29th byte is next payload field in the first generic payload header after the IKE header
  # - We expect to see something in the range 1 to 54 (0x36)
  payload /^\x00\x00\x00\x00.{16}[\x01-\x36\x84][\x10\x20][\x01-\x05\x22-\x29].{9}[\x01-\x36\x84]/

  enable "spicy_ipsec_udp"
}

signature ipsec_packet_ike_udp {
  ip-proto == udp
  payload /^.{16}[\x01-\x36\x84][\x10\x20][\x01-\x05\x22-\x29].{9}[\x01-\x36\x84]/
  enable "spicy_ipsec_ike_udp"
}

signature ipsec_packet_tcp {
  ip-proto == tcp
  payload /^..\x00\x00\x00\x00.{16}[\x01-\x36\x84][\x10\x20][\x01-\x05\x22-\x29].{9}[\x01-\x36\x84]/
  enable "spicy_ipsec_tcp"
}
