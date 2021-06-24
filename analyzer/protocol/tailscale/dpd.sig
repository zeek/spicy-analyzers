# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature tailscale_packet {
  ip-proto == udp
  payload /^\x54\x53\xf0\x9f\x92\xac/
  enable "spicy_Tailscale"
}
