# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature STUN {
  ip-proto == udp
  payload /^.{4}\x21\x12\xa4\x42/
  enable "spicy_STUN"
}