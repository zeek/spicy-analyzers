# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature dpd_facefish_rootkit {
  ip-proto == tcp
  payload /^\x00\x00\x00\x02\x00\x00\x00\x00/
  enable "spicy_Facefish_Rootkit"
}