# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

signature dpd_facefish_rootkit_client {
  ip-proto == tcp
  payload /^\x00\x00\x00\x02\x00\x00\x00\x00/
}

signature dpd_facefish_rootkit_server {
  ip-proto == tcp
  payload /^..\x01\x02/
  requires-reverse-signature dpd_facefish_rootkit_client
  enable "spicy_Facefish_Rootkit"
}
