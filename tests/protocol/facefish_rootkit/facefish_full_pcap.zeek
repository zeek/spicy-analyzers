# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: ${ZEEK} -C -r ${TRACES}/facefish_full.pcap %INPUT
# @TEST-EXEC: btest-diff facefish_rootkit.log
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout

@load spicy-analyzers/protocol/facefish_rootkit

event Facefish_Rootkit::facefish_rootkit_message(c: connection, is_orig: bool, msg: Facefish_Rootkit::FacefishMsg) { print cat("facefish_rootkit_message ", is_orig, c$id, msg); }
