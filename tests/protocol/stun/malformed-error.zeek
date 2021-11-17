# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -NN >zeek 2>&1
# @TEST-EXEC: zeek -Cr ${TRACES}/stun-malformed-error.pcap %INPUT
# @TEST-EXEC: test ! -s .stderr
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: zeek-cut -c uid name addl < weird.log > weird.log.cut
# @TEST-EXEC: btest-diff weird.log.cut
#
# @TEST-DOC: Test that truncated errors do not cause integer overflow errors

@load spicy-analyzers/stun
