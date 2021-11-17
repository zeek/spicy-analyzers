# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -C -r ${TRACES}/ipsec-ikev1-zero-length.pcap %INPUT
# @TEST-EXEC: test ! -s .stderr
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: zeek-cut -c uid name addl < weird.log > weird.log.cut
# @TEST-EXEC: btest-diff weird.log.cut
#
# @TEST-DOC: Test that IPSecIKE with length 0 does not produce integer overflow analyzer errors

@load spicy-analyzers/ipsec
