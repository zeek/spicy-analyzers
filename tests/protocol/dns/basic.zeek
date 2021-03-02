# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: ${ZEEK} -r ${TRACES}/dns53.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dns.log
#
# @TEST-DOC: Test DNS analyzer with small trace.

@load spicy-analyzers/protocol/dns
