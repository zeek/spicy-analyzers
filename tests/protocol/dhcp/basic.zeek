# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/dhcp.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dhcp.log
#
# @TEST-DOC: Test DHCP analyzer with small trace.

@load spicy-analyzers/dhcp
