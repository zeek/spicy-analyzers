# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: env >env
# @TEST-EXEC: zeek -r ${TRACES}/tftp_rrq.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tftp.log
#
# @TEST-DOC: Test TFTP analyzer with read request trace.

@load spicy-analyzers/tftp
