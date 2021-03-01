# @TEST-EXEC: ${ZEEK} -r ${TRACES}/tftp_wrq.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tftp.log
#
# @TEST-DOC: Test TFTP analyzer with write request trace.

@load spicy-analyzers/protocol/tftp
