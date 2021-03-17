# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: ${ZEEK} -r ${TRACES}/dns53.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: if zeek-version 32000; then btest-diff .stdout; fi
#
# @TEST-DOC: Test DNS analyzer with small trace.

#@load spicy-analyzers/protocol/dns

@if ( Version::number >= 32000 )
# Check the new signature of the event
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
   print query, original_query; # both are the same with our trace
}
@endif
