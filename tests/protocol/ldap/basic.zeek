# @TEST-EXEC: ${ZEEK} -r ${TRACES}/ldap-simpleauth.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: btest-diff ldap_search.log
#
# @TEST-DOC: Test LDAP analyzer with small trace.

@load spicy-analyzers/protocol/ldap
