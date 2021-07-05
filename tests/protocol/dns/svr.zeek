# @TEST-EXEC: zeek -r ${TRACES}/dns-svr.pcap %INPUT >output
#     Zeek 3.0 prints intervals differently, leading to a change in TTL; not worth worrying about, so we just skip the diff for 3.0.
# @TEST-EXEC: if zeek-version 40000; then btest-diff output; fi
#
# @TEST-DOC: Test the DNS SVR event.

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)
   {
   print c$id, msg, ans, target, priority, weight, p;
   }
