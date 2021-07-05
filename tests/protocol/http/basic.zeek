# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/http-post.pcap frameworks/files/hash-all-files %INPUT
# @TEST-EXEC: cat files.log | sed 's/SHA1,MD5/MD5,SHA1/g' >files.log.tmp && mv -f files.log.tmp files.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff files.log
#
# @TEST-DOC: Test HTTP analyzer with small trace.

@load spicy-analyzers/protocol/http
