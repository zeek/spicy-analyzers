# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/tls/tls-conn-with-extensions.trace
# @TEST-EXEC: mv x509.log x509-tls-conn-with-extensions.log
# @TEST-EXEC: mv ssl.log ssl-tls-conn-with-extensions.log
# @TEST-EXEC: btest-diff x509-tls-conn-with-extensions.log
# @TEST-EXEC: btest-diff ssl-tls-conn-with-extensions.log
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/tls/tls13draft23-chrome67.0.3368.0-canary.pcap
# @TEST-EXEC: mv ssl.log ssl-tls13draft23-chrome67.0.3368.0-canary.log
# @TEST-EXEC: btest-diff ssl-tls13draft23-chrome67.0.3368.0-canary.log
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/tls/ecdhe.pcap
# @TEST-EXEC: mv x509.log x509-ecdhe.log
# @TEST-EXEC: mv ssl.log ssl-ecdhe.log
# @TEST-EXEC: btest-diff x509-ecdhe.log
# @TEST-EXEC: btest-diff ssl-ecdhe.log
