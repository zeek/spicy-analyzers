# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: ${ZEEK} -NN | grep -q ANALYZER_SPICY_OPENVPN_UDP
# @TEST-EXEC: ${ZEEK} -NN | grep -q ANALYZER_SPICY_OPENVPN_UDP_HMAC
# @TEST-EXEC: ${ZEEK} -NN | grep -q ANALYZER_SPICY_OPENVPN_TCP
# @TEST-EXEC: ${ZEEK} -NN | grep -q ANALYZER_SPICY_OPENVPN_TCP_HMAC
#
# @TEST-DOC: Check that OpenVPN analyzer is available.
