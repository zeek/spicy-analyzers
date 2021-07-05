# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -NN | grep -q ANALYZER_SPICY_OPENVPN_UDP
# @TEST-EXEC: zeek -NN | grep -q ANALYZER_SPICY_OPENVPN_UDP_HMAC
# @TEST-EXEC: zeek -NN | grep -q ANALYZER_SPICY_OPENVPN_TCP
# @TEST-EXEC: zeek -NN | grep -q ANALYZER_SPICY_OPENVPN_TCP_HMAC
#
# @TEST-DOC: Check that OpenVPN analyzer is available.
