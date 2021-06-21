# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: set >envs
# @TEST-EXEC: ${ZEEK} -C -r ${TRACES}/openvpn.pcap %INPUT >openvpn.out
# @TEST-EXEC: btest-diff openvpn.out
# @TEST-EXEC: btest-diff conn.log

@load spicy-analyzers/protocol/openvpn

redef OpenVPN::disable_analyzer_after_detection = F;

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg) { print cat(msg); }
event OpenVPN::ack_message(c: connection, is_orig: bool, msg: OpenVPN::AckMsg) { print cat(msg); }
event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::DataMsg) { print cat(msg); }
