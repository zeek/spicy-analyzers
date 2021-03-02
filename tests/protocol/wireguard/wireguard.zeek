# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: set >envs
# @TEST-EXEC: ${ZEEK} -NN >zeek 2>&1
# @TEST-EXEC: ${ZEEK} -C -B dpd -r ${TRACES}/wireguard.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff wireguard.log
# @TEST-EXEC: btest-diff .stdout

@load spicy-analyzers/protocol/wireguard

event wireguard::handshake_initiation(c: connection, is_orig: bool, sender_index: count, unencrypted_ephemeral: string, encrypted_static: string, encrypted_timestamp: string, mac1: string, mac2: string)
	{
	print "Handshake initiation", sender_index, mac2;
	}

event wireguard::handshake_response(c: connection, is_orig: bool, sender_index: count, receiver_index: count, unencrypted_ephemeral: string, encrypted_nothing: string, mac1: string, mac2: string)
	{
	print "Handshake response", sender_index, receiver_index;
	}

event wireguard::packet_cookie_reply(c: connection, is_orig: bool, receiver_index: count, nonce: string, encrypted_cookie: string)
	{
	print "packet_cookie_reply", receiver_index;
	}

event wireguard::packet_data(c: connection, is_orig: bool, receiver_index: count, counter: count, encapsulated_packet_length: count)
	{
	print "packet_data", receiver_index, encapsulated_packet_length;
	}
