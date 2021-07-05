# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -C -B dpd -r ${TRACES}/tailscale_linux.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout
#
# @TEST-DOC: Test Tailscale analyzer with sample trace.

@load spicy-analyzers/protocol/tailscale

event tailscale::packet_data(c: connection, is_orig: bool, receiver_index: count, key_counter: count, encapsulated_packet_length: count)
	{
	print "packet_data", receiver_index, encapsulated_packet_length;
	}

event tailscale::discovery_message(c: connection, is_orig: bool, senderDiscoPub: string)
	{
	print "discovery_message", senderDiscoPub;
	}
