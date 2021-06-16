# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

module Tailscale;

export {
	## Event raised for the Wireguard handshake_initiation packet
	global tailscale::handshake_initiation: event(c: connection, is_orig: bool, sender_index: count, unencrypted_ephemeral: string, encrypted_static: string, encrypted_timestamp: string, mac1: string, mac2: string);

	## Event raised for the Wireguard handshake_response packet
	global tailscale::handshake_response: event(c: connection, is_orig: bool, sender_index: count, receiver_index: count, unencrypted_ephemeral: string, encrypted_nothing: string, mac1: string, mac2: string);

	## Event raised for the Wireguard packet_cookie_reply packet
	global tailscale::packet_cookie_reply:event(c: connection, is_orig: bool, receiver_index: count, nonce: string, encrypted_cookie: string);

	## Event raised for the Wireguard packet_data packet
	global tailscale::packet_data: event(c: connection, is_orig: bool, receiver_index: count, key_counter: count, encapsulated_packet_length: count);

	## Event raised for the Tailscale discovery packet
	global tailscale::discovery_message: event(c: connection, is_orig: bool, senderDiscoPub: string);
}
