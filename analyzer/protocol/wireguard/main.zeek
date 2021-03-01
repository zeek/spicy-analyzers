module Wireguard;

export {
	redef enum Log::ID += { LOG };

	type WireguardPacket: enum {
		WG_HANDSHAKE_INITIATION,
		WG_HANDSHAKE_RESPONSE,
	};

	## The record type which contains the fields of the Wireguard log.
	## Wireguard purposefully contains only very limited information. As such, the only
	## things that we record in the log are wireguard handshakes - since the frequency of handshakes
	## (as well as the successes of them) might be of some interest
	type Info: record {
		### Time the packet was encountered
		ts:             time            &log;
		### Unique ID for the connection
		uid:            string          &log;
		## The connection's 4-tuple of endpoint addresses/ports
		id:             conn_id         &log;
		### The packet type
		packet_type:    WireguardPacket &log;
		### 32 bit identifier chosen by the sender
		sender_index:   count           &log;
		### 32 bit identifier chosen by the receiver
		receiver_index: count           &log &optional;
	};

	## Event that can be handled to access the Wireguard
	## record as it is sent on to the logging framework.
	global log_wireguard: event(rec: Info);

	## Event raised for the wireguard handshake_initiation packet
	global wireguard::handshake_initiation: event(c: connection, is_orig: bool, sender_index: count, unencrypted_ephemeral: string, encrypted_static: string, encrypted_timestamp: string, mac1: string, mac2: string);

	## Event raised for the wireguard handshake_response packet
	global wireguard::handshake_response: event(c: connection, is_orig: bool, sender_index: count, receiver_index: count, unencrypted_ephemeral: string, encrypted_nothing: string, mac1: string, mac2: string);

	## Event raised for the wireguard packet_cookie_reply packet
	global wireguard::packet_cookie_reply:event(c: connection, is_orig: bool, receiver_index: count, nonce: string, encrypted_cookie: string);

	## Event raised for the wireguard packet_data packet
	global wireguard::packet_data: event(c: connection, is_orig: bool, receiver_index: count, counter: count, encapsulated_packet_length: count);
}


event zeek_init() &priority=5
	{
	Log::create_stream(Wireguard::LOG, [$columns=Info, $ev=log_wireguard, $path="wireguard"]);
	}

event wireguard::handshake_initiation(c: connection, is_orig: bool, sender_index: count, unencrypted_ephemeral: string, encrypted_static: string, encrypted_timestamp: string, mac1: string, mac2: string)
	{
	Log::write(Wireguard::LOG, Info($ts=network_time(), $uid=c$uid, $id=c$id, $packet_type=WG_HANDSHAKE_INITIATION, $sender_index=sender_index));
	}

event wireguard::handshake_response(c: connection, is_orig: bool, sender_index: count, receiver_index: count, unencrypted_ephemeral: string, encrypted_nothing: string, mac1: string, mac2: string)
	{
	Log::write(Wireguard::LOG, Info($ts=network_time(), $uid=c$uid, $id=c$id, $packet_type=WG_HANDSHAKE_RESPONSE, $sender_index=sender_index, $receiver_index=receiver_index));
	}

