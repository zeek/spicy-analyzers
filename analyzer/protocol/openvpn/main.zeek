module OpenVPN;

export {
	## Set to true to disable the analyzer after the protocol is confirmed.
	## This helps reduce processing if you will not look at all of the OpenVPN
	## traffic.
	option disable_analyzer_after_detection = F;

	type ControlMsg: record {
		## Opcode
		opcode:	count;
		## Key ID
		key_id:	count;
		## Session ID
		session_id: string &optional;
		## Packet id ack array
		packet_id_ack_array: vector of count &optional;
		## Remote session ID
		remote_session_id: string &optional;
		## Packet ID
		packet_id: count &optional;
		## The amount of data
		data_len: count;
	};

	type AckMsg: record {
		## Opcode
		opcode:	count;
		## Key ID
		key_id:	count;
		## Session ID
		session_id: string &optional;
		## Packet id ack array
		packet_id_ack_array: vector of count &optional;
		## Remote session ID
		remote_session_id: string &optional;
	};

	type DataMsg: record {
		## Opcode
		opcode:	count;
		## Key ID
		key_id:	count;
		## The amount of data
		data_len: count;
		## Peer ID
		peer_id: string &optional;
	};

	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed OpenVPN message.
	global OpenVPN::control_message: event(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg);

	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed OpenVPN message.
	global OpenVPN::data_message: event(c: connection, is_orig: bool, msg: OpenVPN::DataMsg);

	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed OpenVPN message.
	global OpenVPN::ack_message: event(c: connection, is_orig: bool, msg: OpenVPN::AckMsg);

	## The record type which contains OpenVPN info.
	type Info: record {
		## The analyzer ID used for the analyzer instance attached
		## to each connection.  It is not used for logging since it's a
		## meaningless arbitrary number.
		analyzer_id: count &optional;
	};

}

redef record connection += {
	openvpn: Info &optional;
};

function set_session(c: connection)
	{
	if ( ! c?$openvpn )
		c$openvpn = [];
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	set_session(c);
	if ( atype == Analyzer::ANALYZER_SPICY_OPENVPN_UDP || atype == Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC || atype == Analyzer::ANALYZER_SPICY_OPENVPN_TCP || atype == Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC )
		{
		c$openvpn$analyzer_id = aid;
		}
	}

event OpenVPN::data_message(c: connection, is_orig: bool, msg: OpenVPN::DataMsg)
	{
	if (disable_analyzer_after_detection == T && c?$openvpn && c$openvpn?$analyzer_id)
		{
		disable_analyzer(c$id, c$openvpn$analyzer_id);
		delete c$openvpn$analyzer_id;
		}
	}
