# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

module ipsec;

export {
	redef enum Log::ID += { IPSEC_LOG };

	# This is the format of ipsec.log
	type Info: record {
		# Timestamp for when the event happened.
		ts: time &log;
		# Unique ID for the connection.
		uid: string &log;
		# The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		# Is orig
		is_orig: bool &log &optional;
		## Initiator security parameters index
		initiator_spi: string &log &optional;
		## Responder security parameters index
		responder_spi: string &log &optional;
		## Major Version
		maj_ver: count &log &optional;
		## Minor Version
		min_ver: count &log &optional;
		## Exchange Type
		exchange_type: count &log &optional;
		## Flag E
		flag_e: bool &log &optional;
		## Flag C
		flag_c: bool &log &optional;
		## Flag A
		flag_a: bool &log &optional;
		## Flag I
		flag_i: bool &log &optional;
		## Flag V
		flag_v: bool &log &optional;
		## Flag R
		flag_r: bool &log &optional;
		## Message ID
		message_id: count &log &optional;
		## Vendor IDs
		vendor_ids: vector of string &log &optional;
		## Notify Message Types
		notify_messages: vector of string &log &optional;
		## Transforms
		transforms: vector of string &log &optional;
		## KE DH Group number
		ke_dh_groups: vector of count &log &optional;
		## Proposals
		proposals: vector of count &log &optional;
		## Certificate hashes
		certificates: vector of string &log &optional;
		## Transform Attributes
		transform_attributes: vector of string &log &optional;
		## Length of headers plus payload
		length: count &log &optional;
		## Cipher hash of this IPSec transaction info:
		## vendor_ids, notify_messages, transforms, ke_dh_groups, and proposals
		hash: string &log &optional;
		# The analyzer ID used for the analyzer instance attached
		# to each connection.  It is not used for logging since it's a
		# meaningless arbitrary number.
		analyzer_id: count &optional;
	};

	# Event that can be handled to access the IPSec record as it is sent on
	# to the logging framework.
	global log_ipsec: event(rec: ipsec::Info);

	# Records used as arguments in the events below.

	type IKEMsg: record {
		## Initiator security parameters index
		initiator_spi: string;
		## Responder security parameters index
		responder_spi: string;
		## Next Payload
		next_payload: count;
		## Major Version
		maj_ver: count;
		## Minor Version
		min_ver: count;
		## Exchange Type
		exchange_type: count;
		## Flag E
		flag_e: bool;
		## Flag C
		flag_c: bool;
		## Flag A
		flag_a: bool;
		## Flag I
		flag_i: bool;
		## Flag V
		flag_v: bool;
		## Flag R
		flag_r: bool;
		## Message ID
		message_id: count;
		## Length of headers plus payload
		length: count;
	};

	type ESPMsg: record {
		## Security parameters index
		spi: count;
		## Sequence number
		seq: count;
		## Length of payload
		payload_len: count;
	};

	type IKE_SA_Proposal_Msg: record {
		## Associated message ID
		message_id: count;
		## Last or more marker
		last_or_more: string;
		## Proposal length
		proposal_len: count;
		## The proposal number
		proposal_num: count;
		## Protocol ID
		protocol_id: count;
		## SPI size
		spi_size: count;
		## Number of transforms
		num_transforms: count;
		## SPI
		spi: string;
	};

	type IKE_SA_Transform_Msg: record {
		## Associated message ID
		message_id: count;
		## The proposal number
		proposal_num: count;
		## Last or more marker
		last_or_more: string;
		## Transform length
		transform_len: count;
		## Transform type
		transform_type: count;
		## Transform ID
		transform_id: count;
	};

	type IKE_SA_Transform_Attribute_Msg: record {
		## Associated message ID
		message_id: count;
		## The proposal number
		proposal_num: count;
		## Transform ID
		transform_id: count;
		## Autoformat
		AF: bool;
		## Attribute Type
		attribute_type: count;
		## Attribute value
		attribute_val: string;
	};

	type IKE_KE_Msg: record {
		## Associated message ID
		message_id: count;
		## DH Group
		dh_group: count &optional;
		## Key exchange data
		key_exchange_data: string;
	};

	type IKEv1_KE_Msg: record {
		## Associated message ID
		message_id: count;
		## Key exchange data
		key_exchange_data: string;
	};

	type IKE_ID_Msg: record {
		## Associated message ID
		message_id: count;
		## ID type
		id_type: count;
		## Identification data
		identification_data: string;
	};

	type IKEv1_ID_Msg: record {
		## Associated message ID
		message_id: count;
		## Identification data
		identification_data_len: count;
	};

	type IKE_CERT_Msg: record {
		## Associated message ID
		message_id: count;
		## Cert encoding
		cert_encoding: count;
		## Cert data
		cert_data: string;
	};

	type IKE_CERTREQ_Msg: record {
		## Associated message ID
		message_id: count;
		## Cert encoding
		cert_encoding: count;
		## Cert authority
		cert_authority: string;
	};

	type IKE_AUTH_Msg: record {
		## Associated message ID
		message_id: count;
		## Auth method
		auth_method: count;
		## Auth data
		auth_data: string;
	};

	type IKE_NONCE_Msg: record {
		## Associated message ID
		message_id: count;
		## Nonce data length
		nonce_data_len: count;
	};

	type IKE_NOTIFY_Msg: record {
		## Associated message ID
		message_id: count;
		## Protocol ID
		protocol_id: count;
		## SPI size
		spi_size: count;
		## Notify message type
		notify_msg_type: count;
		## SPI
		spi: string;
		## Notification data
		notification_data: string;
	};

	type IKE_DELETE_Msg: record {
		## Associated message ID
		message_id: count;
		## Protocol ID
		protocol_id: count;
		## SPI size
		spi_size: count;
		## Number of SPIs
		num_spi: count;
		## SPIs
		spis: set[string];
	};

	type IKE_VENDORID_Msg: record {
		## Associated message ID
		message_id: count;
		## Vendor ID
		vendor_id: string;
	};

	type IKE_TRAFFICSELECTOR_Msg: record {
		## Associated message ID
		message_id: count;
		## Traffic selector type
		ts_type: count;
		## IP protocol ID
		ip_proto_id: count;
		## Selector length
		selector_len: count;
		## Start port
		start_port: count;
		## End port
		end_port: count;
		## Start address
		start_address: addr;
		## End address
		end_address: addr;
	};

	type IKE_ENCRYPTED_Msg: record {
		## Associated message ID
		message_id: count;
		## Length of payload
		payload_len: count;
	};

	type IKE_CONFIG_ATTR_Msg: record {
		## Associated message ID
		message_id: count;
		## Configuration type
		cfg_type: count;
		## Attribute type
		attribute_type: count;
		## Length
		length: count;
		## Value
		value: string;
	};

	type IKE_EAP_Msg: record {
		## Associated message ID
		message_id: count;
		## Length of payload
		payload_len: count;
	};

	type IKEv1_SA_Msg: record {
		## Associated message ID
		message_id: count;
		## DOI
		doi: count;
		## Situation
		situation: string;
	};

	type IKEv1_HASH_Msg: record {
		## Associated message ID
		message_id: count;
		## Hash length
		hash_data_len: count;
	};

	type IKEv1_P_Msg: record {
		## Associated message ID
		message_id: count;
		## The proposal number
		proposal_num: count;
		## Protocol ID
		protocol_id: count;
		## SPI size
		spi_size: count;
		## Number of transforms
		num_transforms: count;
		## SPI
		spi: string;
	};

	type IKEv1_T_Msg: record {
		## Associated message ID
		message_id: count;
		## The proposal number
		proposal_num: count;
		## Transform number
		transform_num: count;
		## Transform ID
		transform_id: count;
	};

	type IKEv1_SIG_Msg: record {
		## Associated message ID
		message_id: count;
		## Signature data length
		sig_data_len: count;
	};

	## Fires on every IKE message.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ike_message: event(c: connection, is_orig: bool, msg: ipsec::IKEMsg);

	## Fires on every ESP message.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::esp_message: event(c: connection, is_orig: bool, msg: ipsec::ESPMsg);

	## Fires on every IKE SA proposal.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_sa_proposal: event(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Proposal_Msg);

	## Fires on every IKE SA transform.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_sa_transform: event(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Transform_Msg);

	## Fires on every IKE data attribute.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ike_data_attribute: event(c: connection, is_orig: bool, msg: IKE_SA_Transform_Attribute_Msg);

	## Fires on every IKE Key Exchange payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_ke_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_KE_Msg);

	## Fires on every IKE Identification - Initiator payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_idi_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_ID_Msg);

	## Fires on every IKE Identification - Responder payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_idr_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_ID_Msg);

	## Fires on every IKE Certificate payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_cert_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg);

	## Fires on every IKE Certificate Request payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_certreq_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_CERTREQ_Msg);

	## Fires on every IKE Authentication payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_auth_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_AUTH_Msg);

	## Fires on every IKE Nonce payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_nonce_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_NONCE_Msg);

	## Fires on every IKE Notify payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_notify_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg);

	## Fires on every IKE Delete payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	#global ipsec::ikev2_delete_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_DELETE_Msg);

	## Fires on every IKE Vendor ID payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_vendorid_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg);

	## Fires on every IKE Traffic Selector payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_trafficselector_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_TRAFFICSELECTOR_Msg);

	## Fires on every IKE Encrypted payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_encrypted_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_ENCRYPTED_Msg);

	## Fires on every IKE configuration attribute.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_configuration_attribute: event(c: connection, is_orig: bool, msg: ipsec::IKE_CONFIG_ATTR_Msg);

	## Fires on every IKE EAP payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev2_eap_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_EAP_Msg);

	## Fires on every IKEv1 A payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_sa_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_SA_Msg);

	## Fires on every IKEv1 vendor ID payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_vid_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg);

	## Fires on every IKEv1 key exchange payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_ke_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_KE_Msg);

	## Fires on every IKEv1 nonce payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_nonce_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_NONCE_Msg);

	## Fires on every IKEv1 certificate payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_cert_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg);

	## Fires on every IKEv1 certificate request payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_certreq_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_CERTREQ_Msg);

	## Fires on every IKEv1 ID payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_id_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_ID_Msg);

	## Fires on every IKEv1 hash payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_hash_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_HASH_Msg);

	## Fires on every IKEv1 signature payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_sig_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_SIG_Msg);

	## Fires on every IKEv1 proposal payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_p_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_P_Msg);

	## Fires on every IKEv1 transform payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_t_payload: event(c: connection, is_orig: bool, msg: ipsec::IKEv1_T_Msg);

	## Fires on every IKEv1 notification payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_notify_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg);

	## Fires on every IKEv1 delete payload.
	##
	## c: The connection record describing the corresponding UDP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed IPSec message.
	global ipsec::ikev1_delete_payload: event(c: connection, is_orig: bool, msg: ipsec::IKE_DELETE_Msg);

}

redef record connection += {
	ipsec: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(ipsec::IPSEC_LOG, [$columns=Info, $ev=log_ipsec, $path="ipsec"]);
	}

function set_session(c: connection)
	{
	if ( ! c?$ipsec )
		{
		c$ipsec = [$ts=network_time(), $uid=c$uid, $id=c$id];
		c$ipsec$vendor_ids = vector();
		c$ipsec$notify_messages = vector();
		c$ipsec$transforms = vector();
		c$ipsec$ke_dh_groups = vector();
		c$ipsec$proposals = vector();
		c$ipsec$certificates = vector();
		c$ipsec$transform_attributes = vector();
		}
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_SPICY_IPSEC_IKE_UDP ||
		 atype == Analyzer::ANALYZER_SPICY_IPSEC_TCP ||
		 atype == Analyzer::ANALYZER_SPICY_IPSEC_UDP )
		{
		set_session(c);
		c$ipsec$analyzer_id = aid;
		}
	}

event ipsec::ike_message(c: connection, is_orig: bool, msg: ipsec::IKEMsg)
	{
	set_session(c);
	c$ipsec$is_orig = is_orig;
	c$ipsec$initiator_spi = bytestring_to_hexstr(msg$initiator_spi);
	c$ipsec$responder_spi = bytestring_to_hexstr(msg$responder_spi);
	c$ipsec$maj_ver = msg$maj_ver;
	c$ipsec$min_ver = msg$min_ver;
	c$ipsec$exchange_type = msg$exchange_type;
	c$ipsec$flag_e = msg$flag_e;
	c$ipsec$flag_c = msg$flag_c;
	c$ipsec$flag_a = msg$flag_a;
	c$ipsec$flag_i = msg$flag_i;
	c$ipsec$flag_v = msg$flag_v;
	c$ipsec$flag_r = msg$flag_r;
	c$ipsec$message_id = msg$message_id;
	c$ipsec$length = msg$length;


	if ( |c$ipsec$vendor_ids| != 0 || |c$ipsec$notify_messages| != 0 || |c$ipsec$transforms| != 0 ||
		 |c$ipsec$ke_dh_groups| != 0 || |c$ipsec$proposals| != 0 || |c$ipsec$certificates| != 0 ||
		 |c$ipsec$transform_attributes| != 0)
		{
		local cipher_string = cat(c$ipsec$vendor_ids, c$ipsec$notify_messages,
								  c$ipsec$transforms, c$ipsec$ke_dh_groups, c$ipsec$proposals,
								  c$ipsec$certificates, c$ipsec$transform_attributes);
		c$ipsec$hash = md5_hash(cipher_string);
		}

	Log::write(ipsec::IPSEC_LOG, c$ipsec);
	delete c$ipsec;
	}

function ipsec::do_vendorid(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg)
	{
	set_session(c);

	local vendor_id_friendly_name: string;
	vendor_id_friendly_name = fmt("UNKNOWN:%s", bytestring_to_hexstr(msg$vendor_id));

	# Attempt to get friendly name for Vendor ID
	for (i in vendor_ids)
		{
		if(vendor_ids[i] in bytestring_to_hexstr(msg$vendor_id))
			{
			vendor_id_friendly_name = i;
			break;
			}
		}

	c$ipsec$vendor_ids += vendor_id_friendly_name;
	}

event ipsec::ikev2_vendorid_payload(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg)
	{
	ipsec::do_vendorid(c, is_orig, msg);
	}

event ipsec::ikev1_vid_payload(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg)
	{
	ipsec::do_vendorid(c, is_orig, msg);
	}

function ipsec::do_notify(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg)
	{
	set_session(c);

	c$ipsec$notify_messages += notify_message_types[msg$notify_msg_type];
	}

event ipsec::ikev2_notify_payload(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg)
	{
	ipsec::do_notify(c, is_orig, msg);
	}

event ipsec::ikev1_notify_payload(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg)
	{
	ipsec::do_notify(c, is_orig, msg);
	}

event ipsec::ikev2_sa_payload(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Transform_Msg)
	{
	set_session(c);

	local transform_id_string: string;

	if (msg$transform_type == 1) { # Encryption Algorithm (ENCR)
		transform_id_string = encryption_transform_ids[msg$transform_id];
	} else if (msg$transform_type == 2) { #Pseudorandom Function (PRF)
		transform_id_string = prf_transform_ids[msg$transform_id];
	} else if (msg$transform_type == 3) { #Integrity Algorithm (INTEG)
		transform_id_string = integrity_transform_ids[msg$transform_id];
	} else if (msg$transform_type == 4) { #Diffie-Hellman Group (D-H)
		transform_id_string = dhgroup_transform_ids[msg$transform_id];
	} else if (msg$transform_type == 5) { #Extended Sequence Numbers (ESN)
		transform_id_string = esn_transform_ids[msg$transform_id];
	} else {
		# Weird - should never happen
		Reporter::conn_weird("ikev2_unknown_transform_type", c, "");
		transform_id_string = fmt("UNKNOWN:%d", msg$transform_type);
	}

	c$ipsec$transforms += fmt("%s:%s", transform_types_short[msg$transform_type], transform_id_string);
	}

event ipsec::ikev1_t_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_T_Msg)
	{
	set_session(c);

	c$ipsec$transforms += fmt("%s", msg$transform_id);
	}

event ipsec::ikev2_ke_payload(c: connection, is_orig: bool, msg: ipsec::IKE_KE_Msg)
	{
	set_session(c);

	c$ipsec$ke_dh_groups += msg$dh_group;
	}

function ipsec::do_proposal(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Proposal_Msg)
	{
	set_session(c);

	c$ipsec$proposals += msg$proposal_num;
	}

event ipsec::ikev2_sa_proposal(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Proposal_Msg)
	{
	ipsec::do_proposal(c, is_orig, msg);
	}

event ipsec::ikev2_p_payload(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Proposal_Msg)
	{
	ipsec::do_proposal(c, is_orig, msg);
	}

function ipsec::do_cert(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg)
	{
	set_session(c);

	c$ipsec$certificates += md5_hash(msg$cert_data);
	}

event ipsec::ikev2_cert_payload(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg)
	{
	ipsec::do_cert(c, is_orig, msg);
	}

event ipsec::ikev1_cert_payload(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg)
	{
	ipsec::do_cert(c, is_orig, msg);
	}

event ipsec::DataAttribute(c: connection, is_orig: bool, msg: IKE_SA_Transform_Attribute_Msg)
	{
	set_session(c);

	if (msg$AF)
		{
		c$ipsec$transform_attributes += fmt("%s:%s:%s=%s", msg$proposal_num, msg$transform_id,
											attribute_types[msg$attribute_type],
											bytestring_to_count(msg$attribute_val));
		}
	else
		{
		c$ipsec$transform_attributes += fmt("%s:%s:%s=%s", msg$proposal_num, msg$transform_id,
											attribute_types[msg$attribute_type],
											msg$attribute_val);
		}
	}
