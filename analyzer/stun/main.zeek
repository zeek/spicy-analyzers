# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

module STUN;

export {
	redef enum Log::ID += { LOG, LOG_NAT };

	## The record type which contains the fields of the STUN log.
	## This is reported for every STUN message.
	type Info: record {
		### Time the first packet was encountered
		ts:             time            &log &default=network_time();
		### Unique ID for the connection
		uid:            string          &log;
		## The connection's 4-tuple of endpoint addresses/ports
		id:             conn_id         &log;
		## The protocol
		proto:			transport_proto	&log;
		# Is orig
		is_orig: 		bool 			&log;
		## The transaction ID
		trans_id:		string			&log;
		## The STUN method
		method:			string			&log;
		## The STUN class
		class:			string			&log;
		## The attribute type
		attr_type:		string			&log;
		## The attribute value
		attr_val:		string			&log;
	};

	## The record type which contains the fields of the STUN_NAT log.
	## This is reported only when there is a successful binding.
	type NATInfo: record {
		### Time the first packet was encountered
		ts:             time            &log &default=network_time();
		### Unique ID for the connection
		uid:            string          &log;
		## The connection's 4-tuple of endpoint addresses/ports
		id:             conn_id         &log;
		## The protocol
		proto:			transport_proto	&log;
		# Is orig
		is_orig: 		bool 			&log;
		## The WAN address as reported by STUN
		wan_addr:		addr			&log;
		## The mapped port
		wan_port:		count			&log;
		## The NAT'd LAN address as reported by STUN
		lan_addr:		addr			&log;
	};

	## Event that can be handled to access the STUN
	## record as it is sent on to the logging framework.
	global log_stun: event(rec: Info);

	## Event that can be handled to access the STUN NAT
	## record as it is sent on to the logging framework.
	global log_stun_nat: event(rec: NATInfo);

	## Event raised for parsed STUN packets.
	global STUN::STUNPacket: event(c: connection, is_orig: bool, method: count, class: count, trans_id: string);

	## Event raised for the STUN string attribute.
	global STUN::string_attribute: event(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
										 attr_type: count, attr_val: string);

	## Event raised for the STUN mapped address attribute.
	global STUN::mapped_address_attribute: event(c: connection, is_orig: bool, method: count, class: count,
												 trans_id: string, attr_type: count, x_port: count, host: addr);

	## Event raised for the STUN error code attribute.
	global STUN::error_code_attribute: event(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
											 attr_type: count, err_class: count, number: count, reason: string);

}

redef record connection += {
	stuns: vector of Info &optional;
	stun_nat: vector of NATInfo &optional;
};

function set_session(c: connection)
	{
	if ( ! c?$stuns )
		{
		c$stuns = vector();
		}
	if ( ! c?$stun_nat )
		{
		c$stun_nat = vector();
		}
	}

event STUN::STUNPacket(c: connection, is_orig: bool, method: count, class: count, trans_id: string)
	{
	set_session(c);
	for (s in c$stuns)
		{
		Log::write(LOG, c$stuns[s]);
		}
	delete c$stuns;
	for (s in c$stun_nat)
		{
		Log::write(LOG_NAT, c$stun_nat[s]);
		}
	delete c$stun_nat;
	}

event STUN::string_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
							 attr_type: count, attr_val: string)
	{
	set_session(c);
	# PRIORITY || FINGERPRINT
	if (attr_type == 0x0024 || attr_type == 0x8028)
		{
		attr_val = cat(bytestring_to_count(attr_val));
		}
	local i = Info($uid=c$uid, $id=c$id, $proto=get_conn_transport_proto(c$id), $is_orig=is_orig, $trans_id=trans_id,
				   $method=methodtype[method], $class=classtype[class], $attr_type=attrtype[attr_type], $attr_val=attr_val);
	c$stuns += i;
	}

event STUN::mapped_address_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
									 attr_type: count, x_port: count, x_addr: addr)
	{
	set_session(c);
	local attr_val: string;
	local wan_addr: addr;
	local wan_port: count;
	local lan_addr: addr = is_orig ? c$id$resp_h : c$id$orig_h;

	# XOR_MAPPED_ADDRESS || XOR_PEER_ADDRESS || XOR_RELAYED_ADDRESS
	if (attr_type == 0x0020 || attr_type == 0x0012 || attr_type == 0x0016)
		{
		wan_port = x_port^0x2112;
		if (is_v4_addr(x_addr))
			{
			wan_addr = counts_to_addr(vector(addr_to_counts(x_addr)[0]^0x2112A442));
			}
		else
			{
			local cts = addr_to_counts(x_addr);
			cts[0] = cts[0] ^ 0x2112A442;
			cts[1] = cts[1] ^ bytestring_to_count(trans_id[0:4]);
			cts[2] = cts[2] ^ bytestring_to_count(trans_id[4:8]);
			cts[3] = cts[3] ^ bytestring_to_count(trans_id[8:12]);
			wan_addr = counts_to_addr(cts);
			}
		}
	else
		{
		wan_addr = x_addr;
		wan_port = x_port;
		}
	attr_val = cat(wan_addr, ":", wan_port);
	c$stuns += Info($uid=c$uid, $id=c$id, $proto=get_conn_transport_proto(c$id), $is_orig=is_orig, $trans_id=trans_id,
					$method=methodtype[method], $class=classtype[class], $attr_type=attrtype[attr_type], $attr_val=attr_val);
	# MAPPED_ADDRESS || XOR_MAPPED_ADDRESS for BINDING and RESPONSE_SUCCESS
	if ((attr_type == 0x01 || attr_type == 0x020) && wan_addr != lan_addr && method == 0x01 && class == 0x02)
		c$stun_nat += NATInfo($uid=c$uid, $id=c$id, $proto=get_conn_transport_proto(c$id), $is_orig=is_orig, $wan_addr=wan_addr,
					$wan_port=wan_port, $lan_addr=lan_addr);
	}

event STUN::error_code_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
								 attr_type: count, err_class: count, number: count, reason: string)
	{
	set_session(c);

	# https://datatracker.ietf.org/doc/html/rfc8489#section-14.8
	# "The Class represents the hundreds digit of the error code. [...]
	#  The Number represents the binary encoding of the error code module 100"
	if (err_class < 3 || err_class > 6)
		Reporter::conn_weird("stun_invalid_err_class", c, cat("Error class ", err_class, " outside of required range [3, 6]"));

	if (number > 99)
		Reporter::conn_weird("stun_invalid_err_number", c, cat("Error number ", number, " outside of required range [0, 99]"));

	local err_code: count;
	err_code = (err_class * 100) + number;

	local attr_val = cat(err_code, " ", reason);
	local i = Info($uid=c$uid, $id=c$id, $proto=get_conn_transport_proto(c$id), $is_orig=is_orig, $trans_id=trans_id,
				   $method=methodtype[method], $class=classtype[class], $attr_type=attrtype[attr_type], $attr_val=attr_val);
	c$stuns += i;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(STUN::LOG, [$columns=Info, $ev=log_stun, $path="stun"]);
	Log::create_stream(STUN::LOG_NAT, [$columns=NATInfo, $ev=log_stun_nat, $path="stun_nat"]);
	}
