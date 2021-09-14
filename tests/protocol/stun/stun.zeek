# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -NN >zeek 2>&1
# @TEST-EXEC: zeek -Cr ${TRACES}/stun-ice-testcall.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff stun.log
# @TEST-EXEC: btest-diff stun_nat.log
# @TEST-EXEC: btest-diff .stdout

@load spicy-analyzers/stun

event STUN::STUNPacket(c: connection, is_orig: bool, method: count, class: count, trans_id: string)
	{
	print "STUN Packet", c$id, is_orig, method, class, trans_id;
	}

event STUN::string_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
							 attr_type: count, attr_val: string)
	{
	print "String Attr", c$id, is_orig, method, class, trans_id, attr_type, attr_val;
	}

event STUN::mapped_address_attribute(c: connection, is_orig: bool, method: count, class: count,
									 trans_id: string, attr_type: count, x_port: count, x_addr: addr)
	{
	print "Mapped Addr Attr", c$id, is_orig, method, class, trans_id, attr_type, x_port, x_addr;
	}

event STUN::error_code_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string,
								 attr_type: count, err_class: string, number: count, reason: string)
	{
	print "Error Code Attr", c$id, is_orig, method, class, trans_id, attr_type, err_class, number, reason;
	}
