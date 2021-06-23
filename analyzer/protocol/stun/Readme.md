# STUN

Session Traversal Utilities for NAT (STUN)

This will detect STUN and create two logs:

 - stun.log - This log has every STUN message.
 - stun_nat.log - This log has NAT detections from mapped addresses.

Additional logic has been added to the original logic found here:

- https://github.com/r-franke/spicy_stun (BSD License for original code and PCAP here.)
- https://github.com/r-franke/spicy_stun/issues/1 (Permission to move this work over to spicy-analyzers here.)

More info about STUN:

- https://datatracker.ietf.org/doc/html/rfc5389
- https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
- https://datatracker.ietf.org/doc/html/rfc8489

## Example

```
$ zeek -Cr stun-ice-testcall.pcap spicy-analyzers

$ head -n 20 stun.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	stun
#open	2021-06-21-10-11-38
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_orig	trans_id	method	class	attr_type	attr_val
#types	time	string	addr	port	addr	port	bool	string	string	string	string	string
1377211115.073291	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	F	SOpCii5Jfc1z	BINDING	RESPONSE_SUCCESS	MAPPED_ADDRESS	70.199.128.46:4604
1377211125.183611	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	F	KIkrzjV7Aan8	BINDING	RESPONSE_SUCCESS	MAPPED_ADDRESS	70.199.128.46:4604
1377211125.210098	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	F	KIkrzjV7Aan8	BINDING	RESPONSE_SUCCESS	MAPPED_ADDRESS	70.199.128.46:4604
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	T	5YSnBqpVwa9O	BINDING	REQUEST	USERNAME	pLyZHR:GwL3AHBovubLvCqn
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	T	5YSnBqpVwa9O	BINDING	REQUEST	ICE_CONTROLLING	\x18\x8b\x10Li{\xf6[
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	T	5YSnBqpVwa9O	BINDING	REQUEST	USE_CANDIDATE	(empty)
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	T	5YSnBqpVwa9O	BINDING	REQUEST	PRIORITY	1845501695
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	T	5YSnBqpVwa9O	BINDING	REQUEST	MESSAGE_INTEGRITY	`+\xc7\xfc\x0d\x10c\xaa\xc58\x1c\xcb\x96\xa9s\x08s\x9a\x96\x0c
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	T	5YSnBqpVwa9O	BINDING	REQUEST	FINGERPRINT	3512920677
1377211128.184433	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	T	mPEXdyYbuuQm	BINDING	REQUEST	USERNAME	pLyZHR:GwL3AHBovubLvCqn
1377211128.184433	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	T	mPEXdyYbuuQm	BINDING	REQUEST	ICE_CONTROLLING	\x18\x8b\x10Li{\xf6[
1377211128.184433	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	T	mPEXdyYbuuQm	BINDING	REQUEST	USE_CANDIDATE	(empty)

$ head -n 20 stun_nat.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	stun_nat
#open	2021-06-21-10-11-38
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_orig	wan_addr	wan_port	lan_addr
#types	time	string	addr	port	addr	port	bool	addr	count	addr
1377211115.073291	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	F	70.199.128.46	4604	192.168.43.155
1377211125.183611	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	F	70.199.128.46	4604	192.168.43.155
1377211125.210098	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	F	70.199.128.46	4604	192.168.43.155
1377211128.309676	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	F	70.199.128.46	4587	192.168.43.155
1377211128.309677	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	F	70.199.128.46	4587	192.168.43.155
1377211128.358745	C7bUM12MRrKFPP68i3	192.168.43.155	60020	155.212.214.188	23131	F	70.199.128.46	4604	192.168.43.155
1377211128.359514	CrSPRHMrWLlAyTqYj	192.168.43.155	60020	155.212.214.188	23130	F	70.199.128.46	4604	192.168.43.155
1377211128.394673	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	F	70.199.128.46	4587	192.168.43.155
1377211128.405706	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	F	70.199.128.46	4587	192.168.43.155
1377211128.458800	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	F	70.199.128.46	4587	192.168.43.155
1377211128.459477	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	F	70.199.128.46	4587	192.168.43.155
1377211128.940537	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	F	70.199.128.46	4587	192.168.43.155

$ cat conn.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-06-21-10-11-38
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1377211115.029606	CO6ixvpP4A6xAGKg4	192.168.43.155	60020	74.125.141.127	19302	udp	spicy_stun	20.187972	80	128	SF	-	-	0	Dd	4	192	4	240	-
1377211128.184058	C2xdynwRvQNCBFxsf	192.168.43.155	59977	155.212.214.188	23130	udp	spicy_stun	7.955804	2136	1972	SF	-	-	0	Dd	22	2752	22	2588	-
1377211128.232201	CrSPRHMrWLlAyTqYj	192.168.43.155	60020	155.212.214.188	23130	udp	spicy_stun	0.274303	288	288	SF	-	-	0	Dd	4	400	3	372	-
1377211128.184433	Cu0vxM1pLxfdOI3afe	192.168.43.155	59977	155.212.214.188	23131	udp	spicy_stun	7.955427	2088	1872	SF	-	-	0	Dd	21	2676	21	2460	-
1377211128.232522	C7bUM12MRrKFPP68i3	192.168.43.155	60020	155.212.214.188	23131	udp	spicy_stun	0.242014	288	288	SF	-	-	0	Dd	4	400	3	372	-
#close	2021-06-21-10-11-38
```
