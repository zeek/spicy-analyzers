# Facefish_Rootkit

An in depth blog and webinar slides on the development of this analyzer:

- <https://zeek.org/2021/06/10/detecting-the-facefish-linux-rootkit-with-zeek/>
- <https://docs.google.com/presentation/d/1RRej4BeOF0hTpLVxc0Drg-W5PtI-js1TLcMNC3cTNj0/edit#slide=id.gdfd7e8c66a_0_45>

This Spicy analyzer will detect the Facefish Linux rootkit C2 as described in:

- <https://blog.netlab.360.com/ssh_stealer_facefish_en/>
- <https://blogs.juniper.net/en-us/threat-research/linux-servers-hijacked-to-implant-ssh-backdoor>
- <https://thehackernews.com/2021/05/researchers-warn-of-facefish-backdoor.html>
- <https://securityaffairs.co/wordpress/118388/malware/facefish-backdoor.html>

Any detections will be found in "facefish_rootkit.log" while a "Facefish_Rootkit::FACEFISH_ROOTKIT_C2" notice
is also raised.

The testing pcap was made with the following command:

```
echo -n -e \\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x00 | nc 127.0.0.1 9999
```

There is a PCAP of the C2 traffic available here:

<https://www.joesandbox.com/analysis/355141/0/html#network>

The output is as follows:

```
$ zeek -Cr dump-38fb322cc6d09a6ab85784ede56bc5a7.pcap spicy-analyzers

$ cat conn.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-06-03-14-53-30
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1613702572.079957	CWc0UD3fGLX0c6bj89	192.168.2.20	43448	176.111.174.26	443	tcp	-	3.002074	0	0	S0	-	-	0	S	3	180	0	0	-
1613702572.190619	CCo5Jp4eSxYMobOp3i	192.168.2.20	43450	176.111.174.26	443	tcp	-	3.003396	0	0	S0	-	-	0	S	3	180	0	0	-
1613702579.089432	CbPIFh4Olo8i1G0KV2	192.168.2.20	43448	176.111.174.26	443	tcp	-	-	-	-	S0	-	-	0	S	1	60	0	0	-
1613702579.201449	CPyuMa4IZGRzzBEOvh	192.168.2.20	43450	176.111.174.26	443	tcp	-	-	-	-	S0	-	-	0	S	1	60	0	0	-
1613702587.104275	C7nx2B1vfFr2VroO59	192.168.2.20	43448	176.111.174.26	443	tcp	-	-	-	-	S0	-	-	0	S	1	60	0	0	-
1613702603.150049	CUcCUW2x5WZS1yWyci	192.168.2.20	43448	176.111.174.26	443	tcp	-	-	-	-	S0	-	-	0	S	1	60	0	0	-
1613702635.209441	ChmbMq44oJeZIR6tVf	192.168.2.20	43448	176.111.174.26	443	tcp	-	-	-	-	S0	-	-	0	S	1	60	0	0	-
1613702587.216303	Clfyzh4ifzsqqUzvqc	192.168.2.20	43450	176.111.174.26	443	tcp	spicy_facefish_rootkit	29.625531	4304	32	S1	-	-	0	ShADTad	19	5348	12	688	-
#close	2021-06-03-14-53-30

$ cat facefish_rootkit.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	facefish_rootkit
#open	2021-06-03-14-53-30
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	is_orig	payload_len	command	crc32_payload
#types	time	string	addr	port	addr	port	bool	count	string	count
1613702587.313451	Clfyzh4ifzsqqUzvqc	192.168.2.20	43450	176.111.174.26	443	T	0	KeyEx1	0
1613702616.553325	Clfyzh4ifzsqqUzvqc	192.168.2.20	43450	176.111.174.26	443	F	24	KeyEx2	707025536
1613702616.557061	Clfyzh4ifzsqqUzvqc	192.168.2.20	43450	176.111.174.26	443	T	8	KeyEx3	2984358853
1613702616.746288	Clfyzh4ifzsqqUzvqc	192.168.2.20	43450	176.111.174.26	443	T	4272	Registration	2325026424
#close	2021-06-03-14-53-30

$ cat notice.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2021-06-03-14-53-30
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	interval	string	string	string	double	double
1613702587.313451	Clfyzh4ifzsqqUzvqc	192.168.2.20	43450	176.111.174.26	443	-	-	-	tcp	Facefish_Rootkit::FACEFISH_ROOTKIT_C2	Potential Facefish rootkit C2 detected.	More info: https://blog.netlab.360.com/ssh_stealer_facefish_en/	192.168.2.20	176.111.174.26	443	-	-	Notice::ACTION_LOG	60.000000	-	-	-	-
#close	2021-06-03-14-53-30
```
