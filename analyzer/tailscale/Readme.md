# Tailscale

[Tailscale](https://tailscale.com/) is a VPN that modifies the Wireguard protocol
slightly by adding Tailscale discovery messages.  While the generic Wireguard protocol
analyzer in this repo will not support this, this protocol analyzer will.

Relevant code section: <https://github.com/tailscale/tailscale/blob/main/disco/disco.go#L32>

## Example

```
$ zeek -Cr tailscale_linux.pcap spicy-analyzers

$ cat conn.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2021-06-16-09-41-54
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1623328901.893092	CHnAcy2m5OOZBmzxK5	192.168.88.3	41641	18.196.71.179	41641	udp	spicy_tailscale	31.882638	5700	6322	SF	-	-	0	Dd	51	7128	56	7890	-
#close	2021-06-16-09-41-54
```
