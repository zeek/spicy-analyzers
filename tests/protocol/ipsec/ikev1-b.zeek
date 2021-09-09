# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: set >envs
# @TEST-EXEC: zeek -C -r ${TRACES}/ipsec-ikev1-isakmp-aggressive-mode.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ipsec.log
# @TEST-EXEC: btest-diff .stdout

@load spicy-analyzers/ipsec

event ipsec::ike_message(c: connection, is_orig: bool, msg: ipsec::IKEMsg) { print cat("ike_message ", is_orig, c$id, msg); }
event ipsec::esp_message(c: connection, is_orig: bool, msg: ipsec::ESPMsg) { print cat("esp_message ", is_orig, c$id, msg); }
event ipsec::ikev1_sa_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_SA_Msg) { print cat("ikev1_sa_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_vid_payload(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg) { print cat("ikev1_vid_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_ke_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_KE_Msg) { print cat("ikev1_ke_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_nonce_payload(c: connection, is_orig: bool, msg: ipsec::IKE_NONCE_Msg) { print cat("ikev1_n_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_cert_payload(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg) { print cat("ikev1_cert_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_certreq_payload(c: connection, is_orig: bool, msg: ipsec::IKE_CERTREQ_Msg) { print cat("ikev1_certreq_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_id_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_ID_Msg) { print cat("ikev1_id_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_hash_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_HASH_Msg) { print cat("ikev1_hash_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_sig_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_SIG_Msg) { print cat("ikev1_sig_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_p_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_P_Msg) { print cat("ikev1_p_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_t_payload(c: connection, is_orig: bool, msg: ipsec::IKEv1_T_Msg) { print cat("ikev1_t_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_notify_payload(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg) { print cat("ikev1_notify_payload ", is_orig, c$id, msg); }
event ipsec::ikev1_delete_payload(c: connection, is_orig: bool, msg: ipsec::IKE_DELETE_Msg) { print cat("ikev1_delete_payload ", is_orig, c$id, msg); }
event ipsec::ike_data_attribute(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Transform_Attribute_Msg) { print cat("ike_data_attribute ", is_orig, c$id, msg); }
