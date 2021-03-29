# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: set >envs
# @TEST-EXEC: ${ZEEK} -C -r ${TRACES}/ipsec_client.pcapng %INPUT
# @TEST-EXEC: btest-diff ipsec.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout

@load spicy-analyzers/protocol/ipsec

event ipsec::ike_message(c: connection, is_orig: bool, msg: ipsec::IKEMsg) { print cat("ike_message ", is_orig, c$id, msg); }
event ipsec::esp_message(c: connection, is_orig: bool, msg: ipsec::ESPMsg) { print cat("esp_message ", is_orig, c$id, msg); }
event ipsec::ikev2_sa_proposal(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Proposal_Msg) { print cat("ike_sa_proposal ", is_orig, c$id, msg); }
event ipsec::ikev2_sa_transform(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Transform_Msg) { print cat("ike_sa_transform ", is_orig, c$id, msg); }
event ipsec::ike_data_attribute(c: connection, is_orig: bool, msg: ipsec::IKE_SA_Transform_Attribute_Msg) { print cat("ike_data_attribute ", is_orig, c$id, msg); }
event ipsec::ikev2_ke_payload(c: connection, is_orig: bool, msg: ipsec::IKE_KE_Msg) { print cat("ike_ke_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_idi_payload(c: connection, is_orig: bool, msg: ipsec::IKE_ID_Msg) { print cat("ike_idi_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_idr_payload(c: connection, is_orig: bool, msg: ipsec::IKE_ID_Msg) { print cat("ike_idr_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_cert_payload(c: connection, is_orig: bool, msg: ipsec::IKE_CERT_Msg) { print cat("ike_cert_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_certreq_payload(c: connection, is_orig: bool, msg: ipsec::IKE_CERTREQ_Msg) { print cat("ike_certreq_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_auth_payload(c: connection, is_orig: bool, msg: ipsec::IKE_AUTH_Msg) { print cat("ike_auth_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_nonce_payload(c: connection, is_orig: bool, msg: ipsec::IKE_NONCE_Msg) { print cat("ike_nonce_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_notify_payload(c: connection, is_orig: bool, msg: ipsec::IKE_NOTIFY_Msg) { print cat("ike_notify_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_delete_payload(c: connection, is_orig: bool, msg: ipsec::IKE_DELETE_Msg) { print cat("ike_delete_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_vendorid_payload(c: connection, is_orig: bool, msg: ipsec::IKE_VENDORID_Msg) { print cat("ike_vendorid_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_ts_payload(c: connection, is_orig: bool, msg: ipsec::IKE_TRAFFICSELECTOR_Msg) { print cat("ike_ts_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_encrypted_payload(c: connection, is_orig: bool, msg: ipsec::IKE_ENCRYPTED_Msg) { print cat("ike_encrypted_payload ", is_orig, c$id, msg); }
event ipsec::ikev2_configuration_attribute(c: connection, is_orig: bool, msg: ipsec::IKE_CONFIG_ATTR_Msg) { print cat("ike_configuration_attribute ", is_orig, c$id, msg); }
event ipsec::ikev2_eap_payload(c: connection, is_orig: bool, msg: ipsec::IKE_EAP_Msg) { print cat("ike_eap_payload ", is_orig, c$id, msg); }