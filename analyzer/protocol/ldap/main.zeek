# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

module ldap;

export {
  redef enum Log::ID += { LDAP_LOG,
                          LDAP_SEARCH_LOG };

  #############################################################################
  # This is the format of ldap.log (ldap operations minus search-related)
  # Each line represents a unique connection+message_id (requests/responses)
  type Message: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # transport protocol
    proto: string &log &optional;

    # Message ID
    message_id: int &log &optional;

    # LDAP version
    version: int &log &optional;

    # normalized operations (e.g., bind_request and bind_response to "bind")
    opcode: set[string] &log &optional;

    # Result code(s)
    result: set[string] &log &optional;

    # result diagnostic message(s)
    diagnostic_message: vector of string &log &optional;

    # object(s)
    object: vector of string &log &optional;

    # argument(s)
    argument: vector of string &log &optional;
  };

  #############################################################################
  # This is the format of ldap_search.log (search-related messages only)
  # Each line represents a unique connection+message_id (requests/responses)
  type Search: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # transport protocol
    proto: string &log &optional;

    # Message ID
    message_id: int &log &optional;

    # sets of search scope and deref alias
    scope: set[string] &log &optional;
    deref: set[string] &log &optional;

    # base search objects
    base_object: vector of string &log &optional;

    # number of results returned
    result_count: count &log &optional;

    # Result code (s)
    result: set[string] &log &optional;

    # result diagnostic message(s)
    diagnostic_message: vector of string &log &optional;

  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: ldap::Message);
  global log_ldap_search: event(rec: ldap::Search);

  # Event called for each LDAP message (either direction)
  global ldap::message: event(c: connection,
                              message_id: int,
                              opcode: ldap::ProtocolOpcode,
                              result: ldap::ResultCode,
                              matched_dn: string,
                              diagnostic_message: string,
                              object: string,
                              argument: string);

  const PROTOCOL_OPCODES = {
    [ldap::ProtocolOpcode_BIND_REQUEST] = "bind",
    [ldap::ProtocolOpcode_BIND_RESPONSE] = "bind",
    [ldap::ProtocolOpcode_UNBIND_REQUEST] = "unbind",
    [ldap::ProtocolOpcode_SEARCH_REQUEST] = "search",
    [ldap::ProtocolOpcode_SEARCH_RESULT_ENTRY] = "search",
    [ldap::ProtocolOpcode_SEARCH_RESULT_DONE] = "search",
    [ldap::ProtocolOpcode_MODIFY_REQUEST] = "modify",
    [ldap::ProtocolOpcode_MODIFY_RESPONSE] = "modify",
    [ldap::ProtocolOpcode_ADD_REQUEST] = "add",
    [ldap::ProtocolOpcode_ADD_RESPONSE] = "add",
    [ldap::ProtocolOpcode_DEL_REQUEST] = "delete",
    [ldap::ProtocolOpcode_DEL_RESPONSE] = "delete",
    [ldap::ProtocolOpcode_MOD_DN_REQUEST] = "modify",
    [ldap::ProtocolOpcode_MOD_DN_RESPONSE] = "modify",
    [ldap::ProtocolOpcode_COMPARE_REQUEST] = "compare",
    [ldap::ProtocolOpcode_COMPARE_RESPONSE] = "compare",
    [ldap::ProtocolOpcode_ABANDON_REQUEST] = "abandon",
    [ldap::ProtocolOpcode_SEARCH_RESULT_REFERENCE] = "search",
    [ldap::ProtocolOpcode_EXTENDED_REQUEST] = "extended",
    [ldap::ProtocolOpcode_EXTENDED_RESPONSE] = "extended",
    [ldap::ProtocolOpcode_INTERMEDIATE_RESPONSE] = "intermediate"
  } &default = "unknown";

  const BIND_SIMPLE = "bind simple";
  const BIND_SASL = "bind SASL";

  const RESULT_CODES = {
    [ldap::ResultCode_SUCCESS] = "success",
    [ldap::ResultCode_OPERATIONS_ERROR] = "operations error",
    [ldap::ResultCode_PROTOCOL_ERROR] = "protocol error",
    [ldap::ResultCode_TIME_LIMIT_EXCEEDED] = "time limit exceeded",
    [ldap::ResultCode_SIZE_LIMIT_EXCEEDED] = "size limit exceeded",
    [ldap::ResultCode_COMPARE_FALSE] = "compare false",
    [ldap::ResultCode_COMPARE_TRUE] = "compare true",
    [ldap::ResultCode_AUTH_METHOD_NOT_SUPPORTED] = "auth method not supported",
    [ldap::ResultCode_STRONGER_AUTH_REQUIRED] = "stronger auth required",
    [ldap::ResultCode_PARTIAL_RESULTS] = "partial results",
    [ldap::ResultCode_REFERRAL] = "referral",
    [ldap::ResultCode_ADMIN_LIMIT_EXCEEDED] = "admin limit exceeded",
    [ldap::ResultCode_UNAVAILABLE_CRITICAL_EXTENSION] = "unavailable critical extension",
    [ldap::ResultCode_CONFIDENTIALITY_REQUIRED] = "confidentiality required",
    [ldap::ResultCode_SASL_BIND_IN_PROGRESS] = "SASL bind in progress",
    [ldap::ResultCode_NO_SUCH_ATTRIBUTE] = "no such attribute",
    [ldap::ResultCode_UNDEFINED_ATTRIBUTE_TYPE] = "undefined attribute type",
    [ldap::ResultCode_INAPPROPRIATE_MATCHING] = "inappropriate matching",
    [ldap::ResultCode_CONSTRAINT_VIOLATION] = "constraint violation",
    [ldap::ResultCode_ATTRIBUTE_OR_VALUE_EXISTS] = "attribute or value exists",
    [ldap::ResultCode_INVALID_ATTRIBUTE_SYNTAX] = "invalid attribute syntax",
    [ldap::ResultCode_NO_SUCH_OBJECT] = "no such object",
    [ldap::ResultCode_ALIAS_PROBLEM] = "alias problem",
    [ldap::ResultCode_INVALID_DNSYNTAX] = "invalid DN syntax",
    [ldap::ResultCode_ALIAS_DEREFERENCING_PROBLEM] = "alias dereferencing problem",
    [ldap::ResultCode_INAPPROPRIATE_AUTHENTICATION] = "inappropriate authentication",
    [ldap::ResultCode_INVALID_CREDENTIALS] = "invalid credentials",
    [ldap::ResultCode_INSUFFICIENT_ACCESS_RIGHTS] = "insufficient access rights",
    [ldap::ResultCode_BUSY] = "busy",
    [ldap::ResultCode_UNAVAILABLE] = "unavailable",
    [ldap::ResultCode_UNWILLING_TO_PERFORM] = "unwilling to perform",
    [ldap::ResultCode_LOOP_DETECT] = "loop detect",
    [ldap::ResultCode_SORT_CONTROL_MISSING] = "sort control missing",
    [ldap::ResultCode_OFFSET_RANGE_ERROR] = "offset range error",
    [ldap::ResultCode_NAMING_VIOLATION] = "naming violation",
    [ldap::ResultCode_OBJECT_CLASS_VIOLATION] = "object class violation",
    [ldap::ResultCode_NOT_ALLOWED_ON_NON_LEAF] = "not allowed on non-leaf",
    [ldap::ResultCode_NOT_ALLOWED_ON_RDN] = "not allowed on RDN",
    [ldap::ResultCode_ENTRY_ALREADY_EXISTS] = "entry already exists",
    [ldap::ResultCode_OBJECT_CLASS_MODS_PROHIBITED] = "object class mods prohibited",
    [ldap::ResultCode_RESULTS_TOO_LARGE] = "results too large",
    [ldap::ResultCode_AFFECTS_MULTIPLE_DSAS] = "affects multiple DSAs",
    [ldap::ResultCode_CONTROL_ERROR] = "control error",
    [ldap::ResultCode_OTHER] = "other",
    [ldap::ResultCode_SERVER_DOWN] = "server down",
    [ldap::ResultCode_LOCAL_ERROR] = "local error",
    [ldap::ResultCode_ENCODING_ERROR] = "encoding error",
    [ldap::ResultCode_DECODING_ERROR] = "decoding error",
    [ldap::ResultCode_TIMEOUT] = "timeout",
    [ldap::ResultCode_AUTH_UNKNOWN] = "auth unknown",
    [ldap::ResultCode_FILTER_ERROR] = "filter error",
    [ldap::ResultCode_USER_CANCELED] = "user canceled",
    [ldap::ResultCode_PARAM_ERROR] = "param error",
    [ldap::ResultCode_NO_MEMORY] = "no memory",
    [ldap::ResultCode_CONNECT_ERROR] = "connect error",
    [ldap::ResultCode_NOT_SUPPORTED] = "not supported",
    [ldap::ResultCode_CONTROL_NOT_FOUND] = "control not found",
    [ldap::ResultCode_NO_RESULTS_RETURNED] = "no results returned",
    [ldap::ResultCode_MORE_RESULTS_TO_RETURN] = "more results to return",
    [ldap::ResultCode_CLIENT_LOOP] = "client loop",
    [ldap::ResultCode_REFERRAL_LIMIT_EXCEEDED] = "referral limit exceeded",
    [ldap::ResultCode_INVALID_RESPONSE] = "invalid response",
    [ldap::ResultCode_AMBIGUOUS_RESPONSE] = "ambiguous response",
    [ldap::ResultCode_TLS_NOT_SUPPORTED] = "TLS not supported",
    [ldap::ResultCode_INTERMEDIATE_RESPONSE] = "intermediate response",
    [ldap::ResultCode_UNKNOWN_TYPE] = "unknown type",
    [ldap::ResultCode_LCUP_INVALID_DATA] = "LCUP invalid data",
    [ldap::ResultCode_LCUP_UNSUPPORTED_SCHEME] = "LCUP unsupported scheme",
    [ldap::ResultCode_LCUP_RELOAD_REQUIRED] = "LCUP reload required",
    [ldap::ResultCode_CANCELED] = "canceled",
    [ldap::ResultCode_NO_SUCH_OPERATION] = "no such operation",
    [ldap::ResultCode_TOO_LATE] = "too late",
    [ldap::ResultCode_CANNOT_CANCEL] = "cannot cancel",
    [ldap::ResultCode_ASSERTION_FAILED] = "assertion failed",
    [ldap::ResultCode_AUTHORIZATION_DENIED] = "authorization denied"
  } &default = "unknown";

  const SEARCH_SCOPES = {
    [ldap::SearchScope_SEARCH_BASE] = "base",
    [ldap::SearchScope_SEARCH_SINGLE] = "single",
    [ldap::SearchScope_SEARCH_TREE] = "tree",
  } &default = "unknown";

  const SEARCH_DEREF_ALIASES = {
    [ldap::SearchDerefAlias_DEREF_NEVER] = "never",
    [ldap::SearchDerefAlias_DEREF_IN_SEARCHING] = "searching",
    [ldap::SearchDerefAlias_DEREF_FINDING_BASE] = "finding",
    [ldap::SearchDerefAlias_DEREF_ALWAYS] = "always",
  } &default = "unknown";
}

#############################################################################
global OPCODES_FINISHED: set[ldap::ProtocolOpcode] = { ldap::ProtocolOpcode_BIND_RESPONSE,
                                                       ldap::ProtocolOpcode_UNBIND_REQUEST,
                                                       ldap::ProtocolOpcode_SEARCH_RESULT_DONE,
                                                       ldap::ProtocolOpcode_MODIFY_RESPONSE,
                                                       ldap::ProtocolOpcode_ADD_RESPONSE,
                                                       ldap::ProtocolOpcode_DEL_RESPONSE,
                                                       ldap::ProtocolOpcode_MOD_DN_RESPONSE,
                                                       ldap::ProtocolOpcode_COMPARE_RESPONSE,
                                                       ldap::ProtocolOpcode_ABANDON_REQUEST,
                                                       ldap::ProtocolOpcode_EXTENDED_RESPONSE };

global OPCODES_SEARCH: set[ldap::ProtocolOpcode] = { ldap::ProtocolOpcode_SEARCH_REQUEST,
                                                     ldap::ProtocolOpcode_SEARCH_RESULT_ENTRY,
                                                     ldap::ProtocolOpcode_SEARCH_RESULT_DONE,
                                                     ldap::ProtocolOpcode_SEARCH_RESULT_REFERENCE };

#############################################################################
redef record connection += {
  ldap_proto: string &optional;
  ldap_messages: table[int] of Message &optional;
  ldap_searches: table[int] of Search &optional;
};

#############################################################################
event zeek_init() &priority=5 {
  Log::create_stream(ldap::LDAP_LOG, [$columns=Message, $ev=log_ldap, $path="ldap"]);
  Log::create_stream(ldap::LDAP_SEARCH_LOG, [$columns=Search, $ev=log_ldap_search, $path="ldap_search"]);
}

#############################################################################
function set_session(c: connection, message_id: int, opcode: ldap::ProtocolOpcode) {

  if (! c?$ldap_messages )
    c$ldap_messages = table();

  if (! c?$ldap_searches )
    c$ldap_searches = table();

  if ((opcode in OPCODES_SEARCH) && (message_id !in c$ldap_searches)) {
    c$ldap_searches[message_id] = [$ts=network_time(),
                                   $uid=c$uid,
                                   $id=c$id,
                                   $message_id=message_id,
                                   $result_count=0];

  } else if ((opcode !in OPCODES_SEARCH) && (message_id !in c$ldap_messages)) {
    c$ldap_messages[message_id] = [$ts=network_time(),
                                   $uid=c$uid,
                                   $id=c$id,
                                   $message_id=message_id];
  }

}

#############################################################################
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {

  if ( atype == Analyzer::ANALYZER_SPICY_LDAP_TCP ) {
    c$ldap_proto = "tcp";
  }

}

#############################################################################
event ldap::message(c: connection,
                    message_id: int,
                    opcode: ldap::ProtocolOpcode,
                    result: ldap::ResultCode,
                    matched_dn: string,
                    diagnostic_message: string,
                    object: string,
                    argument: string) {

  if (opcode == ldap::ProtocolOpcode_SEARCH_RESULT_DONE) {
    set_session(c, message_id, opcode);

    if ( result != ldap::ResultCode_NOT_SET ) {
      if ( ! c$ldap_searches[message_id]?$result )
        c$ldap_searches[message_id]$result = set();
      add c$ldap_searches[message_id]$result[RESULT_CODES[result]];
    }

    if ( diagnostic_message != "" ) {
      if ( ! c$ldap_searches[message_id]?$diagnostic_message )
        c$ldap_searches[message_id]$diagnostic_message = vector();
      c$ldap_searches[message_id]$diagnostic_message += diagnostic_message;
    }

    if (( ! c$ldap_searches[message_id]?$proto ) && c?$ldap_proto)
      c$ldap_searches[message_id]$proto = c$ldap_proto;

    Log::write(ldap::LDAP_SEARCH_LOG, c$ldap_searches[message_id]);
    delete c$ldap_searches[message_id];

  } else if (opcode !in OPCODES_SEARCH) {
    set_session(c, message_id, opcode);

    if ( ! c$ldap_messages[message_id]?$opcode )
      c$ldap_messages[message_id]$opcode = set();
    add c$ldap_messages[message_id]$opcode[PROTOCOL_OPCODES[opcode]];

    if ( result != ldap::ResultCode_NOT_SET ) {
      if ( ! c$ldap_messages[message_id]?$result )
        c$ldap_messages[message_id]$result = set();
      add c$ldap_messages[message_id]$result[RESULT_CODES[result]];
    }

    if ( diagnostic_message != "" ) {
      if ( ! c$ldap_messages[message_id]?$diagnostic_message )
        c$ldap_messages[message_id]$diagnostic_message = vector();
      c$ldap_messages[message_id]$diagnostic_message += diagnostic_message;
    }

    if ( object != "" ) {
      if ( ! c$ldap_messages[message_id]?$object )
        c$ldap_messages[message_id]$object = vector();
      c$ldap_messages[message_id]$object += object;
    }

    if ( argument != "" ) {
      if ( ! c$ldap_messages[message_id]?$argument )
        c$ldap_messages[message_id]$argument = vector();
      c$ldap_messages[message_id]$argument += argument;
    }

    if (opcode in OPCODES_FINISHED) {

      if ((BIND_SIMPLE in c$ldap_messages[message_id]$opcode) ||
          (BIND_SASL in c$ldap_messages[message_id]$opcode)) {
        # don't have both "bind" and "bind <method>" in the operations list
        delete c$ldap_messages[message_id]$opcode[PROTOCOL_OPCODES[ldap::ProtocolOpcode_BIND_REQUEST]];
      }

      if (( ! c$ldap_messages[message_id]?$proto ) && c?$ldap_proto)
        c$ldap_messages[message_id]$proto = c$ldap_proto;

      Log::write(ldap::LDAP_LOG, c$ldap_messages[message_id]);
      delete c$ldap_messages[message_id];
    }
  }

}

#############################################################################
event ldap::searchreq(c: connection,
                      message_id: int,
                      base_object: string,
                      scope: ldap::SearchScope,
                      deref: ldap::SearchDerefAlias,
                      size_limit: int,
                      time_limit: int,
                      types_only: bool) {

  set_session(c, message_id, ldap::ProtocolOpcode_SEARCH_REQUEST);

  if ( scope != ldap::SearchScope_NOT_SET ) {
    if ( ! c$ldap_searches[message_id]?$scope )
      c$ldap_searches[message_id]$scope = set();
    add c$ldap_searches[message_id]$scope[SEARCH_SCOPES[scope]];
  }

  if ( deref != ldap::SearchDerefAlias_NOT_SET ) {
    if ( ! c$ldap_searches[message_id]?$deref )
      c$ldap_searches[message_id]$deref = set();
    add c$ldap_searches[message_id]$deref[SEARCH_DEREF_ALIASES[deref]];
  }

  if ( base_object != "" ) {
    if ( ! c$ldap_searches[message_id]?$base_object )
      c$ldap_searches[message_id]$base_object = vector();
    c$ldap_searches[message_id]$base_object += base_object;
  }

}

#############################################################################
event ldap::searchres(c: connection,
                      message_id: int,
                      object_name: string) {

  set_session(c, message_id, ldap::ProtocolOpcode_SEARCH_RESULT_ENTRY);

  c$ldap_searches[message_id]$result_count += 1;
}

#############################################################################
event ldap::bindreq(c: connection,
                    message_id: int,
                    version: int,
                    name: string,
                    authType: ldap::BindAuthType,
                    authInfo: string) {

  set_session(c, message_id, ldap::ProtocolOpcode_BIND_REQUEST);

  if ( ! c$ldap_messages[message_id]?$version )
    c$ldap_messages[message_id]$version = version;

  if ( ! c$ldap_messages[message_id]?$opcode )
    c$ldap_messages[message_id]$opcode = set();

  if (authType == ldap::BindAuthType_BIND_AUTH_SIMPLE) {
    add c$ldap_messages[message_id]$opcode[BIND_SIMPLE];
  } else if (authType == ldap::BindAuthType_BIND_AUTH_SASL) {
    add c$ldap_messages[message_id]$opcode[BIND_SASL];
  }

}

#############################################################################
event connection_state_remove(c: connection) {

  # log any "pending" unlogged LDAP messages/searches

  if ( c?$ldap_messages && (|c$ldap_messages| > 0) ) {
    for ( [mid], m in c$ldap_messages ) {
      if (mid > 0) {

        if ((BIND_SIMPLE in m$opcode) || (BIND_SASL in m$opcode)) {
          # don't have both "bind" and "bind <method>" in the operations list
          delete m$opcode[PROTOCOL_OPCODES[ldap::ProtocolOpcode_BIND_REQUEST]];
        }

        if (( ! m?$proto ) && c?$ldap_proto)
          m$proto = c$ldap_proto;

        Log::write(ldap::LDAP_LOG, m);
      }
    }
    delete c$ldap_messages;
  }

  if ( c?$ldap_searches && (|c$ldap_searches| > 0) ) {
    for ( [mid], s in c$ldap_searches ) {
      if (mid > 0) {

        if (( ! s?$proto ) && c?$ldap_proto)
          s$proto = c$ldap_proto;

        Log::write(ldap::LDAP_SEARCH_LOG, s);
      }
    }
    delete c$ldap_searches;
  }

}
