%%  -*- erlang-mode -*-
%%  Copyright Avassa Systems AB
%%
%%  The contents of this file is subject to copyright and may only be used
%%  in accordance with the license received together with this file.
%%
%%  File:    parsec.erl
%%  Author:  Johan Bevemyr
%%  Created: Sat Sep  9 17:23:11 2023
%%  Purpose: Interface with a parsec server to access TPM and other
%%           crypto hardware.

-module('parsec').
-author('jb@avassa.io').

-export([init/0,
         init/1,
         create_rsa_key/3,
         create_ecc_key/3,
         destroy_key/2,
         list_providers/1,
         list_keys/1,
         list_opcodes/2,
         asymmetric_encrypt/3,
         asymmetric_decrypt/3,
         ping/1]).

-export([test/1]).

%% internal

-export([send_request/3,
         response_decode/2,
         request_encode/5,
         request_decode_body/2]).

-define(AUTH_NONE, 0).
-define(AUTH_DIRECT, 1).
-define(AUTH_TOKEN, 2).
-define(AUTH_UID, 3).
-define(AUTH_JWT, 4).

-include("parsec.hrl").

-record(parsec,
        { service_endpoint,
          providers,
          auth_type,
          auth_bin,
          session_handle
        }).

-type opts() ::
        #{ service_endpoint => binary(),
           auth             => none | uid | token | jwt | direct,
           uid              => non_neg_integer(),
           token            => binary(),
           jwt              => binary(),
           direct           => binary()
         }.

-spec init(Opts::opts()) -> #parsec{} | {error, term()}.

init() ->
    init(#{}).

init(Opts) ->
    %% service_endpoint
    Service_Endpoint0 =
        case os:getenv("PARSEC_SERVICE_ENDPOINT") of
            false ->
                <<"/run/parsec/parsec.sock">>;
            "unix:"++PSE ->
                ?l2b(PSE);
            PSE ->
                ?l2b(PSE)
        end,
    Service_Endpoint = maps:get(service_endpoint, Opts, Service_Endpoint0),
    S0 = #parsec{service_endpoint = Service_Endpoint},
    %% auth
    {AuthType, AuthBin} =
        case maps:get(auth, Opts, uid) of
            none ->
                {?AUTH_NONE, <<"">>};
            uid ->
                UID0 = get_uid(),
                UID = maps:get(uid, Opts, UID0),
                {?AUTH_UID, <<UID:4/little-unsigned-integer-unit:8>>};
            token ->
                {?AUTH_TOKEN, maps:get(token, Opts, <<"">>)};
            jwt ->
                {?AUTH_JWT, maps:get(jwt, Opts, <<"">>)};
            direct ->
                {?AUTH_DIRECT, maps:get(direct, Opts, <<"">>)}
        end,
    S1 = S0#parsec{ auth_bin = AuthBin, auth_type = AuthType },
    %% Session Handle
    S2 = S1#parsec{ session_handle = rand:uniform(1 bsl 31) },
    %% probe parsec service
    case list_providers(S2) of
        {ok, #{providers := Providers}} ->
            F = fun(P = #{id := Id}) ->
                        {ok, #{opcodes := OpCodes}} = list_opcodes(S2, Id),
                        P#{opcodes => OpCodes}
                end,
            Providers2 = [F(P) || P <- Providers],
            S2#parsec{ providers = Providers2 };
        _Error->
            {error, "failed to read providers"}
    end.

get_uid() ->
    UidStr = os:cmd("/usr/bin/id -u"),
    Digits = lists:takewhile(fun(C) -> C >= $0 andalso C =< $9 end, UidStr),
    ?l2i([$0|Digits]).

destroy_key(S, Name) ->
    case list_keys(S) of
        {ok, #{keys := Keys}} ->
            case find_key(Keys, Name) of
                not_found ->
                    {error, not_found};
                #{provider_id := Provider} ->
                    send_request(S, Provider, {psa_destroy_key,
                                               #{key_name => Name}})
            end;
        Error ->
            Error
    end.

find_key([], _Name) ->
    not_found;
find_key([K|Ks], Name) ->
    case maps:get(name, K, undefined) of
        Name ->
            K;
        _ ->
            find_key(Ks, Name)
    end.

create_rsa_key(S, Name, Opts) ->
    case get_crypto_provider(S, psa_generate_key) of
        not_found ->
            {error, operation_not_supported};
        Provider ->
            Bits = maps:get(bits, Opts, 2048),
            Params =
                #{key_name => Name,
                  attributes =>
                      #{key_bits => Bits,
                        key_type => #{variant => {rsa_key_pair, #{}}},
                        key_policy =>
                            #{key_algorithm =>
                                  #{variant =>
                                        {asymmetric_encryption,
                                         #{variant => {rsa_pkcs1v15_crypt,#{}}}
                                        }},
                              key_usage_flags =>
                                  #{cache => false,
                                    copy => false,
                                    decrypt => true,
                                    derive => false,
                                    encrypt => true,
                                    export => false,
                                    sign_hash => false,
                                    sign_message => false,
                                    verify_hash => false,
                                    verify_message => false
                                   }}}},
            send_request(S, Provider, {psa_generate_key, Params})
    end.

create_ecc_key(S, Name, Opts) ->
    case get_crypto_provider(S, psa_generate_key) of
        not_found ->
            {error, operation_not_supported};
        Provider ->
            Bits = maps:get(bits, Opts, 256),
            Params =
                #{key_name => Name,
                  attributes =>
                      #{key_bits => Bits,
                        key_type => #{variant =>
                                          {ecc_key_pair,
                                           #{curve_family => 'SECP_R1'}}},
                        key_policy =>
                            #{key_algorithm =>
                                  #{variant =>
                                        {asymmetric_signature,
                                         #{variant =>
                                               {ecdsa,
                                                #{hash_alg =>
                                                      #{variant =>
                                                            {specific,
                                                             'SHA_256'}}}}}}},
                              key_usage_flags =>
                                  #{cache => false,
                                    copy => false,
                                    decrypt => false,
                                    derive => false,
                                    encrypt => false,
                                    export => false,
                                    sign_hash => true,
                                    sign_message => true,
                                    verify_hash => true,
                                    verify_message => true}}}},
            send_request(S, Provider, {psa_generate_key, Params})
    end.

list_opcodes(S, Provider) ->
    send_request(S, 0, {list_opcodes, #{provider_id => Provider}}).

list_providers(S) ->
    Provider = 0,
    send_request(S, Provider, {list_providers, #{}}).

list_keys(S) ->
    Provider = 0,
    send_request(S, Provider, {list_keys, #{}}).

ping(S) ->
    Provider = 0,
    send_request(S, Provider, {ping, #{}}).

asymmetric_encrypt(S, Key, Plaintext) ->
    case get_crypto_provider(S, psa_asymmetric_encrypt) of
        not_found ->
            {error, operation_not_supported};
        Provider ->
            send_request(S, Provider,
                         {psa_asymmetric_encrypt,
                          #{key_name => Key,
                            alg => #{variant => {rsa_pkcs1v15_crypt, #{}}},
                            plaintext => Plaintext}})
    end.

asymmetric_decrypt(S, Key, Ciphertext) ->
    case get_crypto_provider(S, psa_asymmetric_decrypt) of
        not_found ->
            {error, operation_not_supported};
        Provider ->
            send_request(S, Provider,
                         {psa_asymmetric_decrypt,
                          #{key_name => Key,
                            alg => #{variant => {rsa_pkcs1v15_crypt, #{}}},
                            ciphertext => Ciphertext}})
    end.

get_crypto_provider(S, Op) ->
    Providers = S#parsec.providers,
    OpCode = op2opcode(Op),
    find_provider(OpCode, Providers).

find_provider(_OpCode, []) ->
    not_found;
find_provider(OpCode, [P|Ps]) ->
    OpCodes = maps:get(opcodes, P, []),
    case lists:member(OpCode, OpCodes) of
        true ->
            maps:get(id, P);
        false ->
            find_provider(OpCode, Ps)
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%

op2opcode('ping') -> 16#0001;
op2opcode('psa_generate_key') -> 16#0002;
op2opcode('psa_destroy_key') ->  16#0003;
op2opcode('psa_sign_hash') -> 16#0004;
op2opcode('psa_verify_hash') -> 16#0005;
op2opcode('psa_import_key') -> 16#0006;
op2opcode('psa_export_public_key') -> 16#0007;
op2opcode('list_providers') -> 16#0008;
op2opcode('list_opcodes') -> 16#0009;
op2opcode('psa_asymmetric_encrypt') -> 16#000a;
op2opcode('psa_asymmetric_decrypt') -> 16#000b;
op2opcode('psa_export_key') -> 16#000c;
op2opcode('psa_generate_random') -> 16#000d;
op2opcode('list_authenticators') -> 16#000e;
op2opcode('psa_hash_compute') -> 16#000f;
op2opcode('psa_hash_compare') -> 16#0010;
op2opcode('psa_aead_encrypt') -> 16#0011;
op2opcode('psa_aead_decrypt') -> 16#0012;
op2opcode('psa_raw_key_agreement') -> 16#0013;
op2opcode('psa_cipher_encrypt') -> 16#0014;
op2opcode('psa_cipher_decrypt') -> 16#0015;
op2opcode('psa_mac_compute') -> 16#0016;
op2opcode('psa_mac_verify') -> 16#0017;
op2opcode('psa_sign_message') -> 16#0018;
op2opcode('psa_verify_message') -> 16#0019;
op2opcode('list_keys') -> 16#001a;
op2opcode('list_clients') -> 16#001b;
op2opcode('delete_client') -> 16#001c;
op2opcode('attest_key') -> 16#001e;
op2opcode('prepare_key_attestation') -> 16#001f;
op2opcode('can_do_crypto') -> 16#0020;
op2opcode(Unknown) ->
    ?liof("unknown op: ~p\n", [Unknown]),
    16#0000.

opcode2op(16#0001) -> 'ping';
opcode2op(16#0002) -> 'psa_generate_key';
opcode2op(16#0003) -> 'psa_destroy_key';
opcode2op(16#0004) -> 'psa_sign_hash';
opcode2op(16#0005) -> 'psa_verify_hash';
opcode2op(16#0006) -> 'psa_import_key';
opcode2op(16#0007) -> 'psa_export_public_key';
opcode2op(16#0008) -> 'list_providers';
opcode2op(16#0009) -> 'list_opcodes';
opcode2op(16#000a) -> 'psa_asymmetric_encrypt';
opcode2op(16#000b) -> 'psa_asymmetric_decrypt';
opcode2op(16#000c) -> 'psa_export_key';
opcode2op(16#000d) -> 'psa_generate_random';
opcode2op(16#000e) -> 'list_authenticators';
opcode2op(16#000f) -> 'psa_hash_compute';
opcode2op(16#0010) -> 'psa_hash_compare';
opcode2op(16#0011) -> 'psa_aead_encrypt';
opcode2op(16#0012) -> 'psa_aead_decrypt';
opcode2op(16#0013) -> 'psa_raw_key_agreement';
opcode2op(16#0014) -> 'psa_cipher_encrypt';
opcode2op(16#0015) -> 'psa_cipher_decrypt';
opcode2op(16#0016) -> 'psa_mac_compute';
opcode2op(16#0017) -> 'psa_mac_verify';
opcode2op(16#0018) -> 'psa_sign_message';
opcode2op(16#0019) -> 'psa_verify_message';
opcode2op(16#001a) -> 'list_keys';
opcode2op(16#001b) -> 'list_clients';
opcode2op(16#001c) -> 'delete_client';
opcode2op(16#001e) -> 'attest_key';
opcode2op(16#001f) -> 'prepare_key_attestation';
opcode2op(16#0020) -> 'can_do_crypto';
opcode2op(Unknown) ->
    ?liof_bt("unknown code: ~p\n", [Unknown]),
    'undefined'.

status_codes() ->
    #{
      0 => {"success", "success"},
      1 => {"WrongProviderID",
            "Requested provider ID does not match that of the backend"},
      2 => {"ContentTypeNotSupported",
            "Requested content type is not supported by the backend"},
      3 => {"AcceptTypeNotSupported",
            "Requested accept type is not supported by the backend"},
      4 => {"WireProtocolVersionNotSupported",
            "Requested version is not supported by the backend"},
      5 => {"ProviderNotRegistered",
            "No provider registered for the requested provider ID"},
      6 => {"ProviderDoesNotExist",
            "No provider defined for requested provider ID"},
      7 => {"DeserializingBodyFailed",
            "Failed to deserialize the body of the message"},
      8 => {"SerializingBodyFailed",
            "Failed to serialize the body of the message"},
      9 => {"OpcodeDoesNotExist",
            "Requested operation is not defined"},
      10 => {"ResponseTooLarge",
             "Response size exceeds allowed limits"},
      11 => {"AuthenticationError",
             "Authentication failed"},
      12 => {"AuthenticatorDoesNotExist",
             "Authenticator not supported"},
      13 => {"AuthenticatorNotRegistered",
             "Authenticator not supported"},
      14 => {"KeyInfoManagerError",
             "Internal error in the Key Info Manager"},
      15 => {"ConnectionError",
             "Generic input/output error"},
      16 => {"InvalidEncoding",
             "Invalid value for this data type"},
      17 => {"InvalidHeader",
             "Constant fields in header are invalid"},
      18 => {"WrongProviderUuid",
             "The UUID vector needs to only contain 16 bytes"},
      19 => {"NotAuthenticated",
             "Request did not provide a required authentication"},
      20 => {"BodySizeExceedsLimit",
             "Request length specified in the header is above defined limit"},
      21 => {"AdminOperation",
             "The operation requires admin privilege"},
      1132 => {"PsaErrorGenericError",
               "An error occurred that does not correspond to any defined "
               "failure cause"},
      1133 => {"PsaErrorNotPermitted",
               "The requested action is denied by a policy"},
      1134 => {"PsaErrorNotSupported",
               "The requested operation or a parameter is not supported by "
               "this implementation"},
      1135 => {"PsaErrorInvalidArgument",
               "The parameters passed to the function are invalid"},
      1136 => {"PsaErrorInvalidHandle",
               "The key handle is not valid"},
      1137 => {"PsaErrorBadState",
               "The requested action cannot be performed in the current state"},
      1138 => {"PsaErrorBufferTooSmall",
               "An output buffer is too small"},
      1139 => {"PsaErrorAlreadyExists",
               "Asking for an item that already exists"},
      1140 => {"PsaErrorDoesNotExist",
               "Asking for an item that doesn't exist"},
      1141 => {"PsaErrorInsufficientMemory",
               "There is not enough runtime memory"},
      1142 => {"PsaErrorInsufficientStorage",
               "There is not enough persistent storage available"},
      1143 => {"PsaErrorInssuficientData",
               "Insufficient data when attempting to read from a resource"},
      1145 => {"PsaErrorCommunicationFailure",
               "There was a communication failure inside the implementation"},
      1146 => {"PsaErrorStorageFailure",
               "There was a storage failure that may have led to data loss"},
      1147 => {"PsaErrorHardwareFailure",
               "A hardware failure was detected"},
      1148 => {"PsaErrorInsufficientEntropy",
               "There is not enough entropy to generate random data needed "
               "for the requested action"},
      1149 => {"PsaErrorInvalidSignature",
               "The signature, MAC or hash is incorrect"},
      1150 => {"PsaErrorInvalidPadding",
               "The decrypted padding is incorrect"},
      1151 => {"PsaErrorCorruptionDetected",
               "A tampering attempt was detected"},
      1152 => {"PsaErrorDataCorrupt",
               "Stored data has been corrupted"}
     }.

init_header(SessionH, Provider, AuthType, ContentLength, AuthLength, OpCode,
            Status) ->
    Magic = 16#5ec0a710,
    MajorVersion = 16#01,
    MinorVersion = 16#00,
    Flags = 16#0000,
    ContentType = 16#00,
    AcceptType = 16#00,
    Reserved = 16#00,
    #{ magic => Magic,
       header_size => 30,
       major_version => MajorVersion,
       minor_version => MinorVersion,
       flags => Flags,
       provider => Provider,
       session_handle => SessionH,
       content_type => ContentType,
       accept_type => AcceptType,
       auth_type => AuthType,
       content_length => ContentLength,
       auth_length => AuthLength,
       opcode => OpCode,
       status => Status,
       reserved => Reserved }.

header_decode(<<Magic:4/little-unsigned-integer-unit:8,
                HeaderSize:2/little-unsigned-integer-unit:8,
                MajorVersion:1/little-unsigned-integer-unit:8,
                MinorVersion:1/little-unsigned-integer-unit:8,
                Flags:2/little-unsigned-integer-unit:8,
                Provider:1/little-unsigned-integer-unit:8,
                SessionHandle:8/little-unsigned-integer-unit:8,
                ContentType:1/little-unsigned-integer-unit:8,
                AcceptType:1/little-unsigned-integer-unit:8,
                AuthType:1/little-unsigned-integer-unit:8,
                ContentLength:4/little-unsigned-integer-unit:8,
                AuthLength:2/little-unsigned-integer-unit:8,
                OpCode:4/little-unsigned-integer-unit:8,
                Status:2/little-unsigned-integer-unit:8,
                Reserved:2/little-unsigned-integer-unit:8,
                Rest/binary>>)
  when Magic == 16#5ec0a710,
       MajorVersion == 16#01,
       MinorVersion == 16#00,
       Flags == 16#0000,
       ContentType == 16#00,
       AcceptType == 16#00,
       Reserved == 16#00 ->
    Header = #{ magic => Magic,
                header_size => HeaderSize,
                major_version => MajorVersion,
                minor_version => MinorVersion,
                flags => Flags,
                provider => Provider,
                session_handle => SessionHandle,
                content_type => ContentType,
                accept_type => AcceptType, %% Request only
                auth_type => AuthType, %% Request only
                content_length => ContentLength,
                auth_length => AuthLength, %% Request only
                opcode => OpCode,
                status => Status, %% Response only
                reserved => Reserved },
    {ok, Header, Rest}.

header_encode(#{ magic := Magic,
                 header_size := HeaderSize,
                 major_version := MajorVersion,
                 minor_version := MinorVersion,
                 flags := Flags,
                 provider := Provider,
                 session_handle := SessionHandle,
                 content_type := ContentType,
                 accept_type := AcceptType, %% Request only
                 auth_type := AuthType, %% Request only
                 content_length := ContentLength,
                 auth_length := AuthLength, %% Request only
                 opcode := OpCode,
                 status := Status, %% Response only
                 reserved := Reserved })
  when Magic == 16#5ec0a710,
       MajorVersion == 16#01,
       MinorVersion == 16#00,
       Flags == 16#0000,
       ContentType == 16#00,
       AcceptType == 16#00,
       Reserved == 16#00 ->
    <<Magic:4/little-unsigned-integer-unit:8,
      HeaderSize:2/little-unsigned-integer-unit:8,
      MajorVersion:1/little-unsigned-integer-unit:8,
      MinorVersion:1/little-unsigned-integer-unit:8,
      Flags:2/little-unsigned-integer-unit:8,
      Provider:1/little-unsigned-integer-unit:8,
      SessionHandle:8/little-unsigned-integer-unit:8,
      ContentType:1/little-unsigned-integer-unit:8,
      AcceptType:1/little-unsigned-integer-unit:8,
      AuthType:1/little-unsigned-integer-unit:8,
      ContentLength:4/little-unsigned-integer-unit:8,
      AuthLength:2/little-unsigned-integer-unit:8,
      OpCode:4/little-unsigned-integer-unit:8,
      Status:2/little-unsigned-integer-unit:8,
      Reserved:2/little-unsigned-integer-unit:8>>.

response_decode_header(All = <<16#5ec0a710:4/little-unsigned-integer-unit:8,
                               HeaderSize:2/little-unsigned-integer-unit:8,
                               Data/binary>>) ->
    if size(Data) >= HeaderSize ->
            header_decode(All);
       true ->
            {more, HeaderSize-size(Data)}
    end;
response_decode_header(Data) ->
    {more, 6 - size(Data)}.

response_decode_body(Data, Header) ->
    #{ content_length := ContentLength,
       opcode := Opcode } = Header,
    if size(Data) >= ContentLength ->
            <<ResponseBin:ContentLength/binary, Rest/binary>> = Data,
            Response = response_decode_op(Opcode, ResponseBin),
            {ok, Response, Rest};
       true ->
            {more, ContentLength - size(Data)}
    end.

response_decode(Data, ReadF) ->
    case response_decode_header(Data) of
        {ok, Header, Rest1} ->
            Status = maps:get(status, Header),
            case response_decode_body(Rest1, Header) of
                {ok, Response, Rest2} when Status == 0 ->
                    {ok, Response, Rest2};
                {ok, _Response, _Rest2} ->
                    {error, status_message(Status)};
                {more, RestSize} ->
                    response_decode_body(ReadF(RestSize), Header, Rest1, ReadF)
            end;
        {more, RestSize} ->
            response_decode(ReadF(RestSize), Data, ReadF)
    end.

status_message(Status) ->
    case maps:get(Status, status_codes(), undefined) of
        undefined ->
            "unknown status";
        {_, Desc} ->
            Desc
    end.

response_decode(eof, _Data, _ReadF) ->
    {error, not_enough_data};
response_decode({error, Reason}, _Data, _ReadF) ->
    {error, Reason};
response_decode(NewData, OldData, ReadF) ->
    response_decode(<<OldData/binary, NewData/binary>>, ReadF).

response_decode_body(eof, _Header, _Data, _ReadF) ->
    {error, not_enough_data};
response_decode_body({error, Reason}, _Header, _Data, _ReadF) ->
    {error, Reason};
response_decode_body(NewData, Header, OldData, ReadF) ->
    Data = <<OldData/binary, NewData/binary>>,
    case response_decode_body(Data, Header) of
        {ok, Response, Rest} ->
            {ok, Response, Rest};
        {more, RestSize} ->
            response_decode_body(ReadF(RestSize), Header, Data, ReadF)
    end.

response_decode_op(Code, Data) ->
    OpM = opcode2op(Code),
    (catch OpM:decode_msg(Data, mk_result(OpM))).

request_encode(Request, AuthType, AuthBin, SessionH, Provider) ->
    {ok, Op, RequestBin} = request_encode_body(Request),
    Header = init_header(SessionH, Provider, AuthType, size(RequestBin),
                         size(AuthBin), op2opcode(Op), 0),
    HeaderBin = header_encode(Header),
    <<HeaderBin/binary, RequestBin/binary, AuthBin/binary>>.

request_encode_body({Op, Body}) ->
    case Op:encode_msg(Body, mk_operation(Op)) of
        Msg when is_binary(Msg) ->
            {ok, Op, Msg};
        Error ->
            Error
    end.

request_decode_body(Data, Header) ->
    #{ opcode := Op } = Header,
    OpM = opcode2op(Op),
    Response = OpM:decode_msg(Data, mk_operation(OpM)),
    {ok, Response}.

mk_operation(Op) ->
    ?b2a(?io2b([?a2l(Op), ".Operation"])).

mk_result(Op) ->
    ?b2a(?io2b([?a2l(Op), ".Result"])).

send_request(S, Provider, Request) ->
    SocketFile = S#parsec.service_endpoint,
    AuthBin = S#parsec.auth_bin,
    AuthType = S#parsec.auth_type,
    SessionH = S#parsec.session_handle,
    RequestBin = request_encode(Request, AuthType, AuthBin, SessionH, Provider),
    case gen_tcp:connect({local, SocketFile}, 0, [binary, {active, once}]) of
        {ok, Socket} ->
            try
                _ = gen_tcp:send(Socket, RequestBin),
                ReadF =
                    fun(_RestSize) ->
                            receive
                                {tcp, Socket, Data} ->
                                    _ = inet:setopts(Socket, [{active, once}]),
                                    Data;
                                {tcp_closed, Socket} ->
                                    eof
                            end
                    end,
                case response_decode(<<"">>, ReadF) of
                    {ok, Res, _} ->
                        {ok, Res};
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                gen_tcp:close(Socket)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%

test(Opts) ->
    S = init(Opts),
    ?liof("init\n", []),
    {ok, #{}} = create_rsa_key(S, <<"rsa">>, #{}),
    ?liof("create key\n", []),
    {ok, #{keys := Keys}} = list_keys(S),
    [_|_] = lists:filter(fun(#{name := <<"rsa">>}) ->
                                 true;
                            (_) ->
                                 false
                         end, Keys),
    ?liof("list keys\n", []),
    Plaintext = <<"The quick brown fox">>,
    {ok, #{ciphertext := Ciphertext}} = asymmetric_encrypt(S, <<"rsa">>,
                                                           Plaintext),
    ?liof("encrypt\n", []),
    {ok, #{plaintext := Plaintext}} = asymmetric_decrypt(S, <<"rsa">>,
                                                         Ciphertext),
    ?liof("decrypt\n", []),
    {ok, #{}} = destroy_key(S, <<"rsa">>),
    {ok, #{keys := NewKeys}} = list_keys(S),
    [] = lists:filter(fun(#{name := <<"rsa">>}) ->
                                 true;
                            (_) ->
                                 false
                         end, NewKeys),
    ?liof("destoy key\n", []),
    ok.

%%
