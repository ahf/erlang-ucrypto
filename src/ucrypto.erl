%%%
%%% Copyright (c) 2012, 2013 Alexander Færøy.
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%
%%% * Redistributions of source code must retain the above copyright notice, this
%%%   list of conditions and the following disclaimer.
%%%
%%% * Redistributions in binary form must reproduce the above copyright notice,
%%%   this list of conditions and the following disclaimer in the documentation
%%%   and/or other materials provided with the distribution.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
%%% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
%%% WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
%%% DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
%%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
%%% SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
%%% OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
%%% OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%%
%%% ----------------------------------------------------------------------------
%%% @author     Alexander Færøy <ahf@0x90.dk>
%%% @copyright  2012, 2013 Alexander Færøy
%%% @end
%%% ----------------------------------------------------------------------------
%%% @doc uCrypto.
%%% This module contains the public API for the uCrypto library.
%%% @end
%%% ----------------------------------------------------------------------------
-module(ucrypto).
-export([ripemd160/1, ripemd160_init/0, ripemd160_update/2, ripemd160_final/1]).
-export([ec_new_key/1, ec_new_key/3, ec_new_private_key/2, ec_new_public_key/2,
        ec_verify/3, ec_verify/4, ec_verify_hash/4, ec_verify_hash/5,
        ec_sign/2, ec_sign/3, ec_sign_hash/3, ec_sign_hash/4, ec_public_key/1,
        ec_set_public_key/2, ec_private_key/1, ec_set_private_key/2,
        ec_delete_key/1, ec_curve_size/1]).
-export([hex2bin/1, bin2hex/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-on_load(init/0).

%%
%% NIF's.
%%
-define(nif_stub, nif_stub_error(?LINE)).

nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, Line}).

%%
%% Init.
%%
-spec init() -> ok | {error, any()}.
init() ->
    File = case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            case code:which(?MODULE) of
                DirectoryName when is_list(DirectoryName) ->
                    filename:join([filename:dirname(DirectoryName), "../priv", "ucrypto"]);
                _Otherwise ->
                    filename:join("../priv", "ucrypto")
            end;
        Directory ->
            filename:join(Directory, "ucrypto")
    end,
    erlang:load_nif(File, 0).

%%
%% RIPEMD160.
%%
-spec ripemd160(iodata()) -> binary().
ripemd160(Data) ->
    ripemd160_nif(Data).

-spec ripemd160_init() -> binary().
ripemd160_init() ->
    ripemd160_init_nif().

-spec ripemd160_update(binary(), iodata()) -> binary().
ripemd160_update(Context, Data) ->
    ripemd160_update_nif(Context, Data).

-spec ripemd160_final(binary()) -> binary().
ripemd160_final(Context) ->
    ripemd160_final_nif(Context).

ripemd160_nif(_Data) ->
    ?nif_stub.

ripemd160_init_nif() ->
    ?nif_stub.

ripemd160_update_nif(_Context, _Data) ->
    ?nif_stub.

ripemd160_final_nif(_Context) ->
    ?nif_stub.

%%
%% EC.
%%
-type ec_key() :: ucrypto_types:ec_key().
-type ec_signature() :: ucrypto_types:ec_signature().
-type ec_public_key() :: ucrypto_types:ec_public_key().
-type ec_private_key() :: ucrypto_types:ec_private_key().
-type ec_hash_function() :: ucrypto_types:ec_hash_function().
-type ec_curve() :: ucrypto_types:ec_curve().

-spec ec_new_key(ec_curve()) -> ec_key() | {error, any()}.
ec_new_key(Curve) when is_atom(Curve) ->
    case ec_new_by_curve_nif(Curve) of
        KeyRef when is_binary(KeyRef) ->
            case ec_generate_key_nif(KeyRef) of
                ok ->
                    {ec_key, KeyRef};
                Error ->
                    Error
            end;
        error ->
            {error, unable_to_create_key};
        Error ->
            Error
    end.

-spec ec_new_key(ec_curve(), ec_private_key(), ec_public_key()) -> ec_key() | {error, any()}.
ec_new_key(Curve, PrivateKey, PublicKey) when is_atom(Curve), is_binary(PrivateKey), is_binary(PublicKey) ->
    case ec_new_by_curve_nif(Curve) of
        KeyRef when is_binary(KeyRef) ->
            case ec_set_private_key({ec_key, KeyRef}, PrivateKey) of
                {ec_key, KeyRef} ->
                    ec_set_public_key({ec_key, KeyRef}, PublicKey);
                Error ->
                    Error
            end;
        error ->
            {error, unable_to_create_key}
    end.

-spec ec_new_private_key(ec_curve(), ec_private_key()) -> ec_key() | {error, any()}.
ec_new_private_key(Curve, PrivateKey) when is_atom(Curve), is_binary(PrivateKey) ->
    case ec_new_by_curve_nif(Curve) of
        KeyRef when is_binary(KeyRef) ->
            ec_set_private_key({ec_key, KeyRef}, PrivateKey);
        error ->
            {error, unable_to_create_key}
    end.

-spec ec_new_public_key(ec_curve(), ec_public_key()) -> ec_key() | {error, any()}.
ec_new_public_key(Curve, PublicKey) when is_atom(Curve), is_binary(PublicKey) ->
    case ec_new_by_curve_nif(Curve) of
        KeyRef when is_binary(KeyRef) ->
            ec_set_public_key({ec_key, KeyRef}, PublicKey);
        error ->
            {error, unable_to_create_key}
    end.

-spec ec_verify(iodata(), ec_signature(), ec_key()) -> boolean() | {error, any()}.
ec_verify(Data, Signature, {ec_key, KeyRef}) ->
    ec_verify_nif(KeyRef, Data, Signature).

-spec ec_verify(iodata(), ec_signature(), ec_curve(), ec_public_key()) -> boolean() | {error, any()}.
ec_verify(Data, Signature, Curve, PublicKey) when is_atom(Curve), is_binary(PublicKey) ->
    case ec_new_public_key(Curve, PublicKey) of
        {ec_key, KeyRef} ->
            case ec_verify(Data, Signature, {ec_key, KeyRef}) of
                Result when is_boolean(Result) ->
                    ec_delete_key({ec_key, KeyRef}),
                    Result;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec ec_verify_hash(iodata(), ec_hash_function(), ec_signature(), ec_key()) -> boolean() | {error, any()}.
ec_verify_hash(Data, Hash, Signature, Key) ->
    ec_verify(Hash(Data), Signature, Key).

-spec ec_verify_hash(iodata(), ec_hash_function(), ec_signature(), ec_curve(), ec_public_key()) -> boolean() | {error, any()}.
ec_verify_hash(Data, Hash, Signature, Curve, PublicKey) ->
    ec_verify(Hash(Data), Signature, Curve, PublicKey).

-spec ec_sign(iodata(), ec_key()) -> ec_signature() | {error, any()}.
ec_sign(Data, {ec_key, KeyRef}) ->
    case ec_sign_nif(KeyRef, Data) of
        Signature when is_binary(Signature) ->
            Signature;
        error ->
            {error, unable_to_sign_data};
        Error ->
            Error
    end.

-spec ec_sign(iodata(), ec_curve(), ec_private_key()) -> ec_signature() | {error, any()}.
ec_sign(Data, Curve, PrivateKey) when is_atom(Curve), is_binary(PrivateKey) ->
    case ec_new_private_key(Curve, PrivateKey) of
        {ec_key, KeyRef} ->
            case ec_sign(Data, {ec_key, KeyRef}) of
                Result when is_binary(Result) ->
                    ec_delete_key({ec_key, KeyRef}),
                    Result;
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec ec_sign_hash(iodata(), ec_hash_function(), ec_key()) -> ec_signature() | {error, any()}.
ec_sign_hash(Data, Hash, Key) ->
    ec_sign(Hash(Data), Key).

-spec ec_sign_hash(iodata(), ec_hash_function(), ec_curve(), ec_private_key()) -> ec_signature() | {error, any()}.
ec_sign_hash(Data, Hash, Curve, PrivateKey) ->
    ec_sign(Hash(Data), Curve, PrivateKey).

-spec ec_public_key(ec_key()) -> ec_public_key() | {error, any()}.
ec_public_key({ec_key, KeyRef}) ->
    case ec_get_public_key_nif(KeyRef) of
        PublicKey when is_binary(PublicKey) ->
            PublicKey;
        error ->
            {error, unable_to_read_public_key};
        Error ->
            Error
    end.

-spec ec_set_public_key(ec_key(), ec_public_key()) -> ec_key() | {error, any()}.
ec_set_public_key({ec_key, KeyRef}, PublicKey) when is_binary(PublicKey) ->
    case ec_set_public_key_nif(KeyRef, PublicKey) of
        ok ->
            {ec_key, KeyRef};
        error ->
            {error, unable_to_set_public_key};
        Error ->
            Error
    end.

-spec ec_private_key(ec_key()) -> ec_private_key() | {error, any()}.
ec_private_key({ec_key, KeyRef}) ->
    case ec_get_private_key_nif(KeyRef) of
        PrivateKey when is_binary(PrivateKey) ->
            PrivateKey;
        error ->
            {error, unable_to_read_private_key};
        Error ->
            Error
    end.

-spec ec_set_private_key(ec_key(), ec_private_key()) -> ec_key() | {error, any()}.
ec_set_private_key({ec_key, KeyRef}, PrivateKey) when is_binary(PrivateKey) ->
    case ec_set_private_key_nif(KeyRef, PrivateKey) of
        ok ->
            {ec_key, KeyRef};
        error ->
            {error, unable_to_set_private_key};
        Error ->
            Error
    end.

-spec ec_delete_key(ec_key()) -> ok.
ec_delete_key({ec_key, KeyRef}) ->
    ec_delete_key_nif(KeyRef).

-spec ec_curve_size(ec_curve()) -> integer().
ec_curve_size(secp112r1) -> 112;
ec_curve_size(secp112r2) -> 112;
ec_curve_size(secp128r1) -> 128;
ec_curve_size(secp128r2) -> 128;
ec_curve_size(secp160k1) -> 160;
ec_curve_size(secp160r1) -> 160;
ec_curve_size(secp160r2) -> 160;
ec_curve_size(secp192k1) -> 192;
ec_curve_size(secp224k1) -> 224;
ec_curve_size(secp224r1) -> 224;
ec_curve_size(secp256k1) -> 256;
ec_curve_size(secp384r1) -> 384;
ec_curve_size(secp521r1) -> 521.

ec_new_by_curve_nif(_Curve) ->
    ?nif_stub.

ec_generate_key_nif(_Key) ->
    ?nif_stub.

ec_verify_nif(_Key, _Data, _Signature) ->
    ?nif_stub.

ec_sign_nif(_Key, _Data) ->
    ?nif_stub.

ec_get_public_key_nif(_Key) ->
    ?nif_stub.

ec_set_public_key_nif(_Key, _PublicKey) ->
    ?nif_stub.

ec_get_private_key_nif(_Key) ->
    ?nif_stub.

ec_set_private_key_nif(_Key, _PrivateKey) ->
    ?nif_stub.

ec_delete_key_nif(_Key) ->
    ?nif_stub.

%%
%% Utilities.
%%
-spec hex2bin(string()) -> binary().
hex2bin([A, B | Rest]) ->
    <<(list_to_integer([A, B], 16)), (hex2bin(Rest))/binary>>;
hex2bin([A]) ->
    <<(list_to_integer([A], 16))>>;
hex2bin([]) ->
    <<>>.

-spec bin2hex(binary()) -> string().
bin2hex(Bin) when is_binary(Bin) ->
    lists:flatten([integer_to_list(X, 16) || <<X:4/integer>> <= Bin]).

%%
%% Tests.
%%
-ifdef(TEST).

-spec test() -> any().

-spec hex2bin_test() -> any().
hex2bin_test() ->
    [
        ?assertEqual(hex2bin(""), <<>>),
        ?assertEqual(hex2bin("0"), <<0>>),
        ?assertEqual(hex2bin("00"), <<0>>),
        ?assertEqual(hex2bin("F"), <<15>>),
        ?assertEqual(hex2bin("0F"), <<15>>),
        ?assertEqual(hex2bin("F0"), <<240>>),
        ?assertEqual(hex2bin("FF"), <<255>>),
        ?assertEqual(hex2bin("FFFF"), <<255,255>>),
        ?assertEqual(hex2bin("000"), <<0,0>>),
        ?assertEqual(hex2bin("0001"), <<0,1>>),
        ?assertEqual(hex2bin("FFFFFFFF"), <<255,255,255,255>>)
    ].

-spec bin2hex_test() -> any().
bin2hex_test() ->
    [
        ?assertEqual("", bin2hex(<<>>)),
        ?assertEqual("00", bin2hex(<<0>>)),
        ?assertEqual("0F", bin2hex(<<15>>)),
        ?assertEqual("F0", bin2hex(<<240>>)),
        ?assertEqual("FF", bin2hex(<<255>>)),
        ?assertEqual("FFFF", bin2hex(<<255,255>>)),
        ?assertEqual("0000", bin2hex(<<0,0>>)),
        ?assertEqual("0001", bin2hex(<<0,1>>)),
        ?assertEqual("FFFFFFFF", bin2hex(<<255,255,255,255>>))
    ].

-spec ripemd160_simple_test() -> any().
ripemd160_simple_test() ->
    [
        ?assertEqual(hex2bin("9c1185a5c5e9fc54612808977ee8f548b2258d31"), ripemd160("")),
        ?assertEqual(hex2bin("ddadef707ba62c166051b9e3cd0294c27515f2bc"), ripemd160("A")),
        ?assertEqual(hex2bin("5d74fef3f73507f0e8a8ff9ec8cdd88988c472ca"), ripemd160("abcdefghijklmnopqrstuvwxyzæøå"))
    ].

-spec ripemd160_test() -> any().
ripemd160_test() ->
    List = ["abc", "def", "gh", "ijkl", "mno", "pqrs", "tuvwx", "yzæøå"],
    InitialContext = ripemd160_init(),
    FinalContext = lists:foldl(fun(X, Context) -> ripemd160_update(Context, X) end, InitialContext, List),
    ?assertEqual(hex2bin("5d74fef3f73507f0e8a8ff9ec8cdd88988c472ca"), ripemd160_final(FinalContext)).

foreach_curve(Fun) ->
    Curves = [secp112r1, secp112r2, secp128r1, secp128r2,
              secp160k1, secp160r1, secp160r2, secp192k1,
              secp224k1, secp224r1, secp256k1, secp384r1,
              secp521r1],
    lists:foreach(Fun, Curves).

-spec ec_new_key_test() -> any().
ec_new_key_test() ->
    foreach_curve(fun(Curve) -> ?assertEqual({ec_key, <<>>}, ec_new_key(Curve)) end),
    ?assertEqual({error, {unknown_curve, ok}}, ec_new_key(ok)),
    ?assertEqual({error, {unknown_curve, foobar}}, ec_new_key(foobar)).

-spec ec_public_key_test() -> any().
ec_public_key_test() ->
    foreach_curve(fun(Curve) ->
        Key = ec_new_key(Curve),
        ?assertEqual({ec_key, <<>>}, Key),

        PublicKeyData = ec_public_key(Key),
        ?assertEqual(Key, ec_set_public_key(Key, PublicKeyData)),
        ?assertEqual(PublicKeyData, ec_public_key(Key)),

        PublicKey = ec_new_public_key(Curve, PublicKeyData),
        ?assertEqual({ec_key, <<>>}, PublicKey),
        ?assertEqual(PublicKeyData, ec_public_key(PublicKey))
    end).

-spec ec_private_key_test() -> any().
ec_private_key_test() ->
    foreach_curve(fun(Curve) ->
        Key = ec_new_key(Curve),
        ?assertEqual({ec_key, <<>>}, Key),

        PrivateKeyData = ec_private_key(Key),
        ?assertEqual(Key, ec_set_private_key(Key, PrivateKeyData)),
        ?assertEqual(PrivateKeyData, ec_private_key(Key)),

        PrivateKey = ec_new_private_key(Curve, PrivateKeyData),
        ?assertEqual({ec_key, <<>>}, PrivateKey),
        ?assertEqual(PrivateKeyData, ec_private_key(PrivateKey))
    end).

-spec ec_verify_test() -> any().
ec_verify_test() ->
    Curve = secp256k1,
    PublicKeyData = "04218EBA91D19A0AB7EEA223A6D8693E4A48BA42A3FCA8EFE698501646A592143"
                    "1803C9D91977E36B75E155BAFE82DCE76A05B3C2022E0CE2F5FBCD237503C5215",
    SignatureData = "3046022100CBE747BCBFDE88F90798A86908B45903907419BAC49511A7BDFFF5F522B5EC"
                    "D4022100D3AC513B84D7D2E448EA2104B48D9684770751A3D0946A6DF03072306391A951",
    PublicKey = ec_new_public_key(Curve, hex2bin(PublicKeyData)),
    Signature = hex2bin(SignatureData),
    ?assert(ec_verify("Hello world!", Signature, PublicKey)),
    ?assertNot(ec_verify("Hello universe!", Signature, PublicKey)),
    ?assertNot(ec_verify("Hello world!", <<13,37>>, PublicKey)).

-spec ec_verify2_test() -> any().
ec_verify2_test() ->
    foreach_curve(fun(Curve) ->
        Key = ec_new_key(Curve),
        ?assertEqual({ec_key, <<>>}, Key),

        % Subtract 1 to make room for our "X".
        MaxBytes = ec_curve_size(Curve) div 8,
        Message = crypto:rand_bytes(MaxBytes - 1),

        Signature = ec_sign(Message, Key),
        ?assertMatch(X when is_binary(X), Signature),
        ?assert(ec_verify(Message, Signature, Key)),
        ?assertNot(ec_verify(<<Message/binary, "X">>, Signature, Key)),
        ?assertNot(ec_verify(<<"X", Message/binary>>, Signature, Key)),
        ?assertNot(ec_verify(Message, <<1337>>, Key))
    end).

-spec ec_verify_hash_test() -> any().
ec_verify_hash_test() ->
    Curve = secp256k1,
    PublicKeyData = "04F8C19E6176EEB1C73C784DFD84C5416CD4AC1EA6482EFE62565E6E93DEC4FD8"
                    "F8E08C4E806714EC7BB01CD250CB3F11F19C2F0AC9B83220792D3B282D3AB2A23",
    SignatureData = "30460221009FB323D1316549632592A05AC3D9EAA1636E2F8C0278815A946830B59266C7"
                    "D0022100A68D859FE8C990DD87E8710117EDC131606B8672039BF6871A604F45D3151CBB",
    PublicKey = ec_new_public_key(Curve, hex2bin(PublicKeyData)),
    Signature = hex2bin(SignatureData),
    ?assert(ec_verify_hash("Hello world!", fun crypto:sha256/1, Signature, PublicKey)),
    ?assertNot(ec_verify_hash("Hello universe!", fun crypto:sha256/1, Signature, PublicKey)),
    ?assertNot(ec_verify_hash("Hello world!", fun crypto:sha256/1, <<13,37>>, PublicKey)),
    ?assertNot(ec_verify_hash("Hello world!", fun crypto:sha/1, Signature, PublicKey)).

-spec ec_sign_hash_test() -> any().
ec_sign_hash_test() ->
    Curve = secp256k1,
    Key = ec_new_key(Curve),
    Signature = ec_sign_hash("Hello world!", fun crypto:sha256/1, Key),
    ?assert(ec_verify_hash("Hello world!", fun crypto:sha256/1, Signature, Key)),
    ?assertNot(ec_verify_hash("  Hello world!", fun crypto:sha256/1, Signature, Key)).

-spec ec_delete_key_test() -> any().
ec_delete_key_test() ->
    foreach_curve(fun(Curve) ->
        Key = ec_new_key(Curve),
        ?assertEqual(ok, ec_delete_key(Key)),
        ?assertEqual({error, uninitialized_key}, ec_delete_key(Key)),
        ?assertEqual({error, uninitialized_key}, ec_public_key(Key)),
        ?assertEqual({error, uninitialized_key}, ec_private_key(Key)),
        ?assertEqual({error, uninitialized_key}, ec_set_public_key(Key, <<>>)),
        ?assertEqual({error, uninitialized_key}, ec_set_private_key(Key, <<>>)),
        ?assertEqual({error, uninitialized_key}, ec_sign("Foobar", Key)),
        ?assertEqual({error, uninitialized_key}, ec_verify("Foobar", <<255>>, Key))
    end).

-endif.
