%% Copyright (c) 2013, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Helper functions for common_test suites.
-module(ct_helper).

-export([create_static_dir/1]).
-export([delete_static_dir/1]).
-export([make_certs/0]).

-type der_encoded() :: binary().
-type key() :: {'RSAPrivateKey' | 'DSAPrivateKey' | 'PrivateKeyInfo',
	der_encoded()}.

create_static_dir(Path) ->
	ok = file:make_dir(Path),
	ok = file:make_dir(Path ++ "/directory"),
	ok = file:write_file(Path ++ "/unknown", "File with no extension.\n"),
	ok = file:write_file(Path ++ "/style.css", "body{color:red}\n"),
	ok = file:write_file(Path ++ "/index.html",
		"<html><body>Hello!</body></html>\n"),
	ok = file:write_file(Path ++ "/unreadable", "unreadable\n"),
	ok = file:change_mode(Path ++ "/unreadable", 8#0333),
	ok.

delete_static_dir(Path) ->
	ok = file:delete(Path ++ "/unreadable"),
	ok = file:delete(Path ++ "/index.html"),
	ok = file:delete(Path ++ "/style.css"),
	ok = file:delete(Path ++ "/unknown"),
	ok = file:del_dir(Path ++ "/directory"),
	ok = file:del_dir(Path),
	ok.

%% @doc Create a set of certificates.
-spec make_certs()
	-> {CaCert::der_encoded(), Cert::der_encoded(), Key::key()}.
make_certs() ->
	CaInfo = {CaCert, _} = erl_make_certs:make_cert([{key, dsa}]),
	{Cert, {Asn1Type, Der, _}} = erl_make_certs:make_cert([{key, dsa}, {issuer, CaInfo}]),
	{CaCert, Cert, {Asn1Type, Der}}.
