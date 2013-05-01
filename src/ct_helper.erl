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

-export([make_certs/0]).

-type der_encoded() :: binary().
-type key() :: {'RSAPrivateKey' | 'DSAPrivateKey' | 'PrivateKeyInfo',
	der_encoded()}.

%% @doc Create a set of certificates.
-spec make_certs()
	-> {CaCert::der_encoded(), Cert::der_encoded(), Key::key()}.
make_certs() ->
	CaInfo = {CaCert, _} = erl_make_certs:make_cert([{key, dsa}]),
	{Cert, Key0} = erl_make_certs:make_cert([{key, dsa}, {issuer, CaInfo}]),
	Key = erlang:delete_element(3, Key0),
	{CaCert, Cert, Key}.
