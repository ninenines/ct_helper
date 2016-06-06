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

-module(ct_helper).

-export([all/1]).
-export([config/2]).
-export([create_static_dir/1]).
-export([delete_static_dir/1]).
-export([doc/1]).
-export([get_certs_from_ets/0]).
-export([get_loopback_mtu/0]).
-export([ignore/3]).
-export([make_certs/0]).
-export([make_certs_in_ets/0]).
-export([name/0]).
-export([start/1]).

-type der_encoded() :: binary().
-type key() :: {'RSAPrivateKey' | 'DSAPrivateKey' | 'PrivateKeyInfo',
	der_encoded()}.

%% @doc List all test cases in the suite.
%%
%% Functions test and do_* are considered internal and are ignored.

all(Suite) ->
	lists:usort([F || {F, 1} <- Suite:module_info(exports),
		F =/= module_info,
		F =/= test, %% This is leftover from the eunit parse_transform...
		F =/= all,
		F =/= groups,
		string:substr(atom_to_list(F), 1, 5) =/= "init_",
		string:substr(atom_to_list(F), 1, 4) =/= "end_",
		string:substr(atom_to_list(F), 1, 3) =/= "do_"
	]).

%% @doc Quick configuration value retrieval.

config(Key, Config) ->
	{_, Value} = lists:keyfind(Key, 1, Config),
	Value.

%% @doc Create a directory with various useful files for testing.

create_static_dir(Path) ->
	ok = filelib:ensure_dir(Path ++ "/file"),
	ok = file:make_dir(Path ++ "/directory"),
	ok = file:write_file(Path ++ "/unknown", "File with no extension.\n"),
	ok = file:write_file(Path ++ "/file.cowboy", "File with custom extension.\n"),
	ok = file:write_file(Path ++ "/plain.txt", "Timeless space.\n"),
	ok = file:write_file(Path ++ "/style.css", "body{color:red}\n"),
	ok = file:write_file(Path ++ "/index.html",
		"<html><body>Hello!</body></html>\n"),
	ok = file:write_file(Path ++ "/unreadable", "unreadable\n"),
	ok = file:change_mode(Path ++ "/unreadable", 8#0333),
	ok.

%% @doc Delete the directory created with create_static_dir/1

delete_static_dir(Path) ->
	ok = file:delete(Path ++ "/unreadable"),
	ok = file:delete(Path ++ "/index.html"),
	ok = file:delete(Path ++ "/style.css"),
	ok = file:delete(Path ++ "/plain.txt"),
	ok = file:delete(Path ++ "/file.cowboy"),
	ok = file:delete(Path ++ "/unknown"),
	ok = file:del_dir(Path ++ "/directory"),
	ok = file:del_dir(Path),
	ok.

%% @doc Test case description.

doc(String) ->
	ct:comment(String),
	ct:log(String).

%% @doc Retrieve previously created certificates from the ets table.

get_certs_from_ets() ->
	ets:lookup_element(?MODULE, cert_opts, 2).

%% @doc Return the MTU for the loopback interface.

get_loopback_mtu() ->
	{ok, Interfaces} = inet:getiflist(),
	[LocalInterface | _ ] = lists:filter(fun(Interface) ->
		{ok, [{flags, Flags}]} = inet:ifget(Interface, [flags]),
		lists:member(loopback, Flags)
	end, Interfaces),
	{ok, [{mtu, MTU}]} = inet:ifget(LocalInterface, [mtu]),
	MTU.

%% @doc Ignore crashes from Pid occuring in M:F/A.

ignore(M, F, A) ->
	ct_helper_error_h:ignore(M, F, A).

%% @doc Create a set of certificates.

-spec make_certs()
	-> {CaCert::der_encoded(), Cert::der_encoded(), Key::key()}.
make_certs() ->
	CaInfo = {CaCert, _} = erl_make_certs:make_cert([{key, dsa}]),
	{Cert, {Asn1Type, Der, _}} = erl_make_certs:make_cert([{key, dsa}, {issuer, CaInfo}]),
	{CaCert, Cert, {Asn1Type, Der}}.

%% @doc Create a set of certificates and store them in an ets table.

make_certs_in_ets() ->
	{_, Cert, Key} = ct_helper:make_certs(),
	CertOpts = [{cert, Cert}, {key, Key}],
	Pid = spawn(fun() -> receive after infinity -> ok end end),
	?MODULE = ets:new(?MODULE, [ordered_set, public, named_table,
		{heir, Pid, undefined}]),
	ets:insert(?MODULE, {cert_opts, CertOpts}),
	ok.

%% @doc Return the name of the calling function.

name() ->
	element(2, hd(tl(element(2, process_info(self(), current_stacktrace))))).

%% @doc Start and stop applications and their dependencies.

start(Apps) ->
	_ = [do_start(App) || App <- Apps],
	ok.

do_start(App) ->
	case application:start(App) of
		ok ->
			ok;
		{error, {not_started, Dep}} ->
			do_start(Dep),
			do_start(App)
	end.
