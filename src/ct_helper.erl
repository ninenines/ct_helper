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
-export([get_parent_pid/1]).
-export([get_remote_pid_tcp/1]).
-export([get_remote_pid_tls/1]).
-export([ignore/3]).
-export([is_process_down/1]).
-export([is_process_down/2]).
-export([make_certs/0]).
-export([make_certs_in_ets/0]).
-export([make_certs_in_dir/1]).
-export([name/0]).
-export([start/1]).

-type der_encoded() :: binary().
-type key() :: {'RSAPrivateKey' | 'DSAPrivateKey' | 'PrivateKeyInfo',
	der_encoded()}.

-include_lib("ssl/src/ssl_connection.hrl").

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
	ok = file:write_file(Path ++ "/empty.txt", ""),
	ok = file:write_file(Path ++ "/plain.txt", "Timeless space.\n"),
	ok = file:write_file(Path ++ "/UPPER.TXT", "Uppercase file name.\n"),
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
	ok = file:delete(Path ++ "/UPPER.TXT"),
	ok = file:delete(Path ++ "/empty.txt"),
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

%% @doc Get the parent pid of a proc_lib process.

get_parent_pid(Pid) ->
	{_, ProcDict} = process_info(Pid, dictionary),
	{_, [Parent|_]} = lists:keyfind('$ancestors', 1, ProcDict),
	Parent.

%% @doc Find the pid of the remote end of a TCP socket.
%%
%% This function must be run on the same node as the pid we want.

get_remote_pid_tcp(Socket) when is_port(Socket) ->
	get_remote_pid_tcp(inet:sockname(Socket));
get_remote_pid_tcp(SockName) ->
	AllPorts = [{P, erlang:port_info(P)} || P <- erlang:ports()],
	[Pid] = [
		proplists:get_value(connected, I)
	|| {P, I} <- AllPorts,
		I =/= undefined,
		proplists:get_value(name, I) =:= "tcp_inet",
		inet:peername(P) =:= SockName],
	Pid.

%% @doc Find the pid of the remote end of a TLS socket.
%%
%% This function must be run on the same node as the pid we want.

get_remote_pid_tls(Socket) ->
	%% This gives us the pid of the sslsocket process.
	%% We must introspect this process in order to retrieve the connection pid.
	TLSPid = get_remote_pid_tcp(ssl:sockname(Socket)),
	get_tls_state(TLSPid).

-ifdef(OTP_RELEASE).
-if(?OTP_RELEASE >= 22).
get_tls_state(TLSPid) ->
	{_, #state{connection_env=#connection_env{user_application={_, UserPid}}}} = sys:get_state(TLSPid),
	UserPid.
-else.
%% This is defined in ssl_record.hrl starting from OTP-21.3.
-ifdef(KNOWN_RECORD_TYPE).
get_tls_state(TLSPid) ->
	{_, #state{connection_env=#connection_env{user_application={_, UserPid}}}} = sys:get_state(TLSPid),
	UserPid.
-else.
get_tls_state(TLSPid) ->
	{_, #state{user_application={_, UserPid}}} = sys:get_state(TLSPid),
	UserPid.
-endif.
-endif.
-else.
get_tls_state(TLSPid) ->
	{_, #state{user_application={_, UserPid}}} = sys:get_state(TLSPid),
	UserPid.
-endif.

%% @doc Ignore crashes from Pid occuring in M:F/A.

ignore(M, F, A) ->
	ct_helper_error_h:ignore(M, F, A).

%% @doco Similar to erlang:is_process_alive/1 except
%% it uses monitors and waits up to a timeout.
%%
%% The return value is also the opposite of alive (down).

is_process_down(Pid) ->
	is_process_down(Pid, 1000).

is_process_down(Pid, Timeout) ->
	MRef = monitor(process, Pid),
	receive
		{'DOWN', MRef, process, Pid, _} ->
			true
	after Timeout ->
		false
	end.

%% @doc Create a set of certificates.

-spec make_certs()
	-> {CaCert::der_encoded(), Cert::der_encoded(), Key::key()}.
make_certs() ->
	Opts = public_key:pkix_test_data(#{
		root => [{digest, sha256}, {key, {rsa, 2048, 17}}],
		peer => [{digest, sha256}, {key, {rsa, 2048, 17}}]
	}),
	{
		proplists:get_value(cacerts, Opts),
		proplists:get_value(cert, Opts),
		proplists:get_value(key, Opts)
	}.

%% @doc Create a set of certificates and store them in a directory.

make_certs_in_dir(Dir) ->
	{CaCerts, Cert, Key} = make_certs(),
	CertFile = filename:join(Dir, "cert.pem"),
	CaCertsFile = filename:join(Dir, "cacerts.pem"),
	KeyFile = filename:join(Dir, "key.pem"),
	CertPem = public_key:pem_encode([{'Certificate', Cert, not_encrypted}]),
	CaCertsPem = public_key:pem_encode(
		[{'Certificate', CaCert, not_encrypted} || CaCert <- CaCerts]),
	{KeyAsn1Type, KeyDer} = Key,
	KeyPem = public_key:pem_encode([{KeyAsn1Type, KeyDer, not_encrypted}]),
	ok = file:write_file(CertFile, CertPem),
	ok = file:write_file(CaCertsFile, CaCertsPem),
	ok = file:write_file(KeyFile, KeyPem),
	{CaCertsFile, CertFile, KeyFile}.

%% @doc Create a set of certificates and store them in an ets table.
%%
%% The verify options are there so that:
%%
%% - We retrieve client certificates when they are provided.
%% - We accept self-signed certificates.
%%
%% They have no effect otherwise.

make_certs_in_ets() ->
	{CaCerts, Cert, Key} = make_certs(),
	VerifyFun = fun
		(_, {bad_cert, _}, UserState) ->
			{valid, UserState};
		(_, {extension, #'Extension'{critical=true}}, UserState) ->
			{valid, UserState};
		(_, {extension, _}, UserState) ->
			{unknown, UserState};
		(_, valid, UserState) ->
			{valid, UserState};
		(_, valid_peer, UserState) ->
			{valid, UserState}
	end,
	CertOpts = [
		{cert, Cert}, {key, Key}, {cacerts, CaCerts},
		{verify, verify_peer}, {verify_fun, {VerifyFun, []}},
		%% We stick to TLS 1.2 because our certificates are not
		%% secure enough for use with TLS 1.3.
		{versions, ['tlsv1.2']}
	],
	Pid = spawn(fun() -> receive shutdown -> ok after infinity -> ok end end),
	?MODULE = ets:new(?MODULE, [ordered_set, public, named_table,
		{heir, Pid, undefined}]),
	ets:insert(?MODULE, {cert_opts, CertOpts}),
	ok.

%% @doc Return the name of the calling function.
%%
%% DEPRECATED: Use ?FUNCTION_NAME instead.

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
