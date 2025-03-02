%% Copyright (c) 2014, Loïc Hoguin <essen@ninenines.eu>
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

-module(ct_helper_error_h).
-behaviour(gen_event).

%% Public interface.
-export([ignore/3]).
-export([ignore/4]).

%% gen_event.
-export([init/1]).
-export([handle_event/2]).
-export([handle_call/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

%% Public interface.

%% Ignore crashes from self() occuring in M:F/A.
ignore(M, F, A) ->
	ignore(self(), M, F, A).

%% Ignore crashes from Pid occuring in M:F/A.
ignore(Pid, M, F, A) ->
	error_logger ! {expect, {Pid, M, F, A}},
	ok.

%% gen_event.

init(_) ->
	spawn(fun() -> error_logger:tty(false) end),
	{ok, []}.

%% Ignore supervisor and progress reports.
handle_event({info_report, _, {_, progress, _}}, State) ->
	{ok, State};
handle_event({info_report, _, {_, std_info, _}}, State) ->
	{ok, State};
handle_event({error_report, _, {_, supervisor_report, _}}, State) ->
	{ok, State};
%% Ignore gun retry failures.
handle_event({error_report, _, {_, crash_report,
		[[{initial_call, {gun, init, _}}, _, _,
			{error_info, {error, gone, _}}|_]|_]}},
		State) ->
	{ok, State};
%% Ignore emulator reports that are a duplicate of what Ranch gives us.
handle_event(Event = {error, GL, {emulator, "Error in process ~p" ++ _, Args}}, State)
		when node(GL) =:= node(), is_list(Args) ->
	[Pid, _Node, {_Error, [{Mod, Fun, Arity, _}|_]}] = Args,
	Crash = {Pid, Mod, Fun, Arity},
	case lists:member(Crash, State) of
		true ->
			{ok, lists:delete(Crash, State)};
		false ->
			write_event(Event),
			{ok, State}
	end;
%% The emulator always sends strings for errors in older OTP versions,
%% which makes it very difficult to extract the information we need,
%% hence the regexps.
handle_event(Event = {error, GL, {emulator, _, Msg}}, State)
		when node(GL) =:= node(), is_list(Msg) ->
	Result = re:run(Msg,
		"Error in process ([^\s]+).+? with exit value: "
			".+?{stacktrace,\\[{([^,]+),([^,]+),(.+)",
		[{capture, all_but_first, list}]),
	case Result of
		nomatch ->
			write_event(Event),
			{ok, State};
		{match, [PidStr, MStr, FStr, Rest]} ->
			A = case Rest of
				"[]" ++ _ ->
					0;
				"[" ++ Rest2 ->
					count_args(Rest2, 1, 0);
				_ ->
					{match, [AStr]} = re:run(Rest, "([^,]+).+",
						[{capture, all_but_first, list}]),
					list_to_integer(AStr)
			end,
			Crash = {list_to_pid(PidStr), list_to_existing_atom(MStr),
				list_to_existing_atom(FStr), A},
			case lists:member(Crash, State) of
				true ->
					{ok, lists:delete(Crash, State)};
				false ->
					write_event(Event),
					{ok, State}
			end
	end;
%% Cowboy 2.0: error coming from Ranch.
handle_event(Event = {error, GL,
		{_, "Ranch listener" ++ _, [_, _, Pid, {_, [{M, F, A, _}|_]}]}},
		State) when node(GL) =:= node() ->
	A2 = if is_list(A) -> length(A); true -> A end,
	Crash = {Pid, M, F, A2},
	case lists:member(Crash, State) of
		true ->
			{ok, lists:delete(Crash, State)};
		false ->
			write_event(Event),
			{ok, State}
	end;
%% Cowboy 2.0: error coming from Cowboy.
handle_event(Event = {error, GL,
		{_, "Ranch listener" ++ _, [_, _, _, Pid, _, [{M, F, A, _}|_]|_]}},
		State) when node(GL) =:= node() ->
	A2 = if is_list(A) -> length(A); true -> A end,
	Crash = {Pid, M, F, A2},
	case lists:member(Crash, State) of
		true ->
			{ok, lists:delete(Crash, State)};
		false ->
			write_event(Event),
			{ok, State}
	end;
%% Cowboy 2.13+: error coming from Cowboy.
handle_event(Event = {error, GL,
		{_, "Ranch listener" ++ _, [_, _, _, Pid, {_, [{M, F, A, _}|_]}|_]}},
		State) when node(GL) =:= node() ->
	A2 = if is_list(A) -> length(A); true -> A end,
	Crash = {Pid, M, F, A2},
	case lists:member(Crash, State) of
		true ->
			{ok, lists:delete(Crash, State)};
		false ->
			write_event(Event),
			{ok, State}
	end;
handle_event(Event = {error, GL,
		{_, "Ranch listener" ++ _, [_, _, _, _Pid, ct_helper_ignore|_]}},
		State) when node(GL) =:= node() ->
	{ok, State};
%% Cowboy 1.0.
handle_event(Event = {error, GL,
		{_, "Ranch listener" ++ _, [_, _, _, Pid, {cowboy_handler, [_, _, _,
			{stacktrace, [{M, F, A, _}|_]}|_]}]}},
		State) when node(GL) =:= node() ->
	A2 = if is_list(A) -> length(A); true -> A end,
	Crash = {Pid, M, F, A2},
	case lists:member(Crash, State) of
		true ->
			{ok, lists:delete(Crash, State)};
		false ->
			write_event(Event),
			{ok, State}
	end;
handle_event(Event = {_, GL, _}, State) when node(GL) =:= node() ->
	write_event(Event),
	{ok, State};
handle_event(_, State) ->
	{ok, State}.

handle_call(_, State) ->
	{ok, {error, bad_query}, State}.

handle_info({expect, Crash}, State) ->
	{ok, [Crash, Crash|State]};
handle_info(_, State) ->
	{ok, State}.

terminate(_, _) ->
	spawn(fun() -> error_logger:tty(true) end),
	ok.

code_change(_, State, _) ->
	{ok, State}.

%% Internal.

write_event(Event) ->
	_ = error_logger_tty_h:write_event(
		{erlang:universaltime(), Event},
		io),
	ok.

count_args("]" ++ _, N, 0) ->
	N;
count_args("]" ++ Tail, N, Levels) ->
	count_args(Tail, N, Levels - 1);
count_args("[" ++ Tail, N, Levels) ->
	count_args(Tail, N, Levels + 1);
count_args("}" ++ Tail, N, Levels) ->
	count_args(Tail, N, Levels - 1);
count_args("{" ++ Tail, N, Levels) ->
	count_args(Tail, N, Levels + 1);
count_args("," ++ Tail, N, Levels = 0) ->
	count_args(Tail, N + 1, Levels);
count_args("," ++ Tail, N, Levels) ->
	count_args(Tail, N, Levels);
count_args([_|Tail], N, Levels) ->
	count_args(Tail, N, Levels).
