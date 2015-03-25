-module(ed25519_tests).

-include_lib("eunit/include/eunit.hrl").

basic_test_() ->
    {"Start server, check connection and process test vectors",
      setup,
     fun start/0,  % setup function
     fun stop/1,   % teardown function
     fun (SetupData) -> % instantiator
	     [helo(SetupData),
	      process_test_vectors(SetupData)]
     end}.

start() ->
    {ok, Pid} = ed25519:start_link(),
    Pid.
 
stop(Pid) ->
    exit(Pid, normal).

helo(_) ->
    [?_assertEqual(ok, ed25519:helo())].
    
process_test_vectors(_) ->
    {ok, F} = file:open("../test/sign.input", read),
    Result = process_vectors(F, 1),
    [?_assert(Result)].

process_vectors(File, Acc) ->
    %error_logger:info_msg("Line ~p", [Acc]),
    case io:get_line(File, "") of
	eof ->
	    file:close(File),
	    true;
	Line ->
	    case doit(Line) of
		false ->
		    file:close(File),
		    false;
		true ->
		    process_vectors(File, Acc + 1)
	    end
    end.

doit(Line) ->
    [Sk, Pk, M, Sm] = case string:tokens(Line, ":") of
			  [Sk_, Pk_, M_, Sm_, "\n"] ->
			      [Sk_, Pk_, M_, Sm_];
			  [Sk_, Pk_, Sm_, "\n"] ->
			      [Sk_, Pk_, [], Sm_]
		      end,
    L = length(Sm) - length(M),
    {S, _} = lists:split(L, Sm),
    Secret_key = to_bin(Sk),
    Public_key = to_bin(Pk),
    Message = to_list(M),
    Signature = to_bin(S),
    %% error_logger:info_msg("Message ~p", [Message]),
    %% error_logger:info_msg("Sign ~p l ~p", [Sign, byte_size(Secret_key)]),
    %% error_logger:info_msg("Calc Sign ~p", [ed25519:ed25519_sign(Secret_key, Message)]),
    {ok, Signature} =:= ed25519:ed25519_sign(Secret_key, Message) andalso
	{ok, true} =:= ed25519:ed25519_verify(Public_key, Message, Signature).

to_bin(L) ->
    iolist_to_binary(to_list(L, [])).

to_list(L) ->
    to_list(L, []).

to_list([], Acc) ->
    lists:reverse(Acc);
to_list([C1, C2 | Rest], Acc) ->
    to_list(Rest, [(dehex(C1) bsl 4) bor dehex(C2) | Acc]).

dehex(C) when C >= $0, C =< $9 ->
    C - $0;
dehex(C) when C >= $a, C =< $f ->
    C - $a + 10;
dehex(C) when C >= $A, C =< $F ->
    C - $A + 10.
