-module(ed25519).

-behaviour(gen_server).

-include_lib("../include/ed25519.hrl").

%% API
-export([start_link/0, keypairs/0, keypairs/1,
	 ed25519_keypair/0,  ed25519_keypair/1,
	 ed25519_pk_to_curve25519/1, ed25519_sk_to_curve25519/1,
	 dh_scalarmult_base/1, dh_scalarmult/2,
	 ed25519_sign/2, ed25519_verify/3, curve25519_verify/3,
	 helo/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-type ed25519_seed() :: <<_:(?crypto_sign_SEEDBYTES * 8)>>.
-type ed25519_public_key() :: <<_:(?crypto_sign_PUBLICKEYBYTES * 8)>>.
-type ed25519_secret_key() :: <<_:(?crypto_sign_SECRETKEYBYTES * 8)>>.
-type ed25519_bytes() :: <<_:(?crypto_sign_BYTES * 8)>>.
-type curve25519_scaler_bytes() :: <<_:(?crypto_scalarmult_SCALARBYTES * 8)>>.
-type curve25519_bytes() :: <<_:(?crypto_scalarmult_BYTES * 8)>>.

-export_types([ed25519_seed/0, ed25519_public_key/0, ed25519_secret_key/0,
	       ed25519_bytes/0, curve25519_scaler_bytes/0, curve25519_bytes/0]).

-define(SERVER, ?MODULE).
-record(state, {port}).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc
%% The ed25519_keypair function randomly generates a secret key and a
%% corresponding public key.
%% @end
-spec ed25519_keypair() -> {ok, 
			    {Ed25519_pk :: ed25519_public_key(), 
			     Ed25519_sk :: ed25519_secret_key()}} | 
			   {error, Reason :: term()}.
ed25519_keypair() ->
    gen_server:call(?SERVER, ed25519_keypair).

%% @doc
%% The ed25519_keypair function with a seed as argument,
%% deterministically generates a secret key and a corresponding public
%% key.
%% @end
-spec ed25519_keypair(Seed :: ed25519_seed()) 
		     -> {ok, {Ed25519_pk :: ed25519_public_key(), 
			      Ed25519_sk :: ed25519_secret_key()}} | 
			{error, Reason :: term()}.
ed25519_keypair(Seed) ->
    gen_server:call(?SERVER, {ed25519_keypair, Seed}).

%% @doc
%% The keypairs function randomly generates both a ed25519 and curve
%% 25519 secret key and a corresponding public keypair.
%% @end
-spec keypairs() -> {ok, 
		     {Ed25519_pk :: ed25519_public_key(), 
		      Ed25519_sk :: ed25519_secret_key()},
		     {Curve25519_pk :: curve25519_scaler_bytes(),
		      Curve25519_sk :: curve25519_scaler_bytes()}} | 
		    {error, Reason :: term()}.
keypairs() ->
    gen_server:call(?SERVER, keypairs).

%% @doc
%% The keypairs function with a seed as argument,
%% deterministically generates both a ed25519 and curve 25519 secret key and a corresponding public
%% keypair.
%% @end
-spec keypairs(Seed :: ed25519_seed()) 
	      -> {ok, 
		  {Ed25519_pk :: ed25519_public_key(), 
		   Ed25519_sk :: ed25519_secret_key()},
		  {Curve25519_pk :: curve25519_scaler_bytes(),
		   Curve25519_sk :: curve25519_scaler_bytes()}} | 
		 {error, Reason :: term()}.
keypairs(Seed) ->
    gen_server:call(?SERVER, {keypairs, Seed}).

%% @doc
%% The ed25519_pk_to_curve25519() function converts an Ed25519 public
%% key ed25519_pk to a Curve25519 public key.
%% @end
-spec ed25519_pk_to_curve25519(Ed25519_pk :: ed25519_public_key()) 
			      -> {ok, Curve25519_pk :: curve25519_scaler_bytes()} |
				 {error, Reason :: term()}.

ed25519_pk_to_curve25519(Ed25519_pk) ->
    gen_server:call(?SERVER, {ed25519_pk_to_curve25519, Ed25519_pk}).

%% @doc
%% The ed25519_sk_to_curve25519() function converts an Ed25519 secret
%% key ed25519_sk to a Curve25519 secret key.
%% @end
-spec ed25519_sk_to_curve25519(Ed25519_sk :: ed25519_secret_key()) 
			      -> {ok, Curve25519_sk :: curve25519_scaler_bytes()} |
				 {error, Reason :: term()}.

ed25519_sk_to_curve25519(Ed25519_sk) ->
    gen_server:call(?SERVER, {ed25519_sk_to_curve25519, Ed25519_sk}).

%% @doc
%% Given a user's secret key, the scalarmult_base() function computes
%% the user's public key.
%% @end
-spec dh_scalarmult_base(Curve25519_sk :: curve25519_scaler_bytes()) 
			-> {ok, Curve25519_pk :: curve25519_bytes()} |
			   {error, Reason :: term()}.
dh_scalarmult_base(Curve25519_sk) ->
    gen_server:call(?SERVER, {dh_scalarmult_base, Curve25519_sk}).

%% @doc
%% Given a user's secret key and another user's public key, the
%% scalarmult() function computes a secret shared by the two
%% users. This secret can then be used to authenticate and encrypt
%% messages between the two users.
%% @end
-spec dh_scalarmult(Curve25519_sk :: curve25519_scaler_bytes(),  % My secret key
		    Curve25519_pk :: curve25519_scaler_bytes())  % Their public key
		   -> {ok, Shared_secret :: curve25519_bytes()} | 
		      {error, Reason :: term()}.
dh_scalarmult(Curve25519_sk, Curve25519_pk) ->
    gen_server:call(?SERVER, {dh_scalarmult, Curve25519_sk, Curve25519_pk}).

%% @doc
%% The ed25519_sign() function signs the message using the secret key.
%% @end
-spec ed25519_sign(Ed25519_sk :: ed25519_secret_key(), Message :: list())
		  -> {ok, Signatuter :: ed25519_bytes()} |
		     {error, Reason :: term()}.
ed25519_sign(Ed25519_sk, Message) ->
    gen_server:call(?SERVER, {ed25519_sign, Ed25519_sk, Message}).

%% @doc
%% The ed25519_verify() function verifies that the signature is for
%% the given message.
%% @end
-spec ed25519_verify(Ed25519_pk :: ed25519_public_key(), Message :: list(), 
		     Signature :: ed25519_bytes()) 
		    -> {ok, true | false} |
		       {error, Reason :: term()}.
ed25519_verify(Ed25519_pk, Message, Signature) ->
    gen_server:call(?SERVER, {ed25519_verify, Ed25519_pk, Message, Signature}).

%% @doc
%% The curve25519_verify() function verifies that the signature is for
%% the given message. It first converts the curve25519 public key to a
%% ed25519 public key before verifying the signature.
%% @end
-spec curve25519_verify(Curve25519_pk :: curve25519_scaler_bytes(), Message :: list(), 
			Signature :: ed25519_bytes()) 
		       -> {ok, true | false} |
			  {error, Reason :: term()}.
curve25519_verify(Curve25519_pk, Message, Signature) ->
    gen_server:call(?SERVER, {curve25519_verify, Curve25519_pk, Message, Signature}).

%% @doc
%% Say hello to the sodium library.
%% @end
helo() ->
    gen_server:call(?SERVER, helo).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Port = case code:priv_dir(ed25519) of % argument is the name of the application
	       {error, _} ->
		   exit(error);
	       Priv_dir ->
		   open_port({spawn, filename:join([Priv_dir, "ed25519_drv"])},
			     [binary, {packet, 4}, exit_status])
	   end,
    % error_logger:info_msg("Port ~p", [erlang:port_info(Port)]),
    {ok, #state{port = Port}}.

handle_call(Msg, _From, #state{port = Port} = State) ->
    Port ! {self(), {command, encode(Msg)}},
    receive
    	{Port, {data, Data}} ->
    	    {reply, decode(Data), State}
    end;
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Port, Reason}, State) -> % TODO: Ever used?
    error_logger:format("port ~p exited with reason ~p", [Port, Reason]),
    {stop, {port_terminated, Reason}, State};
handle_info({Port, {exit_status, Status}}, #state{port = Port} = State) ->
    decode_exit_status(Status),
    {stop, {port_terminated, Status}, State};
handle_info(Info, State) ->
    error_logger:warning_msg("Unhandled info ~p", [Info]),
    {noreply, State}.

terminate({port_terminated, _Reason}, _State) ->
    %% Port is already closed.
    ok;
terminate(_Reason, #state{port = Port} = _State) ->
    port_close(Port),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
encode(helo) ->
    term_to_binary({0});
encode(ed25519_keypair) ->
    term_to_binary({1});
encode({ed25519_keypair, Seed}) ->
    term_to_binary({2, Seed});
encode(keypairs) ->
    term_to_binary({3});
encode({keypairs, Seed}) ->
    term_to_binary({4, Seed});
encode({ed25519_pk_to_curve25519, Ed25519_pk}) ->
    term_to_binary({5, Ed25519_pk});
encode({ed25519_sk_to_curve25519, Ed25519_sk}) ->
    term_to_binary({6, Ed25519_sk});
encode({dh_scalarmult_base, Curve25519_sk}) ->
    term_to_binary({7, Curve25519_sk});
encode({dh_scalarmult, Curve25519_sk, Curve25519_pk}) ->
    term_to_binary({8, Curve25519_sk, Curve25519_pk});
encode({ed25519_sign, Ed25519_sk, Message}) ->
    term_to_binary({9, Ed25519_sk, Message});
encode({ed25519_verify, Ed25519_pk, Message, Signature}) ->
    term_to_binary({10, Ed25519_pk, Message, Signature});
encode({curve25519_verify, Curve25519_pk, Message, Signature}) ->
    term_to_binary({11, Curve25519_pk, Message, Signature}).

%% @private
decode(Data) ->
    binary_to_term(Data).

%% @private
decode_exit_status(1) -> error_logger:error_msg("Could not allocate memory");
decode_exit_status(2) -> error_logger:error_msg("Could not free memory");
decode_exit_status(3) -> error_logger:error_msg("Could not read from stdin");
decode_exit_status(4) -> error_logger:error_msg("Could not read packet header");
decode_exit_status(5) -> error_logger:error_msg("Could not read packet body");
decode_exit_status(6) -> error_logger:error_msg("Wrong packet body size");
decode_exit_status(7) -> error_logger:error_msg("Could not open library");
decode_exit_status(8) -> error_logger:error_msg("Wrong keader size argument passed to program");
decode_exit_status(Status) when Status > 128 ->
    error_logger:error_msg("Port terminated with signal: ~p", [Status - 128]);
decode_exit_status(Status) -> error_logger:error_msg("Port terminated with status: ~p", [Status]).

