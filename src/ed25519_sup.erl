-module(ed25519_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {#{strategy => one_for_all},
	  [#{id => ed25519,
	     start => {ed25519, start_link, []},
	     restart => permanent,
	     type => worker}]}}.

